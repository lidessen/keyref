package com.lidessen.keyref.source.crypto

import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.util.encoders.Hex
import org.json.JSONObject

/**
 * The §3.9 message envelope: random 256-bit message key, AES-256-GCM body,
 * the key HPKE-wrapped per recipient. The source seals to the active
 * owners at receipt time; the owner backfills the decider's wrap later
 * (§6.30), which is why the wrap records are deliberately not covered by
 * the upload signature.
 * Byte layout (docs/protocol.md §3.9):
 *
 *   u8 wrap_count ‖ per recipient (sorted by device_id hex ascending):
 *       u16be(32) ‖ device_id(hex ascii) ‖ u16be(enc_len) ‖ enc ‖ wrapped(48)
 *   ‖ body = nonce(12) ‖ ct ‖ tag(16)
 *
 * HPKE suite: RFC 9180 Base mode, DHKEM + HKDF-SHA256 + AES-256-GCM
 * (protocol §1.4); the KEM follows the recipient's hpke_kem — X25519 for
 * a 32-byte key, P-256 for a 65-byte SEC1 point (the same length rule as
 * proto/crypto.kemForPublicKey). Per-wrap info = "keyref v1" US
 * source-message US vault_id US recipient_device_id; body AAD = the same
 * shape with purpose "message" and the reporting source device (the
 * server-generated message_id does not exist yet when the source seals).
 *
 * BouncyCastle's org.bouncycastle.crypto.hpke implements RFC 9180; this
 * wrapper isolates the library surface so interop drift against proto/
 * crypto (circl) is a one-file fix. The golden-vector gate is
 * CryptoVectorsTest against ios/Tests/KeyrefCoreTests/Fixtures/vectors.json
 * (design §9.2).
 */
object Envelope {

    private const val US: Byte = 0x1f
    private const val WRAPPED_SIZE = 48 // HPKE ct(32 bytes key) ‖ tag(16) (§3.9)
    private val ID = Regex("^[0-9a-f]{32}$")

    private fun MutableList<Byte>.put(bytes: ByteArray) {
        addAll(bytes.toList())
    }

    fun infoBase(purpose: String, vaultId: String, recipientDeviceId: String): ByteArray {
        val b = ArrayList<Byte>(64)
        b.put("keyref v1".toByteArray(Charsets.US_ASCII)); b.add(US)
        b.put(purpose.toByteArray(Charsets.US_ASCII)); b.add(US)
        b.put(vaultId.toByteArray(Charsets.US_ASCII)); b.add(US)
        b.put(recipientDeviceId.toByteArray(Charsets.US_ASCII))
        return b.toByteArray()
    }

    fun bodyAad(vaultId: String, sourceDeviceId: String): ByteArray =
        infoBase("message", vaultId, sourceDeviceId)

    /** §1.4 KEM id from the public-key encoding (32B X25519 / 65B P-256). */
    private fun kemFor(recipientHpkePub: ByteArray): Short = when (recipientHpkePub.size) {
        32 -> HPKE.kem_X25519_SHA256
        65 -> HPKE.kem_P256_SHA256
        else -> throw IllegalArgumentException("unknown HPKE public key length ${recipientHpkePub.size}")
    }

    private fun hpke(kemId: Short): HPKE =
        HPKE(HPKE.mode_base, kemId, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256)

    /**
     * HPKE-wraps the message key to one recipient; returns enc and the
     * 48-byte wrapped key (empty AAD — all binding lives in info, §1.5).
     */
    fun sealTo(recipientDeviceId: String, vaultId: String, recipientHpkePub: ByteArray, messageKey: ByteArray): Pair<ByteArray, ByteArray> {
        val h = hpke(kemFor(recipientHpkePub))
        val ctx = h.setupBaseS(
            h.deserializePublicKey(recipientHpkePub),
            infoBase("source-message", vaultId, recipientDeviceId),
        )
        val enc = ctx.encapsulation
        val wrapped = ctx.seal(ByteArray(0), messageKey)
        require(wrapped.size == WRAPPED_SIZE) { "unexpected wrap length ${wrapped.size}" }
        return enc to wrapped
    }

    /**
     * Builds the full envelope for one SMS plaintext (the §3.9 JSON) to
     * the given recipients. Recipients are deduped and ordered by
     * device_id hex ascending — the same canonical order the server's
     * backfill merge (§6.30) preserves.
     */
    fun build(
        vaultId: String,
        sourceDeviceId: String,
        recipients: List<Pair<String, ByteArray>>, // device_id to HPKE public key
        plaintext: ByteArray,
    ): ByteArray {
        require(recipients.isNotEmpty()) { "no recipients" }
        val messageKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        try {
            val body = encryptBody(vaultId, sourceDeviceId, messageKey, plaintext)
            val sorted = recipients.sortedBy { it.first }.distinctBy { it.first }
            val out = ArrayList<Byte>(body.size + 128)
            out.add(sorted.size.toByte())
            for ((deviceId, pub) in sorted) {
                val (enc, wrapped) = sealTo(deviceId, vaultId, pub, messageKey)
                val id = deviceId.toByteArray(Charsets.US_ASCII)
                out.add((id.size ushr 8).toByte()); out.add(id.size.toByte())
                out.put(id)
                out.add((enc.size ushr 8).toByte()); out.add(enc.size.toByte())
                out.put(enc)
                out.put(wrapped)
            }
            out.put(body)
            return out.toByteArray()
        } finally {
            messageKey.fill(0x00)
        }
    }

    /** AES-256-GCM body blob: nonce(12) ‖ ct ‖ tag(16), AAD bound (§1.5, §3.9). */
    private fun encryptBody(vaultId: String, sourceDeviceId: String, messageKey: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, javax.crypto.spec.SecretKeySpec(messageKey, "AES"))
        cipher.updateAAD(bodyAad(vaultId, sourceDeviceId))
        val ct = cipher.doFinal(plaintext)
        return cipher.iv + ct
    }

    /**
     * Splits an envelope into its recipient records and the trailing body
     * blob — the Kotlin twin of proto/crypto.SplitMessageEnvelope
     * (structural only; nothing is decrypted). The upload transcript
     * signs H(body) from this split (§3.9, v2 C), and a malformed
     * envelope must fail exactly where the server's strict splitter
     * fails, before any signature is produced.
     */
    fun splitBody(envelope: ByteArray): ByteArray {
        fun fail(what: String): Nothing = throw IllegalArgumentException("message envelope $what")
        if (envelope.isEmpty()) fail("truncated")
        val n = envelope[0].toInt() and 0xFF
        if (n < 1) fail("has no recipients")
        var p = 1
        repeat(n) {
            if (p + 2 > envelope.size) fail("truncated")
            val idLen = ((envelope[p].toInt() and 0xFF) shl 8) or (envelope[p + 1].toInt() and 0xFF)
            p += 2
            if (idLen != 32 || p + idLen + 2 > envelope.size) fail("record truncated")
            val id = String(envelope, p, idLen, Charsets.US_ASCII)
            if (!ID.matches(id)) fail("has a malformed device_id")
            p += idLen
            val encLen = ((envelope[p].toInt() and 0xFF) shl 8) or (envelope[p + 1].toInt() and 0xFF)
            p += 2
            if (encLen == 0 || p + encLen + WRAPPED_SIZE > envelope.size) fail("record truncated")
            p += encLen + WRAPPED_SIZE
        }
        if (p >= envelope.size) fail("has no body")
        return envelope.copyOfRange(p, envelope.size)
    }

    /** The §3.9 plaintext JSON for one SMS (≤ 4 KiB after truncation). */
    fun plaintextJson(sender: String, body: String, sim: String, receivedAt: Long): ByteArray {
        val json = JSONObject()
            .put("v", 1)
            .put("sender", sender)
            .put("body", body)
            .put("sim", sim)
            .put("received_at", receivedAt)
        return json.toString().toByteArray(Charsets.UTF_8)
    }

    fun hex(bytes: ByteArray): String = Hex.toHexString(bytes)
}
