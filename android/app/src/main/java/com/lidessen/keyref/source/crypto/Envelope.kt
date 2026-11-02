package com.lidessen.keyref.source.crypto

import org.bouncycastle.hpke.AEAD.AEAD_AES256GCM
import org.bouncycastle.hpke.HPKE
import org.bouncycastle.hpke.KDF.KDF_HKDF_SHA256
import org.bouncycastle.hpke.KEM.KEM_X25519_HKDF_SHA256
import org.bouncycastle.util.encoders.Hex
import org.json.JSONObject

/**
 * The §3.9 message envelope: random 256-bit message key, AES-256-GCM body,
 * the key HPKE-wrapped to every active owner and any delegated decider.
 * Byte layout (docs/protocol.md §3.9, D15):
 *
 *   u8 wrap_count ‖ per recipient (sorted by device_id hex ascending):
 *       u16be(32) ‖ device_id(hex ascii) ‖ u16be(enc_len) ‖ enc ‖ wrapped(48)
 *   ‖ body = nonce(12) ‖ ct ‖ tag(16)
 *
 * HPKE suite: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-256-GCM
 * (protocol §1.4), info = "keyref v1" US source-message US vault_id US
 * recipient_device_id; body AAD = "keyref v1" US message US vault_id US
 * source_device_id (mirrors the audit envelope D12 — the server-generated
 * message_id does not exist yet when the source seals).
 *
 * BouncyCastle's org.bouncycastle.hpke implements RFC 9180 directly; this
 * wrapper isolates the library surface so interop drift against
 * proto/crypto (circl) is a one-file fix. The golden-vector gate is
 * proto/crypto/testdata (design §9.2).
 */
object Envelope {

    private const val US: Byte = 0x1f

    private fun infoBase(purpose: String, vaultId: String, recipientDeviceId: String): ByteArray {
        val b = ArrayList<Byte>(64)
        b.addAll("keyref v1".toByteArray(Charsets.US_ASCII)); b.add(US)
        b.addAll(purpose.toByteArray(Charsets.US_ASCII)); b.add(US)
        b.addAll(vaultId.toByteArray(Charsets.US_ASCII)); b.add(US)
        b.addAll(recipientDeviceId.toByteArray(Charsets.US_ASCII))
        return b.toByteArray()
    }

    fun bodyAad(vaultId: String, sourceDeviceId: String): ByteArray =
        infoBase("message", vaultId, sourceDeviceId)

    fun sealTo(recipientDeviceId: String, vaultId: String, recipientX25519Pub: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val hpke = HPKE(KEM_X25519_HKDF_SHA256(), KDF_HKDF_SHA256(), AEAD_AES256GCM())
        val sender = hpke.makeSender(org.bouncycastle.math.ec.rfc7748.X25519PublicKeyParameters(recipientX25519Pub, 0))
        val secretWithEnc = sender.setupBaseS(infoBase("source-message", vaultId, recipientDeviceId))
        val enc = secretWithEnc.enc
        val wrapped = sender.seal(ByteArray(0), plaintext)
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
        recipients: List<Pair<String, ByteArray>>, // device_id to X25519 public key
        plaintext: ByteArray,
    ): ByteArray {
        require(recipients.isNotEmpty()) { "no recipients" }
        val hpke = HPKE(KEM_X25519_HKDF_SHA256(), KDF_HKDF_SHA256(), AEAD_AES256GCM())
        val bodyAad = bodyAad(vaultId, sourceDeviceId)
        val messageKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }

        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, javax.crypto.spec.SecretKeySpec(messageKey, "AES"))
        val body = cipher.iv + cipher.doFinal(bodyAad, plaintext)

        val sorted = recipients.sortedBy { it.first }.distinctBy { it.first }
        val out = ArrayList<Byte>(body.size + 128)
        out.add(sorted.size.toByte())
        for ((deviceId, pub) in sorted) {
            val sender = hpke.makeSender(org.bouncycastle.math.ec.rfc7748.X25519PublicKeyParameters(pub, 0))
            val swe = sender.setupBaseS(infoBase("source-message", vaultId, deviceId))
            val enc = swe.enc
            val wrapped = sender.seal(ByteArray(0), messageKey)
            require(wrapped.size == 48) { "unexpected wrap length ${wrapped.size}" } // HPKE ct: 32B key + 16B tag (§3.9)
            val id = deviceId.toByteArray(Charsets.US_ASCII)
            out.add((id.size ushr 8).toByte()); out.add(id.size.toByte())
            out.addAll(id.toList())
            out.add((enc.size ushr 8).toByte()); out.add(enc.size.toByte())
            out.addAll(enc.toList())
            out.addAll(wrapped.toList())
        }
        out.addAll(body.toList())
        messageKey.fill(0x00)
        return out.toByteArray()
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
