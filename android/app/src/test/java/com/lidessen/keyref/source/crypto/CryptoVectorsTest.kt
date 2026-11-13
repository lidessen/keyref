package com.lidessen.keyref.source.crypto

import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.util.encoders.Hex
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The cross-language golden-vector gate for the Android collector
 * (design §9.2): every byte asserted here must equal what the Go
 * reference (proto/) generated into
 * ios/Tests/KeyrefCoreTests/Fixtures/vectors.json. If one of these fails,
 * the Kotlin side drifted from the wire format — fix the code, never the
 * fixture.
 */
class CryptoVectorsTest {

    private val vectors: JSONObject by lazy { JSONObject(loadVectors().readText()) }

    // -- transcripts ------------------------------------------------------

    @Test
    fun pairRegisterTranscriptMatchesGo() {
        val vec = vectors.getJSONObject("pair_register_transcript")
        val fields = vec.getJSONObject("fields")
        val bytes = Transcripts.pairRegister(
            Hex.decode(fields.getString("nonce_raw_hex")),
            fields.getString("proposed_name"),
        )
        assertArrayEquals(Hex.decode(vec.getString("bytes_hex")), bytes)
    }

    /**
     * The §3.4 pair transcript the pairing MAC covers. The fixture's
     * transcript carries two grants; this device only ever registers with
     * an empty grant set, so assert the shared prefix against the fixture
     * and the zero-count tail against the spec (u64be(0) NUL, no grant
     * transcripts behind it).
     */
    @Test
    fun pairTranscriptMatchesGoWithEmptyGrants() {
        val vec = vectors.getJSONObject("pair_transcript")
        val fields = vec.getJSONObject("fields")
        val ownerPub = Hex.decode(fields.getString("owner_sign_public_hex"))
        val hpkePub = Hex.decode(fields.getString("hpke_public_key_hex"))
        val signPub = Hex.decode(fields.getString("sign_public_key_hex"))

        val bytes = Transcripts.pairTranscript(
            fields.getString("vault_id"), ownerPub, fields.getString("nonce"),
            fields.getString("device_id"),
            fields.getString("hpke_kem"), hpkePub, fields.getString("sign_alg"), signPub,
            fields.getString("label"),
        )

        // Everything up to and including the label separator is identical
        // whatever the grant count is: compare against the fixture prefix.
        val fixture = Hex.decode(vec.getString("bytes_hex"))
        val prefixLen = bytes.size - 9 // our tail is u64be(0) ‖ NUL (9 bytes)
        assertTrue("transcript shorter than its own tail", fixture.size >= prefixLen)
        assertArrayEquals(
            "field order or separators drifted from the pair transcript",
            fixture.copyOfRange(0, prefixLen),
            bytes.copyOfRange(0, prefixLen),
        )
        assertEquals(2, fields.getInt("grant_count"))
        assertArrayEquals(Transcripts.u64be(0) + byteArrayOf(0), bytes.copyOfRange(prefixLen, bytes.size))
    }

    @Test
    fun pairConfirmMacMatchesGo() {
        val vec = vectors.getJSONObject("pair_confirm_mac")
        val c = Hex.decode(vec.getString("confirm_secret_hex"))
        val pairTB = Hex.decode(vec.getString("pair_transcript_hex"))
        val mac = Transcripts.pairConfirmMac(c, vec.getString("kind"), pairTB)
        assertArrayEquals(Hex.decode(vec.getString("pairing_mac_hex")), mac)
        // A MAC under a different secret is not merely different, it is the
        // failure the pairing check must catch (§3.13).
        assertTrue(!mac.contentEquals(Hex.decode(vec.getString("wrong_secret_pairing_mac_hex"))))
    }

    /** §3.9 v2 C: the signed tail is H(body), not the whole envelope. */
    @Test
    fun messageUploadTranscriptMatchesGo() {
        val vec = vectors.getJSONObject("message_upload_transcript")
        val fields = vec.getJSONObject("fields")
        val body = Hex.decode(fields.getString("body_hex"))
        val envelope = framedEnvelope(fields.getString("source_device_id"), body)
        val bytes = Transcripts.messageUpload(
            fields.getString("vault_id"),
            fields.getString("source_device_id"),
            fields.getLong("received_at"),
            envelope,
        )
        assertArrayEquals(Hex.decode(vec.getString("bytes_hex")), bytes)
        // The signed bytes end with the raw body digest, no trailing NUL.
        assertArrayEquals(Transcripts.sha256(body), bytes.copyOfRange(bytes.size - 32, bytes.size))
    }

    /** A malformed envelope must fail where the server's splitter fails. */
    @Test
    fun messageUploadRejectsTruncatedEnvelope() {
        val fields = vectors.getJSONObject("message_upload_transcript").getJSONObject("fields")
        val envelope = framedEnvelope(fields.getString("source_device_id"), Hex.decode(fields.getString("body_hex")))
        // Drop the last body byte: the frame still parses, but a body that
        // short is fine for the splitter — cut inside a record instead.
        val truncated = envelope.copyOfRange(0, envelope.size - 40)
        try {
            Transcripts.messageUpload(fields.getString("vault_id"), fields.getString("source_device_id"), 1, truncated)
            throw AssertionError("truncated envelope was accepted")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("envelope"))
        }
    }

    // -- HPKE (§1.4 suite, §3.9 info) -------------------------------------

    @Test
    fun hpkeSealToX25519RecipientMatchesGo() = assertHpkeVector("X25519")

    @Test
    fun hpkeSealToP256RecipientMatchesGo() = assertHpkeVector("P-256")

    /**
     * Deterministic re-seal: deriveKeyPair(seed) + setupBaseS(peer, info,
     * eph) is the RFC 9180 test-vector path BouncyCastle documents, so the
     * encapsulation and ciphertext must byte-match what circl produced
     * into the fixture for the same seed.
     */
    private fun assertHpkeVector(kemName: String) {
        val vec = hpkeVector(kemName)
        val kemId = when (kemName) {
            "X25519" -> HPKE.kem_X25519_SHA256
            "P-256" -> HPKE.kem_P256_SHA256
            else -> throw AssertionError("unknown kem $kemName")
        }
        val h = HPKE(HPKE.mode_base, kemId, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256)
        val eph = h.deriveKeyPair(Hex.decode(vec.getString("encapsulation_seed_hex")))
        val peer = h.deserializePublicKey(Hex.decode(vec.getString("recipient_public_hex")))
        val ctx = h.setupBaseS(peer, Hex.decode(vec.getString("info_hex")), eph)
        assertArrayEquals(
            "encapsulation drifted from circl ($kemName)",
            Hex.decode(vec.getString("enc_hex")),
            ctx.encapsulation,
        )
        val ct = ctx.seal(ByteArray(0), Hex.decode(vec.getString("plaintext_hex")))
        assertArrayEquals(
            "HPKE ciphertext drifted from circl ($kemName)",
            Hex.decode(vec.getString("ct_hex")),
            ct,
        )
    }

    private fun hpkeVector(kemName: String): JSONObject {
        val keys = vectors.keys()
        while (keys.hasNext()) {
            val o = vectors.optJSONObject(keys.next()) ?: continue
            if (o.optString("kem") == kemName) return o
        }
        throw AssertionError("no HPKE vector with kem=$kemName")
    }

    // -- body blob (§1.5 AES-256-GCM) -------------------------------------

    @Test
    fun aeadBlobMatchesGo() {
        val vec = vectors.getJSONObject("aead_blob")
        val key = Hex.decode(vec.getString("key_hex"))
        val nonce = Hex.decode(vec.getString("nonce_hex"))
        val aad = Hex.decode(vec.getString("aad_hex"))
        val pt = Hex.decode(vec.getString("plaintext_hex"))
        val blob = Hex.decode(vec.getString("blob_hex"))

        val enc = Cipher.getInstance("AES/GCM/NoPadding")
        enc.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        enc.updateAAD(aad)
        val ct = enc.doFinal(pt)
        assertArrayEquals(blob, nonce + ct)

        val dec = Cipher.getInstance("AES/GCM/NoPadding")
        dec.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        dec.updateAAD(aad)
        assertArrayEquals(pt, dec.doFinal(blob.copyOfRange(12, blob.size)))
    }

    /** §3.9 body AAD: "keyref v1" US message US vault US source device. */
    @Test
    fun bodyAadMatchesSpec() {
        val vaultId = vectors.getJSONObject("message_upload_transcript")
            .getJSONObject("fields").getString("vault_id")
        val deviceId = vectors.getJSONObject("message_upload_transcript")
            .getJSONObject("fields").getString("source_device_id")
        val expected = (
            "keyref v1" + 0x1f.toChar() + "message" + 0x1f.toChar() +
                vaultId + 0x1f.toChar() + deviceId
            ).toByteArray(Charsets.US_ASCII)
        assertArrayEquals(expected, Envelope.bodyAad(vaultId, deviceId))
    }

    // -- helpers ----------------------------------------------------------

    /** A structurally valid one-record envelope around [body] (§3.9). */
    private fun framedEnvelope(deviceId: String, body: ByteArray): ByteArray {
        val id = deviceId.toByteArray(Charsets.US_ASCII)
        val enc = ByteArray(32) { 0x11 }
        val wrapped = ByteArray(48) { 0x22 }
        val out = ArrayList<Byte>(1 + 2 + id.size + 2 + enc.size + wrapped.size + body.size)
        out.add(1) // wrap_count
        out.add((id.size ushr 8).toByte()); out.add(id.size.toByte())
        out.addAll(id.toList())
        out.add((enc.size ushr 8).toByte()); out.add(enc.size.toByte())
        out.addAll(enc.toList())
        out.addAll(wrapped.toList())
        out.addAll(body.toList())
        return out.toByteArray()
    }

    /** Walks up from the working directory to the repo root. */
    private fun loadVectors(): File {
        val rel = "ios/Tests/KeyrefCoreTests/Fixtures/vectors.json"
        var dir: File? = File(".").absoluteFile
        while (dir != null) {
            val f = File(dir, rel)
            if (f.isFile) return f
            dir = dir.parentFile
        }
        throw AssertionError("vectors.json not found above ${File(".").absolutePath}")
    }
}
