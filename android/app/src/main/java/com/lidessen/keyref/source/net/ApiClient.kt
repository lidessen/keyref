package com.lidessen.keyref.source.net

import android.content.Context
import android.util.Base64
import com.lidessen.keyref.source.crypto.Keys
import com.lidessen.keyref.source.crypto.Transcripts
import com.lidessen.keyref.source.store.SourceState
import java.security.Security
import java.security.Signature
import java.security.spec.ECPublicKeySpec
import java.util.concurrent.TimeUnit
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.json.JSONObject

/**
 * The thin HTTP client for the source device (protocol v1.2 §5.7/§5.16/
 * §5.18/§5.8/§5.28). Every signature uses the §3 transcripts byte-exact;
 * every blob is standard base64 (§1.1).
 *
 * Owner signatures are ECDSA P-256 / ASN.1 DER over SHA-256 (protocol
 * §1.4): the pairing signature, the directory signature and the
 * delegation transcript all verify under the pinned owner public key.
 */
class ApiClient(private val ctx: Context) {

    companion object {
        init {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.insertProviderAt(BouncyCastleProvider(), 1)
            }
        }

        fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
        fun unb64(s: String): ByteArray = Base64.decode(s, Base64.NO_WRAP)
        fun hexBytes(hex: String): ByteArray {
            val out = ByteArray(hex.length / 2)
            for (i in out.indices) {
                out[i] = ((Character.digit(hex[i * 2], 16) shl 4) or Character.digit(hex[i * 2 + 1], 16)).toByte()
            }
            return out
        }

        /** ECDSA P-256 / ASN.1 verify under a SEC1-uncompressed public key. */
        fun verifyOwnerSignature(data: ByteArray, signature: ByteArray, ownerSignPub: ByteArray): Boolean {
            val spec = ECNamedCurveTable.getParameterSpec("P-256")
            val point = spec.curve.decodePoint(ownerSignPub)
            val pub = java.security.KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
                .generatePublic(ECPublicKeySpec(point, spec))
            val verifier = Signature.getInstance("SHA256withECDSA", BouncyCastleProvider.PROVIDER_NAME)
            verifier.initVerify(pub)
            verifier.update(data)
            return verifier.verify(signature)
        }
    }

    private val http: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(8, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    private fun post(origin: String, path: String, body: JSONObject, token: String? = null): Pair<Int, JSONObject> {
        val b = Request.Builder()
            .url(origin.trimEnd('/') + path)
            .post(body.toString().toRequestBody(jsonMedia))
        if (token != null) b.header("Authorization", "Bearer $token")
        http.newCall(b.build()).execute().use { resp ->
            return resp.code to JSONObject(resp.body?.string() ?: "{}")
        }
    }

    private fun get(origin: String, path: String, token: String?): Pair<Int, JSONObject> {
        val b = Request.Builder().url(origin.trimEnd('/') + path).get()
        if (token != null) b.header("Authorization", "Bearer $token")
        http.newCall(b.build()).execute().use { resp ->
            return resp.code to JSONObject(resp.body?.string() ?: "{}")
        }
    }

    private fun identity(): Keys.Identity {
        return Keys.loadIdentity(SourceState.keysFile(ctx))
            ?: throw IllegalStateException("identity not generated")
    }

    /** §6.16 pair/register. */
    fun pairRegister(origin: String, identity: Keys.Identity, nonceHex: String): Int {
        val nonceRaw = hexBytes(nonceHex)
        val tb = Transcripts.pairRegister(nonceRaw, "android-source")
        val sig = Keys.sign(identity, tb)
        val body = JSONObject()
            .put("nonce", nonceHex)
            .put("hpke_kem", "X25519")
            .put("hpke_public_key", b64(identity.x25519Public))
            .put("sign_alg", "ed25519")
            .put("sign_public_key", b64(identity.ed25519Public))
            .put("proposed_name", "android-source")
            .put("signature", b64(sig))
        return post(origin, "/v1/pair/register", body).first
    }

    /** §6.18 pair/status poll result. */
    sealed class PairResult {
        object Pending : PairResult()
        object Expired : PairResult()
        data class Complete(
            val vaultId: String,
            val deviceId: String,
            val ownerSignPub: ByteArray,
            val directorySigned: ByteArray,
            val directorySignature: ByteArray,
        ) : PairResult()
    }

    fun pairStatus(origin: String, nonceHex: String, identity: Keys.Identity): PairResult {
        val (code, body) = get(origin, "/v1/pair/status?nonce=$nonceHex", null)
        if (code == 410) return PairResult.Expired
        if (code != 200) return PairResult.Pending
        return when (body.optString("status")) {
            "pending", "" -> PairResult.Pending
            "expired" -> PairResult.Expired
            "complete" -> {
                val dirSigned = unb64(body.getString("directory_signed"))
                val dirSig = unb64(body.getString("directory_signature"))
                val ownerPub = unb64(body.getString("owner_sign_public_key"))
                val vaultId = body.getString("vault_id")
                val deviceId = body.getString("device_id")
                // Pin: verify the §3.4 pair transcript (empty grant set) and
                // the §3.3 directory signature under the returned owner key,
                // then run the fail-closed directory shape check (§3.3).
                val pairTB = buildPairTranscript(
                    vaultId, ownerPub, hexBytes(nonceHex), deviceId,
                    "X25519", identity.x25519Public, "ed25519", identity.ed25519Public,
                    "android-source"
                )
                if (!verifyOwnerSignature(pairTB, unb64(body.getString("pairing_signature")), ownerPub)) {
                    throw SecurityException("pairing signature verify failed")
                }
                if (!verifyOwnerSignature(dirSigned, dirSig, ownerPub)) {
                    throw SecurityException("directory signature verify failed")
                }
                Transcripts.parseDirectory(dirSigned)
                PairResult.Complete(vaultId, deviceId, ownerPub, dirSigned, dirSig)
            }
            else -> PairResult.Pending
        }
    }

    /**
     * §3.4 pair transcript with an EMPTY grant set: the count is zero and
     * the trailing NUL separator is still present (BuildPairTranscript
     * appends u64be(count) NUL before the concatenated grant transcripts).
     */
    private fun buildPairTranscript(
        vaultId: String, ownerSignPub: ByteArray, nonce: ByteArray, deviceId: String,
        kem: String, hpkePub: ByteArray, signAlg: String, signPub: ByteArray, label: String,
    ): ByteArray {
        val FS: Byte = 0x00
        val b = ArrayList<Byte>(160)
        fun add(bytes: ByteArray) = b.addAll(bytes.toList())
        fun addSep() = b.add(FS)
        add("KEYREF1".toByteArray(Charsets.US_ASCII)); addSep()
        add("pair".toByteArray(Charsets.US_ASCII)); addSep()
        add(vaultId.toByteArray(Charsets.US_ASCII)); addSep()
        add(ownerSignPub); addSep()
        add(nonce); addSep()
        add(deviceId.toByteArray(Charsets.US_ASCII)); addSep()
        add(kem.toByteArray(Charsets.US_ASCII)); addSep()
        add(hpkePub); addSep()
        add(signAlg.toByteArray(Charsets.US_ASCII)); addSep()
        add(signPub); addSep()
        add(label.toByteArray(Charsets.UTF_8)); addSep()
        add(Transcripts.u64be(0)) // grant_count = 0
        addSep()
        return b.toByteArray()
    }

    /** §6.7 session: challenge → signed §3.6 transcript → bearer token. */
    fun ensureSession(): String {
        val existing = SourceState.getToken(ctx)
        val expires = SourceState.getTokenExpires(ctx)
        if (existing.isNotEmpty() && expires > System.currentTimeMillis() + 60_000) return existing
        val origin = SourceState.getOrigin(ctx)
        val deviceId = SourceState.getDeviceId(ctx)
        val (c1, challengeBody) = post(origin, "/v1/session", JSONObject().put("device_id", deviceId))
        if (c1 != 200) throw IllegalStateException("session step1 HTTP $c1")
        val challenge = unb64(challengeBody.getString("challenge"))
        val tb = Transcripts.session(deviceId, challenge)
        val sig = Keys.sign(identity(), tb)
        val (c2, resp) = post(
            origin, "/v1/session",
            JSONObject()
                .put("device_id", deviceId)
                .put("challenge", challengeBody.getString("challenge"))
                .put("signature", b64(sig))
        )
        if (c2 != 200) throw IllegalStateException("session step2 HTTP $c2")
        val token = resp.getString("token")
        SourceState.setToken(ctx, token, resp.getLong("expires_at"))
        return token
    }

    /**
     * §5.8 sync (cursor=0): pull the current directory, verify its
     * signature under the pinned owner key, store signed + signature.
     */
    fun refreshDirectory() {
        val origin = SourceState.getOrigin(ctx)
        val (_, body) = get(origin, "/v1/sync?cursor=0", ensureSession())
        val changes = body.getJSONArray("changes")
        for (i in 0 until changes.length()) {
            val ch = changes.getJSONObject(i)
            if (ch.optString("entity") == "directory") {
                val data = ch.getJSONObject("data")
                val signed = unb64(data.getString("directory_signed"))
                val signature = unb64(data.getString("directory_signature"))
                val ownerPub = hexBytes(SourceState.getOwnerSignPubHex(ctx))
                if (!verifyOwnerSignature(signed, signature, ownerPub)) {
                    throw SecurityException("directory signature verify failed on refresh")
                }
                Transcripts.parseDirectory(signed)
                SourceState.setDirectory(ctx, signed, signature)
                return
            }
        }
        throw IllegalStateException("no directory change in bootstrap")
    }

    /** Active owner X25519 keys from the signed directory (§14.3). */
    fun activeOwnerKeys(): List<Pair<String, ByteArray>> {
        val signed = SourceState.getDirectorySigned(ctx)
        return Transcripts.parseDirectory(signed)
            .filter { it.isActiveOwner }
            .map { it.deviceId to it.hpkePublicKey }
    }

    /** §6.28 POST /v1/messages. Returns true on 201. */
    fun uploadMessage(envelope: ByteArray, receivedAt: Long): Boolean {
        val vaultId = SourceState.getVaultId(ctx)
        val deviceId = SourceState.getDeviceId(ctx)
        val tb = Transcripts.messageUpload(vaultId, deviceId, receivedAt, envelope)
        val sig = Keys.sign(identity(), tb)
        val body = JSONObject()
            .put("envelope", b64(envelope))
            .put("request_signature", b64(sig))
            .put("received_at", receivedAt)
        val origin = SourceState.getOrigin(ctx)
        val req = Request.Builder()
            .url(origin.trimEnd('/') + "/v1/messages")
            .header("Authorization", "Bearer ${ensureSession()}")
            .post(body.toString().toRequestBody(jsonMedia))
            .build()
        http.newCall(req).execute().use { resp ->
            resp.body?.string()
            return resp.code == 201
        }
    }
}
