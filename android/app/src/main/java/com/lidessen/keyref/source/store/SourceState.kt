package com.lidessen.keyref.source.store

import android.content.Context
import android.content.SharedPreferences
import com.lidessen.keyref.source.crypto.Keys
import java.io.File
import org.json.JSONArray
import org.json.JSONObject

/**
 * The collector's local state (design §14.2): origin, pairing result,
 * pinned owner key, session token, and the upload queue. Private keys
 * never land here in the clear — [Keys.saveIdentity] wraps them with the
 * Keystore master key (design §14.2 documents the weaker-than-keyring
 * storage; this device holds no vault secrets).
 */
object SourceState {

    private const val PREFS = "keyref_source"
    private const val KEY_ORIGIN = "origin"
    private const val KEY_VAULT = "vault_id"
    private const val KEY_DEVICE = "device_id"
    private const val KEY_OWNER_SIGN = "owner_sign_pub_hex"
    private const val KEY_TOKEN = "token"
    private const val KEY_TOKEN_EXPIRES = "token_expires_at"
    private const val KEY_DIRECTORY_SIGNED = "directory_signed_b64"
    private const val KEY_DIRECTORY_SIG = "directory_signature_b64"
    private const val KEY_PAIR_NONCE = "pair_nonce"
    private const val KEY_FILTER_SENDERS = "filter_senders"
    private const val KEY_COLLECT_ENABLED = "collect_enabled"
    private const val KEY_LOG = "log_tail"

    // Outbox: queued envelopes awaiting upload (ciphertext at rest, §14.7).
    private const val OUTBOX_FILE = "outbox.jsonl"

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun keysFile(ctx: Context): File = File(ctx.filesDir, "identity.bin")
    fun outboxFile(ctx: Context): File = File(ctx.filesDir, OUTBOX_FILE)

    fun getOrigin(ctx: Context): String = prefs(ctx).getString(KEY_ORIGIN, "") ?: ""
    fun setOrigin(ctx: Context, v: String) = prefs(ctx).edit().putString(KEY_ORIGIN, v).apply()

    fun isPaired(ctx: Context): Boolean = getVaultId(ctx).isNotEmpty()
    fun getVaultId(ctx: Context): String = prefs(ctx).getString(KEY_VAULT, "") ?: ""
    fun getDeviceId(ctx: Context): String = prefs(ctx).getString(KEY_DEVICE, "") ?: ""
    fun getOwnerSignPubHex(ctx: Context): String = prefs(ctx).getString(KEY_OWNER_SIGN, "") ?: ""
    fun getToken(ctx: Context): String = prefs(ctx).getString(KEY_TOKEN, "") ?: ""
    fun getTokenExpires(ctx: Context): Long = prefs(ctx).getLong(KEY_TOKEN_EXPIRES, 0)
    fun getDirectoryB64(ctx: Context): String = prefs(ctx).getString(KEY_DIRECTORY, "") ?: ""
    fun getPairNonce(ctx: Context): String = prefs(ctx).getString(KEY_PAIR_NONCE, "") ?: ""
    fun isCollectEnabled(ctx: Context): Boolean = prefs(ctx).getBoolean(KEY_COLLECT_ENABLED, false)
    fun getSenders(ctx: Context): Set<String> = prefs(ctx).getStringSet(KEY_FILTER_SENDERS, emptySet()) ?: emptySet()
    fun getLogTail(ctx: Context): String = prefs(ctx).getString(KEY_LOG, "") ?: ""

    fun setPaired(
        ctx: Context,
        vaultId: String,
        deviceId: String,
        ownerSignPubHex: String,
        directorySignedB64: String,
        directorySignatureB64: String,
    ) {
        prefs(ctx).edit()
            .putString(KEY_VAULT, vaultId)
            .putString(KEY_DEVICE, deviceId)
            .putString(KEY_OWNER_SIGN, ownerSignPubHex)
            .putString(KEY_DIRECTORY_SIGNED, directorySignedB64)
            .putString(KEY_DIRECTORY_SIG, directorySignatureB64)
            .putString(KEY_PAIR_NONCE, "")
            .apply()
    }

    fun setToken(ctx: Context, token: String, expiresAt: Long) =
        prefs(ctx).edit().putString(KEY_TOKEN, token).putLong(KEY_TOKEN_EXPIRES, expiresAt).apply()

    fun setPairNonce(ctx: Context, nonce: String) = prefs(ctx).edit().putString(KEY_PAIR_NONCE, nonce).apply()

    fun setDirectory(ctx: Context, signed: ByteArray, signature: ByteArray) =
        prefs(ctx).edit()
            .putString(KEY_DIRECTORY_SIGNED, Base64.encodeToString(signed, Base64.NO_WRAP))
            .putString(KEY_DIRECTORY_SIG, Base64.encodeToString(signature, Base64.NO_WRAP))
            .apply()

    fun getDirectorySigned(ctx: Context): ByteArray {
        val b64 = prefs(ctx).getString(KEY_DIRECTORY_SIGNED, "") ?: ""
        return if (b64.isEmpty()) ByteArray(0) else Base64.decode(b64, Base64.NO_WRAP)
    }

    fun setCollectEnabled(ctx: Context, v: Boolean) = prefs(ctx).edit().putBoolean(KEY_COLLECT_ENABLED, v).apply()

    fun setSenders(ctx: Context, senders: Set<String>) =
        prefs(ctx).edit().putStringSet(KEY_FILTER_SENDERS, senders).apply()

    fun appendLog(ctx: Context, line: String) {
        val p = prefs(ctx)
        val old = p.getString(KEY_LOG, "") ?: ""
        val tail = (old + "\n" + line).split("\n").takeLast(8).joinToString("\n")
        p.edit().putString(KEY_LOG, tail).apply()
    }

    /** Complete unpair: forget pairing state, keep the identity keys. */
    fun resetPairing(ctx: Context) {
        prefs(ctx).edit()
            .remove(KEY_VAULT).remove(KEY_DEVICE).remove(KEY_OWNER_SIGN)
            .remove(KEY_TOKEN).remove(KEY_TOKEN_EXPIRES)
            .remove(KEY_DIRECTORY_SIGNED).remove(KEY_DIRECTORY_SIG)
            .remove(KEY_PAIR_NONCE)
            .apply()
        outboxFile(ctx).delete()
    }

    // -- outbox ------------------------------------------------------------

    @Synchronized
    fun enqueue(ctx: Context, envelopeB64: String, receivedAt: Long) {
        val arr = readOutbox(ctx)
        arr.put(JSONObject().put("envelope", envelopeB64).put("received_at", receivedAt))
        writeOutbox(ctx, arr)
    }

    @Synchronized
    fun queueSnapshot(ctx: Context): JSONArray = readOutbox(ctx)

    @Synchronized
    fun removeQueued(ctx: Context, index: Int) {
        val arr = readOutbox(ctx)
        if (index in 0 until arr.length()) {
            val next = JSONArray()
            for (i in 0 until arr.length()) if (i != index) next.put(arr.get(i))
            writeOutbox(ctx, next)
        }
    }

    private fun readOutbox(ctx: Context): JSONArray {
        val f = outboxFile(ctx)
        if (!f.exists()) return JSONArray()
        return runCatching { JSONArray(f.readText()) }.getOrDefault(JSONArray())
    }

    private fun writeOutbox(ctx: Context, arr: JSONArray) {
        outboxFile(ctx).writeText(arr.toString())
    }
}
