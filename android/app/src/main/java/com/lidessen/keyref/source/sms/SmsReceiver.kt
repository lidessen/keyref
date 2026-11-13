package com.lidessen.keyref.source.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import com.lidessen.keyref.source.crypto.Envelope
import com.lidessen.keyref.source.net.ApiClient
import com.lidessen.keyref.source.store.SourceState

/**
 * The collector (design v0.8 §14.2): the system wakes this receiver for
 * every SMS even with the process dead. Flow: local filter rules →
 * envelope at receive time (ciphertext queues locally, §14.7) →
 * WorkManager upload with backoff.
 *
 * The filter rules are DEVICE-LOCAL plaintext (design §14.2): the source
 * cannot decrypt anything, so rules have nowhere to sync — the owner
 * curates the sender allowlist on this phone.
 */
class SmsReceiver : BroadcastReceiver() {

    companion object {
        // A verification code looks like a short standalone digit group
        // (banks/services rarely go below 4 or above 8 digits for OTPs).
        private val CODE_PATTERN = Regex("(^|[^0-9])[0-9]{4,8}([^0-9]|$)")
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        if (!SourceState.isCollectEnabled(context)) return
        val messages = try {
            Telephony.Sms.Intents.getMessagesFromIntent(intent)
        } catch (e: Exception) {
            null
        } ?: return
        if (messages.isEmpty()) return

        val sender = messages.first().originatingAddress ?: return
        val body = messages.joinToString("") { it.messageBody ?: "" }
        val receivedAt = messages.first().timestampMillis

        // §14.2: sender allowlist + code-shape match. An empty allowlist
        // collects nothing — the owner turns collection on per sender.
        val allow = SourceState.getSenders(context)
        if (sender !in allow) return
        if (!CODE_PATTERN.containsMatchIn(body)) return

        // Seal now: wrap the §3.9 plaintext to every active owner. If the
        // directory is stale (new owner added elsewhere), this message
        // stays sealed to the known owners — the 24h TTL and re-synced
        // directory cover the drift, mirroring design §14.3.
        val vaultId = SourceState.getVaultId(context)
        if (vaultId.isEmpty()) return
        val deviceId = SourceState.getDeviceId(context)
        val plaintext = Envelope.plaintextJson(sender, body, "", receivedAt)
        val owners = try {
            ApiClient(context).activeOwnerKeys()
        } catch (e: Exception) {
            SourceState.appendLog(context, "owner keys: ${e.message}")
            return
        }
        if (owners.isEmpty()) {
            SourceState.appendLog(context, "no active owners in directory")
            return
        }
        val envelope = try {
            Envelope.build(vaultId, deviceId, owners, plaintext)
        } catch (e: Exception) {
            SourceState.appendLog(context, "seal: ${e.message}")
            return
        }
        SourceState.enqueue(context, ApiClient.b64(envelope), receivedAt)
        UploadWorker.kick(context)
    }
}
