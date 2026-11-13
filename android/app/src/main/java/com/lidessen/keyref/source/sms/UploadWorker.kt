package com.lidessen.keyref.source.sms

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.Worker
import androidx.work.WorkerParameters
import androidx.work.WorkManager
import com.lidessen.keyref.source.net.ApiClient
import com.lidessen.keyref.source.store.SourceState
import java.util.concurrent.TimeUnit

/**
 * Drains the outbox (design §14.7): every queued envelope is uploaded
 * with its §3.9 upload signature; entries leave the queue only on a 201
 * or on a permanent rejection. Network failures and 5xx retry via
 * WorkManager backoff with the entry still queued; a single 401 renews
 * the session once and retries; a second 401 and other 4xx (quota,
 * invalid request, revoked device) drop the entry with a log — a
 * verification code past its usefulness is not worth an infinite retry
 * loop.
 */
class UploadWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {

    override fun doWork(): Result {
        val ctx = applicationContext
        if (!SourceState.isPaired(ctx)) return Result.success()
        val client = ApiClient(ctx)
        // Refresh the pinned directory first (§14.3): owners added or
        // revoked since the last sync change who fresh messages seal to.
        // A failed refresh keeps the cached directory — the 24h TTL and
        // the next kick cover the drift.
        try {
            client.refreshDirectory()
        } catch (e: Exception) {
            SourceState.appendLog(ctx, "directory refresh: ${e.message}")
        }
        val queue = SourceState.queueSnapshot(ctx)
        for (i in 0 until queue.length()) {
            val entry = queue.getJSONObject(i)
            val envelopeB64 = entry.getString("envelope")
            val envelope = ApiClient.unb64(envelopeB64)
            val receivedAt = entry.getLong("received_at")
            val code = try {
                var status = client.uploadMessage(envelope, receivedAt)
                if (status == 401) {
                    // Token the server no longer accepts: renew once (§6.7)
                    // and retry this entry; a second 401 is permanent.
                    SourceState.setToken(ctx, "", 0)
                    status = client.uploadMessage(envelope, receivedAt)
                }
                status
            } catch (e: Exception) {
                if (HTTP_4XX.containsMatchIn(e.message ?: "")) {
                    // Session establishment was refused for good (e.g. the
                    // device was revoked): drop this entry, keep the rest
                    // of the rules identical for the ones that follow.
                    SourceState.removeQueuedEnvelope(ctx, envelopeB64)
                    SourceState.appendLog(ctx, "upload session rejected (${e.message}), dropped")
                    continue
                }
                SourceState.appendLog(ctx, "upload: ${e.message}")
                return Result.retry()
            }
            when {
                code == 201 -> {
                    SourceState.removeQueuedEnvelope(ctx, envelopeB64)
                    SourceState.appendLog(ctx, "uploaded ✓")
                }
                code == 401 -> {
                    SourceState.removeQueuedEnvelope(ctx, envelopeB64)
                    SourceState.appendLog(ctx, "upload rejected (unauthorized), dropped")
                }
                code >= 500 -> return Result.retry() // server hiccup: keep queued
                else -> {
                    SourceState.removeQueuedEnvelope(ctx, envelopeB64)
                    SourceState.appendLog(ctx, "upload rejected HTTP $code, dropped")
                }
            }
        }
        return Result.success()
    }

    companion object {
        const val NAME = "keyref-source-upload"

        /** Our own OkHttp/ensureSession failure messages ("session step1 HTTP 403"). */
        private val HTTP_4XX = Regex("""\bHTTP 4\d\d\b""")

        /** Schedules the upload worker with exponential backoff (design §14.7). */
        fun kick(context: Context) {
            val req = OneTimeWorkRequestBuilder<UploadWorker>()
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(NAME, ExistingWorkPolicy.REPLACE, req)
        }
    }
}
