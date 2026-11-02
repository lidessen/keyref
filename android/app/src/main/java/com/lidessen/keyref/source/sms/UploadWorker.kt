package com.lidessen.keyref.source.sms

import android.content.Context
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.lidessen.keyref.source.net.ApiClient
import com.lidessen.keyref.source.store.SourceState
import org.json.JSONObject

/**
 * Drains the outbox (design §14.7): every queued envelope is uploaded
 * with its §3.9 upload signature; entries leave the queue only on a 201.
 * Network failures and 5xx retry via WorkManager backoff; a 401 renews
 * the session once; permanent 4xx (quota, auth) drops the entry and logs
 * — a verification code past its usefulness is not worth an infinite
 * retry loop.
 */
class UploadWorker(ctx: Context, params: WorkerParameters) : Worker(ctx, params) {

    override fun doWork(): Result {
        val ctx = applicationContext
        if (!SourceState.isPaired(ctx)) return Result.success()
        val client = ApiClient(ctx)
        val queue = SourceState.queueSnapshot(ctx)
        var sessionRetried = false
        for (i in 0 until queue.length()) {
            val entry = queue.getJSONObject(i)
            val envelope = ApiClient.unb64(entry.getString("envelope"))
            val receivedAt = entry.getLong("received_at")
            val ok = try {
                client.uploadMessage(envelope, receivedAt)
            } catch (e: Exception) {
                // Session may have expired mid-flight: renew once, retry once.
                if (!sessionRetried && e.message?.contains("HTTP 401") == true) {
                    sessionRetried = true
                    SourceState.setToken(ctx, "", 0)
                    try {
                        client.uploadMessage(envelope, receivedAt)
                    } catch (e2: Exception) {
                        SourceState.appendLog(ctx, "upload retry: ${e2.message}")
                        return Result.retry()
                    }
                } else {
                    SourceState.appendLog(ctx, "upload: ${e.message}")
                    return Result.retry()
                }
            }
            if (ok) {
                SourceState.removeQueued(ctx, i)
                SourceState.appendLog(ctx, "uploaded ✓")
            } else {
                // 4xx other than auth: not retryable — drop with a log.
                SourceState.removeQueued(ctx, i)
                SourceState.appendLog(ctx, "upload rejected, dropped")
            }
        }
        return Result.success()
    }
}
