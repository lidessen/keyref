package com.lidessen.keyref.source

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.graphics.createBitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.lidessen.keyref.source.crypto.Keys
import com.lidessen.keyref.source.crypto.Transcripts
import com.lidessen.keyref.source.net.ApiClient
import com.lidessen.keyref.source.store.SourceState
import java.net.URLEncoder
import kotlin.concurrent.thread

/**
 * Pairing + settings for the kind=source collector (design v0.8 §14.2).
 * Pairing direction follows §8.1 unchanged: THIS device registers a pair
 * session and displays the §9.1 QR (`t=source`); the iPhone scans and
 * completes with an empty grant set.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var logText: TextView
    private lateinit var originInput: EditText
    private lateinit var senderInput: EditText
    private lateinit var sendersText: TextView
    private lateinit var qrImage: ImageView
    private lateinit var pairingBox: LinearLayout
    private lateinit var settingsBox: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        logText = findViewById(R.id.logText)
        originInput = findViewById(R.id.originInput)
        senderInput = findViewById(R.id.senderInput)
        sendersText = findViewById(R.id.sendersText)
        qrImage = findViewById(R.id.qrImage)
        pairingBox = findViewById(R.id.pairingBox)
        settingsBox = findViewById(R.id.settingsBox)

        ensureIdentity()

        originInput.setText(SourceState.getOrigin(this))

        findViewById<Button>(R.id.btnPermission).setOnClickListener {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) ==
                PackageManager.PERMISSION_GRANTED
            ) {
                Toast.makeText(this, "短信权限已授权", Toast.LENGTH_SHORT).show()
            } else {
                requestPermissions(arrayOf(Manifest.permission.RECEIVE_SMS), 1)
            }
        }
        findViewById<Button>(R.id.btnBattery).setOnClickListener {
            startActivity(
                Intent(
                    Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                    Uri.parse("package:$packageName")
                )
            )
        }
        findViewById<Button>(R.id.btnPair).setOnClickListener {
            val origin = originInput.text.toString().trim()
            if (!origin.startsWith("http")) {
                Toast.makeText(this, "先填写服务器地址", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            SourceState.setOrigin(this, origin)
            startPairing(origin)
        }
        findViewById<Button>(R.id.btnUnpair).setOnClickListener {
            SourceState.resetPairing(this)
            render()
        }
        findViewById<Button>(R.id.btnToggleCollect).setOnClickListener {
            val next = !SourceState.isCollectEnabled(this)
            if (next && SourceState.getSenders(this).isEmpty()) {
                Toast.makeText(this, "先添加至少一个发信号码", Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            SourceState.setCollectEnabled(this, next)
            render()
        }
        findViewById<Button>(R.id.btnAddSender).setOnClickListener {
            val sender = senderInput.text.toString().trim()
            if (sender.isNotEmpty()) {
                val set = SourceState.getSenders(this).toMutableSet()
                set.add(sender)
                SourceState.setSenders(this, set)
                senderInput.setText("")
                if (SourceState.isCollectEnabled(this)) render() else render()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun ensureIdentity() {
        val f = SourceState.keysFile(this)
        if (Keys.loadIdentity(f) == null) {
            Keys.saveIdentity(f, Keys.generate())
        }
    }

    private fun render() {
        val paired = SourceState.isPaired(this)
        pairingBox.visibility = if (paired) View.GONE else View.VISIBLE
        settingsBox.visibility = if (paired) View.VISIBLE else View.GONE
        val senders = SourceState.getSenders(this).sorted().joinToString("、")
        sendersText.text = if (senders.isEmpty()) "（还没有发信号码）" else senders
        statusText.text = buildString {
            append("短信权限：")
            append(
                if (ContextCompat.checkSelfPermission(this@MainActivity, Manifest.permission.RECEIVE_SMS) ==
                    PackageManager.PERMISSION_GRANTED
                ) "已授权 ✓" else "未授权 ✗"
            )
            append('\n')
            append("设备身份：")
            append(if (paired) "已配对（kind=source）✓" else "未配对")
            append('\n')
            append("采集开关：")
            append(if (SourceState.isCollectEnabled(this@MainActivity)) "开启 ✓" else "关闭")
        }
        logText.text = SourceState.getLogTail(this).ifEmpty { "（暂无日志）" }
    }

    /** §9.1 payload with t=source; QR rendered by zxing. */
    private fun startPairing(origin: String) {
        val identity = Keys.loadIdentity(SourceState.keysFile(this)) ?: return
        val nonceHex = ByteArray(16)
            .also { java.security.SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        SourceState.setPairNonce(this, nonceHex)
        // §3.13 / §9.1: the pairing secret c exists only in this QR — the
        // owner folds it into the completion MAC, the server stores that
        // MAC opaquely and never sees c itself.
        val pairSecret = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        SourceState.setPairSecret(this, ApiClient.b64(pairSecret))
        thread {
            try {
                val status = ApiClient(this).pairRegister(origin, identity, nonceHex)
                if (status != 201) {
                    runOnUiThread { Toast.makeText(this, "register HTTP $status", Toast.LENGTH_LONG).show() }
                    return@thread
                }
                val payload = "keyref://pair?v=1" +
                    "&k=" + enc(ApiClient.b64(identity.x25519Public)) +
                    "&s=" + enc(ApiClient.b64(identity.ed25519Public)) +
                    "&n=" + nonceHex +
                    "&name=" + enc("android-source") +
                    "&u=" + enc(origin) +
                    "&t=source" +
                    "&c=" + enc(ApiClient.b64(pairSecret))
                runOnUiThread { showQr(payload) }
                pollPairing(origin, nonceHex, identity)
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "配对失败：${e.message}", Toast.LENGTH_LONG).show()
                    SourceState.appendLog(this, "pair: ${e.message}")
                    render()
                }
            }
        }
    }

    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")

    private fun showQr(payload: String) {
        val size = 640
        val matrix = QRCodeWriter().encode(
            payload, BarcodeFormat.QR_CODE, size, size,
            mapOf(EncodeHintType.MARGIN to 1)
        )
        val bmp = createBitmap(size, size)
        for (y in 0 until size) {
            for (x in 0 until size) {
                bmp.setPixel(x, y, if (matrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
            }
        }
        qrImage.visibility = View.VISIBLE
        qrImage.setImageBitmap(bmp)
    }

    private fun pollPairing(origin: String, nonceHex: String, identity: Keys.Identity) {
        val deadline = System.currentTimeMillis() + 10 * 60_000
        val client = ApiClient(this)
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(2_000)
            val result = try {
                client.pairStatus(origin, nonceHex, identity)
            } catch (e: SecurityException) {
                // §3.13 / §6.18: a failed §3.4 signature or pairing-MAC
                // check is not a transient poll error — abort the pairing
                // and pin nothing.
                SourceState.appendLog(this, "pair verify: ${e.message}")
                runOnUiThread {
                    Toast.makeText(this, "配对校验失败：${e.message}", Toast.LENGTH_LONG).show()
                    render()
                }
                return
            } catch (e: Exception) {
                SourceState.appendLog(this, "poll: ${e.message}")
                continue
            }
            when (result) {
                is ApiClient.PairResult.Complete -> {
                    // Directory signature verified inside pairStatus; parse
                    // once more to fail closed, then store the pinned state.
                    val owners = Transcripts.parseDirectory(result.directorySigned)
                        .count { it.isActiveOwner }
                    SourceState.setPaired(
                        this, result.vaultId, result.deviceId,
                        ApiClient.b64(result.ownerSignPub),
                        ApiClient.b64(result.directorySigned),
                        ApiClient.b64(result.directorySignature)
                    )
                    SourceState.appendLog(this, "paired ✓ owners=$owners")
                    runOnUiThread {
                        qrImage.visibility = View.GONE
                        Toast.makeText(this, "配对成功", Toast.LENGTH_LONG).show()
                        render()
                    }
                    return
                }
                ApiClient.PairResult.Expired -> {
                    runOnUiThread { Toast.makeText(this, "配对已过期，请重试", Toast.LENGTH_LONG).show() }
                    return
                }
                ApiClient.PairResult.Pending -> Unit
            }
        }
        runOnUiThread { Toast.makeText(this, "配对超时", Toast.LENGTH_LONG).show() }
    }
}
