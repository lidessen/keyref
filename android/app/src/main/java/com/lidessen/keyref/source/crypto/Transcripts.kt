package com.lidessen.keyref.source.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Byte-exact transcript builders and parsers (docs/protocol.md §3).
 * Everything here must match proto/wire byte-for-byte; the cross-language
 * golden vectors (ios/Tests/KeyrefCoreTests/Fixtures/vectors.json, design
 * §9.2) are the gate — see CryptoVectorsTest.
 */
object Transcripts {

    private val PREFIX = "KEYREF1".toByteArray(Charsets.US_ASCII)
    const val FS: Byte = 0x00 // transcript field separator (§1.1)

    fun u64be(v: Long): ByteArray {
        val out = ByteArray(8)
        for (i in 0 until 8) out[i] = ((v ushr ((7 - i) * 8)) and 0xFF).toByte()
        return out
    }

    private fun MutableList<Byte>.put(bytes: ByteArray) {
        addAll(bytes.toList())
    }

    private fun begin(kind: String): ArrayList<Byte> {
        val b = ArrayList<Byte>(128)
        b.put(PREFIX); b.add(FS)
        b.put(kind.toByteArray(Charsets.US_ASCII)); b.add(FS)
        return b
    }

    /** §3.5 pair-register 誊本（source 的 Ed25519 签）。 */
    fun pairRegister(nonce: ByteArray, proposedName: String): ByteArray {
        val b = begin("pair-register")
        b.put(nonce); b.add(FS)
        b.put(proposedName.toByteArray(Charsets.UTF_8))
        return b.toByteArray()
    }

    /** §3.6 session 誊本。 */
    fun session(deviceId: String, challenge: ByteArray): ByteArray {
        val b = begin("session")
        b.put(deviceId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.put(challenge)
        return b.toByteArray()
    }

    /**
     * §3.4 pair transcript with an EMPTY grant set: the count is zero and
     * the trailing NUL separator is still present (BuildPairTranscript
     * appends u64be(count) NUL before the concatenated grant transcripts).
     * [nonceHex] enters as the 32 ASCII hex characters, unlike the raw
     * 16 nonce bytes in §3.5 pair-register. This is also the byte string
     * the §3.13 pairing MAC covers — the owner builds the same bytes on
     * the other side of the QR.
     */
    fun pairTranscript(
        vaultId: String,
        ownerSignPub: ByteArray,
        nonceHex: String,
        deviceId: String,
        kem: String,
        hpkePub: ByteArray,
        signAlg: String,
        signPub: ByteArray,
        label: String,
    ): ByteArray {
        val b = begin("pair")
        b.put(vaultId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.put(ownerSignPub); b.add(FS)
        b.put(nonceHex.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.put(deviceId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.put(kem.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.put(hpkePub); b.add(FS)
        b.put(signAlg.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.put(signPub); b.add(FS)
        b.put(label.toByteArray(Charsets.UTF_8)); b.add(FS)
        b.put(u64be(0)) // grant_count = 0
        b.add(FS)
        return b.toByteArray()
    }

    /**
     * §3.13 pairing confirmation MAC (protocol v2 D): the owner folds the
     * QR-only secret c into the completion, and this device recomputes the
     * same value before it pins the owner key. The server stores the MAC
     * opaquely — it never sees c, so it cannot forge one.
     */
    fun pairConfirmMac(c: ByteArray, kind: String, pairTranscript: ByteArray): ByteArray {
        require(c.size == 32) { "pairing secret must be 32 bytes" }
        require(kind == "cli" || kind == "source" || kind == "decider") { "unknown device kind $kind" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(c, "HmacSHA256"))
        mac.update("keyref v1 pair-confirm".toByteArray(Charsets.US_ASCII))
        mac.update(byteArrayOf(FS))
        mac.update(kind.toByteArray(Charsets.US_ASCII))
        mac.update(byteArrayOf(FS))
        mac.update(pairTranscript)
        return mac.doFinal()
    }

    /**
     * §3.9 message-upload 誊本（source 的 Ed25519 签，protocol v2 C）。
     * receivedAt 是设备自报的短信到达时间。末字段是信封正文 blob 的
     * SHA-256（正文由 Envelope.splitBody 按服务器同款严格切分得到），
     * 包裹记录不签名——owner 之后补写决策器包裹不能使签名失效
     * （§6.30）。誊本因此定长、与信封大小无关。
     */
    fun messageUpload(
        vaultId: String,
        sourceDeviceId: String,
        receivedAt: Long,
        envelope: ByteArray,
    ): ByteArray {
        val body = Envelope.splitBody(envelope)
        val b = begin("message-upload")
        b.put(vaultId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.put(sourceDeviceId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.put(u64be(receivedAt)); b.add(FS)
        b.put(sha256(body))
        return b.toByteArray()
    }

    /** §3.10 delegation 誊本（owner 已签；本机只验证）。 */
    fun delegation(vaultId: String, revision: Long, policyJson: String): ByteArray {
        val b = begin("delegation")
        b.put(vaultId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.put(u64be(revision)); b.add(FS)
        b.put(policyJson.toByteArray(Charsets.UTF_8))
        return b.toByteArray()
    }

    /**
     * §3.3 directory 誊本结构化解析 + 重建比对。与 CLI 侧
     * audit.parseDirectory 逐字对齐：字符串字段读到 NUL，公钥按
     * KEM/签名算法查表取定长，renewal key 读到下一个 NUL（其含 NUL 时
     * 重建比对会失败并整体拒绝——fail-closed），grants_digest 定长
     * 32 字节，记录之间由单个 NUL 连接。调用方必须先用已钉死的 owner
     * 签名公钥验证 [directorySigned] 的签名，再调用本函数。
     */
    fun parseDirectory(directorySigned: ByteArray): List<DeviceRecord> {
        fun fail(what: String): Nothing = throw IllegalArgumentException("bad directory: $what")
        val prefix = begin("directory").toByteArray()
        if (directorySigned.size < prefix.size + 32 + 1 + 8 + 1 ||
            !directorySigned.copyOfRange(0, prefix.size).contentEquals(prefix)
        ) fail("bad prefix")
        var rest = directorySigned.copyOfRange(prefix.size, directorySigned.size)
        val vaultId = rest.copyOfRange(0, 32).toString(Charsets.US_ASCII)
        if (!vaultId.matches(ID) || rest[32] != FS) fail("bad vault id")
        rest = rest.copyOfRange(33, rest.size)
        if (rest[8] != FS) fail("bad revision separator")
        rest = rest.copyOfRange(9, rest.size)

        val records = ArrayList<DeviceRecord>()
        while (rest.isNotEmpty()) {
            fun str(): String {
                val i = rest.indexOf(FS)
                if (i < 0) fail("truncated record")
                val s = rest.copyOfRange(0, i).toString(Charsets.US_ASCII)
                rest = rest.copyOfRange(i + 1, rest.size)
                return s
            }
            fun fixed(n: Int): ByteArray {
                if (rest.size < n + 1 || rest[n] != FS) fail("bad fixed field")
                val b = rest.copyOfRange(0, n)
                rest = rest.copyOfRange(n + 1, rest.size)
                return b
            }
            val deviceId = str()
            if (!deviceId.matches(ID)) fail("bad device id")
            val kind = str()
            val status = str()
            val kem = str()
            val kemLen = when (kem) { "X25519" -> 32; "P-256" -> 65; else -> fail("bad kem") }
            val hpkePub = fixed(kemLen)
            val signAlg = str()
            val signLen = when (signAlg) { "ed25519" -> 32; "ecdsa-p256" -> 65; else -> fail("bad sign alg") }
            val signPub = fixed(signLen)
            // renewal: read to the next NUL; legal lengths are 0 or 32.
            val renNul = rest.indexOf(FS)
            if (renNul < 0) fail("truncated renewal key")
            val renewal = rest.copyOfRange(0, renNul)
            if (renewal.isNotEmpty() && renewal.size != 32) fail("bad renewal key length")
            rest = rest.copyOfRange(renNul + 1, rest.size)
            if (rest.size < 32) fail("truncated grants digest")
            val digest = rest.copyOfRange(0, 32)
            rest = rest.copyOfRange(32, rest.size)
            // receiver_role: one raw byte DIRECTLY after the digest, no
            // separator of its own (protocol §3.3, design v0.8 §14.4).
            // It is new in v1.2 — a parser that skips it will read the
            // role as the record separator and desync the whole directory.
            if (rest.isEmpty()) fail("truncated receiver role")
            val role = rest[0]
            if (role > 2) fail("bad receiver role")
            rest = rest.copyOfRange(1, rest.size)
            if (rest.isNotEmpty()) {
                if (rest[0] != FS) fail("bad record separator")
                rest = rest.copyOfRange(1, rest.size)
            }
            records.add(DeviceRecord(deviceId, kind, status, kem, hpkePub, signAlg, signPub, renewal, digest, role.toInt()))
        }
        return records
    }

    private fun ByteArray.indexOf(byte: Byte, from: Int = 0): Int {
        for (i in maxOf(from, 0) until size) if (this[i] == byte) return i
        return -1
    }

    private val ID = Regex("^[0-9a-f]{32}$")

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
}

/** One §3.3 directory device record (subset the source needs). */
data class DeviceRecord(
    val deviceId: String,
    val kind: String,     // ios | cli | source | decider
    val status: String,   // pending | active | revoked
    val hpkeKem: String,  // X25519 | P-256
    val hpkePublicKey: ByteArray,
    val signAlg: String,
    val signPublicKey: ByteArray,
    val renewalSignPublicKey: ByteArray,
    val grantsDigest: ByteArray,
    /** SMS-inbox role (§14.4): 0 none, 1 primary receiver, 2 inbox. */
    val receiverRole: Int = 0,
) {
    val isActiveOwner: Boolean get() = kind == "ios" && status == "active"
}
