package com.lidessen.keyref.source.crypto

import java.security.MessageDigest

/**
 * Byte-exact transcript builders and parsers (docs/protocol.md §3).
 * Everything here must match proto/wire byte-for-byte; the cross-language
 * golden vectors (design §9.2, proto/crypto/testdata) are the gate.
 */
object Transcripts {

    private val PREFIX = "KEYREF1".toByteArray(Charsets.US_ASCII)
    const val FS: Byte = 0x00 // transcript field separator (§1.1)

    fun u64be(v: Long): ByteArray {
        val out = ByteArray(8)
        for (i in 0 until 8) out[i] = ((v ushr ((7 - i) * 8)) and 0xFF).toByte()
        return out
    }

    private fun begin(kind: String): ByteArray {
        val b = ArrayList<Byte>(128)
        b.addAll(PREFIX.toList()); b.add(FS)
        b.addAll(kind.toByteArray(Charsets.US_ASCII).toList()); b.add(FS)
        return b.toByteArray()
    }

    /** §3.5 pair-register 誊本（source 的 Ed25519 签）。 */
    fun pairRegister(nonce: ByteArray, proposedName: String): ByteArray {
        val b = begin("pair-register")
        b.addAll(nonce.toList()); b.add(FS)
        b.addAll(proposedName.toByteArray(Charsets.UTF_8))
        return b
    }

    /** §3.6 session 誊本。 */
    fun session(deviceId: String, challenge: ByteArray): ByteArray {
        val b = begin("session")
        b.addAll(deviceId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.addAll(challenge.toList())
        return b
    }

    /**
     * §3.9 message-upload 誊本（source 的 Ed25519 签，服务器落库前验证）。
     * receivedAt 是设备自报的短信到达时间；envelope 原始字节直接跟在后面
     * （二进制可含 NUL，誊本只写不读，§1.5）。
     */
    fun messageUpload(
        vaultId: String,
        sourceDeviceId: String,
        receivedAt: Long,
        envelope: ByteArray,
    ): ByteArray {
        val b = begin("message-upload")
        b.addAll(vaultId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.addAll(sourceDeviceId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.addAll(u64be(receivedAt).toList()); b.add(FS)
        b.addAll(envelope.toList())
        return b
    }

    /** §3.10 delegation 誊本（owner 已签；本机只验证）。 */
    fun delegation(vaultId: String, revision: Long, policyJson: String): ByteArray {
        val b = begin("delegation")
        b.addAll(vaultId.toByteArray(Charsets.US_ASCII)); b.add(FS)
        b.addAll(u64be(revision).toList()); b.add(FS)
        b.addAll(policyJson.toByteArray(Charsets.UTF_8))
        return b
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
        val prefix = begin("directory")
        if (directorySigned.size < prefix.size + 32 + 1 + 8 + 1 ||
            !directorySigned.copyOfRange(0, prefix.size).contentEquals(prefix)
        ) fail("bad prefix")
        var rest = directorySigned.copyOfRange(prefix.size, directorySigned.size)
        val vaultId = rest.copyOfRange(0, 32).toString(Charsets.US_ASCII)
        if (!vaultId.matches(Regex("^[0-9a-f]{32}$")) || rest[32] != FS) fail("bad vault id")
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
            if (!deviceId.matches(Regex("^[0-9a-f]{32}$"))) fail("bad device id")
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
