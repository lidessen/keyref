// NEW FILE (v0.7, design §6.7 iCloud 整文件副本): the encrypted snapshot
// file format for 仅本机 entries.
//
// One CloudKit record carries ONE opaque file (CKAsset) per vault. Apple
// sees only a name, a size and a timestamp (§6.7); every byte inside is
// either VMK-anchored ciphertext that already exists locally (item meta /
// secret ciphertexts, vault_wrapped keys) or an owner-signed manifest.
//
// ── Snapshot file layout ────────────────────────────────────────────────
//
//   magic                "KEYREF1SNAP1"  (12 bytes ASCII)
//   u32be                manifest length M
//   manifest bytes       M bytes (the §6.7 snapshot 誊本, below)
//   u32be                signature length S
//   signature            S bytes — owner ECDSA-P256 (DER) over
//                        magic ‖ u32be(M) ‖ manifest
//
// The signature covers the magic and the manifest length so truncation and
// magic swaps cannot pass verification. Downloads are verified BEFORE any
// byte is merged (§6.7: 下载后先验签再入库).
//
// ── Snapshot 誊本 (manifest transcript) ─────────────────────────────────
//
// Reuses the transcript system (KEYREF1 prefix, NUL separators, u64be
// numbers, write-only rebuild): unlike the §3.x transcripts this one is
// also PARSED on the receiving side, so every variable-length binary field
// is u64be length-prefixed — NUL separation alone cannot delimit ciphertext
// that may contain 0x00 bytes.
//
//   "KEYREF1" NUL "snapshot" NUL <vault_id 32 hex> NUL
//   u64be snapshot_revision NUL            // 单调递增（§6.7 冲突规则）
//   u64be entry_count NUL
//   entry, sorted by item_id ascending, joined by a single NUL:
//     <item_id 32 hex> NUL
//     u64be revision NUL                   // the entry's per-item revision
//     u64be len meta_ciphertext      meta_ciphertext
//     u64be len secret_ciphertext    secret_ciphertext
//     u64be len vault_wrapped_meta_key    vault_wrapped_meta_key
//     u64be len vault_wrapped_item_key    vault_wrapped_item_key
//     u64be len writer_device_id     writer_device_id
//   exclusions section (§6.7 每条目覆盖 — the snapshot is a shared whole
//   file, so the per-item override rides INSIDE it; LWW per item_id):
//     NUL u64be exclusion_count NUL
//     count × fixed 44-byte records (no separators between records):
//       <item_id 32 hex> NUL u64be at_millis NUL flag(0x30|0x31) NUL
//
// An entry is exactly the local-only item's stored bytes (§6.6): meta
// ciphertext plus vault_wrapped_meta_key from the server row, secret
// ciphertext plus vault_wrapped_item_key from the local secret store.
import CryptoKit
import Foundation

/// One 仅本机 entry inside a snapshot manifest.
public struct SnapshotEntry: Equatable, Sendable {
    public var itemID: String
    public var revision: UInt64
    public var metaCiphertext: Data
    public var secretCiphertext: Data
    public var vaultWrappedMetaKey: Data
    public var vaultWrappedItemKey: Data
    public var writerDeviceID: String

    public init(itemID: String, revision: UInt64, metaCiphertext: Data,
                secretCiphertext: Data, vaultWrappedMetaKey: Data,
                vaultWrappedItemKey: Data, writerDeviceID: String) {
        self.itemID = itemID
        self.revision = revision
        self.metaCiphertext = metaCiphertext
        self.secretCiphertext = secretCiphertext
        self.vaultWrappedMetaKey = vaultWrappedMetaKey
        self.vaultWrappedItemKey = vaultWrappedItemKey
        self.writerDeviceID = writerDeviceID
    }
}

/// One per-item snapshot override (§6.7 每条目覆盖): whether the item is
/// excluded from the iCloud copy, and WHEN the decision was written — the
/// timestamp makes the merge last-writer-wins per item (SnapshotEngine
/// .mergeExclusions), so one device's exclusion cannot be silently flipped
/// by another device's upload, and a re-include propagates the same way.
public struct SnapshotExclusion: Equatable, Sendable {
    public var itemID: String
    public var excluded: Bool
    public var atMillis: Int64

    public init(itemID: String, excluded: Bool, atMillis: Int64) {
        self.itemID = itemID
        self.excluded = excluded
        self.atMillis = atMillis
    }
}

/// The decoded snapshot manifest: vault id, the monotonic snapshot_revision
/// and the 仅本机 entry list (§6.7 条目清单).
public struct SnapshotManifest: Equatable, Sendable {
    public var vaultID: String
    public var snapshotRevision: UInt64
    public var entries: [SnapshotEntry]
    public var exclusions: [SnapshotExclusion]

    public init(vaultID: String, snapshotRevision: UInt64, entries: [SnapshotEntry],
                exclusions: [SnapshotExclusion] = []) {
        self.vaultID = vaultID
        self.snapshotRevision = snapshotRevision
        self.entries = entries
        self.exclusions = exclusions
    }
}

public enum SnapshotFormatError: Error, Equatable {
    case notASnapshot
    case unsupportedVersion
    case malformed(String)
    case badSignature
}

public enum SnapshotCodec {
    /// ASCII magic: "KEYREF1SNAP" + format version "1".
    public static let magic = Data("KEYREF1SNAP1".utf8)
    static let transcriptKind = "snapshot"
    static let nul = KeyrefEncoding.fieldSeparator

    // MARK: build

    /// Serializes + signs. The signature is the owner's (the signer of item
    /// transcripts, §3.1) so verification keys come from the signed device
    /// directory / the pinned owner key.
    public static func build(_ manifest: SnapshotManifest, signer: TranscriptSigner) throws -> Data {
        try requireID("vault_id", manifest.vaultID)
        let manifestBytes = try manifestBytes(of: manifest)
        var signed = Data()
        signed.append(magic)
        appendU32BE(UInt32(manifestBytes.count), to: &signed)
        signed.append(manifestBytes)
        let signature = try signer.sign(signed)
        var out = signed
        appendU32BE(UInt32(signature.count), to: &out)
        out.append(signature)
        return out
    }

    static func manifestBytes(of manifest: SnapshotManifest) throws -> Data {
        guard manifest.snapshotRevision >= 1 else {
            throw KeyrefWireError.invalidField("snapshot_revision must be >= 1")
        }
        var b = Data()
        b.append(contentsOf: transcriptPrefix.utf8); b.append(nul)
        b.append(contentsOf: transcriptKind.utf8); b.append(nul)
        b.append(contentsOf: manifest.vaultID.utf8); b.append(nul)
        KeyrefEncoding.appendU64BE(manifest.snapshotRevision, to: &b); b.append(nul)
        KeyrefEncoding.appendU64BE(UInt64(manifest.entries.count), to: &b); b.append(nul)
        for (i, entry) in manifest.entries.sorted(by: { $0.itemID < $1.itemID }).enumerated() {
            if i > 0 { b.append(nul) }
            b.append(try entryBytes(entry))
        }
        // Exclusions section: always written (even when empty) so the parser
        // never has to guess whether the section exists.
        b.append(nul)
        KeyrefEncoding.appendU64BE(UInt64(manifest.exclusions.count), to: &b); b.append(nul)
        for e in manifest.exclusions.sorted(by: { $0.itemID < $1.itemID }) {
            try requireID("exclusion item_id", e.itemID)
            b.append(contentsOf: e.itemID.utf8); b.append(nul)
            KeyrefEncoding.appendU64BE(UInt64(bitPattern: e.atMillis), to: &b); b.append(nul)
            b.append(e.excluded ? UInt8(ascii: "1") : UInt8(ascii: "0")); b.append(nul)
        }
        return b
    }

    private static func entryBytes(_ e: SnapshotEntry) throws -> Data {
        try requireID("item_id", e.itemID)
        try requireID("writer_device_id", e.writerDeviceID)
        guard e.revision >= 1 else {
            throw KeyrefWireError.invalidField("entry revision must be >= 1")
        }
        var b = Data()
        b.append(contentsOf: e.itemID.utf8); b.append(nul)
        KeyrefEncoding.appendU64BE(e.revision, to: &b); b.append(nul)
        appendLenField(e.metaCiphertext, to: &b)
        appendLenField(e.secretCiphertext, to: &b)
        appendLenField(e.vaultWrappedMetaKey, to: &b)
        appendLenField(e.vaultWrappedItemKey, to: &b)
        // writer_device_id is length-prefixed like every other variable
        // field — NUL separation cannot delimit the LAST entry's writer
        // (there is no trailing separator to close it).
        appendLenField(Data(e.writerDeviceID.utf8), to: &b)
        return b
    }

    private static func appendLenField(_ field: Data, to b: inout Data) {
        KeyrefEncoding.appendU64BE(UInt64(field.count), to: &b)
        b.append(field)
    }

    private static func appendU32BE(_ v: UInt32, to b: inout Data) {
        withUnsafeBytes(of: v.bigEndian) { b.append(contentsOf: $0) }
    }

    private static func readU32BE(_ d: Data, _ offset: Int) throws -> UInt32 {
        guard offset >= 0, d.count >= offset + 4 else {
            throw SnapshotFormatError.malformed("truncated u32")
        }
        var v: UInt32 = 0
        for i in 0..<4 { v = (v << 8) | UInt32(d[d.startIndex + offset + i]) }
        return v
    }

    // MARK: parse + verify

    /// Parses the file and verifies the owner signature over
    /// magic ‖ len ‖ manifest with ANY of the given trusted owner public
    /// keys (the pinned owner key, plus the owner keys recorded in the
    /// signed device directory — a pre-takeover snapshot is signed by the
    /// pre-takeover owner, §6.7 恢复路径). Throws `badSignature` when no
    /// key verifies: the caller must not merge anything.
    public static func verify(_ data: Data, ownerSignPublicKeys: [Data]) throws -> SnapshotManifest {
        let (signedBytes, signature) = try split(data)
        var verified = false
        for key in ownerSignPublicKeys {
            if (try? verifyOwnerSignature(transcript: signedBytes, signature: signature,
                                          ownerSignPublicKey: key)) != nil {
                verified = true
                break
            }
        }
        guard verified else { throw SnapshotFormatError.badSignature }
        return try parseManifest(signedBytes.dropFirst(magic.count + 4))
    }

    /// Parses without signature verification — only for display/counting;
    /// anything merged into state MUST go through `verify`.
    public static func parseUnverified(_ data: Data) throws -> SnapshotManifest {
        let (signedBytes, _) = try split(data)
        return try parseManifest(signedBytes.dropFirst(magic.count + 4))
    }

    private static func split(_ data: Data) throws -> (signed: Data, signature: Data) {
        guard data.starts(with: magic) else { throw SnapshotFormatError.notASnapshot }
        let m = try Int(readU32BE(data, magic.count))
        let manifestStart = magic.count + 4
        guard data.count >= manifestStart + m else {
            throw SnapshotFormatError.malformed("manifest truncated")
        }
        let manifestEnd = manifestStart + m
        let sigLen = try Int(readU32BE(data, manifestEnd))
        let sigStart = manifestEnd + 4
        guard data.count >= sigStart + sigLen else {
            throw SnapshotFormatError.malformed("signature truncated")
        }
        let signed = data[data.startIndex..<data.startIndex + manifestEnd]
        let signature = data[data.startIndex + sigStart..<data.startIndex + sigStart + sigLen]
        return (Data(signed), Data(signature))
    }

    private static func parseManifest(_ bytes: Data) throws -> SnapshotManifest {
        let sep = nul
        func expect(_ needle: Data) throws {
            guard bytes.starts(with: needle) else {
                throw SnapshotFormatError.malformed("unexpected transcript prefix")
            }
        }
        try expect(Data(transcriptPrefix.utf8) + [sep] + Data(transcriptKind.utf8) + [sep])
        var body = bytes.dropFirst(transcriptPrefix.count + 1 + transcriptKind.count + 1)

        func takeString() throws -> String {
            guard let idx = body.firstIndex(of: sep) else {
                throw SnapshotFormatError.malformed("unterminated string field")
            }
            let s = String(decoding: body[body.startIndex..<idx], as: UTF8.self)
            body = body.dropFirst(body.distance(from: body.startIndex, to: idx) + 1)
            return s
        }
        func takeU64() throws -> UInt64 {
            guard body.count >= 9 else { throw SnapshotFormatError.malformed("short u64 field") }
            let v = try KeyrefEncoding.readU64BE(body, offset: 0)
            guard body[body.startIndex + 8] == sep else {
                throw SnapshotFormatError.malformed("u64 field not NUL-terminated")
            }
            body = body.dropFirst(9)
            return v
        }
        func takeLenField() throws -> Data {
            guard body.count >= 8 else { throw SnapshotFormatError.malformed("short length") }
            let n = try KeyrefEncoding.readU64BE(body, offset: 0)
            body = body.dropFirst(8)
            guard body.count >= Int(n) else { throw SnapshotFormatError.malformed("blob truncated") }
            let d = Data(body.prefix(Int(n)))
            body = body.dropFirst(Int(n))
            return d
        }

        let vaultID = try takeString()
        try requireID("vault_id", vaultID)
        let snapshotRevision = try takeU64()
        guard snapshotRevision >= 1 else {
            throw SnapshotFormatError.malformed("snapshot_revision must be >= 1")
        }
        let count = try takeU64()
        guard count <= 100_000 else { throw SnapshotFormatError.malformed("entry count too large") }

        var entries: [SnapshotEntry] = []
        for i in 0..<count {
            let itemID = try takeString()
            try requireID("item_id", itemID)
            let revision = try takeU64()
            guard revision >= 1 else {
                throw SnapshotFormatError.malformed("entry revision must be >= 1")
            }
            let metaCT = try takeLenField()
            let secretCT = try takeLenField()
            let vwMeta = try takeLenField()
            let vwItem = try takeLenField()
            let writerBytes = try takeLenField()
            let writer = String(decoding: writerBytes, as: UTF8.self)
            try requireID("writer_device_id", writer)
            entries.append(SnapshotEntry(itemID: itemID, revision: revision,
                                         metaCiphertext: metaCT, secretCiphertext: secretCT,
                                         vaultWrappedMetaKey: vwMeta,
                                         vaultWrappedItemKey: vwItem,
                                         writerDeviceID: writer))
            if i < count - 1 {
                guard body.first == sep else {
                    throw SnapshotFormatError.malformed("entry separator missing")
                }
                body = body.dropFirst(1)
            }
        }

        // Exclusions section (§6.7 每条目覆盖) — always present, see
        // manifestBytes. Fixed-width 44-byte records.
        guard body.first == sep else {
            throw SnapshotFormatError.malformed("missing exclusions section")
        }
        body = body.dropFirst(1)
        let exclusionCount = try takeU64()
        guard exclusionCount <= 100_000 else {
            throw SnapshotFormatError.malformed("exclusion count too large")
        }
        var exclusions: [SnapshotExclusion] = []
        for _ in 0..<exclusionCount {
            guard body.count >= 34 else {
                throw SnapshotFormatError.malformed("truncated exclusion id")
            }
            let id = String(decoding: body.prefix(32), as: UTF8.self)
            body = body.dropFirst(32)
            guard body.first == sep else {
                throw SnapshotFormatError.malformed("exclusion id not NUL-terminated")
            }
            body = body.dropFirst(1)
            try requireID("exclusion item_id", id)
            let at = try takeU64()
            guard let flag = body.first,
                  flag == UInt8(ascii: "0") || flag == UInt8(ascii: "1") else {
                throw SnapshotFormatError.malformed("bad exclusion flag")
            }
            body = body.dropFirst(1)
            guard body.first == sep else {
                throw SnapshotFormatError.malformed("exclusion flag not NUL-terminated")
            }
            body = body.dropFirst(1)
            exclusions.append(SnapshotExclusion(itemID: id, excluded: flag == UInt8(ascii: "1"),
                                                atMillis: Int64(bitPattern: at)))
        }
        guard body.isEmpty else {
            throw SnapshotFormatError.malformed("trailing bytes after exclusions")
        }
        return SnapshotManifest(vaultID: vaultID, snapshotRevision: snapshotRevision,
                                entries: entries, exclusions: exclusions)
    }

    private static func requireID(_ name: String, _ v: String) throws {
        guard KeyrefEncoding.isValidID(v) else {
            throw SnapshotFormatError.malformed("\(name) must be 32 lowercase hex characters")
        }
    }
}
