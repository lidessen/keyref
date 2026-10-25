// HPKE info strings and AEAD AADs (docs/protocol.md §3.7).
//
// All bindings use the same separator scheme: UTF-8 fields joined by the
// ASCII unit separator (0x1f). Item-ciphertext AADs deliberately exclude
// the revision (design §9.1): rewrapping keys must not require
// re-encryption, and rollback is covered by signed transcripts plus the
// server-side strict revision checks.
import CryptoKit
import Foundation

public enum KeyrefPurpose {
    public static let vmk = "vmk"
    public static let metaKey = "meta-key"
    public static let itemKey = "item-key"
    public static let oneTimeItemKey = "one-time-item-key"
    public static let auditEventKey = "audit-event-key"
    public static let approvalRequest = "approval-request"
}

public enum KeyrefLabel {
    public static let secret = "secret"
    public static let meta = "meta"
    public static let vaultMetaKey = "vault-meta-key"
    public static let vaultItemKey = "vault-item-key"
    public static let recovery = "recovery"
    public static let audit = "audit"
}

private let domainPrefix = "keyref v1"
private let us = KeyrefEncoding.unitSeparator

private func joined(_ parts: [String]) -> Data {
    var d = Data()
    for (i, p) in parts.enumerated() {
        if i > 0 { d.append(us) }
        d.append(contentsOf: p.utf8)
    }
    return d
}

private func requireHexID(_ name: String, _ v: String) throws {
    guard KeyrefEncoding.isValidID(v) else {
        throw KeyrefWireError.invalidField("\(name) must be 32 lowercase hex characters")
    }
}

/// Builds the HPKE info base
/// "keyref v1" <US> purpose <US> vault_id(hex) <US> recipient_device_id(hex).
public func hpkeInfo(purpose: String, vaultID: String, recipientDeviceID: String) throws -> Data {
    try requireHexID("vault_id", vaultID)
    try requireHexID("recipient_device_id", recipientDeviceID)
    return joined([domainPrefix, purpose, vaultID, recipientDeviceID])
}

/// Builds the one-time item-key info (§3.7, D4): the one-time-item-key
/// base followed by <US> item_id <US> approval_id <US> SHA-256(request
/// ciphertext), so a wrap answers exactly one request for one item.
public func oneTimeItemKeyInfo(vaultID: String, recipientDeviceID: String,
                               itemID: String, approvalID: String,
                               requestCiphertext: Data) throws -> Data {
    try requireHexID("item_id", itemID)
    try requireHexID("approval_id", approvalID)
    var info = try hpkeInfo(purpose: KeyrefPurpose.oneTimeItemKey,
                            vaultID: vaultID, recipientDeviceID: recipientDeviceID)
    info.append(us)
    info.append(contentsOf: itemID.utf8)
    info.append(us)
    info.append(contentsOf: approvalID.utf8)
    info.append(us)
    info.append(Data(SHA256.hash(data: requestCiphertext)))
    return info
}

private func itemAAD(label: String, vaultID: String, itemID: String) throws -> Data {
    try requireHexID("vault_id", vaultID)
    try requireHexID("item_id", itemID)
    return joined([domainPrefix, label, vaultID, itemID])
}

public func secretAAD(vaultID: String, itemID: String) throws -> Data {
    try itemAAD(label: KeyrefLabel.secret, vaultID: vaultID, itemID: itemID)
}

public func metaAAD(vaultID: String, itemID: String) throws -> Data {
    try itemAAD(label: KeyrefLabel.meta, vaultID: vaultID, itemID: itemID)
}

public func vaultWrappedMetaKeyAAD(vaultID: String, itemID: String) throws -> Data {
    try itemAAD(label: KeyrefLabel.vaultMetaKey, vaultID: vaultID, itemID: itemID)
}

public func vaultWrappedItemKeyAAD(vaultID: String, itemID: String) throws -> Data {
    try itemAAD(label: KeyrefLabel.vaultItemKey, vaultID: vaultID, itemID: itemID)
}

/// "keyref v1" <US> "recovery" <US> vault_id(hex)
public func recoveryAAD(vaultID: String) throws -> Data {
    try requireHexID("vault_id", vaultID)
    return joined([domainPrefix, KeyrefLabel.recovery, vaultID])
}

/// "keyref v1" <US> "audit" <US> vault_id(hex) <US> device_id(hex); the
/// device is the reporting device (§3.7).
public func auditAAD(vaultID: String, deviceID: String) throws -> Data {
    try requireHexID("vault_id", vaultID)
    try requireHexID("device_id", deviceID)
    return joined([domainPrefix, KeyrefLabel.audit, vaultID, deviceID])
}
