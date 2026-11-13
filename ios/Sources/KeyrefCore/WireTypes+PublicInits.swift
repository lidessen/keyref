// NEW FILE (added for the KeyrefUI layer, not a modification of existing
// files): public construction helpers for the wire types the UI drives when
// performing owner flows — item writes (§6.10), tombstones (§6.11), grant
// writes/deletions (§6.12, §6.13), directory publishes (§6.15) and local row
// mirrors of applied sync data (§8.3). The synthesized memberwise
// initializers of these structs are internal to KeyrefCore, and an extension
// cannot redeclare them at a wider access level, so the UI builds rows via
// these `make` factories instead.
import Foundation

public extension ItemData {
    static func make(vaultID: String, itemID: String, revision: UInt64, tombstone: Bool,
                     metaCiphertext: Data, secretCiphertext: Data,
                     vaultWrappedMetaKey: Data, vaultWrappedItemKey: Data,
                     writerDeviceID: String, signature: Data, updatedAt: Int64) -> ItemData {
        var row = ItemData(vaultID: vaultID, itemID: itemID, revision: revision,
                           tombstone: tombstone, metaCiphertext: metaCiphertext,
                           secretCiphertext: secretCiphertext,
                           vaultWrappedMetaKey: vaultWrappedMetaKey,
                           vaultWrappedItemKey: vaultWrappedItemKey,
                           writerDeviceID: writerDeviceID, signature: signature,
                           updatedAt: updatedAt)
        return row
    }
}

public extension GrantData {
    static func make(deviceID: String, itemID: String, kind: String,
                     hpkeEnc: Data, wrappedKey: Data, expiresAt: Int64,
                     revision: UInt64, signature: Data, deleted: Bool) -> GrantData {
        GrantData(deviceID: deviceID, itemID: itemID, kind: kind,
                  hpkeEnc: hpkeEnc, wrappedKey: wrappedKey, expiresAt: expiresAt,
                  revision: revision, signature: signature, deleted: deleted)
    }
}

public extension DeviceData {
    static func make(deviceID: String, kind: String, status: String, label: String,
                     createdAt: Int64, revokedAt: Int64?) -> DeviceData {
        DeviceData(deviceID: deviceID, kind: kind, status: status, label: label,
                   createdAt: createdAt, revokedAt: revokedAt)
    }
}

public extension DirectoryData {
    static func make(directoryRevision: UInt64, signed: Data, signature: Data) -> DirectoryData {
        DirectoryData(directoryRevision: directoryRevision, signed: signed, signature: signature)
    }
}

public extension PutItemRequest {
    static func make(revision: UInt64, tombstone: Bool, metaCiphertext: Data,
                     secretCiphertext: Data, vaultWrappedMetaKey: Data,
                     vaultWrappedItemKey: Data, writerDeviceID: String,
                     signature: Data) -> PutItemRequest {
        PutItemRequest(revision: revision, tombstone: tombstone,
                       metaCiphertext: metaCiphertext, secretCiphertext: secretCiphertext,
                       vaultWrappedMetaKey: vaultWrappedMetaKey,
                       vaultWrappedItemKey: vaultWrappedItemKey,
                       writerDeviceID: writerDeviceID, signature: signature)
    }
}

public extension DeleteItemRequest {
    static func make(revision: UInt64, signature: Data) -> DeleteItemRequest {
        DeleteItemRequest(revision: revision, signature: signature)
    }
}

public extension PutGrantsRequest {
    static func make(grants: [GrantData]) -> PutGrantsRequest {
        PutGrantsRequest(grants: grants)
    }
}

public extension DeleteGrantRequest {
    static func make(deviceID: String, itemID: String, kind: String,
                     revision: UInt64, signature: Data) -> DeleteGrantRequest {
        DeleteGrantRequest(deviceID: deviceID, itemID: itemID, kind: kind,
                           revision: revision, signature: signature)
    }
}

public extension PutDirectoryRequest {
    static func make(directoryRevision: UInt64, directorySigned: Data,
                     signature: Data) -> PutDirectoryRequest {
        PutDirectoryRequest(directoryRevision: directoryRevision,
                            directorySigned: directorySigned, signature: signature)
    }
}

public extension PlanLimits {
    static func make(items: Int64?, devicesIOS: Int64?, devicesCLI: Int64?,
                     storageBytes: Int64?, auditRetentionDays: Int64?,
                     auditMaxEvents: Int64?, requestsPerDay: Int64?,
                     requestsPerMinute: Int64?) -> PlanLimits {
        PlanLimits(items: items, devicesIOS: devicesIOS, devicesCLI: devicesCLI,
                   storageBytes: storageBytes, auditRetentionDays: auditRetentionDays,
                   auditMaxEvents: auditMaxEvents, requestsPerDay: requestsPerDay,
                   requestsPerMinute: requestsPerMinute)
    }
}

public extension AccountUsage {
    static func make(items: Int64, devicesActive: Int64, storageBytes: Int64,
                     auditEvents: Int64, requestsToday: Int64) -> AccountUsage {
        AccountUsage(items: items, devicesActive: devicesActive,
                     storageBytes: storageBytes, auditEvents: auditEvents,
                     requestsToday: requestsToday)
    }
}

public extension CreateVaultRequest {
    static func make(vaultID: String, device: DeviceInput,
                     recoveryWrap: Data, recoveryKDFJSON: String,
                     recoverySignPub: Data, directoryRevision: UInt64,
                     directorySigned: Data, signature: Data,
                     pow: PoWSolution?) -> CreateVaultRequest {
        CreateVaultRequest(vaultID: vaultID, device: device,
                           recoveryWrap: recoveryWrap, recoveryKDFJSON: recoveryKDFJSON,
                           recoverySignPub: recoverySignPub,
                           directoryRevision: directoryRevision,
                           directorySigned: directorySigned, signature: signature, pow: pow)
    }
}

public extension DeviceInput {
    static func make(deviceID: String, kind: String, hpkeKEM: String,
                     hpkePublicKey: Data, signAlg: String, signPublicKey: Data,
                     label: String, renewalSignPublicKey: Data) -> DeviceInput {
        DeviceInput(deviceID: deviceID, kind: kind, hpkeKEM: hpkeKEM,
                    hpkePublicKey: hpkePublicKey, signAlg: signAlg,
                    signPublicKey: signPublicKey, label: label,
                    renewalSignPublicKey: renewalSignPublicKey)
    }
}

public extension RecoveryDirectoryRequest {
    static func make(vaultID: String, directoryRevision: UInt64,
                     directorySigned: Data, recoverySignature: Data,
                     ownerSignature: Data) -> RecoveryDirectoryRequest {
        RecoveryDirectoryRequest(vaultID: vaultID, directoryRevision: directoryRevision,
                                 directorySigned: directorySigned,
                                 recoverySignature: recoverySignature,
                                 ownerSignature: ownerSignature)
    }
}

public extension VaultFlows {
    /// Builds a TakeoverPlan from pre-signed parts (UI 本机重建 path, §9.5:
    /// the takeover transcript only refreshes this device's row).
    static func makeTakeoverPlan(vaultID: String, vmk: Data,
                                 request: RecoveryDirectoryRequest,
                                 directoryTranscript: Data) -> TakeoverPlan {
        TakeoverPlan(vaultID: vaultID, vmk: vmk, request: request,
                     directoryTranscript: directoryTranscript)
    }
}

public extension PairingOffer {
    /// Builds an offer from parts (UI tests, previews). `kind` is the QR
    /// `t` parameter and `confirmSecret` the QR `c` secret (§9.1, v2 D).
    static func make(hpkeKEM: String, hpkePublicKey: Data,
                     signAlg: String, signPublicKey: Data,
                     nonce: String, label: String, origin: URL,
                     kind: String = DeviceKind.cli,
                     confirmSecret: Data) -> PairingOffer {
        PairingOffer(hpkeKEM: hpkeKEM, hpkePublicKey: hpkePublicKey,
                     signAlg: signAlg, signPublicKey: signPublicKey,
                     nonce: nonce, label: label, origin: origin,
                     kind: kind, confirmSecret: confirmSecret)
    }
}
