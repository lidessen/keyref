// NEW FILE (v0.7, design §6.6 存储类别): sealing a 仅本机 item. The meta
// material (meta ciphertext + vault_wrapped_meta_key) is uploaded so the
// CLI can `list` / `get` the meta and reference the item; the secret
// ciphertext and the vault_wrapped_item_key stay on this phone in the
// local secret store (§6.6: 服务器行 secret_ciphertext = NULL). The signed
// §3.1 transcript therefore carries empty secret_ciphertext and
// vault_wrapped_item_key fields — exactly what the server row will hold —
// and the returned secret material never leaves this device.
import Foundation

public extension ItemCrypto {
    /// Everything produced when sealing a local-only item.
    struct SealedLocalOnlyItem: Sendable {
        /// The signed transcript bytes cover meta + vault_wrapped_meta_key
        /// with EMPTY secret/vault_wrapped_item_key fields (§6.6).
        public var transcript: ItemTranscript
        public var signature: Data
        public var metaKey: Data
        public var itemKey: Data
        /// 仅本机：never uploaded — stored by the caller in the local
        /// secret store and delivered verbatim in approval decisions (§6.6).
        public var secretCiphertext: Data
        public var vaultWrappedItemKey: Data
    }

    /// Seals a local-only item under fresh meta/item keys. The meta's
    /// sensitivity is forced to `approval` (the derived §6.6 value); passing
    /// anything else in `meta.policy.sensitivity` is overridden, never
    /// silently kept.
    static func sealLocalOnlyItem(vaultID: String, itemID: String, revision: UInt64,
                                  writerDeviceID: String, vmk: Data,
                                  signer: TranscriptSigner,
                                  meta: ItemMeta, secret: SecretPlaintext) throws -> SealedLocalOnlyItem {
        var localMeta = meta
        localMeta.policy.sensitivity = StorageClass.localOnly.sensitivity
        let metaKey = randomKey()
        let itemKey = randomKey()
        let metaCT = try sealMeta(key: metaKey, meta: localMeta, vaultID: vaultID, itemID: itemID)
        let secretCT = try sealSecret(key: itemKey, secret: secret, vaultID: vaultID, itemID: itemID)
        let vwMeta = try wrapMetaKeyWithVMK(vmk: vmk, metaKey: metaKey, vaultID: vaultID, itemID: itemID)
        let vwItem = try wrapItemKeyWithVMK(vmk: vmk, itemKey: itemKey, vaultID: vaultID, itemID: itemID)
        let t = ItemTranscript(vaultID: vaultID, itemID: itemID, revision: revision,
                               metaCiphertext: metaCT, secretCiphertext: Data(),
                               vaultWrappedMetaKey: vwMeta, vaultWrappedItemKey: Data(),
                               writerDeviceID: writerDeviceID)
        let signature = try signer.sign(t.buildBytes())
        return SealedLocalOnlyItem(transcript: t, signature: signature,
                                   metaKey: metaKey, itemKey: itemKey,
                                   secretCiphertext: secretCT, vaultWrappedItemKey: vwItem)
    }

    /// Rotates a local-only item's secret on this phone only (§8.4 定期轮换:
    /// 仅本机条目只轮换本地包裹，不动服务器): new item key, re-encrypt, re-wrap
    /// under the VMK. The meta ciphertext is untouched (the server row keeps
    /// its meta), so the local record's own revision advances instead of the
    /// server row's.
    static func rotateLocalOnlySecret(vaultID: String, itemID: String, vmk: Data,
                                      meta: ItemMeta, secret: SecretPlaintext,
                                      oldRecord: LocalSecretRecord) throws -> LocalSecretRecord {
        let itemKey = randomKey()
        let secretCT = try sealSecret(key: itemKey, secret: secret, vaultID: vaultID, itemID: itemID)
        let vwItem = try wrapItemKeyWithVMK(vmk: vmk, itemKey: itemKey, vaultID: vaultID, itemID: itemID)
        return LocalSecretRecord(itemID: itemID, secretCiphertext: secretCT,
                                 vaultWrappedItemKey: vwItem,
                                 revision: oldRecord.revision + 1,
                                 updatedAt: oldRecord.updatedAt)
    }
}
