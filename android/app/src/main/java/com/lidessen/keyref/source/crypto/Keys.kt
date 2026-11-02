package com.lidessen.keyref.source.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519

/**
 * The collector's software keys (design v0.8 §14.2): X25519 (HPKE) and
 * Ed25519 (request signing). Android Keystore cannot hold either algorithm
 * natively (design §14.2 documents this), so the private keys are encrypted
 * at rest with an AndroidKeyStore AES-GCM key and live in a private file.
 * Loss of the device is recoverable by revoking and re-pairing — this
 * device holds no secrets of its own.
 */
object Keys {

    private const val KEYSTORE_ALIAS = "keyref_source_master"
    const val X25519_SIZE = 32
    const val ED25519_SIZE = 32
    const val ED25519_SIG_SIZE = 64

    data class Identity(
        val x25519Public: ByteArray,   // 32 bytes, raw (protocol §1.4)
        val x25519Private: ByteArray,
        val ed25519Public: ByteArray,  // 32 bytes, raw
        val ed25519Private: ByteArray,
    )

    fun generate(): Identity {
        val rng = SecureRandom()
        val xPriv = ByteArray(X25519_SIZE).also { X25519.generatePrivateKey(rng, it) }
        val xPub = ByteArray(X25519_SIZE).also { X25519.generatePublicKey(xPriv, 0, it, 0) }
        val ePriv = ByteArray(Ed25519.SECRET_KEY_SIZE).also { Ed25519.generatePrivateKey(rng, it) }
        val ePub = ByteArray(ED25519_SIZE).also { Ed25519.generatePublicKey(ePriv, 0, it, 0) }
        return Identity(xPub, xPriv, ePub, ePriv)
    }

    fun sign(identity: Identity, message: ByteArray): ByteArray {
        val sig = ByteArray(ED25519_SIG_SIZE)
        Ed25519.sign(identity.ed25519Private, 0, message, 0, message.size, sig, 0)
        return sig
    }

    // -- at-rest protection: AndroidKeyStore AES-GCM wrapping ------------

    private fun masterKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getEntry(KEYSTORE_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return gen.generateKey()
    }

    fun saveIdentity(file: File, identity: Identity) {
        val plain = identity.x25519Public + identity.x25519Private +
            identity.ed25519Public + identity.ed25519Private
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, masterKey())
        val ct = cipher.doFinal(plain)
        file.writeBytes(cipher.iv + ct)
    }

    fun loadIdentity(file: File): Identity? {
        if (!file.exists()) return null
        val blob = file.readBytes()
        if (blob.size < 12 + 128) return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, masterKey(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        val plain = cipher.doFinal(blob.copyOfRange(12, blob.size))
        if (plain.size != X25519_SIZE * 2 + ED25519_SIZE * 2) return null
        var o = 0
        fun take(n: Int): ByteArray {
            val b = plain.copyOfRange(o, o + n); o += n; return b
        }
        return Identity(take(X25519_SIZE), take(X25519_SIZE), take(ED25519_SIZE), take(ED25519_SIZE))
    }
}
