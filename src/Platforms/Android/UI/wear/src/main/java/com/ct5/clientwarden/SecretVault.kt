package com.ct5.clientwarden

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.annotation.Keep
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/*
 * The Android secret store the native core uses (Android has no keychain library backend).
 *
 * Values are AES-256-GCM encrypted under a non-exportable AndroidKeyStore key and kept in
 * private SharedPreferences. Secrets marked "user auth" use a second key that only works for
 * 10 seconds after a biometric or device-credential prompt, so the UI shows BiometricPrompt
 * right before asking the core to read or write one.
 *
 * Called from native code on a background thread; the names and signatures are part of the
 * JNI contract:
 *   static byte[] get(String key)                                  null if missing/unreadable
 *   static boolean set(String key, byte[] value, boolean userAuth)
 *   static boolean remove(String key)
 */
@Keep
object SecretVault {
    private const val c_keystore = "AndroidKeyStore"
    private const val c_key = "clientwarden-secrets"
    private const val c_auth_key = "clientwarden-secrets-auth"
    private const val c_prefs = "clientwarden-secrets"
    private const val c_auth_seconds = 10
    private const val c_iv_size = 12
    private const val c_tag_bits = 128

    private lateinit var prefs: SharedPreferences
    private val lock = Any()

    fun init(context: Context) {
        prefs = context.getSharedPreferences(c_prefs, Context.MODE_PRIVATE)
    }

    /*
     * Creates the auth-bound key ahead of the prompt that's about to authorise its first use
     */
    fun prepareAuthKey() {
        synchronized(lock) {
            try {
                key(userAuth = true, create = true)
            } catch (e: Exception) {
                // set() will report the failure
            }
        }
    }

    @JvmStatic
    @Keep
    fun get(key: String): ByteArray? = synchronized(lock) {
        val stored = prefs.getString(key, null) ?: return null
        if (stored.length < 2 || stored[1] != ':') {
            return null
        }
        val auth = stored[0] == 'a'
        return try {
            val blob = Base64.decode(stored.substring(2), Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(auth, create = false) ?: return null,
                GCMParameterSpec(c_tag_bits, blob, 0, c_iv_size))
            cipher.updateAAD(key.toByteArray())
            cipher.doFinal(blob, c_iv_size, blob.size - c_iv_size)
        } catch (e: Exception) {
            /*
             * Not authenticated recently, or the key was invalidated (e.g. new fingerprint
             * enrolled). The core treats a missing secret as "not available".
             */
            null
        }
    }

    @JvmStatic
    @Keep
    fun set(key: String, value: ByteArray, userAuth: Boolean): Boolean = synchronized(lock) {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key(userAuth, create = true))
            cipher.updateAAD(key.toByteArray())
            val sealed = cipher.doFinal(value)
            val blob = cipher.iv + sealed
            prefs.edit()
                .putString(key, (if (userAuth) "a:" else "n:") + Base64.encodeToString(blob, Base64.NO_WRAP))
                .commit()
        } catch (e: Exception) {
            false
        } finally {
            value.fill(0)
        }
    }

    @JvmStatic
    @Keep
    fun remove(key: String): Boolean = synchronized(lock) {
        return prefs.edit().remove(key).commit()
    }

    private fun key(userAuth: Boolean, create: Boolean): SecretKey? {
        val alias = if (userAuth) c_auth_key else c_key
        val store = KeyStore.getInstance(c_keystore).apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        if (!create) {
            return null
        }
        return try {
            generate(alias, userAuth, strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generate(alias, userAuth, strongBox = false)
        }
    }

    private fun generate(alias: String, userAuth: Boolean, strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .apply {
                if (userAuth) {
                    setUserAuthenticationRequired(true)
                    setUserAuthenticationParameters(c_auth_seconds,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                    setInvalidatedByBiometricEnrollment(true)
                }
            }
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, c_keystore)
        generator.init(spec)
        return generator.generateKey()
    }
}
