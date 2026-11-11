package com.ct5.clientwarden

import androidx.annotation.Keep

/*
 * The JNI surface of libclientwarden. Everything goes through the shared JSON bridge:
 * call(method, argsJson) returns {"ok": true, "result": ...} or {"ok": false, "error": "..."}.
 *
 * The native side calls back into onEvent (from any thread) with {"event": "state", ...}
 * and into SecretVault for the Android Keystore.
 */
@Keep
object Native {
    init {
        System.loadLibrary("clientwarden")
    }

    /*
     * Must run once before the first call: where the vault keeps its files, and where
     * bundled resources (the passphrase word list) were copied to.
     */
    @JvmStatic
    external fun nativeInit(dataDir: String, resourceDir: String)

    /*
     * Blocking; never call this from the main thread (it can hit the network).
     */
    @JvmStatic
    external fun call(method: String, args: String): String

    @Volatile
    var listener: ((String) -> Unit)? = null

    @JvmStatic
    @Keep
    fun onEvent(event: String) {
        listener?.invoke(event)
    }
}
