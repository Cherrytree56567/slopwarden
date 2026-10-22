#pragma once
#include <jni.h>
#include <string_view>

#include "utils/secure_string/secure_string.h"

/*
 * Shared JNI plumbing for the Android binding: the cached JavaVM and app classes, attaching
 * the core's background threads, and converting strings without going through JNI's
 * "modified UTF-8" (which mangles emoji and other characters outside the BMP).
 */
namespace clientwarden::android {
    /**
     * @brief The JNIEnv for the calling thread, attaching it to the VM if it's one of the core's
     * own threads (it's detached again when the thread exits).
     *
     * @return The env, or nullptr before JNI_OnLoad
     */
    JNIEnv* Env();

    /**
     * @brief com.ct5.clientwarden.Native, cached in JNI_OnLoad (FindClass can't see app classes
     * from a native thread).
     */
    jclass NativeClass();

    /**
     * @brief com.ct5.clientwarden.SecretVault, cached in JNI_OnLoad.
     */
    jclass SecretVaultClass();

    /**
     * @brief Converts a Java string to UTF-8 in secure memory.
     *
     * @param env The JNI env
     * @param value The string (null gives an empty result)
     * @return The UTF-8 text
     */
    SecureString FromJava(JNIEnv* env, jstring value);

    /**
     * @brief Converts UTF-8 to a new Java string.
     *
     * @param env The JNI env
     * @param value The UTF-8 text
     * @return A local reference, or nullptr if out of memory
     */
    jstring ToJava(JNIEnv* env, std::string_view value);

    /**
     * @brief Clears any pending Java exception.
     *
     * @param env The JNI env
     * @return True if there was one
     */
    bool ClearException(JNIEnv* env);
}
