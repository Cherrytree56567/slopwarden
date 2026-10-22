#include "Jni.h"

#include <cstdint>
#include <vector>

#include <botan/secmem.h>

namespace clientwarden::android {
    namespace {
        JavaVM* g_vm = nullptr;
        jclass g_native = nullptr;
        jclass g_secret_vault = nullptr;

        /*
         * Detaches a thread the binding attached, when that thread exits; the VM refuses to
         * let an attached thread die.
         */
        struct ThreadAttachment {
            bool attached = false;

            ~ThreadAttachment() {
                if (attached && g_vm) {
                    g_vm->DetachCurrentThread();
                }
            }
        };

        thread_local ThreadAttachment t_attachment;

        jclass GlobalClass(JNIEnv* env, const char* name) {
            jclass local = env->FindClass(name);
            if (!local) {
                ClearException(env);
                return nullptr;
            }
            jclass global = static_cast<jclass>(env->NewGlobalRef(local));
            env->DeleteLocalRef(local);
            return global;
        }
    }

    JNIEnv* Env() {
        if (!g_vm) {
            return nullptr;
        }
        JNIEnv* env = nullptr;
        if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
            return env;
        }
        if (g_vm->AttachCurrentThreadAsDaemon(&env, nullptr) != JNI_OK) {
            return nullptr;
        }
        t_attachment.attached = true;
        return env;
    }

    jclass NativeClass() {
        return g_native;
    }

    jclass SecretVaultClass() {
        return g_secret_vault;
    }

    SecureString FromJava(JNIEnv* env, jstring value) {
        SecureString out;
        if (!value) {
            return out;
        }
        jsize length = env->GetStringLength(value);
        const jchar* chars = env->GetStringChars(value, nullptr);
        if (!chars) {
            ClearException(env);
            return out;
        }
        out.reserve(static_cast<size_t>(length) * 3);
        for (jsize i = 0; i < length; ++i) {
            uint32_t code = chars[i];
            if (code >= 0xD800 && code <= 0xDBFF && i + 1 < length && chars[i + 1] >= 0xDC00 && chars[i + 1] <= 0xDFFF) {
                code = 0x10000 + ((code - 0xD800) << 10) + (chars[i + 1] - 0xDC00);
                ++i;
            } else if (code >= 0xD800 && code <= 0xDFFF) {
                code = 0xFFFD; // unpaired surrogate
            }
            if (code < 0x80) {
                out.push_back(static_cast<char>(code));
            } else if (code < 0x800) {
                out.push_back(static_cast<char>(0xC0 | (code >> 6)));
                out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            } else if (code < 0x10000) {
                out.push_back(static_cast<char>(0xE0 | (code >> 12)));
                out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            } else {
                out.push_back(static_cast<char>(0xF0 | (code >> 18)));
                out.push_back(static_cast<char>(0x80 | ((code >> 12) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
            }
        }
        env->ReleaseStringChars(value, chars);
        return out;
    }

    jstring ToJava(JNIEnv* env, std::string_view value) {
        std::vector<jchar, Botan::secure_allocator<jchar>> units;
        units.reserve(value.size());
        size_t i = 0;
        while (i < value.size()) {
            unsigned char lead = static_cast<unsigned char>(value[i]);
            uint32_t code = 0xFFFD;
            size_t extra = 0;
            if (lead < 0x80) {
                code = lead;
            } else if ((lead & 0xE0) == 0xC0) {
                code = lead & 0x1F;
                extra = 1;
            } else if ((lead & 0xF0) == 0xE0) {
                code = lead & 0x0F;
                extra = 2;
            } else if ((lead & 0xF8) == 0xF0) {
                code = lead & 0x07;
                extra = 3;
            }
            ++i;
            bool valid = lead < 0x80 || extra > 0;
            for (size_t k = 0; k < extra; ++k, ++i) {
                if (i >= value.size() || (static_cast<unsigned char>(value[i]) & 0xC0) != 0x80) {
                    valid = false;
                    break;
                }
                code = (code << 6) | (static_cast<unsigned char>(value[i]) & 0x3F);
            }
            if (!valid || code > 0x10FFFF || (code >= 0xD800 && code <= 0xDFFF)) {
                code = 0xFFFD;
            }
            if (code >= 0x10000) {
                code -= 0x10000;
                units.push_back(static_cast<jchar>(0xD800 + (code >> 10)));
                units.push_back(static_cast<jchar>(0xDC00 + (code & 0x3FF)));
            } else {
                units.push_back(static_cast<jchar>(code));
            }
        }
        jstring result = env->NewString(units.data(), static_cast<jsize>(units.size()));
        if (!result) {
            ClearException(env);
        }
        return result;
    }

    bool ClearException(JNIEnv* env) {
        if (!env->ExceptionCheck()) {
            return false;
        }
        env->ExceptionClear();
        return true;
    }
}

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    clientwarden::android::g_vm = vm;
    clientwarden::android::g_native = clientwarden::android::GlobalClass(env, "com/ct5/clientwarden/Native");
    clientwarden::android::g_secret_vault = clientwarden::android::GlobalClass(env, "com/ct5/clientwarden/SecretVault");
    return JNI_VERSION_1_6;
}
