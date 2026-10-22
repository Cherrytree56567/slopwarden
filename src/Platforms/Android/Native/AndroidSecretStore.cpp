#include <algorithm>
#include <memory>

#include "Jni.h"
#include "platform/secret_store/platform_secret_store.h"

/*
 * Secrets on Android live in com.ct5.clientwarden.SecretVault, which encrypts them with
 * AndroidKeyStore keys (UserAuth entries use a key that needs biometrics or the device
 * credential). The keychain library's Android backend is a stub, so this replaces it.
 */
namespace {
    using clientwarden::SecretProtection;
    using clientwarden::SecureString;

    /*
     * Holds a local reference for the length of a call.
     */
    template <typename T>
    struct LocalRef {
        JNIEnv* env;
        T ref;

        ~LocalRef() {
            if (ref) {
                env->DeleteLocalRef(ref);
            }
        }
    };

    class AndroidSecretStore : public clientwarden::SecretStore {
    public:
        std::optional<SecureString> get(std::string_view key) override {
            JNIEnv* env = clientwarden::android::Env();
            jclass vault = clientwarden::android::SecretVaultClass();
            if (!env || !vault) {
                return std::nullopt;
            }
            jmethodID method = env->GetStaticMethodID(vault, "get", "(Ljava/lang/String;)[B");
            if (!method) {
                clientwarden::android::ClearException(env);
                return std::nullopt;
            }
            LocalRef<jstring> name { env, clientwarden::android::ToJava(env, key) };
            LocalRef<jbyteArray> value { env, static_cast<jbyteArray>(env->CallStaticObjectMethod(vault, method, name.ref)) };
            if (clientwarden::android::ClearException(env) || !value.ref) {
                return std::nullopt;
            }

            jsize length = env->GetArrayLength(value.ref);
            SecureString out(static_cast<size_t>(length), '\0');
            env->GetByteArrayRegion(value.ref, 0, length, reinterpret_cast<jbyte*>(out.data()));
            Wipe(env, value.ref, length);
            return out;
        }

        bool set(std::string_view key, std::string_view value, SecretProtection protection) override {
            JNIEnv* env = clientwarden::android::Env();
            jclass vault = clientwarden::android::SecretVaultClass();
            if (!env || !vault) {
                return false;
            }
            jmethodID method = env->GetStaticMethodID(vault, "set", "(Ljava/lang/String;[BZ)Z");
            if (!method) {
                clientwarden::android::ClearException(env);
                return false;
            }
            LocalRef<jstring> name { env, clientwarden::android::ToJava(env, key) };
            jsize length = static_cast<jsize>(value.size());
            LocalRef<jbyteArray> bytes { env, env->NewByteArray(length) };
            if (!bytes.ref) {
                clientwarden::android::ClearException(env);
                return false;
            }
            env->SetByteArrayRegion(bytes.ref, 0, length, reinterpret_cast<const jbyte*>(value.data()));
            jboolean stored = env->CallStaticBooleanMethod(vault, method, name.ref, bytes.ref, protection == SecretProtection::UserAuth ? JNI_TRUE : JNI_FALSE);
            bool failed = clientwarden::android::ClearException(env);
            Wipe(env, bytes.ref, length);
            return !failed && stored == JNI_TRUE;
        }

        bool remove(std::string_view key) override {
            JNIEnv* env = clientwarden::android::Env();
            jclass vault = clientwarden::android::SecretVaultClass();
            if (!env || !vault) {
                return false;
            }
            jmethodID method = env->GetStaticMethodID(vault, "remove", "(Ljava/lang/String;)Z");
            if (!method) {
                clientwarden::android::ClearException(env);
                return false;
            }
            LocalRef<jstring> name { env, clientwarden::android::ToJava(env, key) };
            jboolean removed = env->CallStaticBooleanMethod(vault, method, name.ref);
            return !clientwarden::android::ClearException(env) && removed == JNI_TRUE;
        }

    private:
        /*
         * Zeroes a Java byte array that held a secret, so it doesn't linger on the Java heap.
         */
        static void Wipe(JNIEnv* env, jbyteArray array, jsize length) {
            jbyte* bytes = env->GetByteArrayElements(array, nullptr);
            if (bytes) {
                std::fill(bytes, bytes + length, 0);
                env->ReleaseByteArrayElements(array, bytes, 0);
            }
        }
    };
}

namespace clientwarden {
    std::shared_ptr<SecretStore> createPlatformSecretStore() {
        return std::make_shared<AndroidSecretStore>();
    }
}
