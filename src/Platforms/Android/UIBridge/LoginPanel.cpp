#include <jni.h>
#include <mutex>
#include <type_traits>
#include <string>
#include "Vault.h"

namespace {
    /*
     * Ordinals of the Kotlin enums these bridges drive.
    */
    enum class MainView : jint { Login = 0, Unlock = 1, Vault = 2 };
    enum class LoginScreenType : jint { Generic = 0, TOTP = 1, DeviceVerify = 2, Passkey = 3 };

    JavaVM* g_vm = nullptr;
    jclass g_mainActivityObject = nullptr;
    jclass g_loginScreen = nullptr;

    /*
     * Calls `INSTANCE.<method>(ordinal)` on a Kotlin object.
    */
    void callObjectSetter(JNIEnv* env, jclass objectClass, const char* signature, const char* method, jint ordinal) {
        if (objectClass == nullptr) {
            return;
        }

        jfieldID instanceField = env->GetStaticFieldID(objectClass, "INSTANCE", signature);
        jmethodID setter = env->GetMethodID(objectClass, method, "(I)V");
        if (instanceField == nullptr || setter == nullptr) {
            env->ExceptionClear();
            return;
        }

        jobject instance = env->GetStaticObjectField(objectClass, instanceField);
        env->CallVoidMethod(instance, setter, ordinal);
        env->DeleteLocalRef(instance);
    }

    /*
     * The NDK declares AttachCurrentThread(JNIEnv**, ...) while desktop
     * JDK headers use void**; accept either.
    */
    template <typename VM>
    jint attachThread(VM* vm, JNIEnv** env) {
        if constexpr (std::is_invocable_v<decltype(&VM::AttachCurrentThread), VM*, JNIEnv**, void*>) {
            return vm->AttachCurrentThread(env, nullptr);
        } else {
            return vm->AttachCurrentThread(reinterpret_cast<void**>(env), nullptr);
        }
    }

    void setScreenType(JNIEnv* env, LoginScreenType type) {
        callObjectSetter(env, g_loginScreen, "Lcom/ct5/clientwarden/LoginScreen;", "setScreenType", static_cast<jint>(type));
    }

    void setMainView(JNIEnv* env, MainView view) {
        callObjectSetter(env, g_mainActivityObject, "Lcom/ct5/clientwarden/MainActivityObject;", "setUIType", static_cast<jint>(view));
    }

    std::string toString(JNIEnv* env, jstring str) {
        const char* chars = env->GetStringUTFChars(str, nullptr);
        std::string out(chars);
        env->ReleaseStringUTFChars(str, chars);
        return out;
    }

    /*
     * Auto-lock and remote logout happen on vault background threads,
     * which have to attach to the JVM before calling into Kotlin.
    */
    void watchVaultState() {
        static std::once_flag once;
        std::call_once(once, [] {
            ClientWarden::Vault::Instance().OnStateChange([](ClientWarden::AuthState state) {
                if (g_vm == nullptr || (state != ClientWarden::AuthState::LoggedOut && state != ClientWarden::AuthState::Unlockable)) {
                    return;
                }

                JNIEnv* env = nullptr;
                bool attached = false;
                if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_EDETACHED) {
                    if (attachThread(g_vm, &env) != JNI_OK) {
                        return;
                    }
                    attached = true;
                }

                setMainView(env, state == ClientWarden::AuthState::LoggedOut ? MainView::Login : MainView::Unlock);

                if (attached) {
                    g_vm->DetachCurrentThread();
                }
            });
        });
    }
}

/*
 * FindClass only sees app classes from threads the JVM started, so the
 * classes are cached here for use from vault background threads.
*/
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    g_vm = vm;
    for (auto [name, slot] : { std::pair { "com/ct5/clientwarden/MainActivityObject", &g_mainActivityObject },
                               std::pair { "com/ct5/clientwarden/LoginScreen", &g_loginScreen } }) {
        jclass local = env->FindClass(name);
        if (local == nullptr) {
            env->ExceptionClear();
            continue;
        }
        *slot = static_cast<jclass>(env->NewGlobalRef(local));
        env->DeleteLocalRef(local);
    }
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_ct5_clientwarden_UIBridge_cbLogin(JNIEnv* env, jobject _this, jstring j_username, jstring j_password,
    jstring j_vaultURL, jstring j_mainURL, jstring j_apiURL, jstring j_iconURL, jstring j_wssURL) {
    try {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
        watchVaultState();

        /*
         * The main URL isn't needed by the vault; Bitwarden serves the
         * identity endpoints from the vault URL.
        */
        v_inst.SetServer(ClientWarden::ServerUrls {
            toString(env, j_vaultURL),
            toString(env, j_apiURL),
            toString(env, j_iconURL),
            toString(env, j_wssURL)
        });

        std::string password = toString(env, j_password);
        ClientWarden::LoginResult result = v_inst.Login(toString(env, j_username), password);
        Botan::secure_scrub_memory(password.data(), password.size());

        switch (result) {
            case ClientWarden::LoginResult::Success:
                setMainView(env, MainView::Vault);
                return JNI_TRUE;
            case ClientWarden::LoginResult::NeedsTotp:
                setScreenType(env, LoginScreenType::TOTP);
                setMainView(env, MainView::Login);
                return JNI_TRUE;
            case ClientWarden::LoginResult::NeedsDeviceVerification:
                setScreenType(env, LoginScreenType::DeviceVerify);
                setMainView(env, MainView::Login);
                return JNI_TRUE;
            case ClientWarden::LoginResult::NeedsPasskey:
                /*
                 * TODO: Passkey Login Support
                */
                return JNI_TRUE;
            default:
                /*
                 * TODO: TOAST
                */
                return JNI_FALSE;
        }
    } catch (...) {
        return JNI_FALSE;
    }
}
