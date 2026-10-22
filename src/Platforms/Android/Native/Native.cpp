#include <filesystem>
#include <mutex>

#include <spdlog/sinks/android_sink.h>
#include <spdlog/spdlog.h>

#include "Jni.h"
#include "JsonBridge/JsonBridge.h"
#include "platform/paths/paths.h"
#include "utils/logger/logger.h"

/*
 * com.ct5.clientwarden.Native: the Kotlin UI's only way into the vault. nativeInit tells the
 * core where the app's storage is, call() runs a JsonBridge method, and bridge events are
 * forwarded to Native.onEvent on the core's thread (Kotlin posts them to the main thread).
 */
namespace {
    std::mutex g_paths_mutex;
    std::filesystem::path g_data_directory;
    std::filesystem::path g_resource_directory;

    void ForwardEvent(clientwarden::SecureString event) {
        JNIEnv* env = clientwarden::android::Env();
        jclass native = clientwarden::android::NativeClass();
        if (!env || !native) {
            return;
        }
        jmethodID on_event = env->GetStaticMethodID(native, "onEvent", "(Ljava/lang/String;)V");
        if (!on_event) {
            clientwarden::android::ClearException(env);
            return;
        }
        jstring json = clientwarden::android::ToJava(env, event);
        if (json) {
            env->CallStaticVoidMethod(native, on_event, json);
            clientwarden::android::ClearException(env);
            env->DeleteLocalRef(json);
        }
    }
}

std::filesystem::path clientwarden::paths::dataDirectory() {
    std::lock_guard<std::mutex> lock(g_paths_mutex);
    return g_data_directory;
}

std::filesystem::path clientwarden::paths::resourceDirectory() {
    std::lock_guard<std::mutex> lock(g_paths_mutex);
    return g_resource_directory;
}

extern "C" JNIEXPORT void JNICALL Java_com_ct5_clientwarden_Native_nativeInit(JNIEnv* env, jclass, jstring files_dir, jstring resource_dir) {
    {
        std::lock_guard<std::mutex> lock(g_paths_mutex);
        g_data_directory = std::filesystem::path(clientwarden::android::FromJava(env, files_dir).c_str()) / "ClientWarden";
        g_resource_directory = std::filesystem::path(clientwarden::android::FromJava(env, resource_dir).c_str());
    }

    static std::once_flag once;
    std::call_once(once, []() {
        /*
         * stdout goes nowhere on Android; log to logcat instead.
         */
        clientwarden::Logger::set(std::make_shared<spdlog::logger>("clientwarden", std::make_shared<spdlog::sinks::android_sink_mt>("ClientWarden")));
        clientwarden::bridge::JsonBridge::shared().onEvent(ForwardEvent);
    });
}

extern "C" JNIEXPORT jstring JNICALL Java_com_ct5_clientwarden_Native_call(JNIEnv* env, jclass, jstring method, jstring args) {
    clientwarden::SecureString name = clientwarden::android::FromJava(env, method);
    clientwarden::SecureString arguments = clientwarden::android::FromJava(env, args);
    clientwarden::SecureString response = clientwarden::bridge::JsonBridge::shared().call(name, arguments);
    return clientwarden::android::ToJava(env, response);
}
