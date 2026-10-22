#include "cw_api.h"

#include <cstring>
#include <filesystem>
#include <mutex>

#include "JsonBridge/JsonBridge.h"
#include "platform/paths/paths.h"

/*
 * The paths the front end passed to cw_init; the core asks for them through paths::.
 */
namespace {
    std::mutex g_paths_mutex;
    std::filesystem::path g_data_directory;
    std::filesystem::path g_resource_directory;

    std::filesystem::path utf8Path(const char* text) {
        return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(text ? text : "")));
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

extern "C" {
void cw_init(const char* data_dir, const char* resource_dir) {
    std::lock_guard<std::mutex> lock(g_paths_mutex);
    g_data_directory = utf8Path(data_dir);
    g_resource_directory = utf8Path(resource_dir);
}

char* cw_call(const char* method, const char* args) {
    clientwarden::SecureString response = clientwarden::bridge::JsonBridge::shared().call(
            method ? method : "", args ? args : "{}");
    char* out = new char[response.size() + 1];
    std::memcpy(out, response.data(), response.size());
    out[response.size()] = '\0';
    return out;
}

void cw_free(char* response) {
    if (!response) {
        return;
    }
    volatile char* bytes = response;
    for (size_t i = 0, n = std::strlen(response); i < n; ++i) {
        bytes[i] = 0;
    }
    delete[] response;
}

void cw_on_event(void (*callback)(const char* event, void* context), void* context) {
    if (!callback) {
        clientwarden::bridge::JsonBridge::shared().onEvent(nullptr);
        return;
    }
    clientwarden::bridge::JsonBridge::shared().onEvent(
            [callback, context](clientwarden::SecureString event) { callback(event.c_str(), context); });
}
}
