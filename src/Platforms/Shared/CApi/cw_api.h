#pragma once

/*
 * A C interface over the JSON bridge, for front ends in other languages (the Rust/iced UI on
 * Linux and Windows). Strings are UTF-8 and NUL-terminated. Every response is the bridge's
 * JSON envelope: {"ok": true, "result": ...} or {"ok": false, "error": "..."}.
 */

#ifdef _WIN32
#define CW_API __declspec(dllexport)
#else
#define CW_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Tells the core where to keep its data and find its resources. Call once, before
 * anything else.
 *
 * @param data_dir The app's data directory (created if missing)
 * @param resource_dir Where clientgen.txt (the passphrase word list) is
 */
CW_API void cw_init(const char* data_dir, const char* resource_dir);

/**
 * @brief Runs a bridge method, e.g. cw_call("auth.unlock", "{\"password\":\"...\"}").
 *
 * Blocks until done (some calls reach the network), so call it off the UI thread.
 *
 * @param method The method name
 * @param args A JSON object, or NULL for none
 * @return The JSON response; release it with cw_free
 */
CW_API char* cw_call(const char* method, const char* args);

/**
 * @brief Wipes and frees a string returned by cw_call.
 *
 * @param response The string (NULL is ignored)
 */
CW_API void cw_free(char* response);

/**
 * @brief Receives events the vault raises by itself, e.g. {"event":"state","state":"Unlockable"}
 * after auto-lock. Called on a background thread; the string is only valid during the call.
 *
 * @param callback The listener, or NULL to stop listening
 * @param context Passed back to the listener
 */
CW_API void cw_on_event(void (*callback)(const char* event, void* context), void* context);

#ifdef __cplusplus
}
#endif
