#pragma once
#include <algorithm> // botan/secmem.h uses std::fill without including it
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>
#include <botan/secmem.h>
#include <nlohmann/json.hpp>

namespace clientwarden {
    /**
     * @brief Byte buffer that zeroes its memory when freed.
     *
     * Used for every key, ciphertext and decrypted payload in the vault core.
     */
    using SecureBytes = Botan::secure_vector<uint8_t>;

    /**
     * @brief String that zeroes its memory when freed.
     *
     * The vault core uses this instead of the standard string everywhere (ADR 3), so no text,
     * secret or not, is left behind in freed memory.
     */
    using SecureString =
            std::basic_string<char, std::char_traits<char>, Botan::secure_allocator<char>>;

    /**
     * @brief JSON document whose strings (and object keys) live in secure memory.
     *
     * Server responses carry ciphertext, tokens and ids; storing them in SecureString keeps
     * them out of ordinary heap memory even before decryption.
     */
    using Json = nlohmann::basic_json<std::map, std::vector, SecureString, bool, std::int64_t,
            std::uint64_t, double, std::allocator, nlohmann::adl_serializer,
            std::vector<std::uint8_t>>;

    /**
     * @brief Formats an integer as decimal text.
     *
     * @param value The number to format
     * @return The decimal representation
     */
    SecureString toSecureString(std::int64_t value);

    /**
     * @brief Parses a decimal integer.
     *
     * @param text Decimal digits, optionally signed
     * @param out Receives the value on success
     * @return True if the whole of text was a valid integer
     */
    bool parseInt(std::string_view text, std::int64_t& out);

    /**
     * @brief Lowercases ASCII letters.
     *
     * @param text The text to lowercase
     * @return A lowercased copy
     */
    SecureString toLower(std::string_view text);

    /**
     * @brief Removes leading and trailing ASCII whitespace.
     *
     * @param text The text to trim
     * @return A trimmed copy
     */
    SecureString trim(std::string_view text);

    /**
     * @brief Looks up a key without inserting it or invoking undefined behaviour.
     *
     * const operator[] on nlohmann::json is undefined for missing keys, and server data can
     * omit anything, so all reads of untrusted JSON go through this.
     *
     * @param object The JSON object to read from (anything else yields null)
     * @param key The key to look up
     * @return The value, or a shared null value if absent
     */
    const Json& at(const Json& object, std::string_view key);

    /**
     * @brief Reads a string member.
     *
     * @param object The JSON object to read from
     * @param key The key to look up
     * @return The string, or empty if absent or not a string
     */
    SecureString stringAt(const Json& object, std::string_view key);
}
