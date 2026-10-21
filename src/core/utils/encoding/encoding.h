#pragma once
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "utils/secure_string/secure_string.h"

namespace clientwarden::encoding {
    /**
     * @brief Standard base64 with padding.
     *
     * @param data Bytes to encode
     * @return The base64 text
     */
    SecureString base64Encode(std::span<const uint8_t> data);

    /**
     * @brief Decodes standard base64.
     *
     * @param text Base64 text (padding optional, no whitespace)
     * @return The decoded bytes
     * @throws CryptoError if text isn't valid base64
     */
    SecureBytes base64Decode(std::string_view text);

    /**
     * @brief Unpadded URL-safe base64, as used by WebAuthn.
     *
     * @param data Bytes to encode
     * @return The base64url text
     */
    SecureString base64UrlEncode(std::span<const uint8_t> data);

    /**
     * @brief Lowercase hexadecimal.
     *
     * @param data Bytes to encode
     * @return Two hex digits per byte
     */
    SecureString hexEncode(std::span<const uint8_t> data);

    /**
     * @brief application/x-www-form-urlencoded body from key/value pairs.
     *
     * @param fields The form fields, in order
     * @return The encoded body
     */
    SecureString formEncode(const std::vector<std::pair<SecureString, SecureString>>& fields);

    /**
     * @brief Views text as bytes without copying.
     *
     * @param text The text to view
     * @return A byte span over the same memory
     */
    std::span<const uint8_t> bytesOf(std::string_view text);

    /**
     * @brief Views bytes as text without copying.
     *
     * @param bytes The bytes to view
     * @return A string view over the same memory
     */
    std::string_view textOf(std::span<const uint8_t> bytes);
}
