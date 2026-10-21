#include "encoding.h"

#include <array>

#include "utils/errors/errors.h"

namespace clientwarden::encoding {
    namespace {
        constexpr std::string_view c_alphabet =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        /**
         * @brief Maps a base64 character to its 6-bit value, or -1.
         */
        int decodeChar_(char c) {
            if (c >= 'A' && c <= 'Z')
                return c - 'A';
            if (c >= 'a' && c <= 'z')
                return c - 'a' + 26;
            if (c >= '0' && c <= '9')
                return c - '0' + 52;
            if (c == '+' || c == '-')
                return 62;
            if (c == '/' || c == '_')
                return 63;
            return -1;
        }
    }

    SecureString base64Encode(std::span<const uint8_t> data) {
        SecureString out;
        out.reserve((data.size() + 2) / 3 * 4);
        for (size_t i = 0; i < data.size(); i += 3) {
            uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
            if (i + 1 < data.size())
                chunk |= static_cast<uint32_t>(data[i + 1]) << 8;
            if (i + 2 < data.size())
                chunk |= data[i + 2];

            out.push_back(c_alphabet[(chunk >> 18) & 0x3f]);
            out.push_back(c_alphabet[(chunk >> 12) & 0x3f]);
            out.push_back(i + 1 < data.size() ? c_alphabet[(chunk >> 6) & 0x3f] : '=');
            out.push_back(i + 2 < data.size() ? c_alphabet[chunk & 0x3f] : '=');
        }
        return out;
    }

    SecureBytes base64Decode(std::string_view text) {
        while (!text.empty() && text.back() == '=') {
            text.remove_suffix(1);
        }
        if (text.size() % 4 == 1) {
            throw CryptoError("invalid base64");
        }

        SecureBytes out;
        out.reserve(text.size() * 3 / 4);
        uint32_t buffer = 0;
        int bits = 0;
        for (char c : text) {
            int value = decodeChar_(c);
            if (value < 0) {
                throw CryptoError("invalid base64");
            }
            buffer = (buffer << 6) | static_cast<uint32_t>(value);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
            }
        }
        return out;
    }

    SecureString base64UrlEncode(std::span<const uint8_t> data) {
        SecureString out = base64Encode(data);
        for (char& c : out) {
            if (c == '+')
                c = '-';
            if (c == '/')
                c = '_';
        }
        while (!out.empty() && out.back() == '=') {
            out.pop_back();
        }
        return out;
    }

    SecureString hexEncode(std::span<const uint8_t> data) {
        constexpr std::string_view c_digits = "0123456789abcdef";
        SecureString out;
        out.reserve(data.size() * 2);
        for (uint8_t b : data) {
            out.push_back(c_digits[b >> 4]);
            out.push_back(c_digits[b & 0x0f]);
        }
        return out;
    }

    SecureString formEncode(const std::vector<std::pair<SecureString, SecureString>>& fields) {
        constexpr std::string_view c_digits = "0123456789ABCDEF";
        SecureString out;
        for (size_t i = 0; i < fields.size(); ++i) {
            if (i > 0) {
                out.push_back('&');
            }
            for (int part = 0; part < 2; ++part) {
                std::string_view text = part == 0 ? fields[i].first : fields[i].second;
                for (unsigned char c : text) {
                    bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                      (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
                                      c == '~';
                    if (unreserved) {
                        out.push_back(static_cast<char>(c));
                    } else {
                        out.push_back('%');
                        out.push_back(c_digits[c >> 4]);
                        out.push_back(c_digits[c & 0x0f]);
                    }
                }
                if (part == 0) {
                    out.push_back('=');
                }
            }
        }
        return out;
    }

    std::span<const uint8_t> bytesOf(std::string_view text) {
        return std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size());
    }

    std::string_view textOf(std::span<const uint8_t> bytes) {
        return std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
}
