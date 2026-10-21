#include "secure_string.h"

#include <charconv>

namespace clientwarden {
    SecureString toSecureString(std::int64_t value) {
        char buffer[24];
        std::to_chars_result result = std::to_chars(buffer, buffer + sizeof(buffer), value);
        return SecureString(buffer, result.ptr);
    }

    bool parseInt(std::string_view text, std::int64_t& out) {
        if (!text.empty() && text.front() == '+') {
            text.remove_prefix(1);
        }
        std::from_chars_result result =
                std::from_chars(text.data(), text.data() + text.size(), out);
        return result.ec == std::errc() && result.ptr == text.data() + text.size() && !text.empty();
    }

    SecureString toLower(std::string_view text) {
        SecureString out(text);
        for (char& c : out) {
            if (c >= 'A' && c <= 'Z') {
                c = static_cast<char>(c - 'A' + 'a');
            }
        }
        return out;
    }

    SecureString trim(std::string_view text) {
        const std::string_view space = " \t\r\n\f\v";
        size_t start = text.find_first_not_of(space);
        if (start == std::string_view::npos) {
            return SecureString();
        }
        size_t end = text.find_last_not_of(space);
        return SecureString(text.substr(start, end - start + 1));
    }

    const Json& at(const Json& object, std::string_view key) {
        static const Json c_null;
        if (!object.is_object()) {
            return c_null;
        }
        Json::const_iterator it = object.find(key);
        return it == object.end() ? c_null : *it;
    }

    SecureString stringAt(const Json& object, std::string_view key) {
        const Json& value = at(object, key);
        return value.is_string() ? value.get<SecureString>() : SecureString();
    }
}
