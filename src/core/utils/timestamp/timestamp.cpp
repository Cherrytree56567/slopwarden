#include "timestamp.h"

#include <chrono>
#include <cstdio>

namespace clientwarden::timestamp {
    namespace {
        /**
         * @brief Reads exactly `count` digits starting at `pos`.
         */
        bool digits_(std::string_view text, size_t pos, size_t count, int& out) {
            if (pos + count > text.size()) {
                return false;
            }
            out = 0;
            for (size_t i = pos; i < pos + count; ++i) {
                if (text[i] < '0' || text[i] > '9') {
                    return false;
                }
                out = out * 10 + (text[i] - '0');
            }
            return true;
        }

        /**
         * @brief Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm).
         */
        std::int64_t daysFromCivil_(std::int64_t y, unsigned m, unsigned d) {
            y -= m <= 2;
            std::int64_t era = (y >= 0 ? y : y - 399) / 400;
            unsigned yoe = static_cast<unsigned>(y - era * 400);
            unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
            unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
        }

        std::tm toTm_(std::time_t time, bool local) {
            std::tm tm = {};
#ifdef _WIN32
            local ? localtime_s(&tm, &time) : gmtime_s(&tm, &time);
#else
            local ? localtime_r(&time, &tm) : gmtime_r(&time, &tm);
#endif
            return tm;
        }
    }

    std::time_t parse(std::string_view text) {
        int year = 0;
        int month = 0;
        int day = 0;
        int hour = 0;
        int minute = 0;
        int second = 0;
        bool ok = digits_(text, 0, 4, year) && text.size() > 4 && text[4] == '-' &&
                  digits_(text, 5, 2, month) && text.size() > 7 && text[7] == '-' &&
                  digits_(text, 8, 2, day) && text.size() > 10 && text[10] == 'T' &&
                  digits_(text, 11, 2, hour) && text.size() > 13 && text[13] == ':' &&
                  digits_(text, 14, 2, minute) && text.size() > 16 && text[16] == ':' &&
                  digits_(text, 17, 2, second);
        if (!ok || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 ||
                second > 60) {
            return 0;
        }

        std::int64_t days =
                daysFromCivil_(year, static_cast<unsigned>(month), static_cast<unsigned>(day));
        return static_cast<std::time_t>(days * 86400 + hour * 3600 + minute * 60 + second);
    }

    SecureString format(std::time_t time, int millis) {
        std::tm tm = toTm_(time, false);
        char buffer[32];
        int length = std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                millis);
        return SecureString(buffer, static_cast<size_t>(length));
    }

    SecureString now(int offset_seconds) {
        std::chrono::system_clock::time_point current = std::chrono::system_clock::now();
        std::int64_t ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(current.time_since_epoch())
                        .count();
        return format(
                static_cast<std::time_t>(ms / 1000 + offset_seconds), static_cast<int>(ms % 1000));
    }

    SecureString localString(std::time_t time) {
        std::tm tm = toTm_(time, true);
        char buffer[32];
        int length = std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
        return SecureString(buffer, static_cast<size_t>(length));
    }
}
