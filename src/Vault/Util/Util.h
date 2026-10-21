#pragma once
#include <ctime>
#include <string>
#include <string_view>

#include "Clientwarden.h"

namespace ClientWarden {
    /*
     * Bitwarden timestamps are ISO-8601 UTC, e.g. 2026-08-22T06:53:51.78Z.
     * ParseTime returns 0 for null/malformed input rather than throwing,
     * since server data is untrusted and an unparsable date should sort
     * as "oldest" rather than abort a sync.
    */
    std::time_t ParseTime(std::string_view time);
    std::string FormatTime(std::time_t time);
    std::string NowTime(int offsetSeconds = 0);
    std::string LocalTimeString(std::time_t time);

    std::string NewGuid();
    std::string ToLower(std::string_view str);
}
