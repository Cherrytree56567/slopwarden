#pragma once
#include <ctime>
#include <string_view>

#include "utils/secure_string/secure_string.h"

namespace clientwarden::timestamp {
    /**
     * @brief Parses a Bitwarden ISO-8601 UTC timestamp (e.g. 2026-08-22T06:53:51.78Z).
     *
     * Server data is untrusted, so malformed input yields 0 ("oldest") rather than throwing.
     *
     * @param text The timestamp; fractional seconds and a trailing Z are optional
     * @return Seconds since the Unix epoch, or 0 if unparsable
     */
    std::time_t parse(std::string_view text);

    /**
     * @brief Formats a time as a Bitwarden timestamp with millisecond precision.
     *
     * @param time Seconds since the Unix epoch
     * @param millis Milliseconds to append (0-999)
     * @return e.g. 2026-08-22T06:53:51.000Z
     */
    SecureString format(std::time_t time, int millis = 0);

    /**
     * @brief The current time as a Bitwarden timestamp.
     *
     * @param offset_seconds Seconds to add to the current time
     * @return The formatted timestamp
     */
    SecureString now(int offset_seconds = 0);

    /**
     * @brief Formats a time in the local timezone for display.
     *
     * @param time Seconds since the Unix epoch
     * @return e.g. 2026-08-22 16:53:51
     */
    SecureString localString(std::time_t time);
}
