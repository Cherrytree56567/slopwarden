#include "utc.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sys/time.h>

#include "platform.h"
#include "platform/paths/paths.h"

namespace clientwarden::console::utc {
    namespace {
        std::atomic<int32_t> g_offset = 0; // 32 bits: 64-bit atomics need libatomic on the Wii
        std::atomic<bool> g_learned = false;

        std::filesystem::path file_() {
            return paths::dataDirectory() / "clock.txt";
        }

        /*
         * Days since 1970-01-01 for a civil date (Howard Hinnant's algorithm), so no time zone
         * functions are involved.
         */
        int64_t daysFromCivil_(int64_t y, unsigned m, unsigned d) {
            y -= m <= 2;
            int64_t era = (y >= 0 ? y : y - 399) / 400;
            unsigned yoe = static_cast<unsigned>(y - era * 400);
            unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
            unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            return era * 146097 + static_cast<int64_t>(doe) - 719468;
        }

        /*
         * The console's own clock, without the correction.
         */
        int64_t consoleNow_() {
            return static_cast<int64_t>(std::time(nullptr)) - g_offset.load();
        }
    }

    int64_t offsetSeconds() {
        return g_offset.load();
    }

    void observeServerDate(std::string_view date_header) {
        // "Tue, 21 Oct 2026 11:22:09 GMT"
        static constexpr std::array<const char*, 12> c_months = { "Jan", "Feb", "Mar", "Apr",
            "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
        char buffer[40] = {};
        std::memcpy(buffer, date_header.data(), std::min(date_header.size(), sizeof(buffer) - 1));
        char month[4] = {};
        int day = 0, year = 0, hour = 0, minute = 0, second = 0;
        if (std::sscanf(buffer, "%*3s, %d %3s %d %d:%d:%d", &day, month, &year, &hour, &minute, &second) != 6) {
            return;
        }
        unsigned month_index = 0;
        while (month_index < c_months.size() && std::strcmp(c_months[month_index], month) != 0) {
            ++month_index;
        }
        if (month_index == c_months.size()) {
            return;
        }
        int64_t server = daysFromCivil_(year, month_index + 1, static_cast<unsigned>(day)) * 86400 +
                         hour * 3600 + minute * 60 + second;
        /*
         * The whole difference: the time zone and however fast or slow the console clock
         * runs (TOTP codes are only valid for 30 s). Within a second or two of what we have is
         * just network delay.
         */
        int64_t offset = server - consoleNow_();
        if (g_learned && std::llabs(offset - g_offset.load()) < 2) {
            return;
        }
        g_offset = static_cast<int32_t>(offset);
        g_learned = true;

        if (FILE* f = std::fopen(file_().c_str(), "w")) {
            std::fprintf(f, "%lld\n", static_cast<long long>(offset));
            std::fclose(f);
        }
    }

    void load() {
        if (FILE* f = std::fopen(file_().c_str(), "r")) {
            long long offset = 0;
            if (std::fscanf(f, "%lld", &offset) == 1) {
                g_offset = static_cast<int32_t>(offset);
            }
            std::fclose(f);
        }
    }
}

/*
 * The console's clock is whatever the user set in the system settings, in local time, with no time
 * zone. TOTP codes and token expiry need UTC, so every gettimeofday()/clock_gettime() is
 * shifted by the offset learned from servers' Date headers (below). Wired in with the
 * linker's --wrap so newlib's time functions all go through it.
 */
extern "C" {
int __real___syscall_gettod_r(struct _reent* ptr, struct timeval* tp, struct timezone* tz);
int __real___syscall_clock_gettime(clockid_t clock_id, struct timespec* tp);

int __wrap___syscall_gettod_r(struct _reent* ptr, struct timeval* tp, struct timezone* tz) {
    int result = __real___syscall_gettod_r(ptr, tp, tz);
    if (result == 0 && tp) {
        tp->tv_sec += clientwarden::console::utc::offsetSeconds();
    }
    return result;
}

int __wrap___syscall_clock_gettime(clockid_t clock_id, struct timespec* tp) {
    int result = __real___syscall_clock_gettime(clock_id, tp);
    if (result == 0 && tp && clock_id == CLOCK_REALTIME) {
        tp->tv_sec += clientwarden::console::utc::offsetSeconds();
    }
    return result;
}
}
