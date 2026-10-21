#include "Util.h"

#include <chrono>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace ClientWarden {
    std::shared_ptr<spdlog::logger> Log() {
        static std::once_flag once;
        std::call_once(once, [] {
            if (!logger) {
                logger = spdlog::stdout_color_mt("ClientWarden::Vault");
            }
        });
        return logger;
    }

    std::time_t ParseTime(std::string_view time) {
        std::tm tm = {};
        std::istringstream ss { std::string(time) };
        ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
        if (ss.fail()) {
            return 0;
        }

        #ifdef _WIN32
            return _mkgmtime(&tm);
        #else
            return timegm(&tm);
        #endif
    }

    std::string FormatTime(std::time_t time) {
        std::tm tm = {};
        #ifdef _WIN32
            gmtime_s(&tm, &time);
        #else
            gmtime_r(&time, &tm);
        #endif

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << ".000Z";
        return oss.str();
    }

    std::string NowTime(int offsetSeconds) {
        using namespace std::chrono;
        auto now = system_clock::now();
        auto ms = duration_cast<milliseconds>(now.time_since_epoch()).count() % 1000;
        std::time_t t = system_clock::to_time_t(now) + offsetSeconds;

        std::string base = FormatTime(t);
        std::ostringstream frac;
        frac << std::setfill('0') << std::setw(3) << ms;
        return base.replace(base.size() - 4, 3, frac.str());
    }

    std::string LocalTimeString(std::time_t time) {
        std::tm tm = {};
        #ifdef _WIN32
            localtime_s(&tm, &time);
        #else
            localtime_r(&time, &tm);
        #endif

        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    std::string NewGuid() {
        thread_local boost::uuids::random_generator gen;
        return boost::uuids::to_string(gen());
    }

    std::string ToLower(std::string_view str) {
        std::string out(str);
        for (char& c : out) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return out;
    }
}
