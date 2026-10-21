#pragma once
#include <filesystem>
#include <memory>
#include <spdlog/spdlog.h>

namespace clientwarden {
    /**
     * @brief The shared vault logger, installed once per process.
     *
     * Messages must never contain secrets. Logs go to the console and, once installed with a
     * directory, to cw.log there (see the Reliability goal in Architecturev2).
     */
    class Logger {
    public:
        /**
         * @brief Returns the logger, creating a console-only one if none is installed.
         *
         * @return The process-wide logger
         */
        static std::shared_ptr<spdlog::logger> get();

        /**
         * @brief Installs a console + file logger writing to `directory`/cw.log.
         *
         * @param directory Where the log file lives
         */
        static void installFileLogger(std::filesystem::path directory);

        /**
         * @brief Replaces the logger (tests use this to silence output).
         *
         * @param logger The logger to use from now on
         */
        static void set(std::shared_ptr<spdlog::logger> logger);
    };
}
