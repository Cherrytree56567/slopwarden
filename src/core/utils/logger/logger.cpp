#include "logger.h"

#include <mutex>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace clientwarden {
    namespace {
        std::mutex g_logger_mutex;
        std::shared_ptr<spdlog::logger> g_logger;
    }

    std::shared_ptr<spdlog::logger> Logger::get() {
        std::lock_guard<std::mutex> lock(g_logger_mutex);
        if (!g_logger) {
            g_logger = std::make_shared<spdlog::logger>(
                    "ClientWarden::Vault", std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
        }
        return g_logger;
    }

    void Logger::installFileLogger(std::filesystem::path directory) {
        std::shared_ptr<spdlog::sinks::stdout_color_sink_mt> console =
                std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        std::shared_ptr<spdlog::sinks::basic_file_sink_mt> file =
                std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                        (directory / "cw.log").native(), true);

        std::shared_ptr<spdlog::logger> logger = std::make_shared<spdlog::logger>(
                "ClientWarden::Vault", spdlog::sinks_init_list { console, file });
        logger->set_pattern("[%H:%M:%S] [%n] [%^%l%$] [thread %t] %v");
        logger->set_level(spdlog::level::info);
        logger->flush_on(spdlog::level::warn);
        set(logger);
    }

    void Logger::set(std::shared_ptr<spdlog::logger> logger) {
        std::lock_guard<std::mutex> lock(g_logger_mutex);
        g_logger = std::move(logger);
    }
}
