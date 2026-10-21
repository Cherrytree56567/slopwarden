#include "Vault.h"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

/*
 * The production wiring lives in its own file so the core can be built
 * and tested without the real keychain, filesystem or network.
*/
namespace ClientWarden {
    namespace {
        std::mutex instanceMutex;
        std::unique_ptr<Vault> instance;

        void InstallLogger(const std::filesystem::path& dir) {
            if (logger) {
                return;
            }

            auto console = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            auto file = std::make_shared<spdlog::sinks::basic_file_sink_mt>((dir / "cw.log").string(), true);

            logger = std::make_shared<spdlog::logger>("ClientWarden::Vault", spdlog::sinks_init_list { console, file });
            logger->set_pattern("[%H:%M:%S] [%n] [%^%l%$] [thread %t] %v");
            logger->set_level(spdlog::level::info);
            logger->flush_on(spdlog::level::warn);
            spdlog::register_logger(logger);
        }
    }

    Vault& Vault::Instance() {
        std::lock_guard lock(instanceMutex);
        if (!instance) {
            auto files = std::make_unique<PlatformFileStore>();
            InstallLogger(files->Root());

            instance = std::make_unique<Vault>(Dependencies {
                std::make_unique<KeychainSecretStore>(),
                std::move(files),
                std::make_unique<HttplibTransport>()
            });
        }
        return *instance;
    }

    void Vault::DestroyInstance() {
        std::lock_guard lock(instanceMutex);
        instance.reset();
    }
}
