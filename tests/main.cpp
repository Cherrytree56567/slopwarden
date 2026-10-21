#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>
#include <spdlog/sinks/null_sink.h>

#include "utils/logger/logger.h"

/**
 * @brief Silences the vault logger so expected failures (bad MACs, offline saves) don't drown
 * the Catch2 report.
 */
class TestSetup : public Catch::EventListenerBase {
public:
    using Catch::EventListenerBase::EventListenerBase;

    /**
     * @brief Installs a null logger before any test runs.
     */
    void testRunStarting(const Catch::TestRunInfo&) override {
        clientwarden::Logger::set(std::make_shared<spdlog::logger>("ClientWarden::Vault",
            std::make_shared<spdlog::sinks::null_sink_mt>()));
    }
};

CATCH_REGISTER_LISTENER(TestSetup)
