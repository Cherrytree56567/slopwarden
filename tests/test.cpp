#include <catch2/reporters/catch_reporter_registrars.hpp>
#include <catch2/reporters/catch_reporter_event_listener.hpp>
#include <spdlog/sinks/null_sink.h>
#include "Clientwarden.h"

/*
 * Keep test output readable: the vault logs expected failures (bad MACs,
 * offline saves) that would otherwise drown the Catch2 report.
*/
struct TestSetup : Catch::EventListenerBase {
    using Catch::EventListenerBase::EventListenerBase;

    void testRunStarting(Catch::TestRunInfo const&) override {
        if (!ClientWarden::logger) {
            ClientWarden::logger = std::make_shared<spdlog::logger>("ClientWarden::Vault", std::make_shared<spdlog::sinks::null_sink_mt>());
        }
    }
};

CATCH_REGISTER_LISTENER(TestSetup)
