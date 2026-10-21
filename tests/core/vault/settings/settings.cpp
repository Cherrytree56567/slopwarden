#include <catch2/catch_test_macros.hpp>

#include "utils/encoding/encoding.h"
#include "vault/settings/settings.h"

using namespace clientwarden;

TEST_CASE("Settings defaults") {
    Settings settings(std::make_shared<MemoryFileStore>());
    settings.load();
    REQUIRE(settings.getAutoLockSeconds() == 300);
    REQUIRE(settings.getClipboardClearSeconds() == 30);
    REQUIRE_FALSE(settings.getAllowScreenshots());
    REQUIRE(settings.getTimeoutAction() == TimeoutAction::Lock);
}

TEST_CASE("Settings are clamped and persisted") {
    std::shared_ptr<MemoryFileStore> files = std::make_shared<MemoryFileStore>();
    {
        Settings settings(files);
        settings.setAutoLockSeconds(1);
        settings.setClipboardClearSeconds(45);
        settings.setAllowScreenshots(true);
        settings.setTimeoutAction(TimeoutAction::Logout);
        REQUIRE(settings.getAutoLockSeconds() == 5);
    }

    Settings reloaded(files);
    reloaded.load();
    REQUIRE(reloaded.getAutoLockSeconds() == 5);
    REQUIRE(reloaded.getClipboardClearSeconds() == 45);
    REQUIRE(reloaded.getAllowScreenshots());
    REQUIRE(reloaded.getTimeoutAction() == TimeoutAction::Logout);

    reloaded.setAutoLockSeconds(100000000);
    REQUIRE(reloaded.getAutoLockSeconds() == 7 * 24 * 3600);
    reloaded.setClipboardClearSeconds(100000);
    REQUIRE(reloaded.getClipboardClearSeconds() == 600);
}

TEST_CASE("Settings::load clamps and ignores bad values") {
    std::shared_ptr<MemoryFileStore> files = std::make_shared<MemoryFileStore>();
    files->write("settings.json", encoding::bytesOf(
        R"({"autoLockDelay":0,"clipboardClear":"x","allowScreenshots":1,"timeoutAction":"explode"})"));
    Settings settings(files);
    settings.load();
    REQUIRE(settings.getAutoLockSeconds() == 5);
    REQUIRE(settings.getClipboardClearSeconds() == 30);
    REQUIRE_FALSE(settings.getAllowScreenshots());
    REQUIRE(settings.getTimeoutAction() == TimeoutAction::Lock);

    files->write("settings.json", encoding::bytesOf("not json"));
    settings.load();
    REQUIRE(settings.getAutoLockSeconds() == 300);
}

TEST_CASE("Settings::reset restores defaults and deletes the file") {
    std::shared_ptr<MemoryFileStore> files = std::make_shared<MemoryFileStore>();
    Settings settings(files);
    settings.setAllowScreenshots(true);
    REQUIRE(files->exists("settings.json"));

    settings.reset();
    REQUIRE_FALSE(settings.getAllowScreenshots());
    REQUIRE_FALSE(files->exists("settings.json"));
}
