#include <catch2/catch_test_macros.hpp>

#include "core/support_vault.h"
#include "items/login_item/login_item.h"

using namespace clientwarden;
using namespace clientwarden::testing;

TEST_CASE("Base domains") {
    REQUIRE(AutoFill::baseDomain("accounts.google.com") == "google.com");
    REQUIRE(AutoFill::baseDomain("google.com") == "google.com");
    REQUIRE(AutoFill::baseDomain("www.bbc.co.uk") == "bbc.co.uk");
    REQUIRE(AutoFill::baseDomain("bbc.co.uk") == "bbc.co.uk");
    REQUIRE(AutoFill::baseDomain("localhost") == "localhost");
    REQUIRE(AutoFill::baseDomain("192.168.1.10") == "192.168.1.10");
}

TEST_CASE("URI match rules") {
    std::vector<SecureString> none;
    REQUIRE(AutoFill::uriMatches("https://github.com", "https://gist.github.com/x", UriMatch::Domain, none));
    REQUIRE(AutoFill::uriMatches("github.com", "https://github.com/login", UriMatch::Domain, none));
    REQUIRE_FALSE(AutoFill::uriMatches("https://github.com", "https://gitlab.com", UriMatch::Domain, none));
    REQUIRE_FALSE(AutoFill::uriMatches("https://a.co.uk", "https://b.co.uk", UriMatch::Domain, none));

    REQUIRE(AutoFill::uriMatches("https://github.com", "https://github.com/x", UriMatch::Host, none));
    REQUIRE_FALSE(AutoFill::uriMatches("https://github.com", "https://gist.github.com", UriMatch::Host, none));
    REQUIRE_FALSE(AutoFill::uriMatches("https://site.com:8443", "https://site.com", UriMatch::Host, none));

    REQUIRE(AutoFill::uriMatches("https://site.com/app", "https://site.com/app/login", UriMatch::StartsWith, none));
    REQUIRE_FALSE(AutoFill::uriMatches("https://site.com/app", "https://site.com/other", UriMatch::StartsWith, none));

    REQUIRE(AutoFill::uriMatches("https://site.com/a", "https://site.com/a", UriMatch::Exact, none));
    REQUIRE_FALSE(AutoFill::uriMatches("https://site.com/a", "https://site.com/a/", UriMatch::Exact, none));

    REQUIRE(AutoFill::uriMatches("^https://.*\\.example\\.com/", "https://x.example.com/", UriMatch::RegularExpression, none));
    REQUIRE_FALSE(AutoFill::uriMatches("(", "https://x", UriMatch::RegularExpression, none));

    REQUIRE_FALSE(AutoFill::uriMatches("https://github.com", "https://github.com", UriMatch::Never, none));

    std::vector<SecureString> equivalent = { "google.com", "youtube.com" };
    REQUIRE(AutoFill::uriMatches("https://google.com", "https://www.youtube.com", UriMatch::Domain, equivalent));
}

TEST_CASE("Matching logins for a page") {
    Fixture fixture;
    fixture.m_server->m_domains = { { "equivalentDomains", Json::array({ Json::array({ "google.com", "youtube.com" }) }) },
        { "globalEquivalentDomains", Json::array() } };
    std::shared_ptr<BitwardenVault> vault = loggedInVault(fixture);
    std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();

    /*
     * Regression: a bare-domain URI used to make the whole lookup throw.
    */
    std::shared_ptr<LoginItem> bare = orchestrator->createItem<LoginItem>();
    bare->setName("Bare").addWebsite("github.com").commit();
    std::shared_ptr<LoginItem> google = orchestrator->createItem<LoginItem>();
    google->setName("Google").addWebsite("https://accounts.google.com").commit();
    std::shared_ptr<LoginItem> binned = orchestrator->createItem<LoginItem>();
    binned->setName("Binned").addWebsite("https://github.com").commit();
    binned->bin();
    REQUIRE(vault->syncNow());

    std::shared_ptr<AutoFill> autofill = vault->getAutoFill();
    REQUIRE(autofill->matchingLogins("https://github.com/login", false) == std::vector<SecureString> { bare->getId() });
    REQUIRE(autofill->matchingLogins("https://www.youtube.com/", false) == std::vector<SecureString> { google->getId() });
    REQUIRE(autofill->matchingLogins("https://example.org", false).empty());
    REQUIRE(autofill->matchingLogins("https://github.com", true).empty());
}
