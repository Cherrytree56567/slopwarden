#import "SDKHandlerBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include <vector>
#include <string>
#include "vault_manager/vault_manager.h"
#include "utils/logger/logger.h"
#include "items/login_item/login_item.h"

/*
 * Callbacks for the AutoFill extension. Failures return empty strings
 * and are logged rather than toasted, since there's no window to show
 * them in.
 */
@implementation SDKHandlerBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * in SDK Handler. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_getLogins];
    [self cb_getTitle];
    [self cb_getUsername];
    [self cb_getPassword];
    [self cb_createPasskey];
    [self cb_getPasskeys];
    [self cb_getPasskeyInfo];
}

static clientwarden::SecureString LowerUUID(NSString* uuid) {
    return clientwarden::toLower(uuid.UTF8String);
}

static NSString* NS(const clientwarden::SecureString& s) {
    return [[NSString alloc] initWithBytes:s.data() length:s.size() encoding:NSUTF8StringEncoding];
}

/*
 * Comma-separated ids of usable logins for `website`, using Bitwarden's URI match rules and
 * equivalent domains (vault AutoFill).
 */
static NSString* MatchingLogins(NSString* website, bool passkeysOnly) {
    std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();
    std::vector<clientwarden::SecureString> matched = v_inst->getAutoFill()->matchingLogins(website.UTF8String, passkeysOnly);

    clientwarden::SecureString joined;
    for (const clientwarden::SecureString& id : matched) {
        if (!joined.empty()) {
            joined += ",";
        }
        joined += id;
    }
    return NS(joined);
}

/*
 * Loads a login for the extension, or nullptr if it isn't one.
 */
static std::shared_ptr<clientwarden::LoginItem> LoadLogin(NSString* uuid) {
    std::shared_ptr<clientwarden::Orchestrator> orchestrator = clientwarden::VaultManager::instance().getActiveVault()->getOrchestrator();
    clientwarden::SecureString id = LowerUUID(uuid);
    if (orchestrator->getItemType(id) != clientwarden::CipherType::Login) {
        return nullptr;
    }
    return orchestrator->getItem<clientwarden::LoginItem>(id);
}

+ (void)cb_getLogins {
    SDKHandler.instance.cb_getLogins = ^NSString* (NSString* website) {
        try {
            return MatchingLogins(website, false);
        } catch (const std::exception& e) {
            clientwarden::Logger::get()->warn("AutoFill login lookup failed: {}", e.what());
            return @"";
        }
    };
}

+ (void)cb_getTitle {
    SDKHandler.instance.cb_getTitle = ^NSString* (NSString* uuid) {
        try {
            std::shared_ptr<clientwarden::Orchestrator> orchestrator = clientwarden::VaultManager::instance().getActiveVault()->getOrchestrator();
            clientwarden::SecureString id = LowerUUID(uuid);
            return orchestrator->hasItem(id) ? NS(orchestrator->getGenericItem(id)->getName()) : @"";
        } catch (const std::exception& e) {
            clientwarden::Logger::get()->warn("AutoFill title lookup failed: {}", e.what());
            return @"";
        }
    };
}

+ (void)cb_getUsername {
    SDKHandler.instance.cb_getUsername = ^NSString* (NSString* uuid) {
        try {
            std::shared_ptr<clientwarden::LoginItem> login = LoadLogin(uuid);
            return login ? NS(login->getUsername()) : @"";
        } catch (const std::exception& e) {
            clientwarden::Logger::get()->warn("AutoFill username lookup failed: {}", e.what());
            return @"";
        }
    };
}

+ (void)cb_getPassword {
    SDKHandler.instance.cb_getPassword = ^NSString* (NSString* uuid) {
        try {
            std::shared_ptr<clientwarden::LoginItem> login = LoadLogin(uuid);
            return login ? NS(login->getPassword()) : @"";
        } catch (const std::exception& e) {
            clientwarden::Logger::get()->warn("AutoFill password lookup failed: {}", e.what());
            return @"";
        }
    };
}

/*
 * Passkey creation and assertion aren't implemented in the vault yet.
 * These used to report success with empty credentials; they now report
 * failure (an empty string) so the extension can fall back cleanly.
 */
+ (void)cb_createPasskey {
    SDKHandler.instance.cb_createPasskey = ^NSString* (NSString* info) {
        clientwarden::Logger::get()->info("AutoFill passkey creation is not supported yet");
        return @"";
    };
}

+ (void)cb_getPasskeys {
    SDKHandler.instance.cb_getPasskeys = ^NSString* (NSString* website) {
        try {
            return MatchingLogins(website, true);
        } catch (const std::exception& e) {
            clientwarden::Logger::get()->warn("AutoFill passkey lookup failed: {}", e.what());
            return @"";
        }
    };
}

+ (void)cb_getPasskeyInfo {
    SDKHandler.instance.cb_getPasskeyInfo = ^NSString* (NSString* uuid) {
        clientwarden::Logger::get()->info("AutoFill passkey assertion is not supported yet");
        return @"";
    };
}

@end
