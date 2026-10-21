#import "SDKHandlerBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include <boost/algorithm/string/join.hpp>
#include <boost/url.hpp>
#include <vector>
#include <string>
#include "Vault.h"
#include "Util/Util.h"

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

/*
 * Lowercased host of a URL, accepting bare domains ("github.com") as
 * well as full URLs.
 */
static std::optional<std::string> HostOf(std::string_view url) {
    auto parsed = boost::urls::parse_uri(url);
    if (!parsed || parsed->host().empty()) {
        parsed = boost::urls::parse_uri("https://" + std::string(url));
    }
    if (!parsed || parsed->host().empty()) {
        return std::nullopt;
    }
    return ClientWarden::ToLower(parsed->host());
}

static std::string LowerUUID(NSString* uuid) {
    return ClientWarden::ToLower(uuid.UTF8String);
}

static NSString* NS(const ClientWarden::SecretString& s) {
    return [[NSString alloc] initWithBytes:s.data() length:s.size() encoding:NSUTF8StringEncoding];
}

/*
 * Comma-separated ids of usable logins with a URI on the same host as
 * `website`.
 */
static NSString* MatchingLogins(NSString* website, bool passkeysOnly) {
    std::optional<std::string> host = HostOf(website.UTF8String);
    if (!host) {
        return @"";
    }

    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
    ClientWarden::ItemQuery query = v_inst.Query();
    query.NotInBin().NotArchived().OfType(ClientWarden::CipherType::Login);
    if (passkeysOnly) {
        query.WithPasskey();
    }

    std::vector<std::string> matched;
    for (const auto& id : query.Ids()) {
        std::optional<ClientWarden::Item> item = v_inst.GetItem(id);
        if (!item) {
            continue;
        }
        for (const auto& uri : item->Uris()) {
            if (HostOf(std::string_view(uri.data(), uri.size())) == host) {
                matched.push_back(id);
                break;
            }
        }
    }

    return [NSString stringWithUTF8String: boost::algorithm::join(matched, ",").c_str()];
}

/*
 * Decrypts one field of a login, or "" if it isn't one.
 */
static NSString* LoginField(NSString* uuid, ClientWarden::FieldId field) {
    std::optional<ClientWarden::Item> item = ClientWarden::Vault::Instance().GetItem(LowerUUID(uuid));
    if (!item || item->Type() != ClientWarden::CipherType::Login) {
        return @"";
    }
    return NS(item->Get(field));
}

+ (void)cb_getLogins {
    SDKHandler.instance.cb_getLogins = ^NSString* (NSString* website) {
        try {
            return MatchingLogins(website, false);
        } catch (const std::exception& e) {
            ClientWarden::Log()->warn("AutoFill login lookup failed: {}", e.what());
            return @"";
        }
    };
}

+ (void)cb_getTitle {
    SDKHandler.instance.cb_getTitle = ^NSString* (NSString* uuid) {
        try {
            std::optional<ClientWarden::Item> item = ClientWarden::Vault::Instance().GetItem(LowerUUID(uuid));
            return item ? NS(item->Name()) : @"";
        } catch (const std::exception& e) {
            ClientWarden::Log()->warn("AutoFill title lookup failed: {}", e.what());
            return @"";
        }
    };
}

+ (void)cb_getUsername {
    SDKHandler.instance.cb_getUsername = ^NSString* (NSString* uuid) {
        try {
            return LoginField(uuid, ClientWarden::Fields::Login::Username);
        } catch (const std::exception& e) {
            ClientWarden::Log()->warn("AutoFill username lookup failed: {}", e.what());
            return @"";
        }
    };
}

+ (void)cb_getPassword {
    SDKHandler.instance.cb_getPassword = ^NSString* (NSString* uuid) {
        try {
            return LoginField(uuid, ClientWarden::Fields::Login::Password);
        } catch (const std::exception& e) {
            ClientWarden::Log()->warn("AutoFill password lookup failed: {}", e.what());
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
        ClientWarden::Log()->info("AutoFill passkey creation is not supported yet");
        return @"";
    };
}

+ (void)cb_getPasskeys {
    SDKHandler.instance.cb_getPasskeys = ^NSString* (NSString* website) {
        try {
            return MatchingLogins(website, true);
        } catch (const std::exception& e) {
            ClientWarden::Log()->warn("AutoFill passkey lookup failed: {}", e.what());
            return @"";
        }
    };
}

+ (void)cb_getPasskeyInfo {
    SDKHandler.instance.cb_getPasskeyInfo = ^NSString* (NSString* uuid) {
        ClientWarden::Log()->info("AutoFill passkey assertion is not supported yet");
        return @"";
    };
}

@end
