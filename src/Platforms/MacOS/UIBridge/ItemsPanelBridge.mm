#import "ItemsPanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"
#include "ItemElements.h"

@implementation ItemsPanelBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_query];
    [self cb_new];
}

ItemType ItemTypeFor(ClientWarden::CipherType type) {
    switch (type) {
        case ClientWarden::CipherType::Login: return ItemTypeLogin;
        case ClientWarden::CipherType::Card: return ItemTypeCard;
        case ClientWarden::CipherType::Identity: return ItemTypeIdentity;
        case ClientWarden::CipherType::Note: return ItemTypeNote;
        case ClientWarden::CipherType::SSHKey: return ItemTypeSSHKey;
        case ClientWarden::CipherType::BankAccount: return ItemTypeBankAccount;
        case ClientWarden::CipherType::DriversLicense: return ItemTypeDriversLicense;
        case ClientWarden::CipherType::Passport: return ItemTypePassport;
        default: return ItemTypeNote;
    }
}

ClientwardenImage* PlaceholderImageFor(ClientWarden::CipherType type) {
    NSString* symbol = @"questionmark.app.dashed";
    switch (type) {
        case ClientWarden::CipherType::Login: symbol = @"globe"; break;
        case ClientWarden::CipherType::Card: symbol = @"creditcard"; break;
        case ClientWarden::CipherType::Identity: symbol = @"person.text.rectangle"; break;
        case ClientWarden::CipherType::Note: symbol = @"pad.header"; break;
        case ClientWarden::CipherType::SSHKey: symbol = @"key.viewfinder"; break;
        case ClientWarden::CipherType::BankAccount: symbol = @"dollarsign.circle"; break;
        case ClientWarden::CipherType::DriversLicense: symbol = @"licenseplate"; break;
        case ClientWarden::CipherType::Passport: symbol = @"list.bullet.rectangle.portrait"; break;
        default: break;
    }
    return [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:symbol];
}

/*
 * Builds the list rows: decrypted name, item type and an icon (the
 * site favicon for logins, an SF Symbol otherwise).
 */
NSArray<ItemElement*>* MakeItemElements(const std::vector<ClientWarden::ItemSummary>& ciphers) {
    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
    NSMutableArray<ItemElement*>* items = [NSMutableArray array];

    for (const auto& cipher : ciphers) {
        std::optional<ClientWarden::Item> item = v_inst.GetItem(cipher.id);
        if (!item) {
            continue;
        }

        NSUUID* uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String: cipher.id.c_str()]];

        ClientWarden::SecretString c_name = item->Name();
        NSString* name = [[NSString alloc] initWithBytes:c_name.data() length:c_name.size() encoding:NSUTF8StringEncoding];

        ClientwardenImage* img = nil;
        if (cipher.type == ClientWarden::CipherType::Login) {
            std::vector<ClientWarden::SecretString> uris = item->Uris();
            std::optional<std::string> icon = uris.empty() ? std::nullopt : v_inst.Icon(uris[0]);
            if (icon) {
                img = [[ClientwardenImage alloc] initWithType:ImageTypeAppSupport path:[NSString stringWithUTF8String: icon->c_str()]];
            }
        }
        if (!img) {
            img = PlaceholderImageFor(cipher.type);
        }

        [items addObject:[[ItemElement alloc] initWithName:name uuid:uuid type:ItemTypeFor(cipher.type) image:img]];
    }

    return items;
}

/*
 * Query takes in a string and passes back an array of ItemElement
 * with all the items that match the search query
 */
+ (void)cb_query {
    ItemsPanel.instance.cb_query = ^NSArray* _Nonnull(NSString* name) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            std::vector<ClientWarden::ItemSummary> ciphers = v_inst.Query()
                .NotInBin()
                .NameContains(name.UTF8String)
                .Run();

            return MakeItemElements(ciphers);
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to query"];
                [[ToastStore instance] addToast:toast];
            });
            
            NSMutableArray<ItemElement*>* items = [NSMutableArray array];
            return items;
        }
    };
}

/*
 * New creates a new item and passes back an item Element
 */
+ (void)cb_new {
    ItemsPanel.instance.cb_new = ^ItemElement* _Nullable(ItemType i_type) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            ClientWarden::CipherType type;
            switch (i_type) {
                case ItemTypeLogin: type = ClientWarden::CipherType::Login; break;
                case ItemTypeCard: type = ClientWarden::CipherType::Card; break;
                case ItemTypeIdentity: type = ClientWarden::CipherType::Identity; break;
                case ItemTypeNote: type = ClientWarden::CipherType::Note; break;
                case ItemTypeSSHKey: type = ClientWarden::CipherType::SSHKey; break;
                case ItemTypeBankAccount: type = ClientWarden::CipherType::BankAccount; break;
                case ItemTypeDriversLicense: type = ClientWarden::CipherType::DriversLicense; break;
                case ItemTypePassport: type = ClientWarden::CipherType::Passport; break;
                default:
                    dispatch_async(dispatch_get_main_queue(), ^{
                        Toast* toast = [[Toast alloc] initWithMessage:@"Failed to create new item: Invalid Item Type"];
                        [[ToastStore instance] addToast:toast];
                    });
                    return nil;
            }

            ClientWarden::Item item = v_inst.NewItem(type);
            item.SetName("New Item");
            v_inst.Save(item);
            
            NSString* s_uuid = [NSString stringWithUTF8String: item.Id().c_str()];
            NSUUID* uuid = [[NSUUID alloc] initWithUUIDString: s_uuid];

            return [[ItemElement alloc] initWithName:@"New Item" uuid:uuid type:i_type image:PlaceholderImageFor(type)];
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to create new item"];
                [[ToastStore instance] addToast:toast];
            });

            return nil;
        }
    };
}

@end