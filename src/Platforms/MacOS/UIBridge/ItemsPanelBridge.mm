#import "ItemsPanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "vault_manager/vault_manager.h"
#include "items/bank_account_item/bank_account_item.h"
#include "items/card_item/card_item.h"
#include "items/drivers_license_item/drivers_license_item.h"
#include "items/identity_item/identity_item.h"
#include "items/login_item/login_item.h"
#include "items/note_item/note_item.h"
#include "items/passport_item/passport_item.h"
#include "items/ssh_key_item/ssh_key_item.h"
#include "ItemElements.h"

/*
 * Creates an unsaved organisation item of the requested type in one collection.
 */
static std::shared_ptr<clientwarden::GenericItem> NewOrganizationItemOfType(std::shared_ptr<clientwarden::Orchestrator> orchestrator,
    clientwarden::CipherType type, std::string_view organization, std::vector<clientwarden::SecureString> collections) {
    switch (type) {
        case clientwarden::CipherType::Login: return orchestrator->createItem<clientwarden::LoginItem>(organization, collections);
        case clientwarden::CipherType::Card: return orchestrator->createItem<clientwarden::CardItem>(organization, collections);
        case clientwarden::CipherType::Identity: return orchestrator->createItem<clientwarden::IdentityItem>(organization, collections);
        case clientwarden::CipherType::SshKey: return orchestrator->createItem<clientwarden::SshKeyItem>(organization, collections);
        case clientwarden::CipherType::BankAccount: return orchestrator->createItem<clientwarden::BankAccountItem>(organization, collections);
        case clientwarden::CipherType::DriversLicense: return orchestrator->createItem<clientwarden::DriversLicenseItem>(organization, collections);
        case clientwarden::CipherType::Passport: return orchestrator->createItem<clientwarden::PassportItem>(organization, collections);
        default: return orchestrator->createItem<clientwarden::NoteItem>(organization, collections);
    }
}

/*
 * Creates an unsaved item of the requested type through its builder class.
 */
static std::shared_ptr<clientwarden::GenericItem> NewItemOfType(std::shared_ptr<clientwarden::Orchestrator> orchestrator,
    clientwarden::CipherType type) {
    switch (type) {
        case clientwarden::CipherType::Login: return orchestrator->createItem<clientwarden::LoginItem>();
        case clientwarden::CipherType::Card: return orchestrator->createItem<clientwarden::CardItem>();
        case clientwarden::CipherType::Identity: return orchestrator->createItem<clientwarden::IdentityItem>();
        case clientwarden::CipherType::SshKey: return orchestrator->createItem<clientwarden::SshKeyItem>();
        case clientwarden::CipherType::BankAccount: return orchestrator->createItem<clientwarden::BankAccountItem>();
        case clientwarden::CipherType::DriversLicense: return orchestrator->createItem<clientwarden::DriversLicenseItem>();
        case clientwarden::CipherType::Passport: return orchestrator->createItem<clientwarden::PassportItem>();
        default: return orchestrator->createItem<clientwarden::NoteItem>();
    }
}

@implementation ItemsPanelBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_query];
    [self cb_new];
    [self cb_newInCollection];
}

ItemType ItemTypeFor(clientwarden::CipherType type) {
    switch (type) {
        case clientwarden::CipherType::Login: return ItemTypeLogin;
        case clientwarden::CipherType::Card: return ItemTypeCard;
        case clientwarden::CipherType::Identity: return ItemTypeIdentity;
        case clientwarden::CipherType::Note: return ItemTypeNote;
        case clientwarden::CipherType::SshKey: return ItemTypeSSHKey;
        case clientwarden::CipherType::BankAccount: return ItemTypeBankAccount;
        case clientwarden::CipherType::DriversLicense: return ItemTypeDriversLicense;
        case clientwarden::CipherType::Passport: return ItemTypePassport;
        default: return ItemTypeNote;
    }
}

ClientwardenImage* PlaceholderImageFor(clientwarden::CipherType type) {
    NSString* symbol = @"questionmark.app.dashed";
    switch (type) {
        case clientwarden::CipherType::Login: symbol = @"globe"; break;
        case clientwarden::CipherType::Card: symbol = @"creditcard"; break;
        case clientwarden::CipherType::Identity: symbol = @"person.text.rectangle"; break;
        case clientwarden::CipherType::Note: symbol = @"pad.header"; break;
        case clientwarden::CipherType::SshKey: symbol = @"key.viewfinder"; break;
        case clientwarden::CipherType::BankAccount: symbol = @"dollarsign.circle"; break;
        case clientwarden::CipherType::DriversLicense: symbol = @"licenseplate"; break;
        case clientwarden::CipherType::Passport: symbol = @"list.bullet.rectangle.portrait"; break;
        default: break;
    }
    return [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:symbol];
}

/*
 * Builds the list rows: decrypted name, item type and an icon (the
 * site favicon for logins, an SF Symbol otherwise).
 */
NSArray<ItemElement*>* MakeItemElements(const std::vector<clientwarden::ItemSummary>& ciphers) {
    std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();
    std::shared_ptr<clientwarden::Orchestrator> orchestrator = v_inst->getOrchestrator();
    NSMutableArray<ItemElement*>* items = [NSMutableArray array];

    for (const clientwarden::ItemSummary& cipher : ciphers) {
        try {
            NSUUID* uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String: cipher.m_id.c_str()]];

            clientwarden::SecureString c_name = orchestrator->getGenericItem(cipher.m_id)->getName();
            NSString* name = [[NSString alloc] initWithBytes:c_name.data() length:c_name.size() encoding:NSUTF8StringEncoding];

            ClientwardenImage* img = nil;
            if (cipher.m_type == clientwarden::CipherType::Login) {
                std::vector<clientwarden::SecureString> uris = orchestrator->getItem<clientwarden::LoginItem>(cipher.m_id)->getWebsites();
                std::optional<std::filesystem::path> icon = uris.empty() ? std::nullopt : orchestrator->getIcon(uris[0]);
                if (icon) {
                    img = [[ClientwardenImage alloc] initWithType:ImageTypeAppSupport path:[NSString stringWithUTF8String: icon->c_str()]];
                }
            }
            if (!img) {
                img = PlaceholderImageFor(cipher.m_type);
            }

            [items addObject:[[ItemElement alloc] initWithName:name uuid:uuid type:ItemTypeFor(cipher.m_type) image:img]];
        } catch (const clientwarden::VaultError&) {
            /*
             * Skip items this client can't open yet (e.g. organisation items).
             */
        }
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
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();
            std::vector<clientwarden::ItemSummary> ciphers = v_inst->getOrchestrator()->query()
                .notInBin()
                .nameContains(name.UTF8String)
                .run();

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
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();

            clientwarden::CipherType type;
            switch (i_type) {
                case ItemTypeLogin: type = clientwarden::CipherType::Login; break;
                case ItemTypeCard: type = clientwarden::CipherType::Card; break;
                case ItemTypeIdentity: type = clientwarden::CipherType::Identity; break;
                case ItemTypeNote: type = clientwarden::CipherType::Note; break;
                case ItemTypeSSHKey: type = clientwarden::CipherType::SshKey; break;
                case ItemTypeBankAccount: type = clientwarden::CipherType::BankAccount; break;
                case ItemTypeDriversLicense: type = clientwarden::CipherType::DriversLicense; break;
                case ItemTypePassport: type = clientwarden::CipherType::Passport; break;
                default:
                    dispatch_async(dispatch_get_main_queue(), ^{
                        Toast* toast = [[Toast alloc] initWithMessage:@"Failed to create new item: Invalid Item Type"];
                        [[ToastStore instance] addToast:toast];
                    });
                    return nil;
            }

            std::shared_ptr<clientwarden::GenericItem> item = NewItemOfType(v_inst->getOrchestrator(), type);
            item->setName("New Item");
            item->commit();
            
            NSString* s_uuid = [NSString stringWithUTF8String: item->getId().c_str()];
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

/*
 * New item inside the selected collection (and therefore its organisation). Organisation
 * items are created online only.
 */
+ (void)cb_newInCollection {
    ItemsPanel.instance.cb_newInCollection = ^ItemElement* _Nullable(ItemType i_type, NSUUID* collectionUUID) {
        try {
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();
            clientwarden::SecureString collection = clientwarden::toLower(collectionUUID.UUIDString.UTF8String);

            clientwarden::SecureString organization;
            for (const clientwarden::CollectionInfo& info : v_inst->getOrganizations()->getCollections("")) {
                if (info.m_id == collection) {
                    organization = info.m_organization_id;
                }
            }
            if (organization.empty()) {
                return nil;
            }

            clientwarden::CipherType type = clientwarden::CipherType::Note;
            switch (i_type) {
                case ItemTypeLogin: type = clientwarden::CipherType::Login; break;
                case ItemTypeCard: type = clientwarden::CipherType::Card; break;
                case ItemTypeIdentity: type = clientwarden::CipherType::Identity; break;
                case ItemTypeSSHKey: type = clientwarden::CipherType::SshKey; break;
                case ItemTypeBankAccount: type = clientwarden::CipherType::BankAccount; break;
                case ItemTypeDriversLicense: type = clientwarden::CipherType::DriversLicense; break;
                case ItemTypePassport: type = clientwarden::CipherType::Passport; break;
                default: break;
            }

            std::shared_ptr<clientwarden::GenericItem> item =
                NewOrganizationItemOfType(v_inst->getOrchestrator(), type, organization, { collection });
            item->setName("New Item");
            item->commit();

            NSUUID* uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:item->getId().c_str()]];
            return [[ItemElement alloc] initWithName:@"New Item" uuid:uuid type:i_type image:PlaceholderImageFor(type)];
        } catch (const clientwarden::VaultError& e) {
            NSString* message = [NSString stringWithUTF8String:e.what()];
            dispatch_async(dispatch_get_main_queue(), ^{
                [[ToastStore instance] addToast:[[Toast alloc] initWithMessage:message]];
            });
            return nil;
        }
    };
}

@end
