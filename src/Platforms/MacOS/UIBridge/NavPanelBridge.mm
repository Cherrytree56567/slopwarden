#import "NavPanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "vault_manager/vault_manager.h"
#include "ItemElements.h"

#include <functional>

@implementation NavPanelBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_AllItems];
    [self cb_Favorites];
    [self cb_Trash];
    [self cb_archived];
    [self cb_types];
    [self cb_Folder];
    [self getFolders];
    [self cb_CreateFolder];
    [self cb_DeleteFolder];
    [self cb_RenameFolder];
    [self cb_organizations];
}

+ (void)toast:(NSString*)message {
    dispatch_async(dispatch_get_main_queue(), ^{
        Toast* toast = [[Toast alloc] initWithMessage:message];
        [[ToastStore instance] addToast:toast];
    });
}

/*
 * Runs a vault query and returns its rows, or an empty list and a toast
 * if the vault is locked or the query fails.
 */
+ (NSArray<ItemElement*>*)items:(std::function<void(clientwarden::CipherQuery&)>)filter failure:(NSString*)failure {
    try {
        clientwarden::CipherQuery query = clientwarden::VaultManager::instance().getActiveVault()->getOrchestrator()->query();
        filter(query);
        return MakeItemElements(query.run());
    } catch (...) {
        [self toast:failure];
        return [NSMutableArray array];
    }
}

+ (clientwarden::SecureString)lowerUUID:(NSUUID*)uuid {
    return clientwarden::toLower(uuid.UUIDString.UTF8String);
}

+ (void)cb_AllItems {
    NavigationPanel.instance.cb_allItems = ^NSArray* _Nonnull {
        return [NavPanelBridge items:[](auto& q) { q.notInBin().notArchived(); } failure:@"Failed to Get All Items"];
    };
}

+ (void)cb_Favorites {
    NavigationPanel.instance.cb_favorites = ^NSArray* _Nonnull {
        return [NavPanelBridge items:[](auto& q) { q.notInBin().notArchived().favorites(); } failure:@"Failed to Get Favorites"];
    };
}

+ (void)cb_Trash {
    NavigationPanel.instance.cb_trash = ^NSArray* _Nonnull {
        return [NavPanelBridge items:[](auto& q) { q.inBin(); } failure:@"Failed to Get Trash Items"];
    };
}

+ (void)cb_archived {
    NavigationPanel.instance.cb_archived = ^NSArray* _Nonnull {
        return [NavPanelBridge items:[](auto& q) { q.notInBin().archived(); } failure:@"Failed to Get Archived Items"];
    };
}

/*
 * One list per item type, all filtered the same way.
 */
+ (void)cb_types {
    using clientwarden::CipherType;

    auto byType = ^NSArray* _Nonnull (CipherType type, NSString* failure) {
        return [NavPanelBridge items:[type](auto& q) { q.notInBin().notArchived().ofType(type); } failure:failure];
    };

    NavigationPanel* nav = NavigationPanel.instance;
    nav.cb_login = ^NSArray* _Nonnull { return byType(CipherType::Login, @"Failed to Get Login Items"); };
    nav.cb_card = ^NSArray* _Nonnull { return byType(CipherType::Card, @"Failed to Get Card Items"); };
    nav.cb_identity = ^NSArray* _Nonnull { return byType(CipherType::Identity, @"Failed to Get Identity Items"); };
    nav.cb_note = ^NSArray* _Nonnull { return byType(CipherType::Note, @"Failed to Get Note Items"); };
    nav.cb_SSHKey = ^NSArray* _Nonnull { return byType(CipherType::SshKey, @"Failed to Get SSH Key Items"); };
    nav.cb_BankAccount = ^NSArray* _Nonnull { return byType(CipherType::BankAccount, @"Failed to Get Bank Account Items"); };
    nav.cb_DriversLicense = ^NSArray* _Nonnull { return byType(CipherType::DriversLicense, @"Failed to Get Driver's License Items"); };
    nav.cb_Passport = ^NSArray* _Nonnull { return byType(CipherType::Passport, @"Failed to Get Passport Items"); };
}

+ (void)cb_Folder {
    NavigationPanel.instance.cb_folder = ^NSArray* _Nonnull(NSUUID* uuid) {
        clientwarden::SecureString c_uuid = [NavPanelBridge lowerUUID:uuid];
        if (c_uuid.empty()) {
            [NavPanelBridge toast:@"Empty UUID"];
            return [NSMutableArray array];
        }
        return [NavPanelBridge items:[c_uuid](auto& q) { q.notInBin().notArchived().inFolder(c_uuid); } failure:@"Failed to Get Folder Items"];
    };
}

+ (void)getFolders {
    NavigationPanel.instance.cb_getFolders = ^NSArray* _Nonnull {
        NSMutableArray<Folder*>* folders = [NSMutableArray array];

        try {
            NSUUID* emptyUUID = [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
            [folders addObject:[[Folder alloc] initWithUuid:emptyUUID name:@""]];

            for (const std::shared_ptr<clientwarden::Folder>& folder : clientwarden::VaultManager::instance().getActiveVault()->getOrchestrator()->getFolders()) {
                clientwarden::SecureString c_id = folder->getId();
                clientwarden::SecureString c_name = folder->getName();
                NSUUID* uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String: c_id.c_str()]];
                NSString* name = [[NSString alloc] initWithBytes:c_name.data() length:c_name.size() encoding:NSUTF8StringEncoding];
                [folders addObject:[[Folder alloc] initWithUuid:uuid name:name]];
            }
        } catch (...) {
            [NavPanelBridge toast:@"Failed to Get Folders"];
            return [NSMutableArray array];
        }

        return folders;
    };
}

/*
 * CreateFolder uses a name and creates a folder and passes back a UUID.
 * Offline, the folder is created locally and uploaded on the next sync.
 */
+ (void)cb_CreateFolder {
    NavigationPanel.instance.cb_createFolder = ^NSUUID* _Nullable(NSString* name) {
        try {
            std::shared_ptr<clientwarden::Folder> folder = clientwarden::VaultManager::instance().getActiveVault()->getOrchestrator()->createFolder();
            folder->setName(name.UTF8String).commit();
            clientwarden::SecureString c_uuid = folder->getId();
            return [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:c_uuid.c_str()]];
        } catch (...) {
            [NavPanelBridge toast:@"Failed to Create Folder"];
            return nil;
        }
    };
}

/*
 * DeleteFolder uses a UUID and passes back a result bool
 */
+ (void)cb_DeleteFolder {
    NavigationPanel.instance.cb_deleteFolder = ^BOOL(NSUUID* uuid) {
        try {
            clientwarden::SecureString c_uuid = [NavPanelBridge lowerUUID:uuid];
            if (c_uuid.empty()) {
                [NavPanelBridge toast:@"Empty UUID"];
                return NO;
            }

            clientwarden::VaultManager::instance().getActiveVault()->getOrchestrator()->getFolder(c_uuid)->remove();
            return YES;
        } catch (...) {
            [NavPanelBridge toast:@"Failed to Delete Folder"];
            return NO;
        }
    };
}

/*
 * RenameFolder uses a UUID and name and passes back a result bool
 */
+ (void)cb_RenameFolder {
    NavigationPanel.instance.cb_renameFolder = ^BOOL(NSUUID* uuid, NSString* name) {
        try {
            clientwarden::SecureString c_uuid = [NavPanelBridge lowerUUID:uuid];
            if (c_uuid.empty()) {
                [NavPanelBridge toast:@"Empty UUID"];
                return NO;
            }

            clientwarden::VaultManager::instance().getActiveVault()->getOrchestrator()->getFolder(c_uuid)->setName(name.UTF8String).commit();
            return YES;
        } catch (...) {
            [NavPanelBridge toast:@"Failed to Rename Folder"];
            return NO;
        }
    };
}

/*
 * Organisations and collections: the sidebar tree, the item lists for each, and collection
 * management for members allowed to do it.
 */
+ (void)cb_organizations {
    NavigationPanel* nav = NavigationPanel.instance;

    nav.cb_getOrganizations = ^NSArray* _Nonnull {
        NSMutableArray<Organization*>* organizations = [NSMutableArray array];
        try {
            std::shared_ptr<clientwarden::Organizations> parts =
                clientwarden::VaultManager::instance().getActiveVault()->getOrganizations();
            std::vector<clientwarden::CollectionInfo> collections = parts->getCollections("");

            for (const clientwarden::OrganizationInfo& info : parts->getOrganizations()) {
                if (!info.m_key_available || !info.m_enabled) {
                    continue;
                }
                NSUUID* uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:info.m_id.c_str()]];
                NSMutableArray<VaultCollection*>* children = [NSMutableArray array];
                for (const clientwarden::CollectionInfo& collection : collections) {
                    if (collection.m_organization_id != info.m_id) {
                        continue;
                    }
                    NSUUID* collectionUUID = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:collection.m_id.c_str()]];
                    NSString* name = [[NSString alloc] initWithBytes:collection.m_name.data() length:collection.m_name.size() encoding:NSUTF8StringEncoding];
                    [children addObject:[[VaultCollection alloc] initWithUuid:collectionUUID organizationUUID:uuid name:name
                        readOnly:collection.m_read_only manage:collection.m_manage]];
                }
                NSString* name = [[NSString alloc] initWithBytes:info.m_name.data() length:info.m_name.size() encoding:NSUTF8StringEncoding];
                [organizations addObject:[[Organization alloc] initWithUuid:uuid name:name
                    canManageCollections:info.m_can_manage_collections collections:children]];
            }
        } catch (...) {
            /*
             * Polled every second; stay quiet while locked.
             */
        }
        return organizations;
    };

    nav.cb_organization = ^NSArray* _Nonnull(NSUUID* uuid) {
        clientwarden::SecureString id = [NavPanelBridge lowerUUID:uuid];
        return [NavPanelBridge items:[id](clientwarden::CipherQuery& q) { q.notInBin().notArchived().inOrganization(id); }
            failure:@"Failed to Get Organization Items"];
    };

    nav.cb_collection = ^NSArray* _Nonnull(NSUUID* uuid) {
        clientwarden::SecureString id = [NavPanelBridge lowerUUID:uuid];
        return [NavPanelBridge items:[id](clientwarden::CipherQuery& q) { q.notInBin().notArchived().inCollection(id); }
            failure:@"Failed to Get Collection Items"];
    };

    nav.cb_createCollection = ^NSUUID* _Nullable(NSUUID* organization, NSString* name) {
        try {
            std::optional<clientwarden::SecureString> id = clientwarden::VaultManager::instance().getActiveVault()
                ->getOrganizations()->createCollection([NavPanelBridge lowerUUID:organization], name.UTF8String);
            if (!id) {
                return nil;
            }
            return [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:id->c_str()]];
        } catch (const clientwarden::VaultError& e) {
            [NavPanelBridge toast:[NSString stringWithUTF8String:e.what()]];
            return nil;
        }
    };

    nav.cb_renameCollection = ^BOOL(NSUUID* uuid, NSString* name) {
        try {
            return (BOOL)clientwarden::VaultManager::instance().getActiveVault()
                ->getOrganizations()->renameCollection([NavPanelBridge lowerUUID:uuid], name.UTF8String);
        } catch (...) {
            return NO;
        }
    };

    nav.cb_deleteCollection = ^BOOL(NSUUID* uuid) {
        try {
            return (BOOL)clientwarden::VaultManager::instance().getActiveVault()
                ->getOrganizations()->deleteCollection([NavPanelBridge lowerUUID:uuid]);
        } catch (...) {
            return NO;
        }
    };
}

@end
