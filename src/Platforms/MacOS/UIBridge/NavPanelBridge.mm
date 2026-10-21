#import "NavPanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"
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
+ (NSArray<ItemElement*>*)items:(std::function<void(ClientWarden::ItemQuery&)>)filter failure:(NSString*)failure {
    try {
        ClientWarden::ItemQuery query = ClientWarden::Vault::Instance().Query();
        filter(query);
        return MakeItemElements(query.Run());
    } catch (...) {
        [self toast:failure];
        return [NSMutableArray array];
    }
}

+ (std::string)lowerUUID:(NSUUID*)uuid {
    std::string c_uuid = uuid.UUIDString.UTF8String;
    std::transform(c_uuid.begin(), c_uuid.end(), c_uuid.begin(), ::tolower);
    return c_uuid;
}

+ (void)cb_AllItems {
    NavigationPanel.instance.cb_allItems = ^NSArray* _Nonnull {
        return [NavPanelBridge items:[](auto& q) { q.NotInBin().NotArchived(); } failure:@"Failed to Get All Items"];
    };
}

+ (void)cb_Favorites {
    NavigationPanel.instance.cb_favorites = ^NSArray* _Nonnull {
        return [NavPanelBridge items:[](auto& q) { q.NotInBin().NotArchived().Favorites(); } failure:@"Failed to Get Favorites"];
    };
}

+ (void)cb_Trash {
    NavigationPanel.instance.cb_trash = ^NSArray* _Nonnull {
        return [NavPanelBridge items:[](auto& q) { q.InBin(); } failure:@"Failed to Get Trash Items"];
    };
}

+ (void)cb_archived {
    NavigationPanel.instance.cb_archived = ^NSArray* _Nonnull {
        return [NavPanelBridge items:[](auto& q) { q.NotInBin().Archived(); } failure:@"Failed to Get Archived Items"];
    };
}

/*
 * One list per item type, all filtered the same way.
 */
+ (void)cb_types {
    using ClientWarden::CipherType;

    auto byType = ^NSArray* _Nonnull (CipherType type, NSString* failure) {
        return [NavPanelBridge items:[type](auto& q) { q.NotInBin().NotArchived().OfType(type); } failure:failure];
    };

    NavigationPanel* nav = NavigationPanel.instance;
    nav.cb_login = ^NSArray* _Nonnull { return byType(CipherType::Login, @"Failed to Get Login Items"); };
    nav.cb_card = ^NSArray* _Nonnull { return byType(CipherType::Card, @"Failed to Get Card Items"); };
    nav.cb_identity = ^NSArray* _Nonnull { return byType(CipherType::Identity, @"Failed to Get Identity Items"); };
    nav.cb_note = ^NSArray* _Nonnull { return byType(CipherType::Note, @"Failed to Get Note Items"); };
    nav.cb_SSHKey = ^NSArray* _Nonnull { return byType(CipherType::SSHKey, @"Failed to Get SSH Key Items"); };
    nav.cb_BankAccount = ^NSArray* _Nonnull { return byType(CipherType::BankAccount, @"Failed to Get Bank Account Items"); };
    nav.cb_DriversLicense = ^NSArray* _Nonnull { return byType(CipherType::DriversLicense, @"Failed to Get Driver's License Items"); };
    nav.cb_Passport = ^NSArray* _Nonnull { return byType(CipherType::Passport, @"Failed to Get Passport Items"); };
}

+ (void)cb_Folder {
    NavigationPanel.instance.cb_folder = ^NSArray* _Nonnull(NSUUID* uuid) {
        std::string c_uuid = [NavPanelBridge lowerUUID:uuid];
        if (c_uuid.empty()) {
            [NavPanelBridge toast:@"Empty UUID"];
            return [NSMutableArray array];
        }
        return [NavPanelBridge items:[c_uuid](auto& q) { q.NotInBin().NotArchived().InFolder(c_uuid); } failure:@"Failed to Get Folder Items"];
    };
}

+ (void)getFolders {
    NavigationPanel.instance.cb_getFolders = ^NSArray* _Nonnull {
        NSMutableArray<Folder*>* folders = [NSMutableArray array];

        try {
            NSUUID* emptyUUID = [[NSUUID alloc] initWithUUIDString:@"00000000-0000-0000-0000-000000000000"];
            [folders addObject:[[Folder alloc] initWithUuid:emptyUUID name:@""]];

            for (const auto& folder : ClientWarden::Vault::Instance().Folders()) {
                NSUUID* uuid = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String: folder.id.c_str()]];
                NSString* name = [[NSString alloc] initWithBytes:folder.name.data() length:folder.name.size() encoding:NSUTF8StringEncoding];
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
            std::string c_uuid = ClientWarden::Vault::Instance().CreateFolder(name.UTF8String);
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
            std::string c_uuid = [NavPanelBridge lowerUUID:uuid];
            if (c_uuid.empty()) {
                [NavPanelBridge toast:@"Empty UUID"];
                return NO;
            }

            ClientWarden::Vault::Instance().DeleteFolder(c_uuid);
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
            std::string c_uuid = [NavPanelBridge lowerUUID:uuid];
            if (c_uuid.empty()) {
                [NavPanelBridge toast:@"Empty UUID"];
                return NO;
            }

            ClientWarden::Vault::Instance().RenameFolder(c_uuid, name.UTF8String);
            return YES;
        } catch (...) {
            [NavPanelBridge toast:@"Failed to Rename Folder"];
            return NO;
        }
    };
}

@end
