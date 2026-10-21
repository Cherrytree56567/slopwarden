#import "SidePanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include <vector>
#include "Util/Util.h"
#include "Vault.h"

namespace {
    using ClientWarden::CipherType;
    using ClientWarden::FieldId;
    using ClientWarden::Item;
    using ClientWarden::SecretString;
    namespace Fields = ClientWarden::Fields;

    constexpr const char* NoFolder = "00000000-0000-0000-0000-000000000000";

    NSString* NS(const SecretString& s) {
        return [[NSString alloc] initWithBytes:s.data() length:s.size() encoding:NSUTF8StringEncoding] ?: @"";
    }

    NSString* NS(const std::string& s) {
        return [[NSString alloc] initWithBytes:s.data() length:s.size() encoding:NSUTF8StringEncoding] ?: @"";
    }

    std::string_view View(NSString* s) {
        return s ? std::string_view(s.UTF8String) : std::string_view();
    }

    /*
     * Vault ids are lowercase; NSUUID prints uppercase.
    */
    std::string ItemId(NSUUID* uuid) {
        return ClientWarden::ToLower(uuid.UUIDString.UTF8String);
    }

    Item Load(ClientWarden::Vault& vault, NSUUID* uuid) {
        std::optional<Item> item = vault.GetItem(ItemId(uuid));
        if (!item) {
            throw ClientWarden::VaultError("item not found");
        }
        return std::move(*item);
    }

    void ShowToast(NSString* message) {
        dispatch_async(dispatch_get_main_queue(), ^{
            Toast* toast = [[Toast alloc] initWithMessage:message];
            [[ToastStore instance] addToast:toast];
        });
    }

    ItemType ToItemType(CipherType type) {
        switch (type) {
            case CipherType::Card: return ItemTypeCard;
            case CipherType::Identity: return ItemTypeIdentity;
            case CipherType::Note: return ItemTypeNote;
            case CipherType::SSHKey: return ItemTypeSSHKey;
            case CipherType::BankAccount: return ItemTypeBankAccount;
            case CipherType::DriversLicense: return ItemTypeDriversLicense;
            case CipherType::Passport: return ItemTypePassport;
            default: return ItemTypeLogin;
        }
    }

    /*
     * Logins show the site's favicon (or a globe); everything else a
     * fixed SF Symbol per type.
    */
    ClientwardenImage* IconFor(ClientWarden::Vault& vault, const Item& item) {
        NSString* symbol = @"questionmark.app.dashed";
        switch (item.Type()) {
            case CipherType::Login: {
                std::vector<SecretString> uris = item.Uris();
                if (!uris.empty()) {
                    if (auto path = vault.Icon(std::string_view(uris[0].data(), uris[0].size()))) {
                        return [[ClientwardenImage alloc] initWithType:ImageTypeAppSupport path:NS(*path)];
                    }
                }
                symbol = @"globe";
                break;
            }
            case CipherType::Card: symbol = @"creditcard"; break;
            case CipherType::Identity: symbol = @"person.text.rectangle"; break;
            case CipherType::Note: symbol = @"pad.header"; break;
            case CipherType::SSHKey: symbol = @"key.viewfinder"; break;
            case CipherType::BankAccount: symbol = @"dollarsign.circle"; break;
            case CipherType::DriversLicense: symbol = @"licenseplate"; break;
            case CipherType::Passport: symbol = @"list.bullet.rectangle.portrait"; break;
            default: break;
        }
        return [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:symbol];
    }

    /*
     * One-to-one mapping between a SidePanel row and a vault field. The
     * same titles are used to display and to save, so the two can't drift
     * apart. Rows that combine several fields (names, card expiry,
     * locality, websites, TOTP) are handled separately.
    */
    struct FieldRow {
        const char* title;
        FieldId field;
        GenericItemType type;
    };

    const std::vector<FieldRow>& RowsFor(CipherType type) {
        static const std::vector<FieldRow> none;
        static const std::vector<FieldRow> login = {
            { "Username", Fields::Login::Username, GenericItemTypeGeneric },
            { "Password", Fields::Login::Password, GenericItemTypePassword },
        };
        static const std::vector<FieldRow> card = {
            { "Brand", Fields::Card::Brand, GenericItemTypeGeneric },
            { "Cardholder Name", Fields::Card::CardholderName, GenericItemTypeGeneric },
            { "Number", Fields::Card::Number, GenericItemTypePassword },
            { "Code", Fields::Card::Code, GenericItemTypePassword },
        };
        static const std::vector<FieldRow> identity = {
            { "Username", Fields::Identity::Username, GenericItemTypeGeneric },
            { "Company", Fields::Identity::Company, GenericItemTypeGeneric },
            { "SSN", Fields::Identity::SSN, GenericItemTypePassword },
            { "Passport Number", Fields::Identity::PassportNumber, GenericItemTypePassword },
            { "Licence Number", Fields::Identity::LicenseNumber, GenericItemTypeGeneric },
            { "Email", Fields::Identity::Email, GenericItemTypeGeneric },
            { "Phone", Fields::Identity::Phone, GenericItemTypeGeneric },
            { "Address 1", Fields::Identity::Address1, GenericItemTypeGeneric },
            { "Address 2", Fields::Identity::Address2, GenericItemTypeGeneric },
            { "Address 3", Fields::Identity::Address3, GenericItemTypeGeneric },
        };
        static const std::vector<FieldRow> sshKey = {
            { "Fingerprint", Fields::SSHKey::Fingerprint, GenericItemTypeGeneric },
            { "Private Key", Fields::SSHKey::PrivateKey, GenericItemTypeMl_password },
            { "Public Key", Fields::SSHKey::PublicKey, GenericItemTypePassword },
        };
        static const std::vector<FieldRow> bankAccount = {
            { "Bank Name", Fields::BankAccount::BankName, GenericItemTypeGeneric },
            { "Name On Account", Fields::BankAccount::NameOnAccount, GenericItemTypeGeneric },
            { "Account Type", Fields::BankAccount::AccountType, GenericItemTypeGeneric },
            { "Account Number", Fields::BankAccount::AccountNumber, GenericItemTypePassword },
            { "Routing Number", Fields::BankAccount::RoutingNumber, GenericItemTypePassword },
            { "Branch Number", Fields::BankAccount::BranchNumber, GenericItemTypeGeneric },
            { "Pin", Fields::BankAccount::Pin, GenericItemTypePassword },
            { "Swift Code", Fields::BankAccount::SwiftCode, GenericItemTypeGeneric },
            { "IBAN", Fields::BankAccount::Iban, GenericItemTypePassword },
            { "Bank Contact Phone", Fields::BankAccount::BankContactPhone, GenericItemTypeGeneric },
        };
        static const std::vector<FieldRow> driversLicense = {
            { "Date of Birth", Fields::DriversLicense::DateOfBirth, GenericItemTypeDate_3 },
            { "License Number", Fields::DriversLicense::LicenseNumber, GenericItemTypePassword },
            { "Issuing Country", Fields::DriversLicense::IssuingCountry, GenericItemTypeGeneric },
            { "Issuing State", Fields::DriversLicense::IssuingState, GenericItemTypeGeneric },
            { "Issuing Date", Fields::DriversLicense::IssueDate, GenericItemTypeDate_3 },
            { "Expiration Date", Fields::DriversLicense::ExpirationDate, GenericItemTypeDate_3 },
            { "Issuing Authority", Fields::DriversLicense::IssuingAuthority, GenericItemTypeGeneric },
            { "License Class", Fields::DriversLicense::LicenseClass, GenericItemTypeGeneric },
        };
        static const std::vector<FieldRow> passport = {
            { "Date Of Birth", Fields::Passport::DateOfBirth, GenericItemTypeDate_3 },
            { "Sex", Fields::Passport::Sex, GenericItemTypeGeneric },
            { "Birth Place", Fields::Passport::BirthPlace, GenericItemTypeGeneric },
            { "Nationality", Fields::Passport::Nationality, GenericItemTypeGeneric },
            { "Issuing Country", Fields::Passport::IssuingCountry, GenericItemTypeGeneric },
            { "Passport Number", Fields::Passport::PassportNumber, GenericItemTypeGeneric },
            { "Passport Type", Fields::Passport::PassportType, GenericItemTypeGeneric },
            { "National Identification Number", Fields::Passport::NationalIdentificationNumber, GenericItemTypeGeneric },
            { "Issuing Authority", Fields::Passport::IssuingAuthority, GenericItemTypeGeneric },
            { "Issue Date", Fields::Passport::IssueDate, GenericItemTypeDate_3 },
            { "Expiration Date", Fields::Passport::ExpirationDate, GenericItemTypeDate_3 },
        };

        switch (type) {
            case CipherType::Login: return login;
            case CipherType::Card: return card;
            case CipherType::Identity: return identity;
            case CipherType::SSHKey: return sshKey;
            case CipherType::BankAccount: return bankAccount;
            case CipherType::DriversLicense: return driversLicense;
            case CipherType::Passport: return passport;
            default: return none;
        }
    }

    GenericItemData* Row(NSString* title, NSString* value, GenericItemType type) {
        return [[GenericItemData alloc] initWithTitle:title value:value type:type];
    }

    NSString* Joined(const Item& item, std::initializer_list<FieldId> fields, NSString* separator) {
        NSMutableArray<NSString*>* parts = [NSMutableArray array];
        for (FieldId f : fields) {
            [parts addObject:NS(item.Get(f))];
        }
        return [parts componentsJoinedByString:separator];
    }

    /*
     * Splits "a, b, c" into exactly `count` trimmed parts.
    */
    std::vector<std::string> Split(NSString* value, NSString* separator, size_t count) {
        NSArray<NSString*>* parts = [value ?: @"" componentsSeparatedByString:separator];
        std::vector<std::string> out;
        for (size_t i = 0; i < count; ++i) {
            NSString* part = i < parts.count ? [parts[i] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet] : @"";
            out.emplace_back(part.UTF8String);
        }
        return out;
    }

    void Display(ClientWarden::Vault& vault, const Item& item, NSMutableArray<GenericItemData*>* rows,
        NSMutableArray<PasswordHistoryItem*>* history) {
        CipherType type = item.Type();

        if (type == CipherType::Identity) {
            [rows addObject:[[GenericItemData alloc] initWithTitle:@"Name"
                                                             value:NS(item.Get(Fields::Identity::Title))
                                                           value_1:NS(item.Get(Fields::Identity::FirstName))
                                                           value_2:NS(item.Get(Fields::Identity::MiddleName))
                                                           value_3:NS(item.Get(Fields::Identity::LastName))]];
        } else if (type == CipherType::DriversLicense) {
            [rows addObject:[[GenericItemData alloc] initWithTitle:@"Name"
                                                             value:NS(item.Get(Fields::DriversLicense::FirstName))
                                                           value_1:NS(item.Get(Fields::DriversLicense::MiddleName))
                                                           value_2:NS(item.Get(Fields::DriversLicense::LastName))]];
        } else if (type == CipherType::Passport) {
            [rows addObject:[[GenericItemData alloc] initWithTitle:@"Name"
                                                             value:NS(item.Get(Fields::Passport::GivenName))
                                                           value_1:NS(item.Get(Fields::Passport::Surname))]];
        }

        for (const FieldRow& row : RowsFor(type)) {
            [rows addObject:Row(@(row.title), NS(item.Get(row.field)), row.type)];
        }

        if (type == CipherType::Card) {
            NSString* expiration = Joined(item, { Fields::Card::ExpMonth, Fields::Card::ExpYear }, @"/");
            [rows addObject:Row(@"Expiration Date", expiration, GenericItemTypeDate)];
        } else if (type == CipherType::Identity) {
            NSString* locality = Joined(item, { Fields::Identity::PostalCode, Fields::Identity::City,
                Fields::Identity::State, Fields::Identity::Country }, @", ");
            [rows addObject:Row(@"Locality", locality, GenericItemTypeGeneric)];
        } else if (type == CipherType::Login) {
            std::string id = item.Id();

            /*
             * The code is generated on demand so it stays current while
             * the panel is open.
            */
            [rows addObject:[[GenericItemData alloc] initWithTitle:@"Two Factor Authentication"
                                                             value:NS(item.Get(Fields::Login::Totp))
                                                              type:GenericItemTypeTotp
                                                        cb_getTOTP:^TOTPResult* _Nonnull {
                try {
                    std::optional<Item> current = ClientWarden::Vault::Instance().GetItem(id);
                    if (auto code = current ? current->Totp() : std::nullopt) {
                        return [[TOTPResult alloc] initWithRefreshDate:(int64_t)code->validUntil
                                                              maxTimer:(NSInteger)code->period
                                                                 value:NS(code->code)];
                    }
                } catch (...) {
                }
                return [[TOTPResult alloc] initWithRefreshDate:0 maxTimer:30 value:@""];
            }]];

            NSMutableArray<NSString*>* websites = [NSMutableArray array];
            for (const auto& uri : item.Uris()) {
                [websites addObject:NS(uri)];
            }
            [rows addObject:Row(@"Websites", [websites componentsJoinedByString:@"\n"], GenericItemTypeWebsite)];

            for (const auto& entry : item.PasswordHistory()) {
                NSDate* date = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)entry.lastUsed];
                NSString* s_date = [NSDateFormatter localizedStringFromDate:date
                                                                  dateStyle:NSDateFormatterMediumStyle
                                                                  timeStyle:NSDateFormatterShortStyle];
                [history addObject:[[PasswordHistoryItem alloc] initWithDate:s_date password:NS(entry.password)]];
            }
        }
    }

    /*
     * Writes the SidePanel rows back into the item's type-specific fields.
    */
    void Apply(Item& item, NSArray<GenericItemData*>* itemFields) {
        CipherType type = item.Type();
        const auto& rows = RowsFor(type);

        for (GenericItemData* itemField in itemFields) {
            NSString* title = itemField.title;

            bool matched = false;
            for (const FieldRow& row : rows) {
                if ([title isEqualToString:@(row.title)]) {
                    item.Set(row.field, View(itemField.value));
                    matched = true;
                    break;
                }
            }
            if (matched) {
                continue;
            }

            if (type == CipherType::Login && [title isEqualToString:@"Two Factor Authentication"]) {
                item.Set(Fields::Login::Totp, View(itemField.value));
            } else if (type == CipherType::Login && [title isEqualToString:@"Websites"]) {
                for (const auto& uri : item.Uris()) {
                    item.RemoveUri(std::string_view(uri.data(), uri.size()));
                }
                for (NSString* line in [itemField.value ?: @"" componentsSeparatedByString:@"\n"]) {
                    NSString* trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
                    if (trimmed.length > 0) {
                        item.AddUri(View(trimmed));
                    }
                }
            } else if (type == CipherType::Card && [title isEqualToString:@"Expiration Date"]) {
                auto parts = Split(itemField.value, @"/", 2);
                item.Set(Fields::Card::ExpMonth, parts[0]);
                item.Set(Fields::Card::ExpYear, parts[1]);
            } else if (type == CipherType::Identity && [title isEqualToString:@"Name"]) {
                item.Set(Fields::Identity::Title, View(itemField.value));
                item.Set(Fields::Identity::FirstName, View(itemField.value_1));
                item.Set(Fields::Identity::MiddleName, View(itemField.value_2));
                item.Set(Fields::Identity::LastName, View(itemField.value_3));
            } else if (type == CipherType::Identity && [title isEqualToString:@"Locality"]) {
                auto parts = Split(itemField.value, @",", 4);
                item.Set(Fields::Identity::PostalCode, parts[0]);
                item.Set(Fields::Identity::City, parts[1]);
                item.Set(Fields::Identity::State, parts[2]);
                item.Set(Fields::Identity::Country, parts[3]);
            } else if (type == CipherType::DriversLicense && [title isEqualToString:@"Name"]) {
                item.Set(Fields::DriversLicense::FirstName, View(itemField.value));
                item.Set(Fields::DriversLicense::MiddleName, View(itemField.value_1));
                item.Set(Fields::DriversLicense::LastName, View(itemField.value_2));
            } else if (type == CipherType::Passport && [title isEqualToString:@"Name"]) {
                item.Set(Fields::Passport::GivenName, View(itemField.value));
                item.Set(Fields::Passport::Surname, View(itemField.value_1));
            }
        }
    }
}

@implementation SidePanelBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_favorite];
    [self cb_duplicate];
    [self cb_delete];
    [self cb_restore];
    [self cb_permDel];
    [self cb_archive];
    [self cb_unarchive];
    [self cb_moveToFolder];
    [self cb_deleteMultiple];
    [self cb_restoreMultiple];
    [self cb_permDelMultiple];
    [self cb_archiveMultiple];
    [self cb_unarchiveMultiple];
    [self cb_sidebar];
    [self cb_downloadAttachment];
    [self cb_uploadAttachment];
    [self cb_removeAttachment];
    [self cb_save];
    [self cb_genRandPasswd];
    [self cb_genSimplPasswd];
    [self cb_genPinPasswd];
}

/*
 * Favorite uses a bool and a UUID to apply favorite status to an item
 */
+ (void)cb_favorite {
    SidePanel.instance.cb_favorite = ^BOOL(BOOL fav, NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            Item item = Load(v_inst, uuid);
            item.SetFavorite((bool)fav);
            v_inst.Save(item);

            return YES;
        } catch (...) {
            ShowToast(@"Failed to Favorite Item");
            return NO;
        }
    };
}

/*
 * Duplicate duplicates and item with a UUID and ItemType and passes back
 * an ItemType to be added to the Items Panel
 */
+ (void)cb_duplicate {
    SidePanel.instance.cb_duplicate = ^ItemElement* _Nullable(NSUUID* uuid, ItemType i_type) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            Item copy = v_inst.Duplicate(Load(v_inst, uuid));

            NSUUID* dupUUID = [[NSUUID alloc] initWithUUIDString:NS(copy.Id())];
            return [[ItemElement alloc] initWithName:NS(copy.Name()) uuid:dupUUID type:i_type image:IconFor(v_inst, copy)];
        } catch (...) {
            ShowToast(@"Failed to Duplicate Item");
            return nil;
        }
    };
}

/*
 * Delete moves the item with the UUID in the bin and passes back a result bool
 */
+ (void)cb_delete {
    SidePanel.instance.cb_delete = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            Item item = Load(v_inst, uuid);
            v_inst.MoveToBin(item);
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Delete Item");
            return NO;
        }
    };
}

/*
 * Restore moves the item with the UUID out of the bin and passes back a result bool
 */
+ (void)cb_restore {
    SidePanel.instance.cb_restore = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            Item item = Load(v_inst, uuid);
            v_inst.Restore(item);
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Restore Item");
            return NO;
        }
    };
}

/*
 * Archive moves the item with the UUID to the Archive and passes back a result bool
 */
+ (void)cb_archive {
    SidePanel.instance.cb_archive = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            Item item = Load(v_inst, uuid);
            v_inst.Archive(item);
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Archive Item");
            return NO;
        }
    };
}

/*
 * UnArchive moves the item with the UUID out of the Archive and passes back a result bool
 */
+ (void)cb_unarchive {
    SidePanel.instance.cb_unarchive = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            Item item = Load(v_inst, uuid);
            v_inst.Unarchive(item);
            return YES;
        } catch (...) {
            ShowToast(@"Failed to UnArchive Item");
            return NO;
        }
    };
}

/*
 * Permanantly Delete deletes the item with the UUID and passes back a result bool
 */
+ (void)cb_permDel {
    SidePanel.instance.cb_permDel = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            v_inst.Delete(Load(v_inst, uuid));
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Permanently Delete Item");
            return NO;
        }
    };
}

/*
 * Move to Folder files the item under the folder UUID, or under no
 * folder when given the nil UUID.
 */
+ (void)cb_moveToFolder {
    SidePanel.instance.cb_moveToFolder = ^BOOL(NSUUID* folderUUID, NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            Item item = Load(v_inst, uuid);
            std::string folder = ItemId(folderUUID);
            item.SetFolderId(folder == NoFolder ? std::nullopt : std::optional<std::string>(folder));
            v_inst.Save(item);

            return YES;
        } catch (...) {
            ShowToast(@"Failed to Move Item");
            return NO;
        }
    };
}

/*
 * cb_deleteMultiple takes in an array of uuid, and bin's them each. It doesn't
 * use an api to delete them all at once, bc Im too lazy and it would cause issues
 * bc of the way things are structured.
 */
+ (void)cb_deleteMultiple {
    SidePanel.instance.cb_deleteMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            for (NSUUID* uuid in uuids) {
                Item item = Load(v_inst, uuid);
                v_inst.MoveToBin(item);
            }
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Delete Items");
            return NO;
        }
    };
}

/*
 * cb_restoreMultiple takes in an array of UUID's and restores each one of them and
 * then returns true
 */
+ (void)cb_restoreMultiple {
    SidePanel.instance.cb_restoreMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            for (NSUUID* uuid in uuids) {
                Item item = Load(v_inst, uuid);
                v_inst.Restore(item);
            }
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Restore Items");
            return NO;
        }
    };
}

/*
 * cb_permDelMultiple takes in an array of UUID's and permanantly deletes each one of
 * them and then returns true
 */
+ (void)cb_permDelMultiple {
    SidePanel.instance.cb_permDelMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            for (NSUUID* uuid in uuids) {
                v_inst.Delete(Load(v_inst, uuid));
            }
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Permanantly Delete Items");
            return NO;
        }
    };
}

/*
 * cb_archiveMultiple takes in an array of UUID's and archives each one of them and
 * then returns true
 */
+ (void)cb_archiveMultiple {
    SidePanel.instance.cb_archiveMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            for (NSUUID* uuid in uuids) {
                Item item = Load(v_inst, uuid);
                v_inst.Archive(item);
            }
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Archive Items");
            return NO;
        }
    };
}

/*
 * cb_unarchiveMultiple takes in an array of UUID's and archives each one of them and
 * then returns true
 */
+ (void)cb_unarchiveMultiple {
    SidePanel.instance.cb_unarchiveMultiple = ^BOOL(NSArray<NSUUID*>* _Nonnull uuids) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();
            for (NSUUID* uuid in uuids) {
                Item item = Load(v_inst, uuid);
                v_inst.Unarchive(item);
            }
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Unarchive Items");
            return NO;
        }
    };
}

/*
 * Sidebar fills the SidePanel with the item's info using a UUID
 * and passes back a result bool
 */
static bool sidebar(NSUUID* uuid) {
    try {
        ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

        Item item = Load(v_inst, uuid);

        NSMutableArray<GenericItemData*>* itemFields = [NSMutableArray array];
        NSMutableArray<FieldItemData*>* customFields = [NSMutableArray array];
        NSMutableArray<NSString*>* itemHistory = [NSMutableArray array];
        NSMutableArray<PasswordHistoryItem*>* passwordHistory = [NSMutableArray array];
        NSMutableArray<AttachmentItemData*>* attachments = [NSMutableArray array];

        Display(v_inst, item, itemFields, passwordHistory);

        for (const auto& field : item.CustomFields()) {
            [customFields addObject:[[FieldItemData alloc] initWithTitle:NS(field.name)
                                                                   value:NS(field.value)
                                                                    type:(FieldItemType)((int)field.type)]];
        }

        for (const auto& attachment : item.Attachments()) {
            [attachments addObject:[[AttachmentItemData alloc] initWithAttachID:NS(attachment.id) name:NS(attachment.fileName)]];
        }

        auto when = [](std::time_t t) { return t ? NS(ClientWarden::LocalTimeString(t)) : @""; };
        [itemHistory addObject:[NSString stringWithFormat:@"Creation: %@", when(item.Created())]];
        [itemHistory addObject:[NSString stringWithFormat:@"Modification: %@", when(item.Revised())]];
        if (item.Deleted() != 0) {
            [itemHistory addObject:[NSString stringWithFormat:@"Deletion: %@", when(item.Deleted())]];
        }

        NSUUID* folderUUID = [[NSUUID alloc] initWithUUIDString:NS(item.FolderId().value_or(NoFolder))];

        [SidePanel.instance viewItemWithName:NS(item.Name()) uuid:uuid type:ToItemType(item.Type()) icon:IconFor(v_inst, item)
                            repromptItem:item.Reprompt() folderUUID:folderUUID favorite:item.Favorite()
                            itemFields:itemFields customFields:customFields itemHistory:itemHistory passwordHistory:passwordHistory
                            attachmentItems:attachments notes:NS(item.Notes())];

        return true;
    } catch (...) {
        ShowToast(@"Failed to View Item");
        return false;
    }
}

+ (void)cb_sidebar {
    SidePanel.instance.cb_sidebar = ^BOOL(NSUUID* uuid) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            if (Load(v_inst, uuid).Reprompt()) {
                [SidePanel.instance closeItem];
                SidePanel.instance.isReprompt = true;
                SidePanel.instance.repromptFailed = false;
                SidePanel.instance.uuid = uuid;
                SidePanel.instance.repromptPassword = @"";
                return YES;
            }
            return (BOOL)sidebar(uuid);
        } catch (...) {
            ShowToast(@"Failed to View Item");
            return NO;
        }
    };

    SidePanel.instance.cb_sidebarReprompt = ^BOOL(NSUUID* uuid, NSString* password) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            if (v_inst.VerifyMasterPassword(View(password))) {
                SidePanel.instance.isReprompt = false;
                SidePanel.instance.repromptFailed = false;
                return (BOOL)sidebar(uuid);
            }

            SidePanel.instance.repromptFailed = true;
            return YES;
        } catch (...) {
            ShowToast(@"Failed to Verify Password");
            return NO;
        }
    };
}

/*
 * Download Attachment uses a UUID and attachID to get the
 * attachment from the selected item and use an item picker
 * to determine where to save the item and save the item
 * while updating the progress bar of the download
 */
+ (void)cb_downloadAttachment {
    SidePanel.instance.cb_downloadAttachment = ^BOOL(NSUUID* uuid, NSString* attachID) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::string c_attachID = attachID.UTF8String;
            auto attachment = Load(v_inst, uuid).FindAttachment(c_attachID);
            if (!attachment) {
                throw ClientWarden::VaultError("attachment not found");
            }

            NSSavePanel* panel = [NSSavePanel savePanel];
            panel.nameFieldStringValue = NS(attachment->fileName);
            panel.canCreateDirectories = YES;

            [panel beginWithCompletionHandler:^(NSModalResponse result) {
                if (result != NSModalResponseOK || !panel.URL) {
                    ShowToast(@"Failed to get Download Location");
                    return;
                }

                std::string path = panel.URL.path.UTF8String;

                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    bool ok = false;
                    try {
                        ClientWarden::Vault& vault = ClientWarden::Vault::Instance();
                        ok = vault.DownloadAttachment(Load(vault, uuid), c_attachID, path, [attachID](float progress) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                                [SidePanel.instance updateProgressWithId:attachID progress:(double)progress];
                            });
                        });
                    } catch (...) {
                    }

                    if (!ok) {
                        ShowToast(@"Failed to Download Attachment");
                    }
                    dispatch_async(dispatch_get_main_queue(), ^{
                        [SidePanel.instance updateProgressWithId:attachID progress:0.0];
                    });
                });
            }];

            return YES;
        } catch (...) {
            ShowToast(@"Failed to Download Attachment");
            return NO;
        }
    };
}

/*
 * Upload Attachment uses a UUID to upload the
 * selected file with NSOpenPanel to the selected
 * item while updating the upload progress bar.
 * If the item is over 500MB, it will not be uploaded.
 */
+ (void)cb_uploadAttachment {
    SidePanel.instance.cb_uploadAttachment = ^BOOL(NSUUID* uuid) {
        try {
            NSOpenPanel* panel = [NSOpenPanel openPanel];
            panel.canChooseFiles = YES;
            panel.canChooseDirectories = NO;
            panel.allowsMultipleSelection = NO;

            [panel beginWithCompletionHandler:^(NSModalResponse result) {
                if (result != NSModalResponseOK || !panel.URL) {
                    ShowToast(@"Failed to Get Upload Item");
                    return;
                }

                NSString* path = panel.URL.path;
                NSString* fileName = panel.URL.lastPathComponent;

                NSError* attrRes = nil;
                NSDictionary* attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:&attrRes];

                if (!attrs) {
                    ShowToast(@"Failed to Get File Attributes");
                    return;
                }
                if ([attrs fileSize] > 500ULL * 1024 * 1024) {
                    ShowToast(@"Attachment too big");
                    return;
                }

                NSString* tempAttachID = [[NSUUID UUID] UUIDString];
                AttachmentItemData* attachmentItem = [[AttachmentItemData alloc] initWithAttachID:tempAttachID name:fileName];

                dispatch_async(dispatch_get_main_queue(), ^{
                    [SidePanel.instance addAttachmentItem:attachmentItem];
                });

                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    NSError* res = nil;
                    NSData* fileData = [NSData dataWithContentsOfFile:path options:0 error:&res];

                    std::optional<std::string> newID;
                    if (fileData) {
                        try {
                            ClientWarden::Vault& vault = ClientWarden::Vault::Instance();
                            Item item = Load(vault, uuid);
                            std::span<const uint8_t> content(static_cast<const uint8_t*>(fileData.bytes), fileData.length);

                            newID = vault.AddAttachment(item, View(fileName), content, [tempAttachID](float progress) {
                                dispatch_async(dispatch_get_main_queue(), ^{
                                    [SidePanel.instance updateProgressWithId:tempAttachID progress:(double)progress];
                                });
                            });
                        } catch (...) {
                        }
                    }

                    if (!newID) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                            Toast* toast = [[Toast alloc] initWithMessage:fileData ? @"Failed to Upload Attachment" : @"Failed to Read File"];
                            [[ToastStore instance] addToast:toast];
                            [SidePanel.instance deleteAttachmentViewWithId:tempAttachID];
                        });
                        return;
                    }

                    NSString* attachID = NS(*newID);

                    dispatch_async(dispatch_get_main_queue(), ^{
                        [SidePanel.instance updateAttachIDWithId:tempAttachID attachID:attachID];
                        [SidePanel.instance updateProgressWithId:attachID progress:0.0];
                    });
                });
            }];

            return YES;
        } catch (...) {
            ShowToast(@"Failed to Upload Attachment");
            return NO;
        }
    };
}

/*
 * Remove Attachment uses a UUID and attachment ID to
 * remove the attachment from the selected item while
 * returning a result bool
 */
+ (void)cb_removeAttachment {
    SidePanel.instance.cb_removeAttachment = ^BOOL(NSUUID* uuid, NSString* attachID) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            Item item = Load(v_inst, uuid);
            if (!v_inst.RemoveAttachment(item, attachID.UTF8String)) {
                throw ClientWarden::VaultError("server refused to remove attachment");
            }

            [SidePanel.instance deleteAttachmentViewWithId:attachID];

            return YES;
        } catch (...) {
            ShowToast(@"Failed to Remove Attachment");
            return NO;
        }
    };
}

/*
 * Save Item uses a UUID and returns a bool.
 * First it reads Sidepanel.instance to get
 * all the values, it then overrides all the
 * values from the vault with the new ones.
 * This is pretty much the only way, since
 * we do not track changes and it would be
 * less efficient.
 */
+ (void)cb_save {
    SidePanel.instance.cb_save = ^BOOL(NSUUID* uuid, NSString* name, ItemType type, BOOL reprompt, NSUUID* folderUUID,
                                       NSArray<GenericItemData*>* itemFields, NSArray<FieldItemData*>* customFields, NSString* notes) {
        try {
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            Item item = Load(v_inst, uuid);

            item.ClearCustomFields();
            for (FieldItemData* field in customFields) {
                item.AddCustomField((ClientWarden::CustomFieldType)((int)field.type), View(field.title), View(field.value));
            }

            std::string folder = ItemId(folderUUID);
            item.SetFolderId(folder == NoFolder ? std::nullopt : std::optional<std::string>(folder));
            item.SetNotes(View(notes));
            item.SetName(View(name));
            item.SetReprompt((bool)reprompt);

            Apply(item, itemFields);

            /*
             * Offline saves are kept locally and uploaded on the next
             * sync, so only an exception counts as failure here.
            */
            v_inst.Save(item);

            return YES;
        } catch (...) {
            ShowToast(@"Failed to Save Item");
            return NO;
        }
    };
}

/*
 * Generate a random Password using Letters, Symbols (optional),
 * Capital Letters (optional) and numbers (optional) using a size.
 * EG:
 * Numbers = True, Symbols = True, Caps = True, Size = 8
 * = iG4h!uC#
 */
+ (void)cb_genRandPasswd {
    SidePanel.instance.cb_genRandPasswd = ^NSString* (BOOL numbers, BOOL symbols, BOOL caps, NSInteger size) {
        try {
            return NS(ClientWarden::PasswordGenerator::Random({ (int)size, (bool)caps, (bool)numbers, (bool)symbols }));
        } catch (...) {
            ShowToast(@"Failed to Generate Random Password");
            return @"";
        }
    };
}

/*
 * Generate a memorable Password using Words using a size.
 * EG:
 * Caps = True, Size = 4
 * = Cats-password-heart-elephant
 */
+ (void)cb_genSimplPasswd {
    SidePanel.instance.cb_genSimplPasswd = ^NSString* (BOOL caps, NSInteger size) {
        try {
            int words = (int)std::clamp<NSInteger>(size, 3, 20);
            return NS(ClientWarden::Vault::Instance().Generator().Passphrase(words, (bool)caps));
        } catch (...) {
            ShowToast(@"Failed to Generate Simple Password");
            return @"";
        }
    };
}

/*
 * Generate a numeric pin using a size.
 * EG:
 * Size = 6
 * = 402917
 */
+ (void)cb_genPinPasswd {
    SidePanel.instance.cb_genPinPasswd = ^NSString* (NSInteger size) {
        try {
            return NS(ClientWarden::PasswordGenerator::Pin((int)std::clamp<NSInteger>(size, 4, 64)));
        } catch (...) {
            ShowToast(@"Failed to Generate Pin");
            return @"";
        }
    };
}

@end
