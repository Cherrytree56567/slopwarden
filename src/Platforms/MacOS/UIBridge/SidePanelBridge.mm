#import "SidePanelBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include <ctime>
#include <functional>
#include <vector>
#include "items/bank_account_item/bank_account_item.h"
#include "items/card_item/card_item.h"
#include "items/drivers_license_item/drivers_license_item.h"
#include "items/identity_item/identity_item.h"
#include "items/login_item/login_item.h"
#include "items/note_item/note_item.h"
#include "items/passport_item/passport_item.h"
#include "items/ssh_key_item/ssh_key_item.h"
#include "utils/timestamp/timestamp.h"
#include "vault_manager/vault_manager.h"

namespace {
    using clientwarden::BankAccountItem;
    using clientwarden::CardItem;
    using clientwarden::CipherType;
    using clientwarden::DriversLicenseItem;
    using clientwarden::GenericItem;
    using clientwarden::IdentityItem;
    using clientwarden::LoginItem;
    using clientwarden::NoteItem;
    using clientwarden::Orchestrator;
    using clientwarden::PassportItem;
    using clientwarden::SecureString;
    using clientwarden::SshKeyItem;
    using clientwarden::Vault;

    constexpr const char* NoFolder = "00000000-0000-0000-0000-000000000000";

    NSString* NS(std::string_view s) {
        return [[NSString alloc] initWithBytes:s.data() length:s.size() encoding:NSUTF8StringEncoding] ?: @"";
    }

    std::string_view View(NSString* s) {
        return s ? std::string_view(s.UTF8String) : std::string_view();
    }

    std::shared_ptr<Vault> ActiveVault() {
        return clientwarden::VaultManager::instance().getActiveVault();
    }

    /*
     * Vault ids are lowercase; NSUUID prints uppercase.
    */
    SecureString ItemId(NSUUID* uuid) {
        return clientwarden::toLower(uuid.UUIDString.UTF8String);
    }

    /*
     * Loads an item as its concrete type (so the typed field rows below can
     * downcast it), throwing VaultError if it doesn't exist.
    */
    std::shared_ptr<GenericItem> LoadId(std::shared_ptr<Vault> vault, std::string_view id) {
        std::shared_ptr<Orchestrator> orchestrator = vault->getOrchestrator();
        std::optional<CipherType> type = orchestrator->getItemType(id);
        if (!type) {
            throw clientwarden::VaultError("item not found");
        }
        switch (*type) {
            case CipherType::Login: return orchestrator->getItem<LoginItem>(id);
            case CipherType::Card: return orchestrator->getItem<CardItem>(id);
            case CipherType::Identity: return orchestrator->getItem<IdentityItem>(id);
            case CipherType::Note: return orchestrator->getItem<NoteItem>(id);
            case CipherType::SshKey: return orchestrator->getItem<SshKeyItem>(id);
            case CipherType::BankAccount: return orchestrator->getItem<BankAccountItem>(id);
            case CipherType::DriversLicense: return orchestrator->getItem<DriversLicenseItem>(id);
            case CipherType::Passport: return orchestrator->getItem<PassportItem>(id);
            default: return orchestrator->getGenericItem(id);
        }
    }

    std::shared_ptr<GenericItem> Load(std::shared_ptr<Vault> vault, NSUUID* uuid) {
        return LoadId(vault, ItemId(uuid));
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
            case CipherType::SshKey: return ItemTypeSSHKey;
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
    ClientwardenImage* IconFor(std::shared_ptr<Vault> vault, GenericItem& item) {
        NSString* symbol = @"questionmark.app.dashed";
        switch (item.getType()) {
            case CipherType::Login: {
                std::vector<SecureString> uris = static_cast<LoginItem&>(item).getWebsites();
                if (!uris.empty()) {
                    if (std::optional<std::filesystem::path> path = vault->getOrchestrator()->getIcon(uris[0])) {
                        return [[ClientwardenImage alloc] initWithType:ImageTypeAppSupport
                                                                  path:[NSString stringWithUTF8String:path->c_str()]];
                    }
                }
                symbol = @"globe";
                break;
            }
            case CipherType::Card: symbol = @"creditcard"; break;
            case CipherType::Identity: symbol = @"person.text.rectangle"; break;
            case CipherType::Note: symbol = @"pad.header"; break;
            case CipherType::SshKey: symbol = @"key.viewfinder"; break;
            case CipherType::BankAccount: symbol = @"dollarsign.circle"; break;
            case CipherType::DriversLicense: symbol = @"licenseplate"; break;
            case CipherType::Passport: symbol = @"list.bullet.rectangle.portrait"; break;
            default: break;
        }
        return [[ClientwardenImage alloc] initWithType:ImageTypeSystemImage path:symbol];
    }

    /*
     * One-to-one mapping between a SidePanel row and a typed item field. The
     * same titles are used to display and to save, so the two can't drift
     * apart. Rows that combine several fields (names, card expiry,
     * locality, websites, TOTP) are handled separately.
    */
    struct FieldRow {
        const char* title;
        std::function<SecureString(GenericItem&)> get;
        std::function<void(GenericItem&, std::string_view)> set;
        GenericItemType type;
    };

    /*
     * Builds a row from a typed getter/setter pair. The item passed in is
     * always loaded as T (see LoadId), so the downcast is safe.
    */
    template <typename T>
    FieldRow R(const char* title, SecureString (T::*get)() const, T& (T::*set)(std::string_view), GenericItemType type) {
        return {
            title,
            [get](GenericItem& item) { return (static_cast<T&>(item).*get)(); },
            [set](GenericItem& item, std::string_view value) { (static_cast<T&>(item).*set)(value); },
            type
        };
    }

    const std::vector<FieldRow>& RowsFor(CipherType type) {
        static const std::vector<FieldRow> none;
        static const std::vector<FieldRow> login = {
            R<LoginItem>("Username", &LoginItem::getUsername, &LoginItem::setUsername, GenericItemTypeGeneric),
            R<LoginItem>("Password", &LoginItem::getPassword, &LoginItem::setPassword, GenericItemTypePassword),
        };
        static const std::vector<FieldRow> card = {
            R<CardItem>("Brand", &CardItem::getBrand, &CardItem::setBrand, GenericItemTypeGeneric),
            R<CardItem>("Cardholder Name", &CardItem::getCardholderName, &CardItem::setCardholderName, GenericItemTypeGeneric),
            R<CardItem>("Number", &CardItem::getNumber, &CardItem::setNumber, GenericItemTypePassword),
            R<CardItem>("Code", &CardItem::getCode, &CardItem::setCode, GenericItemTypePassword),
        };
        static const std::vector<FieldRow> identity = {
            R<IdentityItem>("Username", &IdentityItem::getUsername, &IdentityItem::setUsername, GenericItemTypeGeneric),
            R<IdentityItem>("Company", &IdentityItem::getCompany, &IdentityItem::setCompany, GenericItemTypeGeneric),
            R<IdentityItem>("SSN", &IdentityItem::getSsn, &IdentityItem::setSsn, GenericItemTypePassword),
            R<IdentityItem>("Passport Number", &IdentityItem::getPassportNumber, &IdentityItem::setPassportNumber, GenericItemTypePassword),
            R<IdentityItem>("Licence Number", &IdentityItem::getLicenseNumber, &IdentityItem::setLicenseNumber, GenericItemTypeGeneric),
            R<IdentityItem>("Email", &IdentityItem::getEmail, &IdentityItem::setEmail, GenericItemTypeGeneric),
            R<IdentityItem>("Phone", &IdentityItem::getPhone, &IdentityItem::setPhone, GenericItemTypeGeneric),
            R<IdentityItem>("Address 1", &IdentityItem::getAddress1, &IdentityItem::setAddress1, GenericItemTypeGeneric),
            R<IdentityItem>("Address 2", &IdentityItem::getAddress2, &IdentityItem::setAddress2, GenericItemTypeGeneric),
            R<IdentityItem>("Address 3", &IdentityItem::getAddress3, &IdentityItem::setAddress3, GenericItemTypeGeneric),
        };
        static const std::vector<FieldRow> sshKey = {
            R<SshKeyItem>("Fingerprint", &SshKeyItem::getFingerprint, &SshKeyItem::setFingerprint, GenericItemTypeGeneric),
            R<SshKeyItem>("Private Key", &SshKeyItem::getPrivateKey, &SshKeyItem::setPrivateKey, GenericItemTypeMl_password),
            R<SshKeyItem>("Public Key", &SshKeyItem::getPublicKey, &SshKeyItem::setPublicKey, GenericItemTypePassword),
        };
        static const std::vector<FieldRow> bankAccount = {
            R<BankAccountItem>("Bank Name", &BankAccountItem::getBankName, &BankAccountItem::setBankName, GenericItemTypeGeneric),
            R<BankAccountItem>("Name On Account", &BankAccountItem::getNameOnAccount, &BankAccountItem::setNameOnAccount, GenericItemTypeGeneric),
            R<BankAccountItem>("Account Type", &BankAccountItem::getAccountType, &BankAccountItem::setAccountType, GenericItemTypeGeneric),
            R<BankAccountItem>("Account Number", &BankAccountItem::getAccountNumber, &BankAccountItem::setAccountNumber, GenericItemTypePassword),
            R<BankAccountItem>("Routing Number", &BankAccountItem::getRoutingNumber, &BankAccountItem::setRoutingNumber, GenericItemTypePassword),
            R<BankAccountItem>("Branch Number", &BankAccountItem::getBranchNumber, &BankAccountItem::setBranchNumber, GenericItemTypeGeneric),
            R<BankAccountItem>("Pin", &BankAccountItem::getPin, &BankAccountItem::setPin, GenericItemTypePassword),
            R<BankAccountItem>("Swift Code", &BankAccountItem::getSwiftCode, &BankAccountItem::setSwiftCode, GenericItemTypeGeneric),
            R<BankAccountItem>("IBAN", &BankAccountItem::getIban, &BankAccountItem::setIban, GenericItemTypePassword),
            R<BankAccountItem>("Bank Contact Phone", &BankAccountItem::getBankContactPhone, &BankAccountItem::setBankContactPhone, GenericItemTypeGeneric),
        };
        static const std::vector<FieldRow> driversLicense = {
            R<DriversLicenseItem>("Date of Birth", &DriversLicenseItem::getDateOfBirth, &DriversLicenseItem::setDateOfBirth, GenericItemTypeDate_3),
            R<DriversLicenseItem>("License Number", &DriversLicenseItem::getLicenseNumber, &DriversLicenseItem::setLicenseNumber, GenericItemTypePassword),
            R<DriversLicenseItem>("Issuing Country", &DriversLicenseItem::getIssuingCountry, &DriversLicenseItem::setIssuingCountry, GenericItemTypeGeneric),
            R<DriversLicenseItem>("Issuing State", &DriversLicenseItem::getIssuingState, &DriversLicenseItem::setIssuingState, GenericItemTypeGeneric),
            R<DriversLicenseItem>("Issuing Date", &DriversLicenseItem::getIssueDate, &DriversLicenseItem::setIssueDate, GenericItemTypeDate_3),
            R<DriversLicenseItem>("Expiration Date", &DriversLicenseItem::getExpirationDate, &DriversLicenseItem::setExpirationDate, GenericItemTypeDate_3),
            R<DriversLicenseItem>("Issuing Authority", &DriversLicenseItem::getIssuingAuthority, &DriversLicenseItem::setIssuingAuthority, GenericItemTypeGeneric),
            R<DriversLicenseItem>("License Class", &DriversLicenseItem::getLicenseClass, &DriversLicenseItem::setLicenseClass, GenericItemTypeGeneric),
        };
        static const std::vector<FieldRow> passport = {
            R<PassportItem>("Date Of Birth", &PassportItem::getDateOfBirth, &PassportItem::setDateOfBirth, GenericItemTypeDate_3),
            R<PassportItem>("Sex", &PassportItem::getSex, &PassportItem::setSex, GenericItemTypeGeneric),
            R<PassportItem>("Birth Place", &PassportItem::getBirthPlace, &PassportItem::setBirthPlace, GenericItemTypeGeneric),
            R<PassportItem>("Nationality", &PassportItem::getNationality, &PassportItem::setNationality, GenericItemTypeGeneric),
            R<PassportItem>("Issuing Country", &PassportItem::getIssuingCountry, &PassportItem::setIssuingCountry, GenericItemTypeGeneric),
            R<PassportItem>("Passport Number", &PassportItem::getPassportNumber, &PassportItem::setPassportNumber, GenericItemTypeGeneric),
            R<PassportItem>("Passport Type", &PassportItem::getPassportType, &PassportItem::setPassportType, GenericItemTypeGeneric),
            R<PassportItem>("National Identification Number", &PassportItem::getNationalIdentificationNumber,
                &PassportItem::setNationalIdentificationNumber, GenericItemTypeGeneric),
            R<PassportItem>("Issuing Authority", &PassportItem::getIssuingAuthority, &PassportItem::setIssuingAuthority, GenericItemTypeGeneric),
            R<PassportItem>("Issue Date", &PassportItem::getIssueDate, &PassportItem::setIssueDate, GenericItemTypeDate_3),
            R<PassportItem>("Expiration Date", &PassportItem::getExpirationDate, &PassportItem::setExpirationDate, GenericItemTypeDate_3),
        };

        switch (type) {
            case CipherType::Login: return login;
            case CipherType::Card: return card;
            case CipherType::Identity: return identity;
            case CipherType::SshKey: return sshKey;
            case CipherType::BankAccount: return bankAccount;
            case CipherType::DriversLicense: return driversLicense;
            case CipherType::Passport: return passport;
            default: return none;
        }
    }

    GenericItemData* Row(NSString* title, NSString* value, GenericItemType type) {
        return [[GenericItemData alloc] initWithTitle:title value:value type:type];
    }

    NSString* Joined(std::initializer_list<SecureString> values, NSString* separator) {
        NSMutableArray<NSString*>* parts = [NSMutableArray array];
        for (const SecureString& value : values) {
            [parts addObject:NS(value)];
        }
        return [parts componentsJoinedByString:separator];
    }

    /*
     * Splits "a, b, c" into exactly `count` trimmed parts.
    */
    std::vector<SecureString> Split(NSString* value, NSString* separator, size_t count) {
        NSArray<NSString*>* parts = [value ?: @"" componentsSeparatedByString:separator];
        std::vector<SecureString> out;
        for (size_t i = 0; i < count; ++i) {
            NSString* part = i < parts.count ? [parts[i] stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet] : @"";
            out.emplace_back(part.UTF8String);
        }
        return out;
    }

    void Display(std::shared_ptr<Vault> vault, GenericItem& item, NSMutableArray<GenericItemData*>* rows,
        NSMutableArray<PasswordHistoryItem*>* history) {
        CipherType type = item.getType();

        if (type == CipherType::Identity) {
            IdentityItem& identity = static_cast<IdentityItem&>(item);
            [rows addObject:[[GenericItemData alloc] initWithTitle:@"Name"
                                                             value:NS(identity.getTitle())
                                                           value_1:NS(identity.getFirstName())
                                                           value_2:NS(identity.getMiddleName())
                                                           value_3:NS(identity.getLastName())]];
        } else if (type == CipherType::DriversLicense) {
            DriversLicenseItem& licence = static_cast<DriversLicenseItem&>(item);
            [rows addObject:[[GenericItemData alloc] initWithTitle:@"Name"
                                                             value:NS(licence.getFirstName())
                                                           value_1:NS(licence.getMiddleName())
                                                           value_2:NS(licence.getLastName())]];
        } else if (type == CipherType::Passport) {
            PassportItem& passport = static_cast<PassportItem&>(item);
            [rows addObject:[[GenericItemData alloc] initWithTitle:@"Name"
                                                             value:NS(passport.getGivenName())
                                                           value_1:NS(passport.getSurname())]];
        }

        /*
         * Items in "hide passwords" collections never send secret values to the UI.
        */
        bool hide = !item.canViewPassword();

        for (const FieldRow& row : RowsFor(type)) {
            if (hide && row.type == GenericItemTypePassword) {
                continue;
            }
            [rows addObject:Row(@(row.title), NS(row.get(item)), row.type)];
        }

        if (type == CipherType::Card) {
            CardItem& card = static_cast<CardItem&>(item);
            [rows addObject:Row(@"Expiration Date", Joined({ card.getExpMonth(), card.getExpYear() }, @"/"), GenericItemTypeDate)];
        } else if (type == CipherType::Identity) {
            IdentityItem& identity = static_cast<IdentityItem&>(item);
            NSString* locality = Joined({ identity.getPostalCode(), identity.getCity(), identity.getState(),
                identity.getCountry() }, @", ");
            [rows addObject:Row(@"Locality", locality, GenericItemTypeGeneric)];
        } else if (type == CipherType::Login) {
            LoginItem& login = static_cast<LoginItem&>(item);
            SecureString id = login.getId();

            /*
             * The code is generated on demand so it stays current while
             * the panel is open.
            */
            if (!hide) [rows addObject:[[GenericItemData alloc] initWithTitle:@"Two Factor Authentication"
                                                             value:NS(login.getTotpSecret())
                                                              type:GenericItemTypeTotp
                                                        cb_getTOTP:^TOTPResult* _Nonnull {
                try {
                    std::shared_ptr<LoginItem> current = ActiveVault()->getOrchestrator()->getItem<LoginItem>(id);
                    if (std::optional<clientwarden::TotpCode> code = current->getTotp(std::time(nullptr))) {
                        return [[TOTPResult alloc] initWithRefreshDate:(int64_t)code->m_valid_until
                                                              maxTimer:(NSInteger)code->m_period
                                                                 value:NS(code->m_code)];
                    }
                } catch (...) {
                }
                return [[TOTPResult alloc] initWithRefreshDate:0 maxTimer:30 value:@""];
            }]];

            NSMutableArray<NSString*>* websites = [NSMutableArray array];
            for (const SecureString& uri : login.getWebsites()) {
                [websites addObject:NS(uri)];
            }
            [rows addObject:Row(@"Websites", [websites componentsJoinedByString:@"\n"], GenericItemTypeWebsite)];

            for (const clientwarden::PasswordHistoryEntry& entry : hide ? std::vector<clientwarden::PasswordHistoryEntry>() : login.getPasswordHistory()) {
                NSDate* date = [NSDate dateWithTimeIntervalSince1970:(NSTimeInterval)entry.m_last_used];
                NSString* s_date = [NSDateFormatter localizedStringFromDate:date
                                                                  dateStyle:NSDateFormatterMediumStyle
                                                                  timeStyle:NSDateFormatterShortStyle];
                [history addObject:[[PasswordHistoryItem alloc] initWithDate:s_date password:NS(entry.m_password)]];
            }
        }
    }

    /*
     * Writes the SidePanel rows back into the item's type-specific fields.
    */
    void Apply(GenericItem& item, NSArray<GenericItemData*>* itemFields) {
        CipherType type = item.getType();
        const std::vector<FieldRow>& rows = RowsFor(type);

        for (GenericItemData* itemField in itemFields) {
            NSString* title = itemField.title;

            bool matched = false;
            for (const FieldRow& row : rows) {
                if ([title isEqualToString:@(row.title)]) {
                    row.set(item, View(itemField.value));
                    matched = true;
                    break;
                }
            }
            if (matched) {
                continue;
            }

            if (type == CipherType::Login && [title isEqualToString:@"Two Factor Authentication"]) {
                static_cast<LoginItem&>(item).setTotp(View(itemField.value));
            } else if (type == CipherType::Login && [title isEqualToString:@"Websites"]) {
                LoginItem& login = static_cast<LoginItem&>(item);
                for (const SecureString& uri : login.getWebsites()) {
                    login.removeWebsite(uri);
                }
                for (NSString* line in [itemField.value ?: @"" componentsSeparatedByString:@"\n"]) {
                    NSString* trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
                    if (trimmed.length > 0) {
                        login.addWebsite(View(trimmed));
                    }
                }
            } else if (type == CipherType::Card && [title isEqualToString:@"Expiration Date"]) {
                std::vector<SecureString> parts = Split(itemField.value, @"/", 2);
                static_cast<CardItem&>(item).setExpMonth(parts[0]).setExpYear(parts[1]);
            } else if (type == CipherType::Identity && [title isEqualToString:@"Name"]) {
                static_cast<IdentityItem&>(item)
                    .setTitle(View(itemField.value))
                    .setFirstName(View(itemField.value_1))
                    .setMiddleName(View(itemField.value_2))
                    .setLastName(View(itemField.value_3));
            } else if (type == CipherType::Identity && [title isEqualToString:@"Locality"]) {
                std::vector<SecureString> parts = Split(itemField.value, @",", 4);
                static_cast<IdentityItem&>(item)
                    .setPostalCode(parts[0])
                    .setCity(parts[1])
                    .setState(parts[2])
                    .setCountry(parts[3]);
            } else if (type == CipherType::DriversLicense && [title isEqualToString:@"Name"]) {
                static_cast<DriversLicenseItem&>(item)
                    .setFirstName(View(itemField.value))
                    .setMiddleName(View(itemField.value_1))
                    .setLastName(View(itemField.value_2));
            } else if (type == CipherType::Passport && [title isEqualToString:@"Name"]) {
                static_cast<PassportItem&>(item)
                    .setGivenName(View(itemField.value))
                    .setSurname(View(itemField.value_1));
            }
        }
    }

    /*
     * Files an item under the folder UUID, or under no folder for the nil UUID.
    */
    void FileUnder(GenericItem& item, NSUUID* folderUUID) {
        SecureString folder = ItemId(folderUUID);
        if (folder == NoFolder) {
            item.removeFolder();
        } else {
            item.setFolder(folder);
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
    [self cb_organizations];
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
            std::shared_ptr<Vault> v_inst = ActiveVault();

            Load(v_inst, uuid)->setFavorite((bool)fav).commit();

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
            std::shared_ptr<Vault> v_inst = ActiveVault();

            SecureString copyId = Load(v_inst, uuid)->duplicate();
            std::shared_ptr<GenericItem> copy = LoadId(v_inst, copyId);

            NSUUID* dupUUID = [[NSUUID alloc] initWithUUIDString:NS(copyId)];
            return [[ItemElement alloc] initWithName:NS(copy->getName()) uuid:dupUUID type:i_type image:IconFor(v_inst, *copy)];
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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
            item->bin();
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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
            item->restore();
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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
            item->archive();
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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
            item->unarchive();
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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            Load(v_inst, uuid)->remove();
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
            std::shared_ptr<Vault> v_inst = ActiveVault();

            std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
            FileUnder(*item, folderUUID);
            item->commit();

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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            for (NSUUID* uuid in uuids) {
                std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
                item->bin();
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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            for (NSUUID* uuid in uuids) {
                std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
                item->restore();
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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            for (NSUUID* uuid in uuids) {
                Load(v_inst, uuid)->remove();
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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            for (NSUUID* uuid in uuids) {
                std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
                item->archive();
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
            std::shared_ptr<Vault> v_inst = ActiveVault();
            for (NSUUID* uuid in uuids) {
                std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
                item->unarchive();
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
        std::shared_ptr<Vault> v_inst = ActiveVault();

        std::shared_ptr<GenericItem> item = Load(v_inst, uuid);

        NSMutableArray<GenericItemData*>* itemFields = [NSMutableArray array];
        NSMutableArray<FieldItemData*>* customFields = [NSMutableArray array];
        NSMutableArray<NSString*>* itemHistory = [NSMutableArray array];
        NSMutableArray<PasswordHistoryItem*>* passwordHistory = [NSMutableArray array];
        NSMutableArray<AttachmentItemData*>* attachments = [NSMutableArray array];

        Display(v_inst, *item, itemFields, passwordHistory);

        bool hide = !item->canViewPassword();
        for (const GenericItem::CustomField& field : item->getFields()) {
            bool secret = hide && field.m_type == clientwarden::CustomFieldType::Hidden;
            [customFields addObject:[[FieldItemData alloc] initWithTitle:NS(field.m_name)
                                                                   value:secret ? @"" : NS(field.m_value)
                                                                    type:(FieldItemType)((int)field.m_type)]];
        }

        for (const GenericItem::Attachment& attachment : item->getAttachments()) {
            [attachments addObject:[[AttachmentItemData alloc] initWithAttachID:NS(attachment.m_id) name:NS(attachment.m_file_name)]];
        }

        NSString* (^when)(std::time_t) = ^NSString*(std::time_t t) {
            return t ? NS(clientwarden::timestamp::localString(t)) : @"";
        };
        [itemHistory addObject:[NSString stringWithFormat:@"Creation: %@", when(item->getCreationDate())]];
        [itemHistory addObject:[NSString stringWithFormat:@"Modification: %@", when(item->getRevisionDate())]];
        if (item->getDeletionDate() != 0) {
            [itemHistory addObject:[NSString stringWithFormat:@"Deletion: %@", when(item->getDeletionDate())]];
        }

        NSUUID* folderUUID = [[NSUUID alloc] initWithUUIDString:NS(item->getFolderId().value_or(NoFolder))];

        [SidePanel.instance viewItemWithName:NS(item->getName()) uuid:uuid type:ToItemType(item->getType()) icon:IconFor(v_inst, *item)
                            repromptItem:item->getReprompt() folderUUID:folderUUID favorite:item->getFavorite()
                            itemFields:itemFields customFields:customFields itemHistory:itemHistory passwordHistory:passwordHistory
                            attachmentItems:attachments notes:NS(item->getNotes())];

        /*
         * Ownership: organisation name and collection names, and whether it's read-only.
        */
        NSUUID* organizationUUID = [[NSUUID alloc] initWithUUIDString:NS(item->getOrganizationId().value_or(NoFolder))];
        NSString* organizationName = @"";
        NSMutableArray<NSUUID*>* collectionUUIDs = [NSMutableArray array];
        NSMutableArray<NSString*>* collectionNames = [NSMutableArray array];
        if (std::optional<SecureString> organization = item->getOrganizationId()) {
            for (const clientwarden::OrganizationInfo& info : v_inst->getOrganizations()->getOrganizations()) {
                if (info.m_id == *organization) {
                    organizationName = NS(info.m_name);
                }
            }
            std::vector<SecureString> ids = item->getCollectionIds();
            for (const clientwarden::CollectionInfo& collection : v_inst->getOrganizations()->getCollections(*organization)) {
                if (std::find(ids.begin(), ids.end(), collection.m_id) != ids.end()) {
                    [collectionUUIDs addObject:[[NSUUID alloc] initWithUUIDString:NS(collection.m_id)]];
                    [collectionNames addObject:NS(collection.m_name)];
                }
            }
        }
        [SidePanel.instance setOwnershipWithOrganizationUUID:organizationUUID organizationName:organizationName
                                            collectionUUIDs:collectionUUIDs collectionNames:collectionNames
                                                   readOnly:!item->canEdit()];

        return true;
    } catch (...) {
        ShowToast(@"Failed to View Item");
        return false;
    }
}

+ (void)cb_sidebar {
    SidePanel.instance.cb_sidebar = ^BOOL(NSUUID* uuid) {
        try {
            std::shared_ptr<Vault> v_inst = ActiveVault();

            if (Load(v_inst, uuid)->getReprompt()) {
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
            std::shared_ptr<Vault> v_inst = ActiveVault();

            if (v_inst->verifyMasterPassword(View(password))) {
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
            std::shared_ptr<Vault> v_inst = ActiveVault();

            SecureString c_attachID = attachID.UTF8String;
            std::optional<GenericItem::Attachment> attachment;
            for (GenericItem::Attachment& candidate : Load(v_inst, uuid)->getAttachments()) {
                if (candidate.m_id == c_attachID) {
                    attachment = candidate;
                }
            }
            if (!attachment) {
                throw clientwarden::VaultError("attachment not found");
            }

            NSSavePanel* panel = [NSSavePanel savePanel];
            panel.nameFieldStringValue = NS(attachment->m_file_name);
            panel.canCreateDirectories = YES;

            [panel beginWithCompletionHandler:^(NSModalResponse result) {
                if (result != NSModalResponseOK || !panel.URL) {
                    ShowToast(@"Failed to get Download Location");
                    return;
                }

                std::filesystem::path path(panel.URL.path.UTF8String);

                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    bool ok = false;
                    try {
                        ok = Load(ActiveVault(), uuid)->downloadAttachment(c_attachID, path, [attachID](float progress) {
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

                    std::optional<SecureString> newID;
                    if (fileData) {
                        try {
                            std::shared_ptr<GenericItem> item = Load(ActiveVault(), uuid);
                            std::span<const uint8_t> content(static_cast<const uint8_t*>(fileData.bytes), fileData.length);

                            newID = item->addAttachment(View(fileName), content, [tempAttachID](float progress) {
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
            std::shared_ptr<Vault> v_inst = ActiveVault();

            std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
            if (!item->removeAttachment(View(attachID))) {
                throw clientwarden::VaultError("server refused to remove attachment");
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
            std::shared_ptr<Vault> v_inst = ActiveVault();

            std::shared_ptr<GenericItem> item = Load(v_inst, uuid);

            /*
             * Hidden values aren't shown for "hide passwords" items, so keep the stored ones
             * rather than saving the blanks the UI sends back.
            */
            std::vector<GenericItem::CustomField> previous = item->getFields();
            bool hide = !item->canViewPassword();

            item->clearFields();
            for (FieldItemData* field in customFields) {
                clientwarden::CustomFieldType kind = (clientwarden::CustomFieldType)((int)field.type);
                SecureString value(View(field.value));
                if (hide && kind == clientwarden::CustomFieldType::Hidden && value.empty()) {
                    for (const GenericItem::CustomField& old : previous) {
                        if (old.m_type == kind && old.m_name == View(field.title)) {
                            value = old.m_value;
                        }
                    }
                }
                item->addField(kind, View(field.title), value);
            }

            FileUnder(*item, folderUUID);
            item->setNotes(View(notes)).setName(View(name)).setReprompt((bool)reprompt);

            Apply(*item, itemFields);

            /*
             * Offline saves are kept locally and uploaded on the next
             * sync, so only an exception counts as failure here.
            */
            item->commit();

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
            return NS(ActiveVault()->getGenerator()->password(
                clientwarden::PasswordOptions { (int)size, (bool)caps, (bool)numbers, (bool)symbols }));
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
            return NS(ActiveVault()->getGenerator()->passphrase(words, (bool)caps, '-'));
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
            return NS(ActiveVault()->getGenerator()->pin((int)std::clamp<NSInteger>(size, 4, 64)));
        } catch (...) {
            ShowToast(@"Failed to Generate Pin");
            return @"";
        }
    };
}

/*
 * Organisation actions: move a personal item into an organisation, change an organisation
 * item's collections, and the drag-onto-collection shortcut for either.
 */
+ (void)cb_organizations {
    SidePanel.instance.cb_shareToOrganization = ^BOOL(NSUUID* uuid, NSUUID* organization, NSArray<NSUUID*>* collections) {
        try {
            std::vector<SecureString> ids;
            for (NSUUID* collection in collections) {
                ids.push_back(ItemId(collection));
            }
            return (BOOL)Load(ActiveVault(), uuid)->shareTo(ItemId(organization), ids);
        } catch (const clientwarden::VaultError& e) {
            ShowToast([NSString stringWithUTF8String:e.what()]);
            return NO;
        }
    };

    SidePanel.instance.cb_setCollections = ^BOOL(NSUUID* uuid, NSArray<NSUUID*>* collections) {
        try {
            std::vector<SecureString> ids;
            for (NSUUID* collection in collections) {
                ids.push_back(ItemId(collection));
            }
            return (BOOL)Load(ActiveVault(), uuid)->setCollections(ids);
        } catch (const clientwarden::VaultError& e) {
            ShowToast([NSString stringWithUTF8String:e.what()]);
            return NO;
        }
    };

    SidePanel.instance.cb_moveToCollection = ^BOOL(NSUUID* collectionUUID, NSUUID* uuid) {
        try {
            std::shared_ptr<Vault> v_inst = ActiveVault();
            SecureString collection = ItemId(collectionUUID);

            SecureString organization;
            for (const clientwarden::CollectionInfo& info : v_inst->getOrganizations()->getCollections("")) {
                if (info.m_id == collection) {
                    organization = info.m_organization_id;
                }
            }
            if (organization.empty()) {
                return NO;
            }

            std::shared_ptr<GenericItem> item = Load(v_inst, uuid);
            std::optional<SecureString> current = item->getOrganizationId();
            if (!current) {
                return (BOOL)item->shareTo(organization, { collection });
            }
            if (*current != organization) {
                ShowToast(@"Items can't move between organizations");
                return NO;
            }

            std::vector<SecureString> ids = item->getCollectionIds();
            if (std::find(ids.begin(), ids.end(), collection) == ids.end()) {
                ids.push_back(collection);
            }
            return (BOOL)item->setCollections(ids);
        } catch (const clientwarden::VaultError& e) {
            ShowToast([NSString stringWithUTF8String:e.what()]);
            return NO;
        }
    };
}

@end
