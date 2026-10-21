#import "SendBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include <fstream>
#include <iterator>
#include "vault_manager/vault_manager.h"

/*
 * Bridges the Send panel to the vault's Sends part. Strings cross as NSString; secrets stay in
 * SecureString on the C++ side.
 */
namespace {
    using clientwarden::SecureString;

    NSString* NS(const SecureString& s) {
        return [[NSString alloc] initWithBytes:s.data() length:s.size() encoding:NSUTF8StringEncoding] ?: @"";
    }

    std::string_view View(NSString* s) {
        return s ? std::string_view(s.UTF8String) : std::string_view();
    }

    void ShowToast(NSString* message) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [[ToastStore instance] addToast:[[Toast alloc] initWithMessage:message]];
        });
    }

    std::shared_ptr<clientwarden::Sends> ActiveSends() {
        return clientwarden::VaultManager::instance().getActiveVault()->getSends();
    }

    /*
     * A new Send exists only here until it's saved (its key material was generated on creation),
     * and the last Send opened from a link is kept for "Save File…".
     */
    std::shared_ptr<clientwarden::Send> g_draft;
    std::optional<clientwarden::ReceivedSend> g_received;

    SendDetail* Detail(clientwarden::Send& send) {
        SendDetail* detail = [SendDetail new];
        detail.id = NS(send.getId());
        detail.kind = send.getType() == clientwarden::SendType::File ? SendKindFile : SendKindText;
        detail.name = NS(send.getName());
        detail.notes = NS(send.getNotes());
        detail.text = NS(send.getText());
        detail.textHidden = send.getTextHidden();
        detail.fileName = NS(send.getFileName());
        detail.fileSize = NS(send.getFileSize());
        detail.maxAccessCount = send.getMaxAccessCount().value_or(0);
        detail.accessCount = send.getAccessCount();
        detail.expirationDate = (double)send.getExpirationDate();
        detail.deletionDate = (double)send.getDeletionDate();
        detail.disabled = send.getDisabled();
        detail.hideEmail = send.getHideEmail();
        detail.hasPassword = send.hasPassword();
        detail.shareUrl = NS(send.getShareUrl());
        return detail;
    }

    /*
     * Reads a file the user chose into secure memory.
     */
    std::optional<clientwarden::SecureBytes> ReadFile(NSString* path) {
        std::ifstream in(path.UTF8String, std::ios::binary);
        if (!in) {
            return std::nullopt;
        }
        clientwarden::SecureBytes content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        return content;
    }
}

@implementation SendBridge

+ (void)setupCallbacks {
    SendPanel* panel = SendPanel.instance;

    panel.cb_getSends = ^NSArray* _Nonnull {
        NSMutableArray<SendDetail*>* sends = [NSMutableArray array];
        try {
            for (const std::shared_ptr<clientwarden::Send>& send : ActiveSends()->getSends()) {
                [sends addObject:Detail(*send)];
            }
        } catch (const clientwarden::VaultError& e) {
            ShowToast([NSString stringWithUTF8String:e.what()]);
        }
        return sends;
    };

    panel.cb_newSend = ^SendDetail* _Nullable(SendKind kind) {
        try {
            g_draft = ActiveSends()->createSend(kind == SendKindFile ? clientwarden::SendType::File : clientwarden::SendType::Text);
            return Detail(*g_draft);
        } catch (const clientwarden::VaultError& e) {
            ShowToast([NSString stringWithUTF8String:e.what()]);
            return nil;
        }
    };

    panel.cb_saveSend = ^SendDetail* _Nullable(SendDetail* detail, NSString* password, NSString* filePath) {
        try {
            std::shared_ptr<clientwarden::Send> send = detail.id.length == 0 ? g_draft : ActiveSends()->getSend(View(detail.id));
            if (!send) {
                return nil;
            }

            send->setName(View(detail.name)).setNotes(View(detail.notes));
            if (send->getType() == clientwarden::SendType::Text) {
                send->setText(View(detail.text), detail.textHidden);
            } else if (send->getId().empty()) {
                std::optional<clientwarden::SecureBytes> content = ReadFile(filePath);
                if (!content) {
                    ShowToast(@"Choose a file to send");
                    return nil;
                }
                send->setFile(View(filePath.lastPathComponent), *content);
            }
            send->setMaxAccessCount(detail.maxAccessCount > 0 ? std::optional<int>((int)detail.maxAccessCount) : std::nullopt)
                .setExpirationDate((std::time_t)detail.expirationDate)
                .setDeletionDate((std::time_t)detail.deletionDate)
                .setDisabled(detail.disabled)
                .setHideEmail(detail.hideEmail)
                .setPassword(View(password));

            if (!send->commit()) {
                return nil;
            }
            if (send == g_draft) {
                g_draft.reset();
            }
            return Detail(*send);
        } catch (const clientwarden::VaultError& e) {
            ShowToast([NSString stringWithUTF8String:e.what()]);
            return nil;
        }
    };

    panel.cb_deleteSend = ^BOOL(NSString* id) {
        try {
            return (BOOL)ActiveSends()->getSend(View(id))->remove();
        } catch (...) {
            return NO;
        }
    };

    panel.cb_removeSendPassword = ^BOOL(NSString* id) {
        try {
            return (BOOL)ActiveSends()->getSend(View(id))->removePassword();
        } catch (...) {
            return NO;
        }
    };

    panel.cb_openSend = ^ReceivedSendData* _Nonnull(NSString* link, NSString* password) {
        ReceivedSendData* data = [ReceivedSendData new];
        try {
            clientwarden::ReceivedSend received;
            clientwarden::ReceiveResult result = ActiveSends()->open(View(link), View(password), received);
            data.status = (NSInteger)result;
            if (result == clientwarden::ReceiveResult::Success) {
                data.kind = received.m_type == clientwarden::SendType::File ? SendKindFile : SendKindText;
                data.name = NS(received.m_name);
                data.text = NS(received.m_text);
                data.textHidden = received.m_text_hidden;
                data.fileName = NS(received.m_file_name);
                data.fileSize = NS(received.m_file_size);
                data.creator = NS(received.m_creator);
                g_received = std::move(received);
            }
        } catch (...) {
            data.status = (NSInteger)clientwarden::ReceiveResult::Failed;
        }
        return data;
    };

    panel.cb_downloadReceivedFile = ^BOOL(NSString* path) {
        try {
            return g_received && ActiveSends()->downloadReceivedFile(*g_received, std::filesystem::path(path.UTF8String), nullptr);
        } catch (...) {
            return NO;
        }
    };
}

@end
