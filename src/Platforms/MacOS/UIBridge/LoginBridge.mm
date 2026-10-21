#import "LoginBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "vault_manager/vault_manager.h"

@implementation LoginBridge

/*
 * Setup Callbacks will be called inside of the swift class
 * onAppear. Setup Callbacks will setup all the necessary
 * callbacks for that class.
 */
+ (void)setupCallbacks {
    [self cb_login];
    [self cb_submitCode];
    [self cb_usePasskey];
}

/*
 * Login takes in an email and password as well as a
 * vault, main, api, wss and icon URL and sets the URI
 * in the vault and sets up the vault for the new user.
 */
+ (void)cb_login {
    Login.instance.cb_login = ^BOOL(NSString* email, NSString* password, NSString* vaultURL, NSString* mainURL, 
                                                NSString* apiURL, NSString* wssURL, NSString* iconURL) {
        try {
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();

            /*
             * The main URL isn't needed by the vault; Bitwarden only uses it
             * for the web UI.
            */
            v_inst->setServer(clientwarden::ServerUrls { vaultURL.UTF8String, apiURL.UTF8String, iconURL.UTF8String, wssURL.UTF8String });

            clientwarden::LoginResult result = v_inst->login(email.UTF8String, password.UTF8String);

            if (![self presentLoginResult:result]) {
                return NO;
            }
            if (result != clientwarden::LoginResult::Success) {
                return YES;
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                ClientwardenWindow.instance.state = WindowStateVault;
            });

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Login.instance.ViewType = LoginViewTypeLogin;
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Authenticate"];
                [[ToastStore instance] addToast:toast];
            });

            return NO;
        }
    };
}

/*
 * SubmitCode is used when BitWarden requests a TOTP
 * code or a Device Verification code.
 */
+ (void)cb_submitCode {
    Login.instance.cb_submitCode = ^BOOL(NSString* code) {
        try {
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();

            clientwarden::LoginResult result = v_inst->submitCode(code.UTF8String);

            if (result != clientwarden::LoginResult::Success) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Login.instance.ViewType = LoginViewTypeLogin;
                    Toast* toast = [[Toast alloc] initWithMessage:@"Failed to Authenticate"];
                    [[ToastStore instance] addToast:toast];
                });
                return NO;
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                Login.instance.ViewType = LoginViewTypeLogin;
                ClientwardenWindow.instance.state = WindowStateVault;
            });

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to submit code"];
                [[ToastStore instance] addToast:toast];
            });
            return NO;
        }
    };
}

static LoginBridge* p_loginBridge = nil;

/*
 * Moves the login view to the next step for a login result, or shows why
 * it failed. Returns NO on failure.
 */
+ (BOOL)presentLoginResult:(clientwarden::LoginResult)result {
    using clientwarden::LoginResult;

    if (result == LoginResult::NeedsTotp || result == LoginResult::NeedsDeviceVerification || result == LoginResult::NeedsPasskey) {
        LoginViewType view = result == LoginResult::NeedsPasskey ? LoginViewTypePasskey : LoginViewTypeTOTP;
        dispatch_async(dispatch_get_main_queue(), ^{
            Login.instance.ViewType = view;
            ClientwardenWindow.instance.state = WindowStateLogin;
        });
        return YES;
    }
    if (result == LoginResult::Success) {
        return YES;
    }

    NSString* message = result == LoginResult::InvalidCredentials ? @"Wrong Email or Password"
        : result == LoginResult::Offline ? @"Can't reach the server" : @"Failed to Authenticate";
    dispatch_async(dispatch_get_main_queue(), ^{
        Toast* toast = [[Toast alloc] initWithMessage:message];
        [[ToastStore instance] addToast:toast];
    });
    return NO;
}

/*
 * usePasskey is used when BitWarden requests a Passkey
 * to be used to login.
 */
+ (void)cb_usePasskey {
    Login.instance.cb_usePasskey = ^BOOL() {
        try {
            p_loginBridge = [LoginBridge new];
            std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();

            std::optional<clientwarden::PasskeyRequest> passkey = v_inst->getPendingPasskey();

            if (!passkey) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"No passkey requested"];
                    [[ToastStore instance] addToast:toast];
                });
                return NO;
            }

            NSData* challenge = [NSData dataWithBytes:passkey->m_challenge.data() length:passkey->m_challenge.size()];
            NSString* rpID = [NSString stringWithUTF8String:passkey->m_relying_party.c_str()];
            
            ASAuthorizationPlatformPublicKeyCredentialProvider* provider = 
                [[ASAuthorizationPlatformPublicKeyCredentialProvider alloc] initWithRelyingPartyIdentifier:rpID];

            ASAuthorizationPlatformPublicKeyCredentialAssertionRequest* request =
                [provider createCredentialAssertionRequestWithChallenge:challenge];

            ASAuthorizationController* controller = [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]];
            controller.delegate = p_loginBridge;
            controller.presentationContextProvider = p_loginBridge;
            [controller performRequests];

            return YES;
        } catch (...) {
            dispatch_async(dispatch_get_main_queue(), ^{
                Toast* toast = [[Toast alloc] initWithMessage:@"Failed to use passkey"];
                [[ToastStore instance] addToast:toast];
            });
            return NO;
        }
    };
}

#pragma mark - ASAuthorizationControllerDelegate

- (void)authorizationController:(ASAuthorizationController *)controller
    didCompleteWithAuthorization:(ASAuthorization *)authorization {
    std::shared_ptr<clientwarden::Vault> v_inst = clientwarden::VaultManager::instance().getActiveVault();

    ASAuthorizationPlatformPublicKeyCredentialAssertion* cred =
        (ASAuthorizationPlatformPublicKeyCredentialAssertion *)authorization.credential;

    NSData* credentialID = cred.credentialID;
    NSData* authData = cred.rawAuthenticatorData;
    NSData* clientData = cred.rawClientDataJSON;
    NSData* signature = cred.signature;
    
    auto bytes = [](NSData* data) {
        return std::span<const uint8_t>(static_cast<const uint8_t*>(data.bytes), data.length);
    };

    bool result = v_inst->submitPasskey(bytes(credentialID), bytes(authData), bytes(clientData), bytes(signature)) ==
        clientwarden::LoginResult::Success;

    if (!result) {
        dispatch_async(dispatch_get_main_queue(), ^{
            Toast* toast = [[Toast alloc] initWithMessage:@"Failed to use passkey"];
            [[ToastStore instance] addToast:toast];
        });
        return;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        Login.instance.ViewType = LoginViewTypeLogin;
        ClientwardenWindow.instance.state = WindowStateVault;
    });
}

- (void)authorizationController:(ASAuthorizationController *)controller
            didCompleteWithError:(NSError *)error {
    dispatch_async(dispatch_get_main_queue(), ^{
        Toast* toast = [[Toast alloc] initWithMessage:@"Failed to use passkey"];
        [[ToastStore instance] addToast:toast];
    });
}

#pragma mark - Presentation

- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller {
    return NSApplication.sharedApplication.keyWindow ?: NSApplication.sharedApplication.windows.firstObject;
}

@end