#import "LoginBridge.h"
#import <Cocoa/Cocoa.h>
#import "clientwarden-Swift.h"
#include "Vault.h"

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
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            /*
             * The main URL isn't needed by the vault; Bitwarden only uses it
             * for the web UI.
            */
            v_inst.SetServer(ClientWarden::ServerUrls { vaultURL.UTF8String, apiURL.UTF8String, iconURL.UTF8String, wssURL.UTF8String });

            ClientWarden::LoginResult result = v_inst.Login(email.UTF8String, password.UTF8String);

            if (![self presentLoginResult:result]) {
                return NO;
            }
            if (result != ClientWarden::LoginResult::Success) {
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
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            ClientWarden::LoginResult result = v_inst.SubmitCode(code.UTF8String);

            if (result != ClientWarden::LoginResult::Success) {
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
+ (BOOL)presentLoginResult:(ClientWarden::LoginResult)result {
    using ClientWarden::LoginResult;

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
            ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

            std::optional<ClientWarden::PasskeyRequest> passkey = v_inst.PendingPasskey();

            if (!passkey) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    Toast* toast = [[Toast alloc] initWithMessage:@"No passkey requested"];
                    [[ToastStore instance] addToast:toast];
                });
                return NO;
            }

            NSData* challenge = [NSData dataWithBytes:passkey->challenge.data() length:passkey->challenge.size()];
            NSString* rpID = [NSString stringWithUTF8String:passkey->relyingParty.c_str()];
            
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
    ClientWarden::Vault& v_inst = ClientWarden::Vault::Instance();

    ASAuthorizationPlatformPublicKeyCredentialAssertion* cred =
        (ASAuthorizationPlatformPublicKeyCredentialAssertion *)authorization.credential;

    NSData* credentialID = cred.credentialID;
    NSData* authData = cred.rawAuthenticatorData;
    NSData* clientData = cred.rawClientDataJSON;
    NSData* signature = cred.signature;
    
    auto bytes = [](NSData* data) {
        return std::span<const uint8_t>(static_cast<const uint8_t*>(data.bytes), data.length);
    };

    bool result = v_inst.SubmitPasskey(bytes(credentialID), bytes(authData), bytes(clientData), bytes(signature)) ==
        ClientWarden::LoginResult::Success;

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