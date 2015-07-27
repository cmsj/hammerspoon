#import <Cocoa/Cocoa.h>
#import <MultipeerConnectivity/MultipeerConnectivity.h>
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>
#import <LuaSkin/LuaSkin.h>
#import "../hammerspoon.h"
#import "MYAnonymousIdentity.h"

NSString *sessionStateToString(MCSessionState state) {
    switch (state) {
        case MCSessionStateNotConnected: return @"Not Connected";
        case MCSessionStateConnecting: return @"Connecting";
        case MCSessionStateConnected: return @"Connected"; 
        default: return @"Unknown";
    }
}

NSString *SecIdentityRefFingerprint(SecIdentityRef identityRef) {
    NSMutableString *output = [[NSMutableString alloc] init];
    SecCertificateRef certRef;

    SecIdentityCopyCertificate(identityRef, &certRef);
    CFDataRef data = SecCertificateCopyData(certRef);

    unsigned char md5[CC_MD5_DIGEST_LENGTH+1];
    CC_MD5(CFDataGetBytePtr(data), (CC_LONG)CFDataGetLength(data), md5);
    md5[CC_MD5_DIGEST_LENGTH] = 0;

    for (unsigned int i = 0; i < (unsigned int)CFDataGetLength(data); i++) {
        [output appendFormat:@"%02x", md5[i]];
    }

    CFRelease(certRef);
    CFRelease(data);

    return (NSString *)output;
}

@interface HSRemoteHandler : NSObject <MCSessionDelegate, MCNearbyServiceAdvertiserDelegate> {
    SecIdentityRef peerCertificate;
}

@property (nonatomic, strong) MCPeerID *peerID;
@property (nonatomic, strong) MCSession *session;
@property (nonatomic, strong) MCNearbyServiceAdvertiser *advertiser;

- (void)advertiseSelf:(BOOL)advertiser;

@end

static HSRemoteHandler *remoteHandler;

@implementation HSRemoteHandler

#pragma mark - lifecycle

- (id)init {
    self = [super init];
    if (self) {
        NSLog(@"Initialising Hammerspoon Remote server");
        // FIXME: displayName should be limited to 63 characters
        NSString *peerName = [NSString stringWithFormat:@"%@@%@", NSUserName(), [[NSHost currentHost] localizedName]];
        self.peerID = [[MCPeerID alloc] initWithDisplayName:peerName];
        if (!self.peerID) {
            NSLog(@"ERROR: peerID is null");
            return nil;
        }
        NSLog(@"Created peer with name: %@ (%@)", self.peerID.displayName, self.peerID);
        NSError *certError;
        peerCertificate = MYGetOrCreateAnonymousIdentity(peerName, kMYAnonymousIdentityDefaultExpirationInterval, &certError);
        NSLog(@"Generated/found my cert with fingerprint: %@", SecIdentityRefFingerprint(peerCertificate));
        self.session = [[MCSession alloc] initWithPeer:self.peerID securityIdentity:@[(__bridge id)peerCertificate] encryptionPreference:MCEncryptionRequired];
        self.session.delegate = self;
    }
    return self;
}

- (void)advertiseSelf:(BOOL)advertise {
    if (advertise) {
        NSLog(@"Starting advertising");
        self.advertiser = [[MCNearbyServiceAdvertiser alloc] initWithPeer:self.peerID discoveryInfo:nil serviceType:@"hmspn-remoteapp"];
        self.advertiser.delegate = self;
        [self.advertiser startAdvertisingPeer];
    } else {
        NSLog(@"Stopping advertising");
        [self.advertiser stopAdvertisingPeer];
        self.advertiser = nil;
    }
}

#pragma mark - MCSessionDelegate protocol

- (void)session:(MCSession *)session peer:(MCPeerID *)peerID didChangeState:(MCSessionState)state {
    NSLog(@"didChangeState: %@", sessionStateToString(state));
}

- (void)session:(MCSession *)session didReceiveData:(NSData *)data fromPeer:(MCPeerID *)peerID {
    NSLog(@"didReceiveData");
}

- (void)session:(MCSession *)session didStartReceivingResourceWithName:(NSString *)resourceName fromPeer:(MCPeerID *)peerID withProgress:(NSProgress *)progress {
    NSLog(@"didStartReceivingResourceWithName");
}

- (void)session:(MCSession *)session didFinishReceivingResourceWithName:(NSString *)resourceName fromPeer:(MCPeerID *)peerID atURL:(NSURL *)localURL withError:(NSError *)error {
    NSLog(@"didFinishReceivingResourceWithName");
}

- (void)session:(MCSession *)session didReceiveStream:(NSInputStream *)stream withName:(NSString *)streamName fromPeer:(MCPeerID *)peerID {
    NSLog(@"didReceiveStream");
}

- (void)session:(MCSession *)session didReceiveCertificate:(NSArray *)certificate fromPeer:(MCPeerID *)peerID certificateHandler:(void (^)(BOOL accept))certificateHandler {
    NSLog(@"didReceiveCertificate");
    if (!certificate) {
        NSLog(@"No certificate received. Refusing to pair");
        certificateHandler(NO);
        return;
    }

    SecIdentityRef identityRef = (__bridge SecIdentityRef)[certificate objectAtIndex:0];

    NSLog(@"Found a MD5 of: %@", SecIdentityRefFingerprint(identityRef));
    // FIXME: Have the user verify
    certificateHandler(YES);
}

#pragma mark - MCNearbyServiceAdvertiserDelegate protocol

- (void)advertiser:(MCNearbyServiceAdvertiser *)advertiser
didNotStartAdvertisingPeer:(NSError *)error {
             NSLog(@"ERROR: Failed to start advertising: %@", error);
}

- (void)advertiser:(MCNearbyServiceAdvertiser *)advertiser didReceiveInvitationFromPeer:(MCPeerID *)peerID
                                                                            withContext:(NSData *)context
                                                                      invitationHandler:(void (^)(BOOL accept,
                                                                                                  MCSession *session))invitationHandler {
    NSLog(@"Got a peer request");
    NSString *pin = [[NSString alloc] initWithData:context encoding:NSUTF8StringEncoding];
    NSAlert *alert = [[NSAlert alloc] init];

    alert.alertStyle = NSWarningAlertStyle;
    alert.messageText = @"Hammerspoon Remote pairing request";
    alert.informativeText = [NSString stringWithFormat:@"%@ would like to connect.\nPlease confirm the Hammerspoon Remote app is showing PIN: %@", peerID.displayName, pin];
    [alert addButtonWithTitle:@"Pair"];
    [alert addButtonWithTitle:@"Cancel"];
    if ([alert runModal] == NSAlertFirstButtonReturn) {
        NSLog(@"User accepted invitation");
        invitationHandler(YES, self.session);
    } else {
        NSLog(@"User declined invitation");
        invitationHandler(NO, self.session);
    }
}
@end

/// hs.remoteapp.start()
/// Function
/// Starts the Hammerspoon Remote server
///
/// Parameters:
///  * None
///
/// Returns:
///  * None
static int remoteapp_start(lua_State *L) {
    [remoteHandler advertiseSelf:YES];
    return 0;
}

/// hs.remoteapp.stop()
/// Function
/// Stops the Hammerspoon Remote server
///
/// Parameters:
///  * None
///
/// Returns:
///  * None
static int remoteapp_stop(lua_State *L) {
    [remoteHandler advertiseSelf:NO];
    [remoteHandler.session disconnect];
    return 0;
}

static int remoteapp_gc(lua_State *L) {
    remoteapp_stop(L);
    return 0;
}

static const luaL_Reg remoteappLib[] = {
    {"start", remoteapp_start},
    {"stop", remoteapp_stop},

    {}
};

static const luaL_Reg remoteappMetaLib[] = {
    {"__gc", remoteapp_gc},

    {}
};

/* NOTE: The substring "hs_remoteapp_internal" in the following function's name
         must match the require-path of this file, i.e. "hs.remoteapp.internal". */

int luaopen_hs_remoteapp_internal(lua_State *L) {
    remoteHandler = [[HSRemoteHandler alloc] init];
    if (!remoteHandler) {
        showError(L, "ERROR: Unable to initialise Hammerspoon Remote server");
    }

    // Table for luaopen
    LuaSkin *skin = [LuaSkin shared];
    [skin registerLibrary:remoteappLib metaFunctions:remoteappMetaLib];

    return 1;
}
