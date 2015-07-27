#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
@interface HSCertManager : NSObject {
    SecKeyRef publicKey;
    SecKeyRef privateKey;
}

- (BOOL)generateRSAKeypair;
@end

@implementation HSCertManager
- (BOOL)generateRSAKeypair {
    int keySize = 2048;
    SecKeyRef pubKey = NULL;
    SecKeyRef privKey = NULL;
    OSStatus err;

#if TARGET_OS_IPHONE
    NSDictionary *pubKeyAttrs = @{(__bridge id)kSecAttrIsPermanent: (NSNumber*)kCFBooleanTrue};
    NSDictionary *privKeyAttrs = @{(__bridge id)kSecAttrIsPermanent: (NSNumber*)kCFBooleanTrue};
    NSDictionary *keyAttrs = @{(__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA},
                               (__bridge id)kSecAttrKeySizeInBits: @(keySize),
                               (__bridge id)kSecPublicKeyAttrs: pubKeyAttrs,
                               (__bridge id)kSecPrivateKeyAttrs: privKeyAttrs};
    err = SecKeyGeneratePair((__bridge CFDictionaryRef)keyAttrs:&pubKey, &privKey);
#else
    err = SecKeyCreatePair(keychain.keychainRefOrDefault,
                           CSSM_ALGID_RSA,
                           keySize,
                           0LL,
                           CSSM_KEYUSE_ENCRYPT | CSSM_KEYUSE_VERIFY | CSSM_KEYUSE_WRAP,        // public key
                           CSSM_KEYATTR_EXTRACTABLE | CSSM_KEYATTR_PERMANENT,
                           CSSM_KEYUSE_ANY,                                 // private key
                           CSSM_KEYATTR_EXTRACTABLE | CSSM_KEYATTR_PERMANENT | CSSM_KEYATTR_SENSITIVE,
                           NULL,                                            // SecAccessRef
                           &pubKey, &privKey);
#endif
    if (err != errSecSuccess) {
        NSLog(@"ERROR: generateRSAKeypair failed: %d", err);
        return NO;
    } else {
        publicKey = pubKey;
        privateKey = privKey;
        return YES;
    }
}

