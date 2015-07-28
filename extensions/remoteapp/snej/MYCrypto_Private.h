//
//  MYCrypto_Private.h
//  MYCrypto
//
//  Created by Jens Alfke on 3/23/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYCryptoConfig.h"
#import "MYKeychain.h"
#import "MYKey.h"
#import "MYSymmetricKey.h"
#import "MYPublicKey.h"
#import "MYPrivateKey.h"
#import "MYCertificate.h"
#import "MYCertificateInfo.h"
#import "MYIdentity.h"

#import "Test.h"
#import <Security/Security.h>


#if MYCRYPTO_USE_IPHONE_API
typedef CFTypeRef SecExternalItemType;
typedef struct OpaqueSecKeychainRef*    SecKeychainRef;
typedef struct OpaqueSecKeychainItemRef*  SecKeychainItemRef;
typedef CFTypeRef MYKeychainAttrType;
#else
typedef OSType MYKeychainAttrType;
#endif


@interface MYKeychain (Private)
- (MYIdentity*) identityWithDigest: (MYSHA1Digest*)pubKeyDigest;
#if TARGET_OS_IPHONE && !MYCRYPTO_USE_IPHONE_API
- (id) initWithKeychainRef: (SecKeychainRef)keychainRef;
@property (readonly) SecKeychainRef keychainRef, keychainRefOrDefault;
@property (readonly) CSSM_CSP_HANDLE CSPHandle;
@property (readonly) NSString* path;
#endif
#if MYCRYPTO_USE_IPHONE_API
+ (CFTypeRef) _addItemWithInfo: (NSMutableDictionary*)info;
#endif
@end


@interface MYKeychainItem (Private);
- (id) initWithKeychainItemRef: (MYKeychainItemRef)itemRef;
- (NSData*) _getContents: (OSStatus*)outError;
- (NSString*) stringValueOfAttribute: (MYKeychainAttrType)attr;
- (BOOL) setValue: (NSString*)valueStr ofAttribute: (MYKeychainAttrType)attr;
+ (NSData*) _getAttribute: (MYKeychainAttrType)attr ofItem: (MYKeychainItemRef)item;
+ (NSString*) _getStringAttribute: (MYKeychainAttrType)attr ofItem: (MYKeychainItemRef)item;
+ (BOOL) _setAttribute: (MYKeychainAttrType)attr ofItem: (MYKeychainItemRef)item
           stringValue: (NSString*)stringValue;
- (id) _attribute: (MYKeychainAttrType)attribute;
@end      


@interface MYKey (Private)
- (id) initWithKeyData: (NSData*)data;
- (id) _initWithKeyData: (NSData*)data
            forKeychain: (SecKeychainRef)keychain;
@property (readonly) SecExternalItemType keyClass, keyType;
@property (readonly) MYSHA1Digest* _keyDigest;
- (NSData*) _crypt: (NSData *)data operation: (BOOL) op;    // YES to encrypt, NO to decrypt
#if !MYCRYPTO_USE_IPHONE_API
@property (readonly) const CSSM_KEY* cssmKey;
@property (readonly) const CSSM_CSP_HANDLE cssmCSPHandle;
- (CSSM_CC_HANDLE) _createSignatureContext: (CSSM_ALGORITHMS)algorithm;
- (CSSM_CC_HANDLE) _createPassThroughContext;
#endif
@property (readonly) NSArray* _itemList;
@end


@interface MYSymmetricKey (Private)
#if !MYCRYPTO_USE_IPHONE_API
- (id) _initWithCSSMKey: (CSSM_KEY*)cssmKey;
#endif
+ (MYSymmetricKey*) _generateSymmetricKeyOfSize: (unsigned)keySizeInBits
                                      algorithm: (CCAlgorithm)algorithm
                                     inKeychain: (MYKeychain*)keychain;
@end


@interface MYPublicKey (Private)
@property (retain) MYCertificate *certificate;
- (BOOL) setValue: (NSString*)valueStr ofAttribute: (MYKeychainAttrType)attr;
#if !TARGET_OS_IPHONE
- (CSSM_WRAP_KEY*) _unwrappedCSSMKey;
#endif
@end


@interface MYPrivateKey (Private)
+ (MYPrivateKey*) _generateRSAKeyPairOfSize: (unsigned)keySize
                                 inKeychain: (MYKeychain*)keychain;
- (id) _initWithKeyRef: (SecKeyRef)privateKey
             publicKey: (MYPublicKey*)publicKey;
- (id) _initWithKeyData: (NSData*)privKeyData 
          publicKeyData: (NSData*)pubKeyData
            forKeychain: (SecKeychainRef)keychain 
             alertTitle: (NSString*)title
            alertPrompt: (NSString*)prompt;
- (id) _initWithKeyData: (NSData*)privKeyData 
          publicKeyData: (NSData*)pubKeyData
            forKeychain: (SecKeychainRef)keychain 
             passphrase: (NSString*)passphrase;
#if !TARGET_OS_IPHONE
- (NSData*) _exportKeyInFormat: (SecExternalFormat)format
                       withPEM: (BOOL)withPEM
                    passphrase: (NSString*)passphrase;
#endif
@end


#if TARGET_OS_IPHONE && !MYCRYPTO_USE_IPHONE_API
@interface MYCertificate (Private)
- (id) initWithCertificateData: (NSData*)data
                          type: (CSSM_CERT_TYPE) type
                      encoding: (CSSM_CERT_ENCODING) encoding;
@end
#endif


@interface MYCertificateInfo (Private)
- (NSData*) subjectPublicKeyData;
- (MYPublicKey*) subjectPublicKey;
- (NSData*) signedData;
- (MYOID*) signatureAlgorithmID;
- (NSData*) signature;
@end


#if !TARGET_OS_IPHONE
@interface MYIdentity (Private)
- (id) initWithData: (NSData*)data
             format: (SecExternalFormat)format
           keychain:(MYKeychain*)keychain
              error: (NSError**)outError;
@end
#endif


#undef check
BOOL check(OSStatus err, NSString *what);

#define checksave(CALL) ({OSStatus err=(CALL); check(err,@""#CALL) || (_error=err, NO);})

#if !MYCRYPTO_USE_IPHONE_API
BOOL checkcssm(CSSM_RETURN err, NSString *what);

SecKeyRef importKey(NSData *data, 
                    SecExternalItemType type,
                    SecKeychainRef keychain,
                    SecKeyImportExportParameters *params /*non-null*/);

NSString* OIDAsString(CSSM_OID OID);
CSSM_ALGORITHMS CSSMFromCCAlgorithm( CCAlgorithm ccAlgorithm );

typedef struct {
    CSSM_ALGORITHMS algorithm;
    uint32 sizeInBits;
} MYCryptoWrappedKeyDesc;

#endif
