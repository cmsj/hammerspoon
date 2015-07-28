//
//  MYAnonymousIdentity.m
//  MYUtilities
//
//  Created by Jens Alfke on 12/5/14.
//

#import "MYAnonymousIdentity.h"
#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>


// Raw data of an anonymous X.509 cert:
static uint8_t const kCertTemplate[816];

// Key size of kCertTemplate:
#define kKeySizeInBits     2048

// These are offsets into kCertTemplate where values need to be substituted:
#define kSerialOffset        15
#define kSerialLength         1
#define kIssueDateOffset    108u
#define kExpDateOffset      123u
#define kDateLength          13
#define kPublicKeyOffset    155u
#define kPublicKeyLength    148u
#define kCSROffset            0
#define kCSRLength          547u
#define kSignatureLength    256u


static BOOL checkErr(OSStatus err, NSError** outError);
static NSData* generateAnonymousCert(SecKeyRef publicKey, SecKeyRef privateKey,
                                     NSTimeInterval expirationInterval,
                                     NSError** outError);
static BOOL checkCertValid(SecCertificateRef cert, NSTimeInterval expirationInterval);
static BOOL generateRSAKeyPair(int sizeInBits,
                               BOOL permanent,
                               NSString* label,
                               SecKeyRef *publicKey,
                               SecKeyRef *privateKey,
                               NSError** outError);
static NSData* getPublicKeyData(SecKeyRef publicKey);
static NSData* signData(SecKeyRef privateKey, NSData* inputData);
static SecCertificateRef addCertToKeychain(NSData* certData, NSString* label,
                                           NSError** outError);
static SecIdentityRef findIdentity(NSString* label, NSTimeInterval expirationInterval);

#if TARGET_OS_IPHONE
static void removePublicKey(SecKeyRef publicKey);
#endif


SecIdentityRef MYGetOrCreateAnonymousIdentity(NSString* label,
                                              NSTimeInterval expirationInterval,
                                              NSError** outError)
{
    NSCParameterAssert(label);
    SecIdentityRef ident = findIdentity(label, expirationInterval);
    if (!ident) {
        NSLog(@"Generating new anonymous self-signed SSL identity labeled \"%@\"...", label);
        SecKeyRef publicKey, privateKey;
        if (!generateRSAKeyPair(kKeySizeInBits, YES, label, &publicKey, &privateKey, outError))
            return NULL;
        NSData* certData = generateAnonymousCert(publicKey,privateKey, expirationInterval,outError);
        if (!certData)
            return NULL;
        SecCertificateRef certRef = addCertToKeychain(certData, label, outError);
        if (!certRef)
            return NULL;
#if TARGET_OS_IPHONE
        removePublicKey(publicKey); // workaround for Radar 18205627
        ident = findIdentity(label, expirationInterval);
        if (!ident)
            checkErr(errSecItemNotFound, outError);
#else
        if (checkErr(SecIdentityCreateWithCertificate(NULL, certRef, &ident), outError))
            CFAutorelease(ident);
#endif
        if (!ident)
            NSLog(@"MYAnonymousIdentity: Can't find identity we just created");
    }
    return ident;
}


static BOOL checkErr(OSStatus err, NSError** outError) {
    if (err == noErr)
        return YES;
    NSDictionary* info = nil;
#if !TARGET_OS_IPHONE
    NSString* message = CFBridgingRelease(SecCopyErrorMessageString(err, NULL));
    if (message)
        info = @{NSLocalizedDescriptionKey: [NSString stringWithFormat:@"%@ (%d)", message, (int)err]};
#endif
    if (outError)
        *outError = [NSError errorWithDomain: NSOSStatusErrorDomain code: err userInfo: info];
    return NO;
}


// Generates an RSA key-pair, optionally adding it to the keychain.
static BOOL generateRSAKeyPair(int sizeInBits,
                               BOOL permanent,
                               NSString* label,
                               SecKeyRef *publicKey,
                               SecKeyRef *privateKey,
                               NSError** outError)
{
#if TARGET_OS_IPHONE
    NSDictionary *keyAttrs = @{(__bridge id)kSecAttrIsPermanent: @(permanent),
                               (__bridge id)kSecAttrLabel: label};
#endif
    NSDictionary *pairAttrs = @{(__bridge id)kSecAttrKeyType:       (__bridge id)kSecAttrKeyTypeRSA,
                                (__bridge id)kSecAttrKeySizeInBits: @(sizeInBits),
                                (__bridge id)kSecAttrLabel:         label,
#if TARGET_OS_IPHONE
                                (__bridge id)kSecPublicKeyAttrs:    keyAttrs,
                                (__bridge id)kSecPrivateKeyAttrs:   keyAttrs
#else
                                (__bridge id)kSecAttrIsPermanent:   @(permanent)
#endif
                                };
    if (!checkErr(SecKeyGeneratePair((__bridge CFDictionaryRef)pairAttrs, publicKey, privateKey),
                  outError))
        return NO;
    CFAutorelease(*publicKey);
    CFAutorelease(*privateKey);
    return YES;
}


// Generates a self-signed certificate, returning the cert data.
static NSData* generateAnonymousCert(SecKeyRef publicKey, SecKeyRef privateKey,
                                     NSTimeInterval expirationInterval,
                                     NSError** outError __unused)
{
    // Read the original template certificate file:
    NSMutableData* data = [NSMutableData dataWithBytes: kCertTemplate length: sizeof(kCertTemplate)];
    uint8_t* buf = data.mutableBytes;

    // Write the serial number:
    SecRandomCopyBytes(kSecRandomDefault, kSerialLength, &buf[kSerialOffset]);
    buf[kSerialOffset] &= 0x7F; // non-negative

    // Write the issue and expiration dates:
    NSDateFormatter *x509DateFormatter = [[NSDateFormatter alloc] init];
    x509DateFormatter.dateFormat = @"yyMMddHHmmss'Z'";
    x509DateFormatter.timeZone = [NSTimeZone timeZoneWithName: @"GMT"];
    NSDate* date = [NSDate date];
    const char* dateStr = [[x509DateFormatter stringFromDate: date] UTF8String];
    memcpy(&buf[kIssueDateOffset], dateStr, kDateLength);
    date = [date dateByAddingTimeInterval: expirationInterval];
    dateStr = [[x509DateFormatter stringFromDate: date] UTF8String];
    memcpy(&buf[kExpDateOffset], dateStr, kDateLength);

    // Copy the public key:
    NSData* keyData = getPublicKeyData(publicKey);
    if (keyData.length != kPublicKeyLength) {
        NSLog(@"ERROR: keyData.length != kPublicKeyLength");
        return nil;
    }
    memcpy(&buf[kPublicKeyOffset], keyData.bytes, kPublicKeyLength);

    // Sign the cert:
    NSData* csr = [data subdataWithRange: NSMakeRange(kCSROffset, kCSRLength)];
    NSData* sig = signData(privateKey, csr);
    if (sig.length != kSignatureLength) {
        NSLog(@"ERROR: sig.length != kSignatureLength");
        return nil;
    }
    [data appendData: sig];

    return data;
}


// Returns the data of an RSA public key, in the format used in an X.509 certificate.
static NSData* getPublicKeyData(SecKeyRef publicKey) {
#if TARGET_OS_IPHONE
    NSDictionary *info = @{(__bridge id)kSecValueRef:   (__bridge id)publicKey,
                           (__bridge id)kSecReturnData: @YES};
    CFTypeRef data;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)info, &data) != noErr) {
        Log(@"SecItemCopyMatching failed; input = %@", info);
        return nil;
    }
    Assert(data!=NULL);
    return CFBridgingRelease(data);
#else
    CFDataRef data = NULL;
    if (SecItemExport(publicKey, kSecFormatBSAFE, 0, NULL, &data) != noErr)
        return nil;
    return (NSData*)CFBridgingRelease(data);
#endif
}


#if TARGET_OS_IPHONE
// workaround for Radar 18205627: When iOS reads an identity from the keychain, it may accidentally
// get the public key instead of the private key. The workaround is to remove the public key so
// that only the private one is obtainable. --jpa 6/2015
static void removePublicKey(SecKeyRef publicKey) {
    NSDictionary* query = @{(__bridge id)kSecValueRef: (__bridge id)publicKey};
    OSStatus err = SecItemDelete((__bridge CFDictionaryRef)query);
    if (err)
        NSLog(@"Couldn't delete public key: err %d", (int)err);
}
#endif


// Signs a data blob using a private key. Padding is PKCS1 with SHA-1 digest.
static NSData* signData(SecKeyRef privateKey, NSData* inputData) {
#if TARGET_OS_IPHONE
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(inputData.bytes, (CC_LONG)inputData.length, digest);

    size_t sigLen = 1024;
    uint8_t sigBuf[sigLen];
    OSStatus err = SecKeyRawSign(privateKey, kSecPaddingPKCS1SHA1,
                                 digest, sizeof(digest),
                                 sigBuf, &sigLen);
    if(err) {
        NSLog(@"SecKeyRawSign failed: %ld", (long)err);
        return nil;
    }
    return [NSData dataWithBytes: sigBuf length: sigLen];

#else
    SecTransformRef transform = SecSignTransformCreate(privateKey, NULL);
    if (!transform)
        return nil;
    NSData* resultData = nil;
    if (SecTransformSetAttribute(transform, kSecDigestTypeAttribute, kSecDigestSHA1, NULL)
        && SecTransformSetAttribute(transform, kSecTransformInputAttributeName,
                                    (__bridge CFDataRef)inputData, NULL)) {
            resultData = CFBridgingRelease(SecTransformExecute(transform, NULL));
        }
    CFRelease(transform);
    return resultData;
#endif
}


// Adds a certificate to the keychain, tagged with a label for future lookup.
static SecCertificateRef addCertToKeychain(NSData* certData, NSString* label,
                                           NSError** outError) {
    SecCertificateRef certRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
    if (!certRef) {
        checkErr(errSecIO, outError);
        return NULL;
    }
    CFAutorelease(certRef);
    NSDictionary* attrs = @{(__bridge id)kSecClass:     (__bridge id)kSecClassCertificate,
                            (__bridge id)kSecValueRef:  (__bridge id)certRef,
#if TARGET_OS_IPHONE
                            (__bridge id)kSecAttrLabel: label
#endif
                            };
    CFTypeRef result;
    OSStatus err = SecItemAdd((__bridge CFDictionaryRef)attrs, &result);
    if (err != noErr) {
        NSLog(@"ERROR: SecItemAdd() returned %i", err);
    }

#if !TARGET_OS_IPHONE
    // kSecAttrLabel is not settable on Mac OS (it's automatically generated from the principal
    // name.) Instead we use the "preference" mapping mechanism, which only exists on Mac OS.
    if (!err)
        err = SecCertificateSetPreferred(certRef, (__bridge CFStringRef)label, NULL);
        if (!err) {
            // Check if this is an identity cert, i.e. we have the corresponding private key.
            // If so, we'll also set the preference for the resulting SecIdentityRef.
            SecIdentityRef identRef;
            if (SecIdentityCreateWithCertificate(NULL,  certRef,  &identRef) == noErr) {
                err = SecIdentitySetPreferred(identRef, (__bridge CFStringRef)label, NULL);
                CFRelease(identRef);
            }
        }
#endif
    checkErr(err, outError);
    return certRef;
}


// Looks up an identity (cert + private key) by the cert's label.
static SecIdentityRef findIdentity(NSString* label, NSTimeInterval expirationInterval) {
    SecIdentityRef identity;
#if TARGET_OS_IPHONE
    NSDictionary* query = @{(__bridge id)kSecClass:     (__bridge id)kSecClassIdentity,
                            (__bridge id)kSecAttrLabel: label,
                            (__bridge id)kSecReturnRef: @YES};
    CFTypeRef ref = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, &ref);
    if (err) {
        AssertEq(err, errSecItemNotFound); // other err indicates query dict is malformed
        return NULL;
    }
    identity = (SecIdentityRef)ref;
#else
    identity = SecIdentityCopyPreferred((__bridge CFStringRef)label, NULL, NULL);
#endif

    if (identity) {
        // Check that the cert hasn't expired yet:
        CFAutorelease(identity);
        SecCertificateRef cert;
        if (SecIdentityCopyCertificate(identity, &cert) == noErr) {
            if (!checkCertValid(cert, expirationInterval)) {
                NSLog(@"SSL identity labeled \"%@\" has expired", label);
                identity = NULL;
                MYDeleteAnonymousIdentity(label);
            }
            CFRelease(cert);
        } else {
            identity = NULL;
        }
    }
    return identity;
}


NSData* MYGetCertificateDigest(SecCertificateRef cert) {
    CFDataRef data = SecCertificateCopyData(cert);
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(CFDataGetBytePtr(data), (CC_LONG)CFDataGetLength(data), digest);
    CFRelease(data);
    return [NSData dataWithBytes: digest length: sizeof(digest)];
}


#if TARGET_OS_IPHONE
static NSDictionary* getItemAttributes(CFTypeRef cert) {
    NSDictionary* query = @{(__bridge id)kSecValueRef: (__bridge id)cert,
                            (__bridge id)kSecReturnAttributes: @YES};
    CFDictionaryRef attrs = NULL;
    OSStatus err = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef*)&attrs);
    if (err) {
        AssertEq(err, errSecItemNotFound);
        return NULL;
    }
    Assert(attrs);
    return CFBridgingRelease(attrs);
}
#endif


#if !TARGET_OS_IPHONE
static double relativeTimeFromOID(NSDictionary* values, CFTypeRef oid) {
    NSNumber* dateNum = values[(__bridge id)oid][@"value"];
    if (!dateNum)
        return 0.0;
    return dateNum.doubleValue - CFAbsoluteTimeGetCurrent();
}
#endif


// Returns YES if the cert has not yet expired.
static BOOL checkCertValid(SecCertificateRef cert, NSTimeInterval expirationInterval __unused) {
#if TARGET_OS_IPHONE
    NSDictionary* attrs = getItemAttributes(cert);
    // The fucked-up iOS Keychain API doesn't expose the cert expiration date, only the date the
    // item was added to the keychain. So derive it based on the current expiration interval:
    NSDate* creationDate = attrs[(__bridge id)kSecAttrCreationDate];
    return creationDate && -[creationDate timeIntervalSinceNow] < expirationInterval;
#else
    CFArrayRef oids = (__bridge CFArrayRef)@[(__bridge id)kSecOIDX509V1ValidityNotAfter,
                                             (__bridge id)kSecOIDX509V1ValidityNotBefore];
    NSDictionary* values = CFBridgingRelease(SecCertificateCopyValues(cert, oids, NULL));
    return relativeTimeFromOID(values, kSecOIDX509V1ValidityNotAfter) >= 0.0
        && relativeTimeFromOID(values, kSecOIDX509V1ValidityNotBefore) <= 0.0;
#endif
}


BOOL MYDeleteAnonymousIdentity(NSString* label) {
    NSDictionary* attrs = @{(__bridge id)kSecClass:     (__bridge id)kSecClassIdentity,
                            (__bridge id)kSecAttrLabel: label};
    OSStatus err = SecItemDelete((__bridge CFDictionaryRef)attrs);
    if (err != noErr && err != errSecItemNotFound)
        NSLog(@"Unexpected error %d deleting identity from keychain", (int)err);
    return (err == noErr);
}


// Original self-signed certificate created by Apple's Certificate Assistant app, saved as DER.
// Hex dump created by:  hexdump -e '"\t" 16/1 "0x%02x, " "\n"' generic.cer
// Also, data was truncated to remove the trailing 256 bytes of signature data,
// which gets replaced anyway.
static uint8_t const kCertTemplate[816] = {
    0x30, 0x82, 0x03, 0x24, 0x30, 0x82, 0x02, 0x0c, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x6c,
    0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x30, 0x4d, 0x31,
    0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x15, 0x48, 0x61, 0x6d, 0x6d, 0x65, 0x72,
    0x73, 0x70, 0x6f, 0x6f, 0x6e, 0x20, 0x52, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x20, 0x43, 0x41, 0x31,
    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x1e, 0x30, 0x1c,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0f, 0x63, 0x6d, 0x73,
    0x6a, 0x40, 0x74, 0x65, 0x6e, 0x73, 0x68, 0x75, 0x2e, 0x6e, 0x65, 0x74, 0x30, 0x1e, 0x17, 0x0d,
    0x31, 0x35, 0x30, 0x37, 0x32, 0x38, 0x31, 0x30, 0x33, 0x32, 0x30, 0x37, 0x5a, 0x17, 0x0d, 0x31,
    0x36, 0x30, 0x37, 0x32, 0x37, 0x31, 0x30, 0x33, 0x32, 0x30, 0x37, 0x5a, 0x30, 0x2a, 0x31, 0x1b,
    0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x48, 0x61, 0x6d, 0x6d, 0x65, 0x72, 0x73,
    0x70, 0x6f, 0x6f, 0x6e, 0x20, 0x52, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x31, 0x0b, 0x30, 0x09, 0x06,
    0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcd, 0xbd, 0x51, 0x99, 0xdd, 0xcb, 0x98,
    0xb4, 0x41, 0xd0, 0x00, 0x01, 0x27, 0xed, 0x49, 0x8d, 0x05, 0xe2, 0xd1, 0xda, 0xde, 0xae, 0xb5,
    0x7f, 0x36, 0xaa, 0x02, 0xf0, 0x21, 0x4b, 0x53, 0x82, 0x8d, 0x59, 0x83, 0xd4, 0xb4, 0x3e, 0x47,
    0xb5, 0xa0, 0x5d, 0x77, 0x7e, 0x94, 0xf3, 0xa1, 0x61, 0x15, 0xc1, 0x0c, 0x3b, 0xf5, 0x16, 0x3f,
    0x95, 0x5a, 0x3f, 0x6b, 0x5f, 0xa5, 0xbb, 0x54, 0x56, 0x6e, 0x52, 0x7a, 0x19, 0x87, 0xe7, 0xee,
    0x17, 0xea, 0x23, 0x83, 0xdc, 0x5f, 0xb7, 0xe4, 0x99, 0x6b, 0x17, 0xe2, 0x15, 0xb7, 0x27, 0x90,
    0x83, 0x2f, 0x9a, 0x57, 0x25, 0x1e, 0x74, 0x6c, 0x72, 0x01, 0x40, 0xb9, 0x17, 0x5d, 0xf7, 0x8a,
    0xa4, 0x31, 0x51, 0x31, 0xe5, 0x12, 0x76, 0x38, 0x38, 0x2e, 0xd6, 0x08, 0xd9, 0xdd, 0x33, 0xe7,
    0xf2, 0x28, 0xf0, 0x4e, 0x25, 0x6f, 0x0c, 0x14, 0xb2, 0xa6, 0xec, 0x90, 0x36, 0xf4, 0xa9, 0x0b,
    0xf0, 0xa7, 0x0b, 0x0c, 0xbd, 0xef, 0xe8, 0x86, 0x08, 0x73, 0xec, 0x56, 0x62, 0x95, 0xef, 0x52,
    0xba, 0x85, 0x5f, 0x38, 0xb3, 0x24, 0xaf, 0xe8, 0x17, 0xfa, 0xf0, 0x7d, 0xb2, 0x7f, 0xa8, 0xea,
    0x9a, 0xbd, 0xf1, 0x8e, 0x40, 0xbf, 0xaf, 0x19, 0xb4, 0x94, 0xeb, 0x1c, 0x24, 0xd6, 0xcf, 0x6a,
    0x99, 0x16, 0x30, 0x28, 0xa8, 0x9a, 0xfe, 0x5d, 0x76, 0xad, 0x84, 0x5f, 0xf5, 0x29, 0xd0, 0xed,
    0xe2, 0xe5, 0x21, 0x9e, 0x0f, 0x14, 0xbe, 0xbd, 0xaf, 0x35, 0x73, 0xeb, 0x33, 0x8f, 0x00, 0x90,
    0x1e, 0x40, 0x1b, 0xbb, 0x8b, 0x6b, 0x12, 0xd7, 0x1d, 0xbc, 0xa9, 0x83, 0x0b, 0xb8, 0x85, 0x09,
    0x89, 0x37, 0xe0, 0xed, 0xf3, 0x08, 0x18, 0xce, 0xa1, 0x9a, 0x77, 0x9a, 0x07, 0xf5, 0x79, 0x56,
    0x49, 0x2d, 0xc4, 0xbe, 0xe5, 0x68, 0x00, 0x2c, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x34,
    0x30, 0x32, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
    0x07, 0x80, 0x30, 0x20, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x16, 0x30, 0x14,
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x03, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x53, 0xd2, 0x88, 0x13, 0xf1, 0x32, 0xbc, 0x18,
    0x12, 0x5b, 0x4d, 0x1b, 0xdb, 0x16, 0x5d, 0x2a, 0x23, 0x6b, 0xf6, 0x16, 0xe5, 0xa7, 0x54, 0x71,
    0xa7, 0xea, 0xc4, 0x9e, 0x08, 0x52, 0x9a, 0x9b, 0x65, 0xbb, 0x1e, 0x65, 0x1c, 0x39, 0x87, 0x13,
    0x35, 0x65, 0x8a, 0xae, 0xc2, 0xfb, 0x15, 0xe4, 0x16, 0xf6, 0x30, 0xfb, 0xa4, 0x27, 0xb5, 0xa7,
    0x68, 0x91, 0xeb, 0x06, 0x8e, 0x11, 0xb4, 0xf3, 0x94, 0x58, 0x7c, 0xce, 0x88, 0x82, 0x42, 0xd1,
    0x05, 0xdd, 0xf1, 0x40, 0xd5, 0x65, 0x6a, 0x9e, 0x2a, 0x86, 0x5e, 0xb2, 0xba, 0x85, 0xbc, 0x8d,
    0x8c, 0x64, 0x9a, 0xb5, 0x65, 0x65, 0xb2, 0xde, 0x98, 0xc2, 0x1f, 0xde, 0x2b, 0xe4, 0x0b, 0xc9,
    0xaf, 0x75, 0xd8, 0xac, 0x28, 0x89, 0xf1, 0x9b, 0xeb, 0x58, 0xa2, 0x40, 0x61, 0x4b, 0x2f, 0x7d,
    0x16, 0xcf, 0x89, 0x3d, 0xe7, 0x47, 0x08, 0xb0, 0x40, 0x71, 0xf4, 0xb9, 0x99, 0x18, 0x71, 0x2d,
    0x13, 0x30, 0xc1, 0x11, 0xf9, 0x35, 0xc3, 0xcb, 0x2c, 0x09, 0xed, 0x7d, 0x7d, 0x6e, 0xa0, 0x5b,
    0x25, 0x6a, 0x8d, 0x8a, 0x23, 0x47, 0x44, 0xfd, 0x51, 0x06, 0x21, 0x40, 0x68, 0x03, 0xd2, 0x2e,
    0xd0, 0x3d, 0x02, 0x71, 0xd0, 0x8c, 0x08, 0x07, 0x80, 0xd9, 0x9b, 0x8c, 0x93, 0xf6, 0x00, 0x46,
    0xbe, 0xc5, 0x1c, 0x0d, 0x2a, 0x54, 0x39, 0x1a, 0x15, 0x3a, 0x16, 0x33, 0x8c, 0x5b, 0xda, 0xb2,
    0xd7, 0x37, 0x22, 0xbe, 0x27, 0x93, 0x1d, 0xe1, 0x8f, 0x88, 0x4a, 0xf9, 0x15, 0x39, 0x8c, 0x56,
    0x8c, 0xfd, 0xae, 0x7e, 0x90, 0xf4, 0x52, 0x76, 0x3e, 0xe3, 0xe0, 0xcd, 0xd6, 0xce, 0xf1, 0x5e,
    0xd4, 0xb4, 0x48, 0x48, 0x73, 0xa4, 0x16, 0x67, 0x2d, 0x7f, 0x44, 0xc2, 0x1a, 0x90, 0x79, 0xbf,
    0xdb, 0x20, 0x02, 0xac, 0x23, 0x40, 0x1c, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


/*
 Copyright (c) 2014-15, Jens Alfke <jens@mooseyard.com>. All rights reserved.

 Redistribution and use in source and binary forms, with or without modification, are permitted
 provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list of conditions
 and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions
 and the following disclaimer in the documentation and/or other materials provided with the
 distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRI-
 BUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
