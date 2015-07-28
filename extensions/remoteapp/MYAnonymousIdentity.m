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
static uint8_t const kCertTemplate[499];

// Key size of kCertTemplate:
#define kKeySizeInBits     2048

// These are offsets into kCertTemplate where values need to be substituted:
#define kSerialOffset        15
#define kSerialLength         1
#define kIssueDateOffset     68
#define kExpDateOffset       83
#define kDateLength          13
#define kPublicKeyOffset    155
#define kPublicKeyLength    270u
#define kCSROffset            0
#define kCSRLength          494u
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
static uint8_t const kCertTemplate[499] = {
    0x30, 0x82, 0x03, 0x67, 0x30, 0x82, 0x02, 0x4f, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
    0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x30, 0x64, 0x31,
    0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x48, 0x61, 0x6d, 0x6d, 0x65, 0x72,
    0x73, 0x70, 0x6f, 0x6f, 0x6e, 0x20, 0x52, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x31, 0x18, 0x30, 0x16,
    0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0f, 0x6f, 0x72, 0x67, 0x2e, 0x68, 0x61, 0x6d, 0x6d, 0x65,
    0x72, 0x73, 0x70, 0x6f, 0x6f, 0x6e, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
    0x02, 0x47, 0x42, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x09, 0x01, 0x16, 0x0f, 0x63, 0x6d, 0x73, 0x6a, 0x40, 0x74, 0x65, 0x6e, 0x73, 0x68, 0x75, 0x2e,
    0x6e, 0x65, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35, 0x30, 0x37, 0x32, 0x38, 0x30, 0x39, 0x31,
    0x33, 0x32, 0x39, 0x5a, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x32, 0x37, 0x30, 0x39, 0x31, 0x33,
    0x32, 0x39, 0x5a, 0x30, 0x64, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12,
    0x48, 0x61, 0x6d, 0x6d, 0x65, 0x72, 0x73, 0x70, 0x6f, 0x6f, 0x6e, 0x20, 0x52, 0x65, 0x6d, 0x6f,
    0x74, 0x65, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0f, 0x6f, 0x72, 0x67,
    0x2e, 0x68, 0x61, 0x6d, 0x6d, 0x65, 0x72, 0x73, 0x70, 0x6f, 0x6f, 0x6e, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x47, 0x42, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x0f, 0x63, 0x6d, 0x73, 0x6a, 0x40, 0x74,
    0x65, 0x6e, 0x73, 0x68, 0x75, 0x2e, 0x6e, 0x65, 0x74, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f,
    0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd8, 0xaf, 0x2e, 0x87, 0xe1, 0x18,
    0xf3, 0x91, 0x9b, 0xec, 0x6b, 0xf4, 0xa2, 0x33, 0x60, 0xf4, 0x5c, 0xda, 0x53, 0x11, 0x6d, 0xf8,
    0xc7, 0xf1, 0x94, 0x67, 0x3e, 0xa0, 0xe3, 0xc4, 0xac, 0x47, 0x38, 0x2c, 0xff, 0xf0, 0x03, 0x84,
    0xf6, 0x69, 0x18, 0xc4, 0xec, 0x37, 0x6b, 0x70, 0xe9, 0x20, 0xf5, 0xe2, 0xe2, 0x59, 0x48, 0xdc,
    0x3a, 0x69, 0xea, 0x70, 0xef, 0x5d, 0x62, 0xb3, 0xc0, 0x0b, 0x4f, 0xb6, 0x3a, 0xda, 0xe6, 0xc9,
    0xd0, 0xce, 0xc8, 0x49, 0x12, 0x8a, 0xdf, 0x7b, 0x87, 0x68, 0x4f, 0xa8, 0xaa, 0xde, 0x4d, 0x70,
    0xc6, 0x98, 0x0f, 0xf7, 0x9d, 0xa9, 0xf8, 0x50, 0x5a, 0x0c, 0x43, 0x49, 0xe2, 0x91, 0x82, 0x32,
    0x5a, 0x34, 0xc4, 0xe4, 0x5e, 0xdf, 0x1b, 0x94, 0xdc, 0x29, 0x9e, 0x1b, 0x10, 0x5f, 0x12, 0x1a,
    0x1c, 0x93, 0xfe, 0xd9, 0xe9, 0xe1, 0xcb, 0x67, 0x22, 0xbd, 0x6e, 0xe5, 0xc7, 0x5f, 0x0e, 0xb9,
    0x63, 0xe8, 0xa2, 0x2f, 0xe8, 0xe1, 0xf0, 0x67, 0x41, 0x7b, 0x66, 0xa6, 0x51, 0xdb, 0x3e, 0xc1,
    0x2f, 0x4d, 0xe3, 0x61, 0x7b, 0xf9, 0xdf, 0x01, 0x5e, 0x90, 0x3e, 0x09, 0xaa, 0xea, 0x1f, 0x80,
    0x2b, 0x2d, 0x02, 0x21, 0x9a, 0xcf, 0x6c, 0xed, 0x4d, 0x2c, 0x9b, 0x9d, 0x54, 0x84, 0x8b, 0x8f,
    0x95, 0x7f, 0x61, 0x49, 0x88, 0x20, 0xf8, 0x87, 0x88, 0x01, 0x0d, 0x54, 0xca, 0x1d, 0xd9, 0x67,
    0xc4, 0x37, 0x44,
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
