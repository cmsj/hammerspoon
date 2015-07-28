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
static uint8_t const kCertTemplate[519];

// Key size of kCertTemplate:
#define kKeySizeInBits     2048

// These are offsets into kCertTemplate where values need to be substituted:
#define kSerialOffset        15
#define kSerialLength         1
#define kIssueDateOffset     79
#define kExpDateOffset       94
#define kDateLength          13
#define kPublicKeyOffset    175
#define kPublicKeyLength    270u
#define kCSROffset            0
#define kCSRLength          514u
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
        NSLog(@"ERROR: keyData.length (%lu) != kPublicKeyLength (%i)", keyData.length, kPublicKeyLength);
        return nil;
    }
    memcpy(&buf[kPublicKeyOffset], keyData.bytes, kPublicKeyLength);

    // Sign the cert:
    NSData* csr = [data subdataWithRange: NSMakeRange(kCSROffset, kCSRLength)];
    NSData* sig = signData(privateKey, csr);
    if (sig.length != kSignatureLength) {
        NSLog(@"ERROR: sig.length (%lu) != kSignatureLength (%i)", sig.length, kSignatureLength);
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
    [certData writeToFile:@"/tmp/mangledCert.cer" atomically:YES];
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
static uint8_t const kCertTemplate[519] = {
    0x30,0x82,0x03,0x03,0x30,0x82,0x01,0xEB,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x6A,
    0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B,0x05,0x00,0x30,
    0x2A,0x31,0x1B,0x30,0x19,0x06,0x03,0x55,0x04,0x03,0x0C,0x12,0x48,0x61,0x6D,0x6D,
    0x65,0x72,0x73,0x70,0x6F,0x6F,0x6E,0x20,0x52,0x65,0x6D,0x6F,0x74,0x65,0x31,0x0B,
    0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x30,0x1E,0x17,0x0D,0x31,
    0x35,0x30,0x37,0x32,0x38,0x31,0x32,0x33,0x32,0x30,0x32,0x5A,0x17,0x0D,0x31,0x35,
    0x30,0x38,0x32,0x37,0x31,0x32,0x33,0x32,0x30,0x32,0x5A,0x30,0x2A,0x31,0x1B,0x30,
    0x19,0x06,0x03,0x55,0x04,0x03,0x0C,0x12,0x48,0x61,0x6D,0x6D,0x65,0x72,0x73,0x70,
    0x6F,0x6F,0x6E,0x20,0x52,0x65,0x6D,0x6F,0x74,0x65,0x31,0x0B,0x30,0x09,0x06,0x03,
    0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x30,0x82,0x01,0x22,0x30,0x0D,0x06,0x09,0x2A,
    0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,0x03,0x82,0x01,0x0F,0x00,0x30,
    0x82,0x01,0x0A,0x02,0x82,0x01,0x01,0x00,0xCA,0xAC,0x0E,0xEE,0x0E,0x2F,0xF8,0xD5,
    0xFC,0xF2,0x09,0x9E,0xD0,0xD1,0x09,0x42,0xD1,0x52,0x6C,0xB2,0x75,0x11,0x16,0x8A,
    0xF3,0x7D,0x9A,0x61,0x58,0x78,0x8B,0xD8,0xE5,0x63,0x84,0x7D,0xE5,0x23,0x5B,0x71,
    0xED,0xBB,0x23,0xBB,0x2B,0xF5,0xEC,0x39,0xEA,0xEB,0xC4,0x82,0x52,0x40,0x3B,0x37,
    0x03,0x91,0xD8,0x3D,0x43,0x08,0xA9,0x4A,0x2A,0x48,0x00,0xF5,0x77,0x2A,0xB7,0x46,
    0x57,0x8D,0xEE,0x69,0x3B,0x32,0x6D,0x9D,0x96,0x01,0xF7,0x9E,0x98,0x02,0xE9,0x89,
    0x0A,0x2E,0x05,0x43,0x25,0xEC,0x46,0xA9,0xFC,0xAB,0x5A,0x43,0x1D,0xBD,0xDD,0xCF,
    0x45,0xC1,0x89,0x7D,0x81,0xAF,0x4D,0x75,0xC4,0xAB,0xB1,0x27,0xDE,0x30,0xE9,0xB7,
    0x86,0xDD,0x56,0xF8,0xEA,0x7D,0xEB,0xE4,0xFB,0x32,0x67,0x0E,0xCF,0xEA,0xCE,0x83,
    0x28,0xFD,0xFB,0xBD,0x9D,0x40,0xAD,0x67,0xFD,0xAD,0xB6,0xE5,0x5E,0x8A,0x15,0x80,
    0x6C,0x9D,0x53,0x46,0x90,0x99,0xD4,0xF1,0x6F,0x56,0x31,0x2A,0x14,0x6E,0xDE,0x3A,
    0x33,0x28,0x7A,0xC6,0x54,0xD9,0xF8,0x39,0xCF,0xE1,0xE3,0x05,0xA9,0xBA,0x30,0x05,
    0xFE,0x50,0x4D,0xC6,0xF5,0xE6,0x7E,0xD6,0x23,0x31,0xA7,0x77,0x49,0x15,0x4F,0x4D,
    0xC5,0xE6,0x69,0x6C,0x52,0xDA,0xB0,0xA0,0x48,0xB6,0x05,0x50,0x72,0xB3,0x1E,0x5A,
    0xC2,0x29,0x4B,0x20,0x85,0x36,0x79,0x92,0x04,0xAE,0x77,0xDC,0x7A,0xA4,0xFB,0xF2,
    0xE4,0xBB,0x52,0x4E,0x7B,0x5D,0x74,0xE6,0x90,0xFA,0x1A,0x1B,0xF1,0x98,0x37,0xA5,
    0xD1,0x72,0xEE,0x22,0x39,0xC6,0x00,0x93,0x02,0x03,0x01,0x00,0x01,0xA3,0x34,0x30,
    0x32,0x30,0x0E,0x06,0x03,0x55,0x1D,0x0F,0x01,0x01,0xFF,0x04,0x04,0x03,0x02,0x07,
    0x80,0x30,0x20,0x06,0x03,0x55,0x1D,0x25,0x01,0x01,0xFF,0x04,0x16,0x30,0x14,0x06,
    0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x02,0x06,0x08,0x2B,0x06,0x01,0x05,0x05,
    0x07,0x03,0x01,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B,
    0x05,0x00,0x03,0x82,0x01,0x01,0x00,
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
