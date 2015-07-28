//
//  MYPrivateKey.h
//  MYCrypto
//
//  Created by Jens Alfke on 4/7/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import "MYKey.h"
#import <CommonCrypto/CommonCryptor.h>
@class MYPublicKey, MYSHA1Digest, MYIdentity, MYSymmetricKey;


/** A private key, used for signing and decrypting data.
    Always paired with a matching public key in a "key-pair".
    MYPublicKeys are instantiated by MYKeychain: either by generating a new key-pair, by
    looking up a key-pair by its attributes, or by importing a key-pair from data. */
@interface MYPrivateKey : MYKey
{
    @private
    MYPublicKey *_publicKey;
}

/** The matching public key. Always non-nil. */
@property (readonly) MYPublicKey *publicKey;

/** The public key's SHA-1 digest. 
    This is a convenient short (20-byte) identifier for the key pair. You can store it in your
    application data, and then later look up either key using MYKeychain methods. */
@property (weak, readonly) MYSHA1Digest *publicKeyDigest;


/** Decrypts data that was encrypted using the public key.
    See the description of -[MYPublicKey encryptData:] for warnings and caveats.
    This method is usually used only to decrypt a symmetric session key, which then decrypts the
    rest of the data. */
- (NSData*) rawDecryptData: (NSData*)data;

/** Generates a signature of data.
    (What's actually signed using RSA is the SHA-256 digest of the data.)
    The resulting signature can be verified using the matching MYPublicKey's
    verifySignature:ofData: method. */
- (NSData*) signData: (NSData*)data;


/** @name Mac-Only
 *  Functionality not available on iPhone. 
 */
//@{
#if !TARGET_OS_IPHONE

/** Exports the private key as a data blob, so that it can be stored as a backup, or transferred
    to another computer. Since the key is sensitive, it must be exported in encrypted form
    using a user-chosen passphrase. This method will display a standard alert panel, run by
    the Security agent, that prompts the user to enter a new passphrase for encrypting the key.
    The same passphrase must be re-entered when importing the key from the data blob.
    (This is a convenient shorthand for the full exportPrivateKeyInFormat... method.
    It uses OpenSSL format, wrapped with PEM, and a default title and prompt for the alert.) */
- (NSData*) exportKey;

/** Exports the private key as a data blob, so that it can be stored as a backup, or transferred
    to another computer. Since the key is sensitive, it must be exported in encrypted form
    using a user-chosen passphrase. This method will display a standard alert panel, run by
    the Security agent, that prompts the user to enter a new passphrase for encrypting the key.
    The same passphrase must be re-entered when importing the key from the data blob.
    @param format  The data format: kSecFormatOpenSSL, kSecFormatSSH, kSecFormatBSAFE or kSecFormatSSHv2.
    @param withPEM  YES if the data should be encoded in PEM format, which converts into short lines
        of printable ASCII characters, suitable for sending in email.
    @param alertTitle  An optional title for the alert panel. (Currently ignored by the OS?)
    @param prompt  An optional prompt message to display in the alert panel. */
- (NSData*) exportKeyInFormat: (SecExternalFormat)format
                      withPEM: (BOOL)withPEM
                   alertTitle: (NSString*)alertTitle
                  alertPrompt: (NSString*)prompt;

/** Decrypts a session key that was wrapped (encrypted) using my matching public key.
    @param wrappedData  The wrapped/encrypted session key
    @param algorithm  The algorithm of the original session key
    @param sizeInBits  The key size (in bits) of the original session key
    @return  The reconstituted session key */
- (MYSymmetricKey*) unwrapSessionKey: (NSData*)wrappedData
                       withAlgorithm: (CCAlgorithm)algorithm
                          sizeInBits: (unsigned)sizeInBits;
#endif
//@}

@end
