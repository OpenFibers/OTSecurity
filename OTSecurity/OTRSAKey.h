//
//  OTRSAKey.h
//  zanmimi
//
//  Created by openthread on 3/31/13.
//  Copyright (c) 2013 openthread. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

typedef enum
{
    otrsa_RSAKeySize512 = 512,
    otrsa_RSAKeySize1024 = 1024,
    otrsa_RSAKeySize2048 = 2048
}otrsa_RSAKeySize;

@class OTRSAPublicKey;
@class OTRSAPrivateKey;

@interface OTRSAKey : NSObject

/*
 Generate OTRSAKey Instance with a specific key size.
 If `publicKeyTagString` is not nil, will store public key into keychian, replace the key with the same tag string in keychain.
 if `publicKeyTagString` is nil, will not store public key into keychain.
 If `privateKeyTagString` is not nil, will store private key into keychian, replace the key with the same tag string in keychain.
 if `privateKeyTagString` is nil, will not store private key into keychain.
 */
+ (BOOL)generatePublicKey:(OTRSAPublicKey **)publicKey
               privateKey:(OTRSAPrivateKey **)privateKey
             publicKeyTag:(NSString *)publicKeyTagString
            privateKeyTag:(NSString *)privateKeyTagString
                  keySize:(otrsa_RSAKeySize)keySize;

//Generate data for persistence
- (NSData *)dataRepresentation;

//Store self to keychain with `tagString`.
//Replace the same tag string key in keychain.
//If successed, return `YES`.
- (BOOL)storeToKeychainWithTagString:(NSString *)keyTagString;

/*
 Delete stored RSA key with tag string.
 If successed, return `YES`. Otherwise return `NO`.
 */
+ (BOOL)deleteStoredRSAKeyInKeychainWithTag:(NSString *)keyTagString;

/*
 Get stored Public RSA key with tag string.
 */
+ (OTRSAPublicKey *)storedPublicRSAKeyInKeychainWithTag:(NSString *)keyTagString;

/*
 Get stored Private RSA key with tag string.
 */
+ (OTRSAPrivateKey *)storedPrivateRSAKeyInKeychainWithTag:(NSString *)keyTagString;

/*
 Get stored RSA key data with tag string.
 */
+ (NSData *)storedKeyDataInKeychainWithTag:(NSString *)keyTagString;

@end

@interface OTRSAPublicKey : OTRSAKey <NSCoding>

//Init RSA public key with persistenced data genterated by `dataRepresentation`
//If `data` is a private key, will return `nil`.
- (id)initWithData:(NSData *)data tag:(NSString *)tag;

//Encrypt with public key
- (NSData *)encryptUTF8String:(NSString *)plainText;
- (NSData *)encryptData:(NSData *)plainData;

//Verify signature of text
- (BOOL)verifySignatureForUTF8StringUsingSHA1Digest:(NSString *)plainText signature:(NSData *)signature;
//Verify signature of data
- (BOOL)verifySignatureForDataUsingSHA1Digest:(NSData *)plainBytes signature:(NSData *)signature;
//Verify signature for SHA1 hash data
- (BOOL)verifySignatureForSHA1HashData:(NSData *)SHA1HashData signature:(NSData *)signature;

@end

@interface OTRSAPrivateKey : OTRSAKey

//Decrypt with private key
- (NSString *)plainUTF8StringFromCipherData:(NSData *)cipherData;
- (NSData *)plainDataFromCipherData:(NSData *)cipherData;

//Sign text
- (NSData *)rawSignUTF8StringUsingSHA1Digest:(NSString *)plainText;
//Sign data
- (NSData *)rawSignDataUsingSHA1Digest:(NSData *)plainText;
//Sign SHA1 hash data
//First calculate plain data's SHA1 value, then use this method sign calculated SHA1 value.
- (NSData *)rawSignSHA1HashData:(NSData *)SHA1HashData;

@end
