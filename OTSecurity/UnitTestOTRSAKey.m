//
//  UnitTestOTRSAKey.m
//  zanmimi
//
//  Created by openthread on 4/2/13.
//  Copyright (c) 2013 openthread. All rights reserved.
//

#import "UnitTestOTRSAKey.h"
#import "OTHashHelper.h"

@implementation UnitTestOTRSAKey

+ (BOOL)testRSA
{
    //0.delete keys
    BOOL deleteSuccessed = [OTRSAKey deleteStoredRSAKeyInKeychainWithTag:@"a"] && [OTRSAKey deleteStoredRSAKeyInKeychainWithTag:@"b"];
    NSLog(@"test 0 : %d (delete RSA keys)", deleteSuccessed);
    
    //1.generate, encrypt and decrypt
    
    OTRSAPublicKey *publicKey;
    OTRSAPrivateKey *privateKey;
    
    [OTRSAKey generatePublicKey:&publicKey
                     privateKey:&privateKey
                   publicKeyTag:@"a"
                  privateKeyTag:@"b"
                        keySize:otrsa_RSAKeySize512];
    
    NSMutableString *plainTextLong = [NSMutableString string];
    for (int i = 0; i<100; i++)
    {
        [plainTextLong appendString:@"0a1f擦擦0[_^"];
    }
    
    NSData *encryptedData = [publicKey encryptUTF8String:plainTextLong];
    NSString *decryptedString = [privateKey plainUTF8StringFromCipherData:encryptedData];
    
    BOOL test1Result = [decryptedString isEqualToString:plainTextLong];
    NSLog(@"test 1 : %d (generate, encode and decode)", test1Result);

    //2.get key from keychain
    
    OTRSAPrivateKey *privateKeyClone = [OTRSAKey storedPrivateRSAKeyInKeychainWithTag:@"b"];
    NSString *decryptedString2 = [privateKeyClone plainUTF8StringFromCipherData:encryptedData];
    
    BOOL test2Result = [decryptedString2 isEqualToString:plainTextLong];
    NSLog(@"test 2 : %d (get key from keychain)", test2Result);
    
    //3.public key export
    
    NSData *publicKeyData = [publicKey dataRepresentation];
    OTRSAPublicKey *publicKeyExported = [[OTRSAPublicKey alloc] initWithData:publicKeyData tag:@""];
    
    NSData *encryptedData3 = [publicKeyExported encryptUTF8String:plainTextLong];
    NSString *decryptedString3 = [privateKey plainUTF8StringFromCipherData:encryptedData3];
    
    BOOL test3Result = [decryptedString3 isEqualToString:plainTextLong];
    NSLog(@"test 3 : %d (public key data representation and init with data)", test3Result);
    
    //4.Permanent Store
    
    NSArray *publicKeyArray = @[publicKey];
    NSData *publicKeyArrayData = [NSKeyedArchiver archivedDataWithRootObject:publicKeyArray];
    
    NSArray *unarchivedPublicKeyArray = [NSKeyedUnarchiver unarchiveObjectWithData:publicKeyArrayData];
    BOOL test5Result = YES;
    if (unarchivedPublicKeyArray.count != 1)
    {
        test5Result = NO;
    }
    else
    {
        OTRSAPublicKey *unarchivedPublicKey = unarchivedPublicKeyArray[0];
        NSData *encryptedData5 = [unarchivedPublicKey encryptUTF8String:plainTextLong];
        NSString *decryptedString5 = [privateKey plainUTF8StringFromCipherData:encryptedData5];
        test5Result = [decryptedString5 isEqualToString:plainTextLong];
    }

    NSLog(@"test 4 : %d (permanent store to file and read key from file)", test5Result);
    
    //5.Store to keychain and stored key in keychain with tag
    BOOL importSuccessed = [publicKeyExported storeToKeychainWithTagString:@"c"];
    OTRSAPublicKey *publicKeyExportedFromKeychain = [OTRSAKey storedPublicRSAKeyInKeychainWithTag:@"c"];
    NSData *encryptedData6 = [publicKeyExportedFromKeychain encryptUTF8String:plainTextLong];
    NSString *decryptedString6 = [privateKey plainUTF8StringFromCipherData:encryptedData6];
    
    BOOL test6Result = importSuccessed && [decryptedString6 isEqualToString:plainTextLong];
    NSLog(@"test 5 : %d (Store to keychain with tag and stored key in keychain with tag)", test6Result);
    
    //7.Stored key data in keychain
    NSData *dataFromTagA = [OTRSAKey storedKeyDataInKeychainWithTag:@"a"];
    NSData *dataFromTagB = [OTRSAKey storedKeyDataInKeychainWithTag:@"b"];
    NSLog(@"a's bits:\n%@",dataFromTagA);
    NSLog(@"b's bits:\n%@",dataFromTagB);
    
    return test1Result && test2Result && test3Result && test5Result;
}

+ (BOOL)testSHA1
{
    NSMutableString *plainText = [NSMutableString string];
    for (int i = 0; i<100; i++)
    {
        [plainText appendString:@"0a1f擦擦0[_^"];
    }
    
    NSString *correctSHA1HashString = @"a57b8c5122c4c51297d517dd33224045536357c6";
    
    NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSString *sha1String = [OTHashHelper SHA1HashStringWithPlainText:plainText];
    NSString *sha1StringFromData = [OTHashHelper SHA1HashStringWithPlainBytes:plainData];

    BOOL successed = ([sha1String isEqualToString:correctSHA1HashString] && [sha1StringFromData isEqualToString:correctSHA1HashString]);
    
    NSLog(@"SHA1 test successed : %d", successed);

    return successed;
}

+ (BOOL)testSign
{
    NSMutableString *plainText = [NSMutableString string];
    for (int i = 0; i<100; i++)
    {
        [plainText appendString:@"0a1f擦擦0[_^"];
    }
    
    OTRSAPublicKey *publicKey;
    OTRSAPrivateKey *privateKey;
    
    [OTRSAKey generatePublicKey:&publicKey
                     privateKey:&privateKey
                   publicKeyTag:@"verifyKey"
                  privateKeyTag:@"signKey"
                        keySize:otrsa_RSAKeySize512];
    
    NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signedData = [privateKey rawSignDataUsingSHA1Digest:plainData];

    BOOL successed = [publicKey verifySignatureForDataUsingSHA1Digest:plainData signature:signedData];
    BOOL verifyStringSuccessed = [publicKey verifySignatureForUTF8StringUsingSHA1Digest:plainText signature:signedData];
    
    NSLog(@"sign and verify successed : %d", successed && verifyStringSuccessed);
    
    return successed;
}

@end
