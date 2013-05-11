//
//  OTRSAKey.m
//  zanmimi
//
//  Created by openthread on 3/31/13.
//  Copyright (c) 2013 openthread. All rights reserved.
//

#import "OTRSAKey.h"
#import "OTHashHelper.h"

#define NSCoding_KeyRef_Key         @"kotrsa_OTRSAKey"

@implementation OTRSAKey
{
    @public
    SecKeyRef _keyRef;
}

#pragma mark - Private Methods

#pragma mark Private Instance Methods

- (id)initWithSecKeyRef:(SecKeyRef)keyRef
{
    self = [super init];
    if (self)
    {
        _keyRef = keyRef;
    }
    return self;
}

- (void)dealloc
{
    if (_keyRef)
    {
        CFRelease(_keyRef);
    }
}

#pragma mark Private Class Methods

+ (NSData *)tagDataFromNSString:(NSString *)string
{
    NSData *tagData = [[NSData alloc] initWithBytes:(const void *)[string UTF8String] length:[string length]];
    return tagData;
}

+ (SecKeyRef)getKeyRefWithTagString:(NSString *)tagString
{
    OSStatus sanityCheck = noErr;
	CFTypeRef publicKeyReference = NULL;
    
    NSData *keyTagData = [OTRSAKey tagDataFromNSString:tagString];
    
    NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:keyTagData forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the key.
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, &publicKeyReference);
    
    if (sanityCheck != noErr)
    {
        publicKeyReference = NULL;
    }
    
    return (SecKeyRef)publicKeyReference;
}

+ (SecKeyRef)getKeyRefWithPersistentKeyRef:(CFTypeRef)persistentRef
{
	OSStatus sanityCheck = noErr;
	SecKeyRef keyRef = NULL;
	
	NSAssert(persistentRef != NULL, @"persistentRef object cannot be NULL." );
	
	NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
	
	// Set the SecKeyRef query dictionary.
	[queryKey setObject:(__bridge id)persistentRef forKey:(__bridge id)kSecValuePersistentRef];
	[queryKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
	
	// Get the persistent key reference.
	sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryKey, (CFTypeRef *)&keyRef);
    
    if (sanityCheck != noErr)
    {
        return nil;
    }
	
	return keyRef;
}

#pragma mark - Public Methods

#pragma mark Generate

+ (BOOL)generatePublicKey:(OTRSAPublicKey **)publicKey
               privateKey:(OTRSAPrivateKey **)privateKey
             publicKeyTag:(NSString *)publicKeyTagString
            privateKeyTag:(NSString *)privateKeyTagString
                  keySize:(otrsa_RSAKeySize)keySize
{
    OSStatus sanityCheck = noErr;
	SecKeyRef publicKeyRef = NULL;
	SecKeyRef privateKeyRef = NULL;
	
    if (!(keySize == 512 || keySize == 1024 || keySize == 2048))
    {
        NSAssert(0, @"%d is an invalid and unsupported key size.", keySize );
        return NO;
    }
	
	// First delete current keys.
    if (publicKeyTagString && publicKeyTagString.length != 0)
    {
        if (![OTRSAKey deleteStoredRSAKeyInKeychainWithTag:publicKeyTagString])
        {
            NSAssert(0, @"Delete previous RSA public key with the same tag string failed");
            return NO;
        }
    }
    if (privateKeyTagString && privateKeyTagString.length != 0)
    {
        if (![OTRSAKey deleteStoredRSAKeyInKeychainWithTag:privateKeyTagString])
        {
            NSAssert(0, @"Delete previous RSA private key with the same tag string failed");
            return NO;
        }
    }
	
	// Container dictionaries.
	NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
	NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
	NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
	
	// Set top level dictionary for the keypair.
	[keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
	
	// Set the private key dictionary.
    if (privateKeyTagString && privateKeyTagString.length != 0)
    {
        NSData *privateTag = [OTRSAKey tagDataFromNSString:privateKeyTagString];
        [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
        [privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    }
    else
    {
        [privateKeyAttr setObject:[NSNumber numberWithBool:NO] forKey:(__bridge id)kSecAttrIsPermanent];
    }
	
	// Set the public key dictionary.
    if (publicKeyTagString && publicKeyTagString.length != 0)
    {
        NSData *publicTag = [OTRSAKey tagDataFromNSString:publicKeyTagString];
        [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
        [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    }
    else
    {
        [publicKeyAttr setObject:[NSNumber numberWithBool:NO] forKey:(__bridge id)kSecAttrIsPermanent];
    }
	
	// Set attributes to top level dictionary.
	[keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
	[keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
	
	// SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
	sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);
    if (!(sanityCheck == noErr && publicKeyRef != NULL && privateKeyRef != NULL))
    {
        NSAssert(0, @"Something really bad went wrong with generating the key pair." );
        return NO;
    }
	
    OTRSAPublicKey *newPublicKey = [[OTRSAPublicKey alloc] initWithSecKeyRef:publicKeyRef];
    OTRSAPrivateKey *newPrivateKey = [[OTRSAPrivateKey alloc] initWithSecKeyRef:privateKeyRef];
    
    *publicKey = newPublicKey;
    *privateKey = newPrivateKey;
    
    return YES;
}

#pragma mark Export to data

//Generate data for persistence
- (NSData *)dataRepresentation
{
	OSStatus sanityCheck = noErr;
	CFTypeRef publicKeyBits = nil;
    
    static NSString *tempExportRSAKeyTag = @"otrsa_export_temp_tag";
    NSData *publicTag = [OTRSAKey tagDataFromNSString:tempExportRSAKeyTag];
    
    [self storeToKeychainWithTagString:tempExportRSAKeyTag];
	
	NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
	// Set the public key query dictionary.
	[queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
	// Get the key bits.
	sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, &publicKeyBits);
    
	if (sanityCheck != noErr)
	{
		publicKeyBits = nil;
	}
    
    [OTRSAKey deleteStoredRSAKeyInKeychainWithTag:tempExportRSAKeyTag];
	
	return (__bridge NSData *)publicKeyBits;
}

#pragma mark Keychain access

//Store self to keychain with `tagString`.
//Replace the same tag string key in keychain.
//If successed, return `YES`.
- (BOOL)storeToKeychainWithTagString:(NSString *)keyTagString
{
    if (!keyTagString || keyTagString.length == 0)
    {
        return NO;
    }
    if (!_keyRef)
    {
        return NO;
    }
    
    if (![OTRSAKey deleteStoredRSAKeyInKeychainWithTag:keyTagString])
    {
        NSAssert(0, @"Delete previous RSA key with the same tag string failed");
        return NO;
    }
    
	OSStatus sanityCheck = noErr;
	
	NSData * peerTag = [OTRSAKey tagDataFromNSString:keyTagString];
	NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];
	
	[peerPublicKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[peerPublicKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[peerPublicKeyAttr setObject:peerTag forKey:(__bridge id)kSecAttrApplicationTag];
	[peerPublicKeyAttr setObject:(__bridge id)_keyRef forKey:(__bridge id)kSecValueRef];
    //	[peerPublicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
	
	sanityCheck = SecItemAdd((__bridge CFDictionaryRef) peerPublicKeyAttr, nil);
	
	if(!(sanityCheck == noErr || sanityCheck == errSecDuplicateItem))
    {
        NSAssert(0, @"Problem adding the peer public key to the keychain, OSStatus == %ld.", sanityCheck );
        return NO;
    }
    
    return YES;
}

/*
 Delete stored RSA key with tag string.
 If successed, return `YES`. Otherwise return `NO`.
 */
+ (BOOL)deleteStoredRSAKeyInKeychainWithTag:(NSString *)keyTagString
{
    OSStatus sanityCheck = noErr;
	if (!keyTagString)
    {
        return NO;
    }
	NSData * peerTag = [OTRSAKey tagDataFromNSString:keyTagString];
    if (!peerTag)
    {
        return NO;
    }
    
	NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];
	
	[peerPublicKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[peerPublicKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[peerPublicKeyAttr setObject:peerTag forKey:(__bridge id)kSecAttrApplicationTag];
	
	sanityCheck = SecItemDelete((__bridge CFDictionaryRef) peerPublicKeyAttr);
	
    if (!(sanityCheck == noErr || sanityCheck == errSecItemNotFound))
    {
        NSAssert(0, @"Problem deleting the peer public key to the keychain, OSStatus == %ld.", sanityCheck );
        return NO;
    }
    
    return YES;
}

/*
 Get stored Public RSA key with tag string.
 */
+ (OTRSAPublicKey *)storedPublicRSAKeyInKeychainWithTag:(NSString *)keyTagString
{
    SecKeyRef keyReference = [OTRSAKey getKeyRefWithTagString:keyTagString];
	
    if (!keyReference)
    {
        return nil;
    }
    
    OTRSAPublicKey *key = [[OTRSAPublicKey alloc] initWithSecKeyRef:keyReference];
    return key;
}

/*
 Get stored Private RSA key with tag string.
 */
+ (OTRSAPrivateKey *)storedPrivateRSAKeyInKeychainWithTag:(NSString *)keyTagString
{
    SecKeyRef keyReference = [OTRSAKey getKeyRefWithTagString:keyTagString];
	
    if (!keyReference)
    {
        return nil;
    }
    
    OTRSAPrivateKey *key = [[OTRSAPrivateKey alloc] initWithSecKeyRef:keyReference];
    return key;
}

/*
 Get stored RSA key data with tag string.
 */
+ (NSData *)storedKeyDataInKeychainWithTag:(NSString *)keyTagString
{
    OSStatus sanityCheck = noErr;
	CFTypeRef publicKeyBits = nil;
    
    NSData *keyTagData = [OTRSAKey tagDataFromNSString:keyTagString];
	
	NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
    
	// Set the public key query dictionary.
	[queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[queryPublicKey setObject:keyTagData forKey:(__bridge id)kSecAttrApplicationTag];
	[queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
	// Get the key bits.
	sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, &publicKeyBits);
    
	if (sanityCheck != noErr)
	{
		publicKeyBits = nil;
	}
	
	return (__bridge NSData *)publicKeyBits;
}

@end




@implementation OTRSAPublicKey

#pragma mark - NSCoding

- (id)initWithCoder:(NSCoder *)aDecoder
{
    NSData *data = [aDecoder decodeObjectForKey:NSCoding_KeyRef_Key];
    self = [self initWithData:data tag:@""];
    return self;
}

- (void)encodeWithCoder:(NSCoder *)aCoder
{
    NSData *data = [self dataRepresentation];
    [aCoder encodeObject:data forKey:NSCoding_KeyRef_Key];
}


//Init RSA key with persistenced data
//Replace key with the same `keyTag`
- (id)initWithData:(NSData *)publicKey tag:(NSString *)peerName
{
    if (!publicKey)
    {
        return nil;
    }
    
	OSStatus sanityCheck = noErr;
	SecKeyRef peerKeyRef = NULL;
	CFTypeRef persistPeer = NULL;
    
    static NSString *tempImportRSAKeyTag = @"otrsa_import_temp_tag";
    NSString *realTagString = (peerName.length ? peerName : tempImportRSAKeyTag);
    
    [OTRSAKey deleteStoredRSAKeyInKeychainWithTag:realTagString];
    
	
	NSData * peerTag = [OTRSAKey tagDataFromNSString:realTagString];
	NSMutableDictionary * peerPublicKeyAttr = [[NSMutableDictionary alloc] init];
	
	[peerPublicKeyAttr setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[peerPublicKeyAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[peerPublicKeyAttr setObject:peerTag forKey:(__bridge id)kSecAttrApplicationTag];
	[peerPublicKeyAttr setObject:publicKey forKey:(__bridge id)kSecValueData];
	[peerPublicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
	
	sanityCheck = SecItemAdd((__bridge CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&persistPeer);
	
	NSAssert( sanityCheck == noErr || sanityCheck == errSecDuplicateItem,
             @"Problem adding the peer public key to the keychain, OSStatus == %ld.", sanityCheck );
	
	if (persistPeer)
    {
		peerKeyRef = [OTRSAKey getKeyRefWithPersistentKeyRef:persistPeer];
	}
    else
    {
		[peerPublicKeyAttr removeObjectForKey:(__bridge id)kSecValueData];
		[peerPublicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
		// Let's retry a different way.
		sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef) peerPublicKeyAttr, (CFTypeRef *)&peerKeyRef);
	}
	
	NSAssert( sanityCheck == noErr, @"Problem acquiring reference to the public key, OSStatus == %ld.", sanityCheck );
	
    if (!peerName.length)
    {
        [OTRSAKey deleteStoredRSAKeyInKeychainWithTag:tempImportRSAKeyTag];
    }
    
	if (!peerKeyRef)
    {
        return nil;
    }
    self = [self initWithSecKeyRef:peerKeyRef];
    
    return self;
}

#pragma mark - Encrypt

- (NSData *)encryptUTF8String:(NSString *)plainText
{
    if (!plainText)
    {
        return nil;
    }
    NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *cipherData = [self encryptData:plainData];
    return cipherData;
}

- (NSData *)encryptData:(NSData *)plainData
{
    if (!plainData || !_keyRef)
    {
        NSCParameterAssert(plainData.length > 0 || _keyRef != NULL);
        return nil;
    }
    
    NSData *dataToEncrypt = [NSData dataWithData:plainData];
    const uint8_t *bytesToEncrypt = dataToEncrypt.bytes;
    
    size_t cipherBufferSize = SecKeyGetBlockSize(_keyRef);
    if (!(cipherBufferSize > 12))
    {
        NSCAssert(cipherBufferSize > 12, @"block size is too small: %zd", cipherBufferSize);
        return nil;
    }
    
    const size_t inputBlockSize = cipherBufferSize - 12; // since we'll use PKCS1 padding
    uint8_t *cipherBuffer = (uint8_t *) malloc(sizeof(uint8_t) * cipherBufferSize);
    
    NSMutableData *accumulator = [[NSMutableData alloc] init];
    
    @try
    {
        for (size_t block = 0; block * inputBlockSize < dataToEncrypt.length; block++)
        {
            size_t blockOffset = block * inputBlockSize;
            const uint8_t *chunkToEncrypt = (bytesToEncrypt + block * inputBlockSize);
            const size_t remainingSize = dataToEncrypt.length - blockOffset;
            const size_t subsize = remainingSize < inputBlockSize ? remainingSize : inputBlockSize;
            
            size_t actualOutputSize = cipherBufferSize;
            OSStatus status = SecKeyEncrypt(_keyRef, kSecPaddingPKCS1, chunkToEncrypt, subsize, cipherBuffer, &actualOutputSize);
            
            if (status != noErr)
            {
                NSLog(@"Cannot encrypt data, last SecKeyEncrypt status: %ld", status);
                return nil;
            }
            [accumulator appendBytes:cipherBuffer length:actualOutputSize];
        }
        return [accumulator copy];
    }
    @finally
    {
        free(cipherBuffer);
    }
}

- (BOOL)verifySignatureForUTF8StringUsingSHA1Digest:(NSString *)plainText signature:(NSData *)signature
{
    NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    BOOL successed = [self verifySignatureForDataUsingSHA1Digest:plainData signature:signature];
    return successed;
}

- (BOOL)verifySignatureForDataUsingSHA1Digest:(NSData *)plainBytes signature:(NSData *)signature
{
    NSData *hashedData = [OTHashHelper SHA1HashBytesWithPlainBytes:plainBytes];
    if (!hashedData)
    {
        return NO;
    }
	BOOL verifySuccessed = [self verifySignatureForSHA1HashData:hashedData signature:signature];
    return verifySuccessed;
}

//Verify signature for SHA1 hash data
- (BOOL)verifySignatureForSHA1HashData:(NSData *)SHA1HashData signature:(NSData *)signature
{
    if (!SHA1HashData)
    {
        return NO;
    }
    
    size_t signedHashBytesSize = 0;
	OSStatus sanityCheck = noErr;
	
	// Get the size of the assymetric block.
    SecKeyRef publicKey = _keyRef;
	signedHashBytesSize = SecKeyGetBlockSize(publicKey);
	
	sanityCheck = SecKeyRawVerify(publicKey,
                                  kSecPaddingPKCS1SHA1,
                                  (const uint8_t *)[SHA1HashData bytes],
                                  CC_SHA1_DIGEST_LENGTH,
                                  (const uint8_t *)[signature bytes],
                                  signedHashBytesSize
								  );
	
	return (sanityCheck == noErr) ? YES : NO;
}


@end

@implementation OTRSAPrivateKey

#pragma mark - Decrypt

- (NSString *)plainUTF8StringFromCipherData:(NSData *)cipherData
{
    if (!cipherData)
    {
        return nil;
    }
    NSData *plainData = [self plainDataFromCipherData:cipherData];
    if (!plainData)
    {
        return nil;
    }
    return [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
}

- (NSData *)plainDataFromCipherData:(NSData *)cipherData
{
    if (!cipherData || !_keyRef)
    {
        NSCParameterAssert(cipherData.length > 0 || _keyRef != NULL);
        return nil;
    }
    
    size_t cipherBufferSize = SecKeyGetBlockSize(_keyRef);
    if (!(cipherBufferSize > 12))
    {
        NSCAssert(cipherBufferSize > 12, @"block size is too small: %zd", cipherBufferSize);
        return nil;
    }
    
    uint8_t *plainBuffer = (uint8_t *) malloc(sizeof(uint8_t) * 1024);
    
    uint8_t *bytesToDecrypt = (uint8_t *)[cipherData bytes];
    NSMutableData *accumulator = [[NSMutableData alloc] init];
    
    @try
    {
        for (size_t block = 0; block * cipherBufferSize < cipherData.length; block++)
        {
            size_t blockOffset = block * cipherBufferSize;
            const uint8_t *chunkToDecrypt = (bytesToDecrypt + block * cipherBufferSize);
            const size_t remainingSize = cipherData.length - blockOffset;
            const size_t subsize = remainingSize < cipherBufferSize ? remainingSize : cipherBufferSize;
            
            size_t actualOutputSize = cipherBufferSize;
            OSStatus status = SecKeyDecrypt(_keyRef, kSecPaddingPKCS1, chunkToDecrypt, subsize, plainBuffer, &actualOutputSize);
            
            if (status != noErr)
            {
                NSLog(@"Cannot encrypt data, last SecKeyEncrypt status: %ld", status);
                return nil;
            }
            
            [accumulator appendBytes:plainBuffer length:actualOutputSize];
        }
        return [NSData dataWithData:accumulator];
    }
    @finally
    {
        free(plainBuffer);
    }
}

- (NSData *)rawSignUTF8StringUsingSHA1Digest:(NSString *)plainText
{
    if (!plainText)
    {
        return nil;
    }
    NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [self rawSignDataUsingSHA1Digest:plainData];
    return signData;
}

- (NSData *)rawSignDataUsingSHA1Digest:(NSData *)plainText
{
    if (!plainText)
    {
        return nil;
    }
	
    NSData *hashData = [OTHashHelper SHA1HashBytesWithPlainBytes:plainText];
    NSData *signedHash = [self rawSignSHA1HashData:hashData];
    return signedHash;
}

- (NSData *)rawSignSHA1HashData:(NSData *)SHA1HashData
{
    if (!SHA1HashData)
    {
        return nil;
    }
    
    OSStatus sanityCheck = noErr;
	NSData * signedHash = nil;
	
	uint8_t * signedHashBytes = NULL;
	size_t signedHashBytesSize = 0;
	
	SecKeyRef privateKey = NULL;
	
	privateKey = _keyRef;
	signedHashBytesSize = SecKeyGetBlockSize(privateKey);
	
	// Malloc a buffer to hold signature.
	signedHashBytes = malloc( signedHashBytesSize * sizeof(uint8_t) );
	memset((void *)signedHashBytes, 0x0, signedHashBytesSize);
    
	// Sign the SHA1 hash.
	sanityCheck = SecKeyRawSign(privateKey,
                                kSecPaddingPKCS1SHA1,
                                (const uint8_t *)[SHA1HashData bytes],
                                CC_SHA1_DIGEST_LENGTH,
                                (uint8_t *)signedHashBytes,
                                &signedHashBytesSize
								);
	
    if ( sanityCheck != noErr)
    {
        NSAssert( sanityCheck == noErr, @"Problem signing the SHA1 hash, OSStatus == %ld.", sanityCheck );
    }
	
	// Build up signed SHA1 blob.
	signedHash = [NSData dataWithBytes:(const void *)signedHashBytes length:(NSUInteger)signedHashBytesSize];
	
	if (signedHashBytes) free(signedHashBytes);
	
	return signedHash;
}


@end