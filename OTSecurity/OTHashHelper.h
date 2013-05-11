//
//  OTHashHelper.h
//  zanmimi
//
//  Created by openthread on 4/9/13.
//  Copyright (c) 2013 openthread. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>

@interface OTHashHelper : NSObject

#pragma mark - SHA1

//Get SHA1 string with text
+ (NSString *)SHA1HashStringWithPlainText:(NSString *)plainText;
//Get SHA1 data with text
+ (NSData *)SHA1HashBytesWithPlainText:(NSString *)plainText;

//Get SHA1 string with data
+ (NSString *)SHA1HashStringWithPlainBytes:(NSData *)plainBytes;
//Get SHA1 data with data
+ (NSData *)SHA1HashBytesWithPlainBytes:(NSData *)plainBytes;

#pragma mark - Base64

//Get base64 encoded string with `data`.
+ (NSString *)base64Encoding:(NSData *)data;

//Get base64 encoded string with `data`, will insert '\n' at each `lineLength`
+ (NSString *)base64EncodingWithData:(NSData *)data lineLength:(unsigned int)lineLength;

@end
