//
//  OTHashHelper.m
//  zanmimi
//
//  Created by openthread on 4/9/13.
//  Copyright (c) 2013 openthread. All rights reserved.
//

#import "OTHashHelper.h"

@implementation OTHashHelper

+ (NSString *)hexStringWithData:(NSData *)hashData
{
    unsigned char *buffer = (unsigned char *)malloc(sizeof(unsigned char) * hashData.length);
	[hashData getBytes:buffer];
    [hashData getBytes:buffer length:hashData.length];
	NSMutableString *hashString = [NSMutableString string];
	for (int i =0 ; i < hashData.length; i++)
    {
        [hashString appendFormat:@"%.2hhx",buffer[i]];//autorelease
	}
	free(buffer);
    
    NSString *resultString = [NSString stringWithString:hashString];
    return resultString;
}

+ (NSString *)SHA1HashStringWithPlainText:(NSString *)plainText
{
    NSData *hashData = [self SHA1HashBytesWithPlainText:plainText];
    if (!hashData)
    {
        return nil;
    }
    
    NSString *resultString = [self hexStringWithData:hashData];
    return resultString;
}

+ (NSData *)SHA1HashBytesWithPlainText:(NSString *)plainText
{
    if (!plainText)
    {
        return nil;
    }
    NSData *plainBytes = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *hashBytes = [self SHA1HashBytesWithPlainBytes:plainBytes];
    return hashBytes;
}

+ (NSString *)SHA1HashStringWithPlainBytes:(NSData *)plainBytes
{
    NSData *hashData = [self SHA1HashBytesWithPlainBytes:plainBytes];
    if (!hashData)
    {
        return nil;
    }
    
    NSString *resultString = [self hexStringWithData:hashData];
    return resultString;
}

+ (NSData *)SHA1HashBytesWithPlainBytes:(NSData *)plainBytes
{
	CC_SHA1_CTX ctx;
	uint8_t * hashBytes = NULL;
	NSData * hash = nil;
	
	// Malloc a buffer to hold hash.
	hashBytes = malloc( CC_SHA1_DIGEST_LENGTH * sizeof(uint8_t) );
	memset((void *)hashBytes, 0x0, CC_SHA1_DIGEST_LENGTH);
	
	// Initialize the context.
	CC_SHA1_Init(&ctx);
	// Perform the hash.
	CC_SHA1_Update(&ctx, (void *)[plainBytes bytes], (CC_LONG)[plainBytes length]);
	// Finalize the output.
	CC_SHA1_Final(hashBytes, &ctx);
	
	// Build up the SHA1 blob.
	hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)CC_SHA1_DIGEST_LENGTH];
	
	if (hashBytes) free(hashBytes);
	
	return hash;
}

+ (NSString *)base64Encoding:(NSData *)data
{
    return [self base64EncodingWithData:data lineLength:0];
}

+ (NSString *)base64EncodingWithData:(NSData *)data lineLength:(unsigned int)lineLength
{
    static char encodingTable[64] =
    {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
        'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
        'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'
    };
    
    const unsigned char     *bytes = [data bytes];
    NSMutableString *result = [NSMutableString stringWithCapacity:[data length]];
    unsigned long ixtext = 0;
    unsigned long lentext = [data length];
    long ctremaining = 0;
    unsigned char inbuf[3], outbuf[4];
    short i = 0;
    short charsonline = 0, ctcopy = 0;
    unsigned long ix = 0;
    
    while( YES ) {
        ctremaining = lentext - ixtext;
        if( ctremaining <= 0 ) break;
        
        for( i = 0; i < 3; i++ ) {
            ix = ixtext + i;
            if( ix < lentext ) inbuf[i] = bytes[ix];
            else inbuf [i] = 0;
        }
        
        outbuf [0] = (inbuf [0] & 0xFC) >> 2;
        outbuf [1] = ((inbuf [0] & 0x03) << 4) | ((inbuf [1] & 0xF0) >> 4);
        outbuf [2] = ((inbuf [1] & 0x0F) << 2) | ((inbuf [2] & 0xC0) >> 6);
        outbuf [3] = inbuf [2] & 0x3F;
        ctcopy = 4;
        
        switch( ctremaining ) {
            case 1:
                ctcopy = 2;
                break;
            case 2:
                ctcopy = 3;
                break;
        }
        
        for( i = 0; i < ctcopy; i++ )
            [result appendFormat:@"%c", encodingTable[outbuf[i]]];
        
        for( i = ctcopy; i < 4; i++ )
            [result appendString:@"="];
        
        ixtext += 3;
        charsonline += 4;
        
        if( lineLength > 0 ) {
            if (charsonline >= lineLength) {
                charsonline = 0;
                [result appendString:@"\n"];
            }
        }
    }
    
    return [NSString stringWithString:result];
}

+ (NSData *)base64DataFromString:(NSString *)string
{
    unsigned long ixtext, lentext;
    unsigned char ch, inbuf[4], outbuf[3];
    short i, ixinbuf;
    Boolean flignore, flendtext = false;
    const unsigned char *tempcstring;
    NSMutableData *theData;
    
    if (string == nil)
    {
        return [NSData data];
    }
    
    ixtext = 0;
    
    tempcstring = (const unsigned char *)[string UTF8String];
    
    lentext = [string length];
    
    theData = [NSMutableData dataWithCapacity: lentext];
    
    ixinbuf = 0;
    
    while (true)
    {
        if (ixtext >= lentext)
        {
            break;
        }
        
        ch = tempcstring [ixtext++];
        
        flignore = false;
        
        if ((ch >= 'A') && (ch <= 'Z'))
        {
            ch = ch - 'A';
        }
        else if ((ch >= 'a') && (ch <= 'z'))
        {
            ch = ch - 'a' + 26;
        }
        else if ((ch >= '0') && (ch <= '9'))
        {
            ch = ch - '0' + 52;
        }
        else if (ch == '+')
        {
            ch = 62;
        }
        else if (ch == '=')
        {
            flendtext = true;
        }
        else if (ch == '/')
        {
            ch = 63;
        }
        else
        {
            flignore = true;
        }
        
        if (!flignore)
        {
            short ctcharsinbuf = 3;
            Boolean flbreak = false;
            
            if (flendtext)
            {
                if (ixinbuf == 0)
                {
                    break;
                }
                
                if ((ixinbuf == 1) || (ixinbuf == 2))
                {
                    ctcharsinbuf = 1;
                }
                else
                {
                    ctcharsinbuf = 2;
                }
                
                ixinbuf = 3;
                
                flbreak = true;
            }
            
            inbuf [ixinbuf++] = ch;
            
            if (ixinbuf == 4)
            {
                ixinbuf = 0;
                
                outbuf[0] = (inbuf[0] << 2) | ((inbuf[1] & 0x30) >> 4);
                outbuf[1] = ((inbuf[1] & 0x0F) << 4) | ((inbuf[2] & 0x3C) >> 2);
                outbuf[2] = ((inbuf[2] & 0x03) << 6) | (inbuf[3] & 0x3F);
                
                for (i = 0; i < ctcharsinbuf; i++)
                {
                    [theData appendBytes: &outbuf[i] length: 1];
                }
            }
            
            if (flbreak)
            {
                break;
            }
        }
    }
    
    return theData;
}

@end
