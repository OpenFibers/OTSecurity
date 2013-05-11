//
//  UnitTestOTRSAKey.h
//  zanmimi
//
//  Created by openthread on 4/2/13.
//  Copyright (c) 2013 openthread. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "OTRSAKey.h"

@interface UnitTestOTRSAKey : NSObject

+ (BOOL)testRSA;

+ (BOOL)testSHA1;

+ (BOOL)testSign;

@end
