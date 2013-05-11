//
//  OTAppDelegate.m
//  OTSecurityDemo
//
//  Created by openthread on 5/11/13.
//  Copyright (c) 2013 openthread. All rights reserved.
//

#import "OTAppDelegate.h"
#import "UnitTestOTRSAKey.h"
#import "OTRSAKey.h"
#import "OTHashHelper.h"

@implementation OTAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    // Override point for customization after application launch.
    self.window.backgroundColor = [UIColor grayColor];
    [self.window makeKeyAndVisible];
    
    
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(memoryWarning)
                                                 name:UIApplicationDidReceiveMemoryWarningNotification
                                               object:nil];
    
    for (int i = 0; i < 1; i++)
    {
        [UnitTestOTRSAKey testRSA];
        [UnitTestOTRSAKey testSHA1];
        [UnitTestOTRSAKey testSign];
    }

    [self memoryWarning];
    
    return YES;
}

- (void)memoryWarning
{
    NSString *path = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *publicKeyPath = [path stringByAppendingPathComponent:@"opensslpub.pem"];
    NSString *cipherDataPath = [path stringByAppendingPathComponent:@"cipher.data"];
    
    NSString *publicKeyBase64String = [[NSString alloc] initWithContentsOfFile:publicKeyPath
                                                                      encoding:NSUTF8StringEncoding
                                                                         error:nil];
    NSData *publicData = [OTHashHelper base64DataFromString:publicKeyBase64String];
    
    OTRSAPublicKey *rsaKey = [[OTRSAPublicKey alloc] initWithData:publicData tag:nil];
    
    NSData *encryptData = [rsaKey encryptUTF8String:@"123"];
    [encryptData writeToFile:cipherDataPath atomically:YES];
}

- (void)applicationWillResignActive:(UIApplication *)application
{
    // Sent when the application is about to move from active to inactive state. This can occur for certain types of temporary interruptions (such as an incoming phone call or SMS message) or when the user quits the application and it begins the transition to the background state.
    // Use this method to pause ongoing tasks, disable timers, and throttle down OpenGL ES frame rates. Games should use this method to pause the game.
}

- (void)applicationDidEnterBackground:(UIApplication *)application
{
    // Use this method to release shared resources, save user data, invalidate timers, and store enough application state information to restore your application to its current state in case it is terminated later. 
    // If your application supports background execution, this method is called instead of applicationWillTerminate: when the user quits.
}

- (void)applicationWillEnterForeground:(UIApplication *)application
{
    // Called as part of the transition from the background to the inactive state; here you can undo many of the changes made on entering the background.
}

- (void)applicationDidBecomeActive:(UIApplication *)application
{
    // Restart any tasks that were paused (or not yet started) while the application was inactive. If the application was previously in the background, optionally refresh the user interface.
}

- (void)applicationWillTerminate:(UIApplication *)application
{
    // Called when the application is about to terminate. Save data if appropriate. See also applicationDidEnterBackground:.
}

@end
