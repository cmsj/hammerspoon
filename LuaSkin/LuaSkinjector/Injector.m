//
//  Injector.m
//  LuaSkin
//
//  Created by Chris Jones on 08/11/2016.
//  Copyright © 2016 Hammerspoon. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <LuaSkin/LuaSkin.h>
#import <dlfcn.h>

static bool LuaSkinjectorInitialised = NO;

OSErr HandleInjectionEvent(const AppleEvent *ev, AppleEvent *reply, long refcon) {
    OSErr resultCode = noErr;

    @autoreleasepool {
        NSString *appPath = [[NSBundle mainBundle] executablePath];
        if (LuaSkinjectorInitialised) {
            NSLog(@"ERROR: Unable to inject LuaSKin into %@, it is already present", appPath);
            return resultCode;
        }
        NSLog(@"LuaSkinjector 0.4 starting up inside: %@", appPath);

        NSArray *runningApps = [NSRunningApplication runningApplicationsWithBundleIdentifier:@"org.hammerspoon.Hammerspoon"];
        if (runningApps.count != 1) {
            NSLog(@"ERROR: Unable to inject LuaSkin into %@, we will only do this when exactly one instance of Hammerspoon is running. Found: %lu instances", appPath, (unsigned long)runningApps.count);
            return resNotFound;
        }

        NSBundle *hammerspoonBundle = [NSBundle bundleWithURL:[runningApps[0] bundleURL]];
        if (!hammerspoonBundle) {
            NSLog(@"ERROR: Unable to inject LuaSkin into %@, could not find Hammerspoon bundle at %@", appPath, [runningApps[0] bundleURL]);
            return resNotFound;
        }

        NSString *frameworkPath = [NSString stringWithFormat:@"%@/Contents/Frameworks/LuaSkin.framework/LuaSkin", [hammerspoonBundle bundlePath]];

        if (!dlopen_preflight(frameworkPath.UTF8String)) {
            NSLog(@"ERROR: Unable to inject LuaSkin into %@, could not preflight dlopen of %@: %s", appPath, frameworkPath, dlerror());
            return resNotFound;
        }

        void *luaSkinHandle = dlopen(frameworkPath.UTF8String, RTLD_LAZY);
        if (!luaSkinHandle) {
            NSLog(@"ERROR: Unable to inject LuaSkin into %@, could not dlopen %@: %s", appPath, frameworkPath, dlerror());
        }

        Class LuaSkinClass = NSClassFromString(@"LuaSkin");
        NSLog(@"Found LuaSkin class: %@", LuaSkinClass);
        id skin = [[LuaSkinClass alloc] init];
        NSLog(@"Instantiated: %@", skin);
        LuaSkinjectorInitialised = YES;
        NSLog(@"LuaSkin injected");
    }

    return resultCode;
}
