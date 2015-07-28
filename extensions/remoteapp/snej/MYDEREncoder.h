//
//  MYDEREncoder.h
//  MYCrypto
//
//  Created by Jens Alfke on 5/29/09.
//  Copyright 2009 Jens Alfke. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface MYDEREncoder : NSObject
{
    @private
    id _rootObject;
    NSMutableData *_output;
    NSError *_error;
    BOOL _forcePrintableStrings;
}

- (id) initWithRootObject: (id)object;
+ (NSData*) encodeRootObject: (id)rootObject error: (NSError**)outError;

@property (weak, readonly) NSData* output;
@property (readonly, strong) NSError *error;

@end
