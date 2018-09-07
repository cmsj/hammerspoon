//
//  HSCalendar.m
//  eventkit
//
//  Created by Chris Jones on 30/08/2018.
//  Copyright © 2018 Hammerspoon. All rights reserved.
//

#import "HSCalendar.h"

@implementation HSCalendar

+ (id)calendarWithEKCalendar:(EKCalendar *)calendar {
    return [[HSCalendar alloc] initWithCalendar:calendar];
}

- (id)initWithCalendar:(EKCalendar *)calendar {
    self = [super init];
    if (self) {
        self.calendar = calendar;
    }
    return self;
}

- (NSString *)getDescription {
    return [NSString stringWithFormat:@"%@::%@", self.calendar.title, self.calendar.calendarIdentifier];
}

@end
