//
//  HSCalendar.h
//  eventkit
//
//  Created by Chris Jones on 30/08/2018.
//  Copyright © 2018 Hammerspoon. All rights reserved.
//

@import Foundation;
@import EventKit;

@interface HSCalendar : NSObject

@property (nonatomic) int selfRefCount;
@property (nonatomic, strong) EKCalendar *calendar;
@property (nonatomic, readonly, getter=getDescription) NSString *description;

+ (id)calendarWithEKCalendar:(EKCalendar *)calendar;
- (id)initWithCalendar:(EKCalendar *)calendar;
- (NSString *)getDescription;

@end
