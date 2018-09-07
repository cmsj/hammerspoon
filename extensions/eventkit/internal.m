@import Cocoa;
@import EventKit;
@import LuaSkin;

#import "HSCalendar.h"

static EKEventStore *eventStore = nil;
static int refTable = LUA_NOREF;

static const char *STORE_TAG = "hs.eventkit.store";

#define get_objectFromUserdata(objType, L, idx, tag) (objType*)*((void**)luaL_checkudata(L, idx, tag))

#pragma mark - Lua API

#pragma mark - Store management

#pragma mark Functions for obtaining authorization to use event store types
static int requestEventStoreAuthorization(EKEntityType type) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TFUNCTION|LS_TOPTIONAL, LS_TBREAK];

    __block int fn = LUA_NOREF;

    if (lua_type(skin.L, 1) == LUA_TFUNCTION) {
        fn = [skin luaRef:refTable atIndex:1];
    }

    [eventStore requestAccessToEntityType:type completion:^(BOOL granted, NSError * _Nullable error) {
        if (fn != LUA_NOREF && fn != LUA_REFNIL) {
            dispatch_async(dispatch_get_main_queue(), ^{
                LuaSkin *_skin = [LuaSkin shared];

                [skin pushLuaRef:refTable ref:fn];
                lua_pushboolean(_skin.L, granted);
                [skin protectedCallAndError:error.localizedDescription nargs:1 nresults:0];

                fn = [skin luaUnref:refTable ref:fn];
            });
        }
    }];

    return 0;
}

static int requestReminderAuthorization(lua_State *L __unused) {
    return requestEventStoreAuthorization(EKEntityTypeReminder);
}

static int requestCalendarAuthorization(lua_State *L __unused) {
    return requestEventStoreAuthorization(EKEntityTypeEvent);
}

#pragma mark Functions for checking authorization to use event store types
static int checkEventStoreAuthorization(EKEntityType type) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TBREAK];

    EKAuthorizationStatus auth = [EKEventStore authorizationStatusForEntityType:type];

    BOOL granted = NO;
    NSString *reason = @"Unknown";

    switch (auth) {
        case EKAuthorizationStatusDenied:
            reason = @"Denied";
            break;
        case EKAuthorizationStatusRestricted:
            reason = @"Restricted";
            break;
        case EKAuthorizationStatusNotDetermined:
            reason = @"Not Determined";
            break;
        case EKAuthorizationStatusAuthorized:
            granted = YES;
            reason = @"Authorised";
            break;
    }

    lua_pushboolean(skin.L, granted);
    [skin pushNSObject:reason];

    return 2;
}

static int checkReminderAuthorization(lua_State *L __unused) {
    return checkEventStoreAuthorization(EKEntityTypeReminder);
}

static int checkCalendarAuthorization(lua_State *L __unused) {
    return checkEventStoreAuthorization(EKEntityTypeEvent);
}

#pragma mark Functions for obtaining all calendar/reminder stores
static int allEventStoreStores(EKEntityType type) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TBREAK];

    NSMutableArray *stores = [[NSMutableArray alloc] init];

    for (EKCalendar *store in [eventStore calendarsForEntityType:type]) {
        [stores addObject:[HSCalendar calendarWithEKCalendar:store]];
    }

    [skin pushNSObject:stores];
    return 1;
}

static int allCalendarStores(lua_State *L) {
    return allEventStoreStores(EKEntityTypeEvent);
}

static int allReminderStores(lua_State *L) {
    return allEventStoreStores(EKEntityTypeReminder);
}

#pragma mark Functions for obtaining default calendar/reminder stores
static int defaultEventStoreStore(EKEntityType type) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TBREAK];

    EKCalendar *calendar = nil;

    switch (type) {
        case EKEntityTypeEvent:
            calendar = eventStore.defaultCalendarForNewEvents;
            break;
        case EKEntityTypeReminder:
            calendar = eventStore.defaultCalendarForNewReminders;
            break;
        default:
            [skin logError:@"Unknown event store type"];
            // FIXME: This really shouldn't happen, but if it does, we would probably go very wrong here
            break;
    }
    [skin pushNSObject:[HSCalendar calendarWithEKCalendar:calendar]];
    return 1;
}

static int defaultCalendarStore(lua_State *L) {
    return defaultEventStoreStore(EKEntityTypeEvent);
}

static int defaultReminderStore(lua_State *L) {
    return defaultEventStoreStore(EKEntityTypeReminder);
}

#pragma mark - Store methods

static int storeTitle(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TUSERDATA, STORE_TAG, LS_TSTRING|LS_TOPTIONAL, LS_TBREAK];

    HSCalendar *store = get_objectFromUserdata(__bridge HSCalendar, L, 1, STORE_TAG);

    if (lua_type(L, 1) == LUA_TSTRING) {
        store.calendar.title = [skin toNSObjectAtIndex:1];
    }

    [skin pushNSObject:store.calendar.title];
    return 1;
}

static int storeIdentifier(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TUSERDATA, STORE_TAG, LS_TBREAK];

    HSCalendar *store = get_objectFromUserdata(__bridge HSCalendar, L, 1, STORE_TAG);

    [skin pushNSObject:store.calendar.calendarIdentifier];
    return 1;
}

static int storeColor(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TUSERDATA, STORE_TAG, LS_TBREAK];

    HSCalendar *store = get_objectFromUserdata(__bridge HSCalendar, L, 1, STORE_TAG);

    [skin pushNSObject:store.calendar.color];
    return 1;
}

static int storeIsImmutable(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TUSERDATA, STORE_TAG, LS_TBREAK];

    HSCalendar *store = get_objectFromUserdata(__bridge HSCalendar, L, 1, STORE_TAG);

    lua_pushboolean(L, store.calendar.immutable);
    return 1;
}

static int storeType(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TUSERDATA, STORE_TAG, LS_TBREAK];

    HSCalendar *store = get_objectFromUserdata(__bridge HSCalendar, L, 1, STORE_TAG);

    NSString *type = @"Unknown";

    switch (store.calendar.type) {
        case EKCalendarTypeLocal:
            type = @"local";
            break;
        case EKCalendarTypeCalDAV:
            type = @"caldav"; // This also includes iCloud calendars
            break;
        case EKCalendarTypeBirthday:
            type = @"birthday";
            break;
        case EKCalendarTypeExchange:
            type = @"exchange";
            break;
        case EKCalendarTypeSubscription:
            type = @"subscription";
            break;
    }

    [skin pushNSObject:type];
    return 1;
}

static int storeAllowedTypes(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TUSERDATA, STORE_TAG, LS_TBREAK];

    HSCalendar *store = get_objectFromUserdata(__bridge HSCalendar, L, 1, STORE_TAG);

    NSMutableArray *types = [[NSMutableArray alloc] init];

    if (store.calendar.allowedEntityTypes & EKEntityMaskEvent) {
        [types addObject:@"calendar"];
    }

    if (store.calendar.allowedEntityTypes & EKEntityMaskReminder) {
        [types addObject:@"reminder"];
    }

    [skin pushNSObject:types];
    return 1;
}

static int storeAllowedAvailabilities(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TUSERDATA, STORE_TAG, LS_TBREAK];

    HSCalendar *store = get_objectFromUserdata(__bridge HSCalendar, L, 1, STORE_TAG);

    NSMutableArray *availabilities = [[NSMutableArray alloc] init];

    if (store.calendar.supportedEventAvailabilities & EKCalendarEventAvailabilityBusy) {
        [availabilities addObject:@"busy"];
    }

    if (store.calendar.supportedEventAvailabilities & EKCalendarEventAvailabilityFree) {
        [availabilities addObject:@"free"];
    }

    if (store.calendar.supportedEventAvailabilities & EKCalendarEventAvailabilityTentative) {
        [availabilities addObject:@"tentative"];
    }

    if (store.calendar.supportedEventAvailabilities & EKCalendarEventAvailabilityUnavailable) {
        [availabilities addObject:@"unavailable"];
    }

    if (store.calendar.supportedEventAvailabilities & EKCalendarEventAvailabilityNone) {
        [availabilities addObject:@"none"];
    }

    [skin pushNSObject:availabilities];
    return 1;
}

static int storeIsSubscribed(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TUSERDATA, STORE_TAG, LS_TBREAK];

    HSCalendar *store = get_objectFromUserdata(__bridge HSCalendar, L, 1, STORE_TAG);

    lua_pushboolean(L, store.calendar.subscribed);
    return 1;
}

#pragma mark - Lua<->NSObject Conversion Functions
// These must not throw a lua error to ensure LuaSkin can safely be used from Objective-C
// delegates and blocks

static int pushHSCalendar(lua_State *L, id obj) {
    HSCalendar *value = obj;
    value.selfRefCount++;
    void** valuePtr = lua_newuserdata(L, sizeof(HSCalendar *));
    *valuePtr = (__bridge_retained void *)value;
    luaL_getmetatable(L, STORE_TAG);
    lua_setmetatable(L, -2);
    return 1;
}

static id toHSCalendarFromLua(lua_State *L, int idx) {
    LuaSkin *skin = [LuaSkin shared];
    HSCalendar *value;
    if (luaL_testudata(L, idx, STORE_TAG)) {
        value = get_objectFromUserdata(__bridge HSCalendar, L, idx, STORE_TAG);
    } else {
        [skin logError:[NSString stringWithFormat:@"expected %s object, found %s", STORE_TAG,
                        lua_typename(L, lua_type(L, idx))]];
    }
    return value;
}

#pragma mark - Lua/Hammerspoon infrastructure

#pragma mark Library-level Garbage Collection
static int eventkit_gc(lua_State *L __unused) {
    eventStore = nil;
    return 0;
}

#pragma mark HSCalendar metamethods
static int calendar_object_tostring(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    HSCalendar *calendar = [skin luaObjectAtIndex:1 toClass:"HSCalendar"];
    [skin pushNSObject:[NSString stringWithFormat:@"%s: %@ (%p)", STORE_TAG, calendar.description, lua_topointer(L, 1)]];
    return 1;
}

static int calendar_object_eq(lua_State *L) {
    // can't get here if at least one of us isn't a userdata type, and we only care if both types are ours,
    // so use luaL_testudata before the macro causes a lua error
    if (luaL_testudata(L, 1, STORE_TAG) && luaL_testudata(L, 2, STORE_TAG)) {
        LuaSkin *skin = [LuaSkin shared] ;
        HSCalendar *obj1 = [skin luaObjectAtIndex:1 toClass:"HSCalendar"] ;
        HSCalendar *obj2 = [skin luaObjectAtIndex:2 toClass:"HSCalendar"] ;
        lua_pushboolean(L, [obj1 isEqualTo:obj2]) ;
    } else {
        lua_pushboolean(L, NO) ;
    }
    return 1 ;
}

static int calendar_object_gc(lua_State* L) {
    HSCalendar *theDevice = get_objectFromUserdata(__bridge_transfer HSCalendar, L, 1, STORE_TAG) ;
    if (theDevice) {
        theDevice.selfRefCount--;
        if (theDevice.selfRefCount == 0) {
            theDevice = nil;
        }
    }

    // Remove the Metatable so future use of the variable in Lua won't think its valid
    lua_pushnil(L) ;
    lua_setmetatable(L, 1) ;
    return 0 ;
}

#pragma mark Lua function library declarations
static const luaL_Reg calendar_lib[] = {
    {"title", storeTitle},
    {"identifier", storeIdentifier},
    {"type", storeType},

    {"color", storeColor},
    {"isImmutable", storeIsImmutable},
    {"isSubscribed", storeIsSubscribed},

    {"allowedEntries", storeAllowedTypes},
    {"allowedAvailabilities", storeAllowedAvailabilities},

    {"__tostring", calendar_object_tostring},
    {"__eq", calendar_object_eq},
    {"__gc", calendar_object_gc},

    {NULL, NULL}
};

static const luaL_Reg eventkit_lib[] = {
    {"requestReminderAuthorization", requestReminderAuthorization},
    {"requestCalendarAuthorization", requestCalendarAuthorization},

    {"checkReminderAuthorization", checkReminderAuthorization},
    {"checkCalendarAuthorization", checkCalendarAuthorization},

    {"allCalendars", allCalendarStores},
    {"allReminderStores", allReminderStores},

    {"defaultCalendar", defaultCalendarStore},
    {"defaultReminderStore", defaultReminderStore},

    {NULL,      NULL}
};

static const luaL_Reg eventkit_metalib[] = {
    {"__gc", eventkit_gc},

    {NULL, NULL}
};

#pragma mark Lua Initialiser
int luaopen_hs_eventkit_internal(lua_State* L __unused) {
    LuaSkin *skin = [LuaSkin shared];

    eventStore = [[EKEventStore alloc] init];

    refTable = [skin registerLibrary:eventkit_lib metaFunctions:eventkit_metalib];

    [skin registerObject:STORE_TAG objectFunctions:calendar_lib];
    [skin registerPushNSHelper:pushHSCalendar forClass:"HSCalendar"];
    [skin registerLuaObjectHelper:toHSCalendarFromLua forClass:"HSCalendar" withTableMapping:STORE_TAG];

    return 1;
}
