#import <Cocoa/Cocoa.h>
#import <LuaSkin/LuaSkin.h>
#import "../Hammerspoon.h"

#pragma mark - Module metadata

#define USERDATA_TAG "hs.spotlight"

static int refTable = LUA_NOREF;

typedef struct _spotlight_userdata_t {
    int selfRef;
    void *search;
} spotlight_userdata_t;

#pragma mark - Lua API - Constructors

/// hs.spotlight.new() -> hs.spotlight object
/// Constructor
/// Creates a new spotlight search
///
/// Parameters:
///  * None
///
/// Returns:
///  * An `hs.spotlight` object
static int spotlightNew(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TSTRING, LS_TBREAK];

    // Create the userdata object
    spotlight_userdata_t *userData = lua_newuserdata(L, sizeof(spotlight_userdata_t));
    memset(userData, 0, sizeof(spotlight_userdata_t));
    luaL_getmetatable(L, USERDATA_TAG);
    lua_setmetatable(L, -2);

    // Create the NSMetadataQuery object with our arguments
    NSMetadataQuery *search = [[NSMetadataQuery alloc] init];
    userData->search = (__bridge_retained void*)search;

    return 1;
}

#pragma mark - Lua API - Methods

/// hs.spotlight:query([queryString]) -> hs.spotlight object or string
/// Method
/// Sets/Gets the search string
///
/// Parameters:
///  * queryString - A string containing a search query, formatted in the [File Metadata Query Expression Syntax](https://developer.apple.com/library/mac/documentation/Carbon/Conceptual/SpotlightQuery/Concepts/QueryFormat.html#//apple_ref/doc/uid/TP40001849-CJBEJBHH). Or, nil to remove the existing query. If this parameter is omitted, the current search query is returned
///
/// Returns:
///  * The `hs.spotlight` object, or the current search query string
///
/// Notes:
///  * If the object is already searching and you set a new query, the current search will be abandoned and a new one will begin
static int spotlightQuery(lua_State *L) {
    LuaSkin *skin = [LuaSkin shared];
    [skin checkArgs:LS_TUSERDATA, USERDATA_TAG, LS_TSTRING | LS_TOPTIONAL, LS_TBREAK];

    spotlight_userdata_t *userData = lua_touserdata(L, 1);
    NSMetadataQuery *search = (__bridge NSMetadataQuery *)userData->search;

    NSString *predicateString = nil;

    switch (lua_type(L, 2)) {
        case LUA_TSTRING:
            predicateString = [skin toNSObjectAtIndex:2];
            search.predicate = [NSPredicate predicateWithFormat:@"%@", predicateString];
            lua_pushvalue(L, 1);
            break;

        case LUA_TNIL:
            [skin pushNSObject:search.predicate.predicateFormat];
            break;

        case LUA_TNONE:
            search.predicate = nil;
            lua_pushvalue(L, 1);

        default:
            [skin logError:@"Unknown type passed to hs.spotlight:query(). This should not be possible"];
            lua_pushnil(L);
            break;
    }

    return 1;
}

#pragma mark - Hammerspoon Infrastructure

static int userdata_tostring(lua_State* L) {
    LuaSkin *skin = [LuaSkin shared];
    spotlight_userdata_t *userData = lua_touserdata(L, 1);
    [skin pushNSObject:[NSString stringWithFormat:@"%s: (%p)", USERDATA_TAG, userData]];
    return 1;
}

static int userdata_gc(lua_State* L) {
    spotlight_userdata_t *userData = lua_touserdata(L, 1);
    NSMetadataQuery *search = (__bridge_transfer NSMetadataQuery *)userData->search;
    userData->search = nil;
    search = nil;

    return 0;
}

static const luaL_Reg spotlightLib[] = {
    {"new", spotlightNew},

    {NULL, NULL}
};

// Metatable for userdata objects
static const luaL_Reg userdataLib[] = {
    {"query", spotlightQuery},

    {"__tostring", userdata_tostring},
    {"__gc", userdata_gc},
    {NULL, NULL}
};

int luaopen_hs_spotlight_internal(__unused lua_State* L) {
    LuaSkin *skin = [LuaSkin shared];

    NSDictionary *searchScopes = @{@"userHome": NSMetadataQueryUserHomeScope,
                                   @"localComputer": NSMetadataQueryLocalComputerScope,
                                   @"network": NSMetadataQueryNetworkScope,
                                   @"indexedLocalComputer": NSMetadataQueryIndexedLocalComputerScope,
                                   @"indexedNetwork": NSMetadataQueryIndexedNetworkScope};

    refTable = [skin registerLibraryWithObject:USERDATA_TAG
                                     functions:spotlightLib
                                 metaFunctions:nil
                               objectFunctions:userdataLib];

    [skin registerLibraryConstantsTable:"searchScope" constants:searchScopes];

    return 1;
}
