#import <LuaSkin/LuaSkin.h>
#import "../hammerspoon.h"
#import <CocoaHTTPServer/HTTPServer.h>
#import <CocoaHTTPServer/HTTPConnection.h>
#import <CocoaHTTPServer/HTTPDataResponse.h>

// Defines

#define USERDATA_TAG "hs.httpserver"
#define get_item_arg(L, idx) ((httpserver_t *)luaL_checkudata(L, idx, USERDATA_TAG))
#define getUserData(L, idx) (__bridge HSHTTPServer *)get_item_arg(L, idx)

// ObjC Class definitions
@interface HSHTTPServer : HTTPServer
@property int fn;
@end

@interface HSHTTPDataResponse : HTTPDataResponse
@end

@interface HSHTTPConnection : HTTPConnection
@end

// ObjC Class implementations

@implementation HSHTTPServer
@end

@implementation HSHTTPDataResponse

-(NSDictionary *)httpHeaders {
    return @{@"Content-Type": @"application/json;charset=utf-8"};
}

@end

@implementation HSHTTPConnection

- (BOOL)supportsMethod:(NSString *)method atPath:(NSString * __unused)path {
    if ([method isEqualToString:@"GET"]) {
        return YES;
    }
    return NO;
}

- (NSObject<HTTPResponse> *)httpResponseForMethod:(NSString *)method URI:(NSString *)path {
    NSLog(@"%@ %@", method, path);
    if ([method isEqualToString:@"GET"]) {
        // FIXME: Get this data from the Lua callback
        NSData *responseData = [@"{\"working\":\"true\"}" dataUsingEncoding:NSUTF8StringEncoding];
        HSHTTPDataResponse *response = [[HSHTTPDataResponse alloc] initWithData:responseData];
        return response;
    }

    return [super httpResponseForMethod:method URI:path];
}

@end

typedef struct _httpserver_t {
    void *server;
} httpserver_t;

/// hs.httpserver.new() -> object
/// Function
/// Creates a new HTTP server
///
/// Parameters:
///  * None
///
/// Returns:
///  * An `hs.httpserver` object
static int httpserver_new(lua_State *L) {
    httpserver_t *httpServer = lua_newuserdata(L, sizeof(httpserver_t));
    memset(httpServer, 0, sizeof(httpserver_t));

    HSHTTPServer *server = [[HSHTTPServer alloc] init];
    [server setConnectionClass:[HSHTTPConnection class]];
    [server setType:@"_http._tcp."];

    server.fn = LUA_NOREF;
    httpServer->server = (__bridge_retained void *)server;

    luaL_getmetatable(L, USERDATA_TAG);
    lua_setmetatable(L, -2);
    return 1;
}

/// hs.httpserver:start() -> object
/// Method
/// Starts an HTTP server object
///
/// Parameters:
///  * None
///
/// Returns:
///  * The `hs.httpserver` object
static int httpserver_start(lua_State *L) {
    httpserver_t *httpServer = get_item_arg(L, 1);
    HSHTTPServer *server = (__bridge HSHTTPServer *)httpServer->server;

    // FIXME: Check for server.fn != LUA_NOREF. No point running without a callback. Or is there? We could just log the requests?
    NSError *error = nil;
    if (![server start:&error]) {
          showError(L, "ERROR: Unable to start hs.httpserver object");
    }

    lua_pushvalue(L, 1);
    return 1;
}

/// hs.httpserver:stop() -> object
/// Method
/// Stops an HTTP server object
///
/// Parameters:
///  * None
///
/// Returns:
///  * The `hs.httpserver` object
static int httpserver_stop(lua_State *L) {
    httpserver_t *httpServer = get_item_arg(L, 1);
    HSHTTPServer *server = (__bridge HSHTTPServer *)httpServer->server;
    [server stop];

    lua_pushvalue(L, 1);
    return 1;
}

/// hs.httpserver:getPort() -> number
/// Method
/// Gets the TCP port the server is configured to listen on
///
/// Parameters:
///  * None
///
/// Returns:
///  * A number containing the TCP port
static int httpserver_getPort(lua_State *L) {
    HSHTTPServer *server = getUserData(L, 1);
    lua_pushinteger(L, [server port]);
    return 1;
}

/// hs.httpserver:setPort(port) -> object
/// Method
/// sets the TCP port the server is configured to listen on
///
/// Parameters:
///  * port - An integer containing a TCP port to listen on
///
/// Returns:
///  * The `hs.httpserver` object
static int httpserver_setPort(lua_State *L) {
    HSHTTPServer *server = getUserData(L, 1);
    [server setPort:luaL_checkinteger(L, 2)];
    lua_pushvalue(L, 1);
    return 1;
}

static int httpserver_objectGC(lua_State *L) {
    lua_pushcfunction(L, httpserver_stop);
    lua_pushvalue(L, 1);
    lua_call(L, 1, 1);

    httpserver_t *httpServer = get_item_arg(L, 1);
    HSHTTPServer *server = (__bridge_transfer HSHTTPServer *)httpServer->server;
    server = nil;

    return 0;
}

static const luaL_Reg httpserverLib[] = {
    {"new", httpserver_new},

    {}
};

// hs.httpserver:name,setName
static const luaL_Reg httpserverObjectLib[] = {
    {"start", httpserver_start},
    {"stop", httpserver_stop},
    {"getPort", httpserver_getPort},
    {"setPort", httpserver_setPort},

    {"__gc", httpserver_objectGC},
    {}
};

int luaopen_hs_httpserver_internal(lua_State *L __unused) {
    // Table for luaopen
    LuaSkin *skin = [LuaSkin shared];
    [skin registerLibraryWithObject:"hs.httpserver" functions:httpserverLib metaFunctions:nil objectFunctions:httpserverObjectLib];

    return 1;
}
