#ifndef Window_application_h
#define Window_application_h

#import <Foundation/Foundation.h>
#import <lua/lua.h>

extern AXError _AXUIElementGetWindow(AXUIElementRef, CGWindowID* out);

BOOL get_window_id(AXUIElementRef win, CGWindowID *id) {
    if (_AXUIElementGetWindow(win, id) != kAXErrorSuccess) {
        return NO;
    }
    return YES;
}

static void new_window(lua_State* L, AXUIElementRef win) {
    AXUIElementRef* winptr = lua_newuserdata(L, sizeof(AXUIElementRef));
    *winptr = win;

    luaL_getmetatable(L, "hs.window");
    lua_setmetatable(L, -2);

    lua_newtable(L);

    pid_t pid;
    if (AXUIElementGetPid(win, &pid) == kAXErrorSuccess) {
        lua_pushinteger(L, pid);
        lua_setfield(L, -2, "pid");
    }

    CGWindowID winid;
    if (get_window_id(win, &winid)) {
        lua_pushinteger(L, winid);
        lua_setfield(L, -2, "id");
    }

    lua_setuservalue(L, -2);
}

#endif
