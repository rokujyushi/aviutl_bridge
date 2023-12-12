#include <lua5.1/lauxlib.h>
#include <lua5.1/lua.h>
#include <windows.h>

#include "bridge.h"
#include "ods.h"

static bool initialized = false;

static int lua_bridge_call_error(lua_State *L, int err) {
  switch (err) {
  case ECALL_OK:
    return luaL_error(L, "success");
  case ECALL_NOT_INITIALIZED:
    return luaL_error(L, "bridge library is not initialized yet");
  case ECALL_FAILED_TO_CONVERT_EXE_PATH:
    return luaL_error(L, "failed to convert exe path");
  case ECALL_FAILED_TO_START_PROCESS:
    return luaL_error(L, "failed to start new process");
  case ECALL_FAILED_TO_SEND_COMMAND:
    return luaL_error(L, "could not send command to child process");
  case ECALL_FAILED_TO_RECEIVE_COMMAND:
    return luaL_error(L, "could not receive reply from child process");
  }
  return luaL_error(L, "unexpected error code");
}

struct recvdata {
  struct call_mem *mem;
  lua_State *L;
};

static void receive_text(void *userdata, void const *const ptr, size_t const len) {
  struct recvdata *const rd = (struct recvdata *)userdata;
  if (rd->mem && rd->mem->mode & MEM_MODE_WRITE && !(rd->mem->mode & MEM_MODE_DIRECT)) {
    lua_getfield(rd->L, -2, "putpixeldata");
    lua_pushvalue(rd->L, -2);
    lua_call(rd->L, 1, 0);
  }
  lua_pushlstring(rd->L, ptr, len);
}

static int lua_bridge_call(lua_State *L) {
  if (!initialized) {
    lua_getglobal(L, "obj");
    lua_getfield(L, -1, "getinfo");
    lua_pushstring(L, "image_max");
    lua_call(L, 1, 2);
    if (!bridge_init(lua_tointeger(L, -2), lua_tointeger(L, -1))) {
      return luaL_error(L, "failed to initialize bridge.dll");
    }
    lua_pop(L, 2);
    initialized = true;
  }

  const char *exe_path = lua_tostring(L, 1);
  if (!exe_path) {
    return luaL_error(L, "invalid exe path");
  }
  size_t buflen;
  const char *buf = lua_tolstring(L, 2, &buflen);

  if (lua_isstring(L, 3)) {
    size_t mflen;
    const char *mf = lua_tolstring(L, 3, &mflen);
    int32_t mode = 0;
    for (size_t i = 0; i < mflen; ++i) {
      switch (mf[i]) {
      case 'r':
      case 'R':
        mode |= MEM_MODE_READ;
        break;
      case 'w':
      case 'W':
        mode |= MEM_MODE_WRITE;
        break;
      case 'p':
      case 'P':
        mode |= MEM_MODE_DIRECT;
        break;
      }
    }
    if (mode & (MEM_MODE_READ | MEM_MODE_WRITE)) {
      struct call_mem m;
      m.mode = mode;
      if (mode & MEM_MODE_DIRECT) {
        m.buf = lua_touserdata(L, 4);
        m.width = lua_tointeger(L, 5);
        m.height = lua_tointeger(L, 6);
        if (!m.buf || m.width == 0 || m.height == 0) {
          return luaL_error(L, "invalid arguments");
        }
      } else {
        lua_getglobal(L, "obj");
        lua_getfield(L, -1, "w");
        lua_getfield(L, -2, "h");
        if (lua_tointeger(L, -1) == 0 || lua_tointeger(L, -2) == 0) {
          return luaL_error(L, "has no image");
        }
        lua_pop(L, 2);
        lua_getfield(L, -1, "getpixeldata");
        lua_call(L, 0, 3);
        m.buf = lua_touserdata(L, -3);
        m.width = lua_tointeger(L, -2);
        m.height = lua_tointeger(L, -1);
        lua_pop(L, 2);
      }
      const int err = bridge_call(exe_path,
                                  buf,
                                  (int32_t)buflen,
                                  &m,
                                  receive_text,
                                  &(struct recvdata){
                                      .mem = &m,
                                      .L = L,
                                  });
      if (err != ECALL_OK) {
        return lua_bridge_call_error(L, err);
      }
      return 1;
    }
  }

  int const err = bridge_call(exe_path,
                              buf,
                              (int32_t)buflen,
                              NULL,
                              receive_text,
                              &(struct recvdata){
                                  .mem = NULL,
                                  .L = L,
                              });
  if (err != ECALL_OK) {
    return lua_bridge_call_error(L, err);
  }
  return 1;
}

static uint64_t cyrb64(uint32_t const *const src, size_t const len, uint32_t const seed) {
  uint32_t h1 = 0x91eb9dc7 ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (size_t i = 0; i < len; ++i) {
    h1 = (h1 ^ src[i]) * 2654435761;
    h2 = (h2 ^ src[i]) * 1597334677;
  }
  h1 = ((h1 ^ (h1 >> 16)) * 2246822507) ^ ((h2 ^ (h2 >> 13)) * 3266489909);
  h2 = ((h2 ^ (h2 >> 16)) * 2246822507) ^ ((h1 ^ (h1 >> 13)) * 3266489909);
  return (((uint64_t)h2) << 32) | ((uint64_t)h1);
}

static inline void to_hex(char *const dst, uint64_t x) {
  const char *chars = "0123456789abcdef";
  for (int i = 15; i >= 0; --i) {
    dst[i] = chars[x & 0xf];
    x >>= 4;
  }
}

static int lua_bridge_calc_hash(lua_State *L) {
  void const *const p = lua_topointer(L, 1);
  int const w = lua_tointeger(L, 2);
  int const h = lua_tointeger(L, 3);
  if (!p) {
    return luaL_error(L, "has no image");
  }
  if (w <= 0 || h <= 0) {
    return luaL_error(L, "invalid arguments");
  }
  char b[16];
  to_hex(b, cyrb64(p, (size_t)(w * h), 0x3fc0b49e));
  lua_pushlstring(L, b, 16);
  return 1;
}

static int finalize(lua_State *L) {
  (void)L;
  if (initialized) {
    if (!bridge_exit()) {
      OutputDebugString("failed to free bridge.dll");
    }
  }
  return 0;
}

EXTERN_C int __declspec(dllexport) luaopen_bridge(lua_State *L);
EXTERN_C int __declspec(dllexport) luaopen_bridge(lua_State *L) {
  struct userdata *ud = lua_newuserdata(L, sizeof(intptr_t));
  if (!ud) {
    return luaL_error(L, "lua_newuserdata failed");
  }

  static char const name[] = "bridge";
  static char const meta_name[] = "bridge_meta";
  static struct luaL_Reg const funcs[] = {
      {"call", lua_bridge_call},
      {"calc_hash", lua_bridge_calc_hash},
      {NULL, NULL},
  };
  luaL_newmetatable(L, meta_name);
  lua_pushstring(L, "__index");
  lua_newtable(L);
  luaL_register(L, NULL, funcs);
  lua_settable(L, -3);
  lua_pushstring(L, "__gc");
  lua_pushcfunction(L, finalize);
  lua_settable(L, -3);
  lua_setmetatable(L, -2);

  lua_pushvalue(L, -1);
  lua_setglobal(L, name);
  lua_getglobal(L, "package");
  lua_getfield(L, -1, "loaded");
  lua_pushvalue(L, -3);
  lua_setfield(L, -2, name);
  lua_pop(L, 2);
  return 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  (void)hinstDLL;
  (void)fdwReason;
  (void)lpvReserved;
  return TRUE;
}
