find_package(Git REQUIRED)
execute_process(
  COMMAND ${GIT_EXECUTABLE} tag --points-at HEAD
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_TAG
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if ("${GIT_TAG}" STREQUAL "")
  set(GIT_TAG "vX.X.X")
endif()
execute_process(
  COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  OUTPUT_VARIABLE GIT_REVISION
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if ("${GIT_REVISION}" STREQUAL "")
  set(GIT_REVISION "unknown")
endif()
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.h.in" "${CMAKE_CURRENT_BINARY_DIR}/version.h" @ONLY NEWLINE_STYLE LF)
configure_file("${PROJECT_SOURCE_DIR}/README.md" "${PROJECT_BINARY_DIR}/bin/bridge.txt" @ONLY NEWLINE_STYLE CRLF)

include(FetchContent)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(LUA_URL "https://github.com/oov/luajit/releases/download/v2.1.20250708-a2/luajit_v2.1.20250708-a2_x86_64.zip")
  FetchContent_Populate(
    lua
    URL ${LUA_URL}
  )
  set(LUA_DLL_NAME "luaJIT.dll")
  set(LUA_DLL "${lua_SOURCE_DIR}/bin/${LUA_DLL_NAME}")
  set(LUA_INCLUDE "${lua_SOURCE_DIR}/include")
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
  set(LUA_URL "https://github.com/oov/lua-5.1.5/releases/download/v5.1.5/lua_v5.1.5_i686.zip")
  FetchContent_Populate(
    lua
    URL ${LUA_URL}
  )
  set(LUA_DLL_NAME "lua51.dll")
  set(LUA_DLL "${lua_SOURCE_DIR}/bin/${LUA_DLL_NAME}")
  set(LUA_INCLUDE "${lua_SOURCE_DIR}/include")
else()
  message(FATAL_ERROR "failed to detect environment")
endif()

add_library(bridge_intf INTERFACE)
target_compile_definitions(bridge_intf INTERFACE
  _WIN32_WINNT=0x0601
  _WINDOWS
  $<$<CONFIG:Release>:NDEBUG>
)
target_compile_options(bridge_intf INTERFACE
  -mstackrealign
  -Wno-declaration-after-statement
  -Wno-unsafe-buffer-usage
  -ffunction-sections
  -fdata-sections
  $<$<CONFIG:Debug>:-O0>
  $<$<CONFIG:Release>:-O2>
  -flto
)
target_link_options(bridge_intf INTERFACE
  -Wl,--gc-sections
  # -Wl,--print-gc-sections
  -Wl,--kill-at
  $<$<CONFIG:Release>:-s>
)

add_library(hashmap STATIC
  3rd/hashmap.c/hashmap.c
)
target_include_directories(hashmap INTERFACE
  3rd/hashmap.c
)
target_link_libraries(hashmap PRIVATE
  bridge_intf
)

add_library(tinycthread STATIC
  3rd/tinycthread/source/tinycthread.c
)
target_include_directories(tinycthread INTERFACE
  3rd/tinycthread/source
)
target_link_libraries(tinycthread PRIVATE
  bridge_intf
)

add_library(bridge_dll SHARED)
set_target_properties(bridge_dll PROPERTIES
  OUTPUT_NAME "bridge.dll"
  PREFIX ""
  SUFFIX ""
  RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin"
)
target_sources(bridge_dll PRIVATE
  luamain.c
  process.c
  bridge.c
  ods.c
)
target_link_libraries(bridge_dll PRIVATE
  bridge_intf
  hashmap
  tinycthread
  ${LUA_DLL}
)
target_include_directories(bridge_dll PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}" # for version.h
  "${LUA_INCLUDE}"
)
target_compile_options(bridge_dll PRIVATE
  -Wall
  -Wextra
  -Werror
  -Weverything
  -Wshadow
  -Werror=return-type
  -pedantic-errors
  -Wno-cast-qual
)
target_link_options(bridge_dll PRIVATE
  -Wl,-delayload,${LUA_DLL_NAME}
)
