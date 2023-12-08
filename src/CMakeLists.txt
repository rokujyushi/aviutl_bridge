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

add_library(bridge_intf INTERFACE)
target_compile_definitions(bridge_intf INTERFACE
  _WIN32_WINNT=0x0601
  _WINDOWS
  $<$<CONFIG:Release>:NDEBUG>
)
target_compile_options(bridge_intf INTERFACE
  -mstackrealign
  -Wall
  -Wextra
  -Werror
  -Weverything
  -Wshadow
  -Werror=return-type
  -pedantic-errors
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
target_compile_options(hashmap PRIVATE
  -Wno-padded
  -Wno-cast-align
  -Wno-extra-semi-stmt
  -Wno-implicit-fallthrough
  -Wno-sign-conversion
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
target_compile_options(tinycthread PRIVATE
  -Wno-reserved-macro-identifier
  -Wno-reserved-identifier
  -Wno-padded
  -Wno-missing-variable-declarations
  -Wno-atomic-implicit-seq-cst
)

find_program(LUA51DLL lua51.dll CMAKE_FIND_ROOT_PATH_BOTH)
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
  ${LUA51DLL}
)
target_include_directories(bridge_dll PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}" # for version.h
)
target_compile_options(bridge_dll PRIVATE
  -Wno-cast-qual
)