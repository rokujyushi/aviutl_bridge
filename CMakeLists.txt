cmake_minimum_required(VERSION 3.10)
project(aviutl_bridge)

add_compile_options(-Wno-unsafe-buffer-usage -Wno-padded)

# 以降、ターゲットやソースファイルの指定など
find_program(CLANG_FORMAT_EXE clang-format)
file(GLOB sources "${PROJECT_SOURCE_DIR}/src/*.c" "${PROJECT_SOURCE_DIR}/src/*.h")
add_custom_target(${PROJECT_NAME}-format ALL
  COMMAND ${CLANG_FORMAT_EXE} -style=file -i ${sources}
)

add_subdirectory(src)
