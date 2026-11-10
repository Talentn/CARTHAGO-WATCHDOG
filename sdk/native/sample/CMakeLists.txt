cmake_minimum_required(VERSION 3.20)
project(carthago_sample CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Directory holding carthago_sentinel.dll and its import library carthago_sentinel.dll.lib
# (cargo build -p carthago-sentinel [--features dev-hooks]).
set(CARTHAGO_SENTINEL_LIB_DIR "" CACHE PATH "Directory with carthago_sentinel.dll and carthago_sentinel.dll.lib")
option(CARTHAGO_SENTINEL_DEV_HOOKS "carthago_sentinel.dll was built with --features dev-hooks" ON)
if(NOT CARTHAGO_SENTINEL_LIB_DIR)
  message(FATAL_ERROR "Set -DCARTHAGO_SENTINEL_LIB_DIR=<cargo target dir>/<profile>")
endif()

add_library(carthago_sentinel SHARED IMPORTED)
set_target_properties(carthago_sentinel PROPERTIES
  IMPORTED_LOCATION "${CARTHAGO_SENTINEL_LIB_DIR}/carthago_sentinel.dll"
  IMPORTED_IMPLIB "${CARTHAGO_SENTINEL_LIB_DIR}/carthago_sentinel.dll.lib"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/../include")

add_executable(carthago-sample main.cpp)
target_link_libraries(carthago-sample PRIVATE carthago_sentinel ws2_32)
if(CARTHAGO_SENTINEL_DEV_HOOKS)
  target_compile_definitions(carthago-sample PRIVATE CARTHAGO_DEV_HOOKS)
endif()
if(MSVC)
  target_compile_options(carthago-sample PRIVATE /W4 /permissive-)
endif()
add_custom_command(TARGET carthago-sample POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CARTHAGO_SENTINEL_LIB_DIR}/carthago_sentinel.dll" "$<TARGET_FILE_DIR:carthago-sample>")
