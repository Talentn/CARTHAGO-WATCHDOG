cmake_minimum_required(VERSION 3.20)
project(sentinel_sample CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Directory holding sentinel.dll and its import library sentinel.dll.lib
# (cargo build -p sn-client-ffi [--features dev-hooks]).
set(SENTINEL_LIB_DIR "" CACHE PATH "Directory with sentinel.dll and sentinel.dll.lib")
option(SENTINEL_DEV_HOOKS "sentinel.dll was built with --features dev-hooks" ON)
if(NOT SENTINEL_LIB_DIR)
  message(FATAL_ERROR "Set -DSENTINEL_LIB_DIR=<cargo target dir>/<profile>")
endif()

add_library(sentinel SHARED IMPORTED)
set_target_properties(sentinel PROPERTIES
  IMPORTED_LOCATION "${SENTINEL_LIB_DIR}/sentinel.dll"
  IMPORTED_IMPLIB "${SENTINEL_LIB_DIR}/sentinel.dll.lib"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/../include")

add_executable(sentinel-sample main.cpp)
target_link_libraries(sentinel-sample PRIVATE sentinel ws2_32)
if(SENTINEL_DEV_HOOKS)
  target_compile_definitions(sentinel-sample PRIVATE SN_DEV_HOOKS)
endif()
if(MSVC)
  target_compile_options(sentinel-sample PRIVATE /W4 /permissive-)
endif()
add_custom_command(TARGET sentinel-sample POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "${SENTINEL_LIB_DIR}/sentinel.dll" "$<TARGET_FILE_DIR:sentinel-sample>")
