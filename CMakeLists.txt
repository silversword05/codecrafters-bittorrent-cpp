cmake_minimum_required(VERSION 3.13)
set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")

project(bittorrent-starter-cpp)

file(GLOB_RECURSE SOURCE_FILES src/*.cc src/*.h)

set(CMAKE_CXX_STANDARD 20) # Enable the C++20 standard
set(CMAKE_CXX_STANDARD_REQUIRED ON)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

add_executable(bittorrent ${SOURCE_FILES})

if(CMAKE_BUILD_TYPE MATCHES "Debug")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()
