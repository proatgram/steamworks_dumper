cmake_minimum_required(VERSION 3.14)

project(steamworks_dumper LANGUAGES CXX)

include(FindPkgConfig)
pkg_check_modules (CAPSTONE REQUIRED capstone)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

add_library(steamworks_dumper
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/steamworks_dumper.cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/steamworks_dumper.h>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/moduleimage.cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/moduleimage.h>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/clientmodule.cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/clientmodule.h>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/dumperbase.cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/dumperbase.h>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/randomstack.cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/randomstack.h>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/enumdumper.cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/enumdumper.h>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/clientinterfacedumper.cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/clientinterfacedumper.h>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/callbackdumper.cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/callbackdumper.h>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/emsgdumper.cpp>
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include/emsgdumper.h>
)

target_link_libraries(steamworks_dumper PUBLIC ${CAPSTONE_LIBRARIES})

target_include_directories(steamworks_dumper PUBLIC $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>)
