cmake_minimum_required(VERSION 2.8...3.15)
project(scf LANGUAGES C CXX)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

include_directories(includes)
add_library(${PROJECT_NAME} SHARED)
target_sources(${PROJECT_NAME} PRIVATE source/main.cpp)

if(CMAKE_COMPILER_IS_GNUCC)
    set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-m32 -c -O3 -w" LINK_FLAGS "-m32 -O3 -static-libgcc -static-libstdc++")
endif()