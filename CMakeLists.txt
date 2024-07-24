cmake_minimum_required(VERSION 2.8...3.15)
set(GCC_COVERAGE_COMPILE_FLAGS "-m32 -c -O2 -w")
project(scf LANGUAGES C CXX)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

include_directories(includes)
add_library(${PROJECT_NAME} SHARED)
target_sources(${PROJECT_NAME} PRIVATE source/main.cpp) 
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-m32 -c -O2 -w" LINK_FLAGS "-m32 -shared -O3")