cmake_minimum_required(VERSION 2.8...3.15)
set(GCC_COVERAGE_COMPILE_FLAGS "-m32 -c -O2 -w")
project(scf LANGUAGES C CXX)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_CXX_STANDARD 20)

include_directories(includes)
add_library(${PROJECT_NAME} SHARED)
target_sources(${PROJECT_NAME} PRIVATE source/main.cpp) 
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS "-m32 -c -O2 -w" LINK_FLAGS "-m32 -shared -O3")