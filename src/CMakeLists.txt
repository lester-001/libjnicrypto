cmake_minimum_required(VERSION 3.17)

file(GLOB_RECURSE HDR_FILES *.hpp)
file(GLOB_RECURSE SRC_FILES CryptUtil.cpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_library(jnicrypto SHARED ${HDR_FILES} ${SRC_FILES})

target_compile_options(jnicrypto PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter) 

target_link_libraries(jnicrypto common-lib)
target_link_libraries(jnicrypto utils)
