cmake_minimum_required(VERSION 3.17)

file(GLOB_RECURSE HDR_FILES *.hpp)
file(GLOB_RECURSE SRC_FILES *.cpp)

add_library(utils ${HDR_FILES} ${SRC_FILES})

target_compile_options(utils PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter -fPIC)
target_compile_options(utils PUBLIC -Wno-format-security -fPIC)

target_link_libraries(utils ext)
