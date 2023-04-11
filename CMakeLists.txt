cmake_minimum_required(VERSION 3.17)
project(ueransim)

# 加入REQUIRED 参数,如果找不到JNI,就报错退出
find_package(JNI REQUIRED)
# 加入jni支持
include_directories(${JAVA_INCLUDE_PATH})
include_directories(${JAVA_INCLUDE_PATH2})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

include_directories(src)

#################### SUB DIRECTORIES ####################

add_subdirectory(src/ext)
add_subdirectory(src/utils)
add_subdirectory(src/lib)
add_subdirectory(src)
