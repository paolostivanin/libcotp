cmake_minimum_required(VERSION 3.5)
project(libcotp)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
    src/base32.c
    src/otp.c)

add_library (cotp SHARED ${SOURCE_FILES})
