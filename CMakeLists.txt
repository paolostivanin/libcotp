cmake_minimum_required(VERSION 3.5)
project(cotp)

# set up versioning.
set(BUILD_MAJOR "1")
set(BUILD_MINOR "0")
set(BUILD_VERSION "3")
set(BUILD_VERSION ${BUILD_MAJOR}.${BUILD_MINOR}.${BUILD_VERSION})

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES src/base32.c src/otp.c)
set(PROJECT_LIBS -lgcrypt)

set(CMAKE_C_FLAGS "-Wall -Werror -fPIC")

add_library (cotp SHARED ${SOURCE_FILES})

target_link_libraries(cotp ${PROJECT_LIBS})

set_target_properties(cotp PROPERTIES VERSION ${BUILD_VERSION} SOVERSION ${BUILD_MAJOR})

#TODO
#install -v -o root -g root -m 755 -T SOLIBS /usr/lib/
#install -v -o root -g root -m 644 -T src/libcotp.h /usr/include/