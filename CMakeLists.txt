cmake_minimum_required(VERSION 3.5)
project(cotp)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

find_package(Gcrypt 1.6.0 REQUIRED)
find_package(Baseencode 1.0.4 REQUIRED)

include_directories(${GCRYPT_INCLUDE_DIR}
        ${BASEENCODE_INCLUDE_DIR})

link_directories(${GCRYPT_LIBRARY_DIRS}
        ${BASEENCODE_LIBRARY_DIRS})

enable_testing()
add_subdirectory(tests)

# set up versioning.
set(BUILD_MAJOR "1")
set(BUILD_MINOR "0")
set(BUILD_VERSION "11")
set(BUILD_VERSION ${BUILD_MAJOR}.${BUILD_MINOR}.${BUILD_VERSION})

set(CMAKE_C_STANDARD 11)

set(COTP_HEADERS src/cotp.h)
set(SOURCE_FILES src/otp.c)

set(CMAKE_C_FLAGS "-Wall -Wextra -O3 -Wno-format-truncation -fstack-protector-strong -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3")

add_library(cotp SHARED ${SOURCE_FILES})

target_link_libraries(cotp ${GCRYPT_LIBRARIES} ${BASEENCODE_LIBRARIES})

set_target_properties(cotp PROPERTIES VERSION ${BUILD_VERSION} SOVERSION ${BUILD_MAJOR})

include(GNUInstallDirs)
set(LIB_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}") # "lib" or "lib64"

install(
  TARGETS cotp
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  COMPONENT library
)

install(
  FILES ${COTP_HEADERS}
  DESTINATION include
)
