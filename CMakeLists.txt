cmake_minimum_required(VERSION 3.5)
project(cotp)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)
find_package(Gcrypt 1.6.0 REQUIRED)
pkg_check_modules(BASEENCODE REQUIRED baseencode>=1.0.5)

include_directories(${GCRYPT_INCLUDE_DIR} ${BASEENCODE_INCLUDE_DIRS})

link_directories(${GCRYPT_LIBRARY_DIRS} ${BASEENCODE_LIBRARY_DIRS})

enable_testing()
add_subdirectory(tests)

# set up versioning.
set(BUILD_MAJOR "1")
set(BUILD_MINOR "2")
set(BUILD_VERSION "5")
set(BUILD_VERSION ${BUILD_MAJOR}.${BUILD_MINOR}.${BUILD_VERSION})

set(CMAKE_C_STANDARD 11)

set(COTP_HEADERS src/cotp.h)
set(SOURCE_FILES src/otp.c)

set(CMAKE_C_FLAGS "-Wall -Wextra -O3 -Wno-format-truncation -fstack-protector-strong -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3")

add_library(cotp SHARED ${SOURCE_FILES})

target_link_libraries(cotp ${GCRYPT_LIBRARIES} ${BASEENCODE_LIBRARIES})

set_target_properties(cotp PROPERTIES VERSION ${BUILD_VERSION} SOVERSION ${BUILD_MAJOR}${BUILD_MINOR})

set(COTP_LIB_DIR "${CMAKE_INSTALL_LIBDIR}")
set(COTP_INC_DIR "${CMAKE_INSTALL_INCLUDEDIR}")

install(
  TARGETS cotp
  ARCHIVE DESTINATION ${COTP_LIB_DIR}
  LIBRARY DESTINATION ${COTP_LIB_DIR}
  COMPONENT library
)

install(
  FILES ${COTP_HEADERS}
  DESTINATION ${COTP_INC_DIR}
)

# Allow adding prefix if CMAKE_INSTALL_INCLUDEDIR not absolute.
if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
    set(PKGCONFIG_TARGET_INCLUDES "${CMAKE_INSTALL_INCLUDEDIR}")
else()
    set(PKGCONFIG_TARGET_INCLUDES "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
endif()
# Allow adding prefix if CMAKE_INSTALL_LIBDIR not absolute.
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
    set(PKGCONFIG_TARGET_LIBS "${CMAKE_INSTALL_LIBDIR}")
else()
    set(PKGCONFIG_TARGET_LIBS "\${exec_prefix}/${CMAKE_INSTALL_LIBDIR}")
endif()

configure_file("cotp.pc.in" "cotp.pc" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/cotp.pc" DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig/)

