cmake_minimum_required(VERSION 3.16)
project(cotp VERSION "2.0.2" LANGUAGES "C")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(HMACWRAPPER "gcrypt" CACHE STRING "library to use during hmac computation")
include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

if("${HMACWRAPPER}" STREQUAL "gcrypt")
  set(HMAC_SOURCE_FILES src/utils/whmac_gcrypt.c)
  find_package(Gcrypt 1.8.0 REQUIRED)
  set(HMAC_INCLUDE_DIR ${GCRYPT_INCLUDE_DIR})
  set(HMAC_LIBRARY_DIRS ${GCRYPT_LIBRARY_DIRS})
  set(HMAC_LIBRARIES ${GCRYPT_LIBRARIES})
  message("copt use gcrypt for hmac")
elseif("${HMACWRAPPER}" STREQUAL "openssl")
  find_package(OpenSSL 3.0.0 REQUIRED)
  set(HMAC_SOURCE_FILES src/utils/whmac_openssl.c)
  set(HMAC_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
  set(HMAC_LIBRARY_DIRS ${OPENSSL_LIBRARY_DIRS})
  set(HMAC_LIBRARIES ${OPENSSL_LIBRARIES})
  message("libcopt use openssl for hmac")
else()
  message("libcopt can't use ${HMACWRAPPER} for hmac")
endif()

option(BUILD_SHARED_LIBS "Build libcotp as a shared library" ON)

include_directories(${HMAC_INCLUDE_DIR} ${BASEENCODE_INCLUDE_DIRS})

link_directories(${HMAC_LIBRARY_DIRS} ${BASEENCODE_LIBRARY_DIRS})

enable_testing()
add_subdirectory(tests)

set(CMAKE_C_STANDARD 11)

set(COTP_HEADERS
        src/cotp.h
        )
set(SOURCE_FILES
        src/otp.c
        ${HMAC_SOURCE_FILES}
        src/utils/base32.c
        )

# Set compiler flags for all targets
add_compile_options(-Wall -Wextra -O3 -Wformat=2 -Wmissing-format-attribute -fstack-protector-strong -Wundef -Wmissing-format-attribute
        -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code -Wchar-subscripts -Wwrite-strings -Wpointer-arith -Wbad-function-cast
        -Wcast-align -Werror=format-security -Werror=implicit-function-declaration -Wno-sign-compare -Wno-format-nonliteral -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)

add_link_options(-Wl,--no-add-needed -Wl,--as-needed -Wl,-z,relro,-z,now)

add_library(cotp ${SOURCE_FILES})

target_link_libraries(cotp ${HMAC_LIBRARIES})
target_include_directories(cotp
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        PRIVATE
            ${HMAC_INCLUDE_DIR}
            ${BASEENCODE_INCLUDE_DIRS})
target_compile_options(cotp PRIVATE
        -Wall -Wextra -O3 -Wformat=2 -Wmissing-format-attribute -fstack-protector-strong -Wundef -Wmissing-format-attribute
        -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code -Wchar-subscripts -Wwrite-strings -Wpointer-arith -Wbad-function-cast
        -Wcast-align -Werror=format-security -Werror=implicit-function-declaration -Wno-sign-compare -Wno-format-nonliteral -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
target_link_directories(cotp PRIVATE
        ${HMACLIBRARY_DIRS} ${BASEENCODE_LIBRARY_DIRS})

set_target_properties(cotp PROPERTIES VERSION ${CMAKE_PROJECT_VERSION} SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR})

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

