cmake_minimum_required(VERSION 3.16)
project(cotp VERSION "3.1.0" LANGUAGES "C")

set(CMAKE_C_STANDARD 11)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(GNUInstallDirs)

find_package(PkgConfig)

option(BUILD_SHARED_LIBS "Build libcotp as a shared library" ON)
option(BUILD_TESTS "Build base32 and cotp tests" OFF)

set(HMAC_WRAPPER "gcrypt" CACHE STRING "library to use during hmac computation")
if("${HMAC_WRAPPER}" STREQUAL "gcrypt")
    set(HMAC_SOURCE_FILES
            src/utils/whmac_gcrypt.c
    )
    find_package(Gcrypt 1.8.0 REQUIRED)
    set(HMAC_INCLUDE_DIR ${GCRYPT_INCLUDE_DIR})
    set(HMAC_LIBRARY_DIRS ${GCRYPT_LIBRARY_DIRS})
    set(HMAC_LIBRARIES ${GCRYPT_LIBRARIES})
    message("libcotp will use gcrypt for hmac")
elseif("${HMAC_WRAPPER}" STREQUAL "openssl")
    find_package(OpenSSL 3.0.0 REQUIRED)
    set(HMAC_SOURCE_FILES
            src/utils/whmac_openssl.c
    )
    set(HMAC_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(HMAC_LIBRARY_DIRS ${OPENSSL_LIBRARY_DIRS})
    set(HMAC_LIBRARIES ${OPENSSL_LIBRARIES})
    message("libcotp will use openssl for hmac")
else()
    message("libcotp can't use ${HMAC_WRAPPER} for hmac")
endif()

include_directories(${HMAC_INCLUDE_DIR})
link_directories(${HMAC_LIBRARY_DIRS})

if (BUILD_TESTS)
    add_subdirectory(tests)
endif ()

set(COTP_HEADERS
        src/cotp.h
)

set(SOURCE_FILES
        src/otp.c
        ${HMAC_SOURCE_FILES}
        src/utils/base32.c
)

# Set compiler flags for all targets
if(NOT MSVC)
    add_compile_options(-Wall -Wextra -O3 -Wformat=2 -Wmissing-format-attribute -fstack-protector-strong -Wundef -Wmissing-format-attribute
            -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code -Wchar-subscripts -Wwrite-strings -Wpointer-arith -Wbad-function-cast
            -Wcast-align -Werror=format-security -Werror=implicit-function-declaration -Wno-sign-compare -Wno-format-nonliteral -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
endif()

add_library(cotp ${SOURCE_FILES})

target_link_libraries(cotp ${HMAC_LIBRARIES})
target_include_directories(cotp
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/src
        PRIVATE
            ${HMAC_INCLUDE_DIR})
if(NOT MSVC)
    target_compile_options(cotp PRIVATE
            -Wall -Wextra -O3 -Wformat=2 -Wmissing-format-attribute -fstack-protector-strong -Wundef -Wmissing-format-attribute
            -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code -Wchar-subscripts -Wwrite-strings -Wpointer-arith -Wbad-function-cast
            -Wcast-align -Werror=format-security -Werror=implicit-function-declaration -Wno-sign-compare -Wno-format-nonliteral -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
endif()
target_link_directories(cotp PRIVATE
        ${HMACLIBRARY_DIRS})

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

if (PkgConfig_FOUND)
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
endif()