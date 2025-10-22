cmake_minimum_required(VERSION 3.16)
project(cotp VERSION "3.2.0" LANGUAGES "C")

set(CMAKE_C_STANDARD 11)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_package(PkgConfig)

option(BUILD_SHARED_LIBS "Build libcotp as a shared library" ON)
option(BUILD_TESTS "Build base32 and cotp tests" OFF)
set(HMAC_WRAPPER "gcrypt" CACHE STRING "Choose between gcrypt (default), openssl or mbedtls for HMAC computation")
set_property(CACHE HMAC_WRAPPER PROPERTY STRINGS "gcrypt" "openssl" "mbedtls")

if("${HMAC_WRAPPER}" STREQUAL "gcrypt")
    set(HMAC_SOURCE_FILES
            src/utils/whmac_gcrypt.c
    )
    find_package(Gcrypt 1.8.0 REQUIRED)
    set(HMAC_INCLUDE_DIR ${GCRYPT_INCLUDE_DIR})
    set(HMAC_LIBRARIES ${GCRYPT_LIBRARIES})
    message(STATUS "libcotp: HMAC backend set to gcrypt")
elseif("${HMAC_WRAPPER}" STREQUAL "openssl")
    find_package(OpenSSL 3.0.0 REQUIRED)
    set(HMAC_SOURCE_FILES
            src/utils/whmac_openssl.c
    )
    set(HMAC_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR})
    set(HMAC_LIBRARIES ${OPENSSL_LIBRARIES})
    message(STATUS "libcotp: HMAC backend set to openssl")
elseif("${HMAC_WRAPPER}" STREQUAL "mbedtls")
    find_package(MbedTLS REQUIRED)
    set(HMAC_SOURCE_FILES
            src/utils/whmac_mbedtls.c
    )
    set(HMAC_INCLUDE_DIR ${MBEDTLS_INCLUDE_DIRS})
    set(HMAC_LIBRARIES ${MBEDTLS_LIBRARIES})
    message(STATUS "libcotp: HMAC backend set to mbedtls")
else()
    message("libcotp can't use ${HMAC_WRAPPER} for hmac")
endif()

include_directories(${HMAC_INCLUDE_DIR})

if (BUILD_TESTS)
    add_subdirectory(tests)
endif ()

set(COTP_HEADERS
        src/cotp.h
)

option(COTP_ENABLE_VALIDATION "Enable helper APIs for OTP validation in a time window" OFF)

set(SOURCE_FILES
        src/otp.c
        ${HMAC_SOURCE_FILES}
        src/utils/base32.c
        src/utils/secure_zero.c
        src/ctx.c
)

if (COTP_ENABLE_VALIDATION)
    list(APPEND SOURCE_FILES src/utils/validation.c)
    target_compile_definitions(cotp PUBLIC COTP_ENABLE_VALIDATION)
endif()


add_compile_options(-Wall -Wextra -O3 -Wformat=2 -Wmissing-format-attribute -fstack-protector-strong -Wundef -Wmissing-format-attribute
        -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code -Wchar-subscripts -Wwrite-strings -Wpointer-arith -Wbad-function-cast
        -Wcast-align -Werror=format-security -Werror=implicit-function-declaration -Wno-sign-compare -Wno-format-nonliteral -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)

add_library(cotp ${SOURCE_FILES})

target_link_libraries(cotp ${HMAC_LIBRARIES})
target_include_directories(cotp
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${HMAC_INCLUDE_DIR})

target_compile_options(cotp PRIVATE
        -Wall -Wextra -O3 -Wformat=2 -Wmissing-format-attribute -fstack-protector-strong -Wundef -Wmissing-format-attribute
        -fdiagnostics-color=always -Wstrict-prototypes -Wunreachable-code -Wchar-subscripts -Wwrite-strings -Wpointer-arith -Wbad-function-cast
        -Wcast-align -Werror=format-security -Werror=implicit-function-declaration -Wno-sign-compare -Wno-format-nonliteral -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)

target_link_directories(cotp PRIVATE ${HMACLIBRARY_DIRS})

set_target_properties(cotp PROPERTIES VERSION ${CMAKE_PROJECT_VERSION} SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR})

set(COTP_LIB_DIR "${CMAKE_INSTALL_LIBDIR}")
set(COTP_INC_DIR "${CMAKE_INSTALL_INCLUDEDIR}")

install(
  TARGETS cotp
  EXPORT cotpTargets
  ARCHIVE DESTINATION ${COTP_LIB_DIR}
  LIBRARY DESTINATION ${COTP_LIB_DIR}
  COMPONENT library
)

install(
  FILES ${COTP_HEADERS}
  DESTINATION ${COTP_INC_DIR}
)

# CMake package config for find_package(COTP CONFIG)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/COTPConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/COTPConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/COTPConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/COTP
)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/COTPConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/COTPConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/COTP
)
install(EXPORT cotpTargets NAMESPACE COTP:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/COTP)

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
