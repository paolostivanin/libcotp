if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "COTP_BUILD_FUZZERS requires Clang (currently: ${CMAKE_C_COMPILER_ID})")
endif ()

set(FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)

add_executable(fuzz_base32_decode fuzz_base32_decode.c)
target_link_libraries(fuzz_base32_decode PRIVATE cotp)
target_compile_options(fuzz_base32_decode PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_base32_decode PRIVATE ${FUZZ_FLAGS})

add_executable(fuzz_get_totp_at fuzz_get_totp_at.c)
target_link_libraries(fuzz_get_totp_at PRIVATE cotp)
target_compile_options(fuzz_get_totp_at PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_get_totp_at PRIVATE ${FUZZ_FLAGS})

add_executable(fuzz_otpauth_uri fuzz_otpauth_uri.c)
target_link_libraries(fuzz_otpauth_uri PRIVATE cotp)
target_compile_options(fuzz_otpauth_uri PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_otpauth_uri PRIVATE ${FUZZ_FLAGS})
