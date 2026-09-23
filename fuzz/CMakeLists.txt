if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "COTP_BUILD_FUZZERS requires Clang (currently: ${CMAKE_C_COMPILER_ID})")
endif ()

# Instrument the library under test too: a sanitized/libFuzzer-linked harness cannot
# collect coverage or run ASan/UBSan checks for code that was compiled without those
# flags. `fuzzer-no-link` adds coverage instrumentation without providing main().
set(FUZZ_LIB_FLAGS -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -g -O1)
set(FUZZ_HARNESS_FLAGS -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)

target_compile_options(cotp PRIVATE ${FUZZ_LIB_FLAGS})
if (BUILD_SHARED_LIBS)
    # Static archives have no link step; the harness supplies the sanitizer runtimes.
    target_link_options(cotp PRIVATE -fsanitize=address,undefined)
endif ()

function(add_cotp_fuzzer name)
    add_executable(${name} ${name}.c)
    target_link_libraries(${name} PRIVATE cotp)
    target_compile_options(${name} PRIVATE ${FUZZ_HARNESS_FLAGS})
    target_link_options(${name} PRIVATE ${FUZZ_HARNESS_FLAGS})
endfunction()

add_cotp_fuzzer(fuzz_base32_decode)
add_cotp_fuzzer(fuzz_base32_encode)
add_cotp_fuzzer(fuzz_get_totp_at)
add_cotp_fuzzer(fuzz_otpauth_uri)
add_cotp_fuzzer(fuzz_yaotp_uri)
