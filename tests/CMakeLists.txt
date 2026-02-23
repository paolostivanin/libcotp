add_executable (test_cotp test_otp.c)
add_executable (test_base32encode test_base32encode.c)
add_executable (test_base32decode test_base32decode.c)
add_executable (test_base32_roundtrip test_base32_roundtrip.c)

target_link_libraries (test_cotp PRIVATE cotp criterion)
target_link_libraries (test_base32encode PRIVATE cotp criterion)
target_link_libraries (test_base32decode PRIVATE cotp criterion)
target_link_libraries (test_base32_roundtrip PRIVATE cotp criterion)

add_test (NAME TestCOTP COMMAND test_cotp)
add_test (NAME TestBase32Encode COMMAND test_base32encode)
add_test (NAME TestBase32Decode COMMAND test_base32decode)
add_test (NAME TestBase32Roundtrip COMMAND test_base32_roundtrip)
