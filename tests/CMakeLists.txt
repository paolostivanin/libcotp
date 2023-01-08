
IF(BUILD_TESTING)
    add_executable (test_cotp test_otp.c)
    add_executable (test_base32 test_base32encode.c test_base32decode.c)

    target_link_libraries (test_cotp -lcotp -lcriterion -lgcrypt)
    target_link_libraries (test_base32 -lcotp -lcriterion -lgcrypt)
    target_link_directories (test_cotp PRIVATE ${PROJECT_BINARY_DIR})
    target_link_directories (test_base32 PRIVATE ${PROJECT_BINARY_DIR})
    add_dependencies (test_cotp cotp)
    add_dependencies (test_base32 cotp)

    add_test (NAME TestCOTP COMMAND test_cotp)
    add_test (NAME TestBase32 COMMAND test_base32)
ENDIF(BUILD_TESTING)
