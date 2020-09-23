
IF(BUILD_TESTING)
    add_executable (test_cotp test_otp.c)

    target_link_libraries (test_cotp -lcotp -lcriterion -lbaseencode -lgcrypt)
    target_link_directories (test_cotp PRIVATE ${PROJECT_BINARY_DIR})
    add_dependencies (test_cotp cotp)

    add_test (NAME TestCOTP COMMAND test_cotp)
ENDIF(BUILD_TESTING)
