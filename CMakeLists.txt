cmake_minimum_required(VERSION 3.5)
project(cotp)

enable_testing()
add_subdirectory(tests)

# set up versioning.
set(BUILD_MAJOR "1")
set(BUILD_MINOR "0")
set(BUILD_VERSION "10")
set(BUILD_VERSION ${BUILD_MAJOR}.${BUILD_MINOR}.${BUILD_VERSION})

set(CMAKE_C_STANDARD 11)

set(COTP_HEADERS src/cotp.h)
set(SOURCE_FILES src/otp.c)
set(PROJECT_LIBS -lgcrypt -lbaseencode)

set(CMAKE_C_FLAGS "-Wall -Werror -fPIC")

add_library(cotp SHARED ${SOURCE_FILES})

target_link_libraries(cotp ${PROJECT_LIBS})

set_target_properties(cotp PROPERTIES VERSION ${BUILD_VERSION} SOVERSION ${BUILD_MAJOR})

install(
  TARGETS cotp
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
  COMPONENT library
)

install(
  FILES ${COTP_HEADERS}
  DESTINATION include
)
