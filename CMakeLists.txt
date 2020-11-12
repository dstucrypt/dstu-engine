cmake_minimum_required(VERSION 3.13)
project(dstu-engine LANGUAGES C VERSION 1.0.0)

option(BUILD_TESTS "Build tests." OFF)
option(ENABLE_CODECOV "Enable code coverage analysis." OFF)

add_subdirectory(engine)
add_subdirectory(keylib)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif(BUILD_TESTS)

add_custom_target(cppcheck COMMAND cppcheck --enable=all ${CMAKE_SOURCE_DIR}/engine ${CMAKE_SOURCE_DIR}/keylib)
