cmake_minimum_required(VERSION 3.13)
project(dstu-engine LANGUAGES C VERSION 1.1.0)

option(BUILD_TESTS "Build tests." OFF)
option(ENABLE_CODECOV "Enable code coverage analysis." OFF)

add_subdirectory(dstulib)
add_subdirectory(engine)
add_subdirectory(keylib)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif(BUILD_TESTS)

add_library(coverage_config INTERFACE)
if(ENABLE_CODECOV AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # Add required flags (GCC & LLVM/Clang)
    target_compile_options(coverage_config INTERFACE
        -O0        # no optimization
        -g         # generate debug info
        --coverage # sets all required flags
    )
    if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
        target_link_options(coverage_config INTERFACE --coverage)
    else()
        target_link_libraries(coverage_config INTERFACE --coverage)
    endif()
else(ENABLE_CODECOV AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    if(ENABLE_CODECOV)
        message(FATAL_ERROR "Unknown compiler id: ${CMAKE_C_COMPILER_ID}")
    endif(ENABLE_CODECOV)
endif(ENABLE_CODECOV AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")

add_custom_target(cppcheck COMMAND cppcheck --enable=all ${CMAKE_SOURCE_DIR}/engine ${CMAKE_SOURCE_DIR}/keylib ${CMAKE_SOURCE_DIR}/dstulib)
