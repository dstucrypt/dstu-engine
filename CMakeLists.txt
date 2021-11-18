cmake_minimum_required(VERSION 3.13)
project(dstu-engine LANGUAGES C VERSION 1.2.2)

option(BUILD_TESTS "Build tests." OFF)
option(ENABLE_CODECOV "Enable code coverage analysis." OFF)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -W -Wall -Wextra -pedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -W -Wall -Wextra -pedantic")

if ( TIDY )
    find_program( CLANG_TIDY_EXE NAMES "clang-tidy" DOC "Path to clang-tidy executable" )
    if ( NOT CLANG_TIDY_EXE )
        message( STATUS "clang-tidy not found." )
    else ()
        message( STATUS "clang-tidy found: ${CLANG_TIDY_EXE}" )
        set( DO_CLANG_TIDY "${CLANG_TIDY_EXE}"
             "-checks=-*,\
clang-analyzer-*,\
misc-*,\
modernize-*,\
performance-*,\
portability-*,\
readability-*,\
bugprone-*,\
-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,\
-bugprone-easily-swappable-parameters,\
-modernize-avoid-bind,\
-modernize-use-trailing-return-type,\
-readability-braces-around-statements, \
-readability-function-cognitive-complexity,\
-readability-magic-numbers" )
    endif ()
endif ()

if ( IWYU )
    find_program( INCLUDE_WHAT_YOU_USE_EXE NAMES "include-what-you-use" DOC "Path to include-what-you-use executable" )
    if ( NOT INCLUDE_WHAT_YOU_USE_EXE )
        message( STATUS "include-what-you-use not found." )
    else ()
        message( STATUS "include-what-you-use found: ${INCLUDE_WHAT_YOU_USE_EXE}" )
        set( DO_INCLUDE_WHAT_YOU_USE "${INCLUDE_WHAT_YOU_USE_EXE}" )
    endif ()
endif ()

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
