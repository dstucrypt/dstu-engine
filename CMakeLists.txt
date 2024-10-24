cmake_minimum_required(VERSION 3.13)
project(dstu-engine LANGUAGES C VERSION 1.3.4)
include(GNUInstallDirs)

option(BUILD_TESTS "Build tests." OFF)
option(ENABLE_CODECOV "Enable code coverage analysis." OFF)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -W -Wall -Wextra -pedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -W -Wall -Wextra -pedantic")

if(TIDY)
    find_program(CLANG_TIDY_EXE NAMES "clang-tidy" DOC "Path to clang-tidy executable")
    if(NOT CLANG_TIDY_EXE)
        message(STATUS "clang-tidy not found.")
    else(NOT CLANG_TIDY_EXE)
        message(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
        set(DO_CLANG_TIDY "${CLANG_TIDY_EXE}"
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
-misc-no-recursion,\
-modernize-use-trailing-return-type,\
-readability-braces-around-statements, \
-readability-function-cognitive-complexity,\
-readability-magic-numbers")
    endif(NOT CLANG_TIDY_EXE)
endif(TIDY)

if(IWYU)
    find_program(INCLUDE_WHAT_YOU_USE_EXE NAMES "include-what-you-use" DOC "Path to include-what-you-use executable")
    if(NOT INCLUDE_WHAT_YOU_USE_EXE)
        message(STATUS "include-what-you-use not found.")
    else(NOT INCLUDE_WHAT_YOU_USE_EXE)
        message(STATUS "include-what-you-use found: ${INCLUDE_WHAT_YOU_USE_EXE}")
        set( DO_INCLUDE_WHAT_YOU_USE "${INCLUDE_WHAT_YOU_USE_EXE}" )
    endif(NOT INCLUDE_WHAT_YOU_USE_EXE)
endif(IWYU)

find_package(OpenSSL 1.1.0 REQUIRED)

try_compile(HAVE_GF2M_CURVES ${CMAKE_CURRENT_BINARY_DIR} "${CMAKE_SOURCE_DIR}/checks/openssl_supports_ec_curve_gf2m.c" LINK_LIBRARIES OpenSSL::Crypto)
if(NOT HAVE_GF2M_CURVES)
    message(FATAL_ERROR "OpenSSL is built without support of elliptic curves over GF2m")
endif(NOT HAVE_GF2M_CURVES)

try_compile(COPY_2ND_ARG_IS_CONST ${CMAKE_CURRENT_BINARY_DIR} "${CMAKE_SOURCE_DIR}/checks/openssl_pkey_meth_copy_signature.c" COMPILE_DEFINITIONS -Werror=incompatible-pointer-types LINK_LIBRARIES OpenSSL::Crypto)
if(COPY_2ND_ARG_IS_CONST)
    message(STATUS "Second argument of PKEY copy method is constant.")
else(COPY_2ND_ARG_IS_CONST)
    message(STATUS "Second argument of PKEY copy method is NOT constant.")
endif(COPY_2ND_ARG_IS_CONST)

try_compile(DECODE_2ND_ARG_IS_CONST ${CMAKE_CURRENT_BINARY_DIR} "${CMAKE_SOURCE_DIR}/checks/openssl_pkey_asn_decode_signature.c" COMPILE_DEFINITIONS -Werror=incompatible-pointer-types LINK_LIBRARIES OpenSSL::Crypto)
if(DECODE_2ND_ARG_IS_CONST)
        message(STATUS "Second argument of PKEY ASN.1 decode method is constant.")
else(DECODE_2ND_ARG_IS_CONST)
        message(STATUS "Second argument of PKEY ASN.1 decode method is NOT constant.")
endif(DECODE_2ND_ARG_IS_CONST)

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
    else(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
        target_link_libraries(coverage_config INTERFACE --coverage)
    endif(CMAKE_VERSION VERSION_GREATER_EQUAL 3.13)
else(ENABLE_CODECOV AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    if(ENABLE_CODECOV)
        message(FATAL_ERROR "Unknown compiler id: ${CMAKE_C_COMPILER_ID}")
    endif(ENABLE_CODECOV)
endif(ENABLE_CODECOV AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")

add_custom_target(cppcheck COMMAND cppcheck --enable=all ${CMAKE_SOURCE_DIR}/engine ${CMAKE_SOURCE_DIR}/keylib ${CMAKE_SOURCE_DIR}/dstulib)
