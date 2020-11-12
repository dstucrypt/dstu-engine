find_package(OpenSSL 1.1.0 REQUIRED)

# Remove when https://gitlab.kitware.com/cmake/cmake/issues/18525 is addressed
set(OPENSSL_ENGINES_DIR "" CACHE PATH "OpenSSL Engines Directory")
if ("${OPENSSL_ENGINES_DIR}" STREQUAL "")
    include(FindPkgConfig)
    pkg_get_variable(OPENSSL_ENGINES_DIR libcrypto enginesdir)
    if ("${OPENSSL_ENGINES_DIR}" STREQUAL "")
        message(FATAL_ERROR "Unable to discover the OpenSSL engines directory. Provide the path using -DOPENSSL_ENGINES_DIR")
    endif()
endif()

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

add_library(dstu MODULE dstu.c md.c cipher.c rbg.c pmeth.c ameth.c sign.c key.c compress.c asn1.c err.c)
set_target_properties(dstu PROPERTIES PREFIX "")
target_link_libraries(dstu PUBLIC dstulib coverage_config OpenSSL::Crypto)

install(TARGETS dstu
        LIBRARY DESTINATION ${OPENSSL_ENGINES_DIR})
