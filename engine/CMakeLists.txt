find_package(OpenSSL 1.1.0 REQUIRED)

# Remove when https://gitlab.kitware.com/cmake/cmake/issues/18525 is addressed
set(OPENSSL_ENGINES_DIR "" CACHE PATH "OpenSSL Engines Directory")
if("${OPENSSL_ENGINES_DIR}" STREQUAL "")
    include(FindPkgConfig)
    pkg_get_variable(OPENSSL_ENGINES_DIR libcrypto enginesdir)
    if("${OPENSSL_ENGINES_DIR}" STREQUAL "")
        message(FATAL_ERROR "Unable to discover the OpenSSL engines directory. Provide the path using -DOPENSSL_ENGINES_DIR")
    endif("${OPENSSL_ENGINES_DIR}" STREQUAL "")
endif("${OPENSSL_ENGINES_DIR}" STREQUAL "")

add_library(dstu MODULE dstu.c md.c cipher.c rbg.c pmeth.c ameth.c sign.c err.c)
set_target_properties(dstu PROPERTIES PREFIX "")
target_link_libraries(dstu PUBLIC dstulib coverage_config OpenSSL::Crypto)

if(COPY_2ND_ARG_IS_CONST)
    target_compile_definitions(dstu PRIVATE COPY_2ND_ARG_IS_CONST)
endif(COPY_2ND_ARG_IS_CONST)

if(DECODE_2ND_ARG_IS_CONST)
    target_compile_definitions(dstu PRIVATE DECODE_2ND_ARG_IS_CONST)
endif(DECODE_2ND_ARG_IS_CONST)

if(CLANG_TIDY_EXE)
    set_target_properties(dstu PROPERTIES C_CLANG_TIDY "${DO_CLANG_TIDY}")
endif(CLANG_TIDY_EXE)
if(INCLUDE_WHAT_YOU_USE_EXE)
    set_target_properties(dstu PROPERTIES C_INCLUDE_WHAT_YOU_USE "${DO_INCLUDE_WHAT_YOU_USE}")
endif(INCLUDE_WHAT_YOU_USE_EXE)

install(TARGETS dstu
        LIBRARY DESTINATION ${OPENSSL_ENGINES_DIR})
