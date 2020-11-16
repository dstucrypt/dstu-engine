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

add_library(dstu MODULE dstu.c md.c cipher.c rbg.c pmeth.c ameth.c sign.c err.c)
set_target_properties(dstu PROPERTIES PREFIX "")
target_link_libraries(dstu PUBLIC dstulib coverage_config OpenSSL::Crypto)

install(TARGETS dstu
        LIBRARY DESTINATION ${OPENSSL_ENGINES_DIR})
