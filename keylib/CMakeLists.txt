find_package(OpenSSL 1.1.0 REQUIRED)

add_library(keylib SHARED key6.c iit_asn1.c jks.c pkcs12.c keystore.c utils.c attrcurvespec_asn1.c)
target_link_libraries(keylib PUBLIC dstulib coverage_config OpenSSL::Crypto)

if ( CLANG_TIDY_EXE )
    set_target_properties ( keylib PROPERTIES C_CLANG_TIDY "${DO_CLANG_TIDY}" )
endif ()
if ( INCLUDE_WHAT_YOU_USE_EXE )
    set_target_properties ( keylib PROPERTIES C_INCLUDE_WHAT_YOU_USE "${DO_INCLUDE_WHAT_YOU_USE}" )
endif ()

install(TARGETS keylib
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION "lib"
        RUNTIME DESTINATION "bin")
install(FILES keylib.h keystore.h key6.h jks.h pkcs12.h
        DESTINATION "include")
