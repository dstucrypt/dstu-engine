find_package(OpenSSL 1.1.0 REQUIRED)

add_library(keylib SHARED key6.c iit_asn1.c jks.c utils.c attrcurvespec_asn1.c)
target_link_libraries(keylib PUBLIC dstulib coverage_config OpenSSL::Crypto)

install(TARGETS keylib
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION "lib"
        RUNTIME DESTINATION "bin")
install(FILES keylib.h key6.h jks.h
        DESTINATION "include")
