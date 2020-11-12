find_package(OpenSSL 1.1.0 REQUIRED)

add_library(keylib SHARED keylib.c iit_asn1.c)
target_link_libraries(keylib PUBLIC dstulib coverage_config OpenSSL::Crypto)
