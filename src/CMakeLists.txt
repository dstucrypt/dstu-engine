find_package(OpenSSL 1.1.0 REQUIRED)

add_library(dstu MODULE dstu.c md.c cipher.c rbg.c pmeth.c ameth.c sign.c key.c compress.c asn1.c params.c err.c)
set_target_properties(dstu PROPERTIES PREFIX "")
target_link_libraries(dstu OpenSSL::Crypto)

add_subdirectory(gost)
