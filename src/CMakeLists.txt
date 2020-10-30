find_package(OpenSSL REQUIRED)

add_library(dstu MODULE dstu.c)
set_target_properties(dstu PROPERTIES PREFIX "")
