enable_language(CXX)

find_package(OpenSSL 1.1.0 REQUIRED)

add_executable(test_engine test.cpp)
target_link_libraries(test_engine PUBLIC coverage_config OpenSSL::Crypto)
add_test(test_engine test_engine)

set_source_files_properties(openssl.cnf PROPERTIES GENERATED TRUE)
configure_file(openssl.cnf.in openssl.cnf ESCAPE_QUOTES @ONLY)
configure_file(private1.pem private1.pem COPYONLY)
configure_file(private2.pem private2.pem COPYONLY)
configure_file(public1.pem public1.pem COPYONLY)
configure_file(public2.pem public2.pem COPYONLY)
configure_file(cms.pem cms.pem COPYONLY)
