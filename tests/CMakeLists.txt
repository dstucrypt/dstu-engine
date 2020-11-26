enable_language(CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 1.1.0 REQUIRED)

add_executable(test_engine test.cpp)
target_link_libraries(test_engine PUBLIC coverage_config OpenSSL::Crypto)
add_test(test_engine test_engine)

add_executable(test_dstu dstu.cpp)
target_link_libraries(test_dstu PUBLIC coverage_config OpenSSL::Crypto)
add_test(test_dstu test_dstu)

add_executable(test_key6 key6.cpp)
target_link_libraries(test_key6 PUBLIC coverage_config keylib OpenSSL::Crypto)
target_include_directories(test_key6 PRIVATE "${CMAKE_SOURCE_DIR}/keylib")
add_test(test_key6 test_key6)

add_executable(test_jks jks.cpp)
target_link_libraries(test_jks PUBLIC coverage_config keylib OpenSSL::Crypto)
target_include_directories(test_jks PRIVATE "${CMAKE_SOURCE_DIR}/keylib")
add_test(test_jks test_jks)

set_source_files_properties(openssl.cnf PROPERTIES GENERATED TRUE)
configure_file(openssl.cnf.in openssl.cnf ESCAPE_QUOTES @ONLY)
configure_file(private1.pem private1.pem COPYONLY)
configure_file(private2.pem private2.pem COPYONLY)
configure_file(public1.pem public1.pem COPYONLY)
configure_file(public2.pem public2.pem COPYONLY)
configure_file(cms.pem cms.pem COPYONLY)
configure_file(Key-6.dat Key-6.dat COPYONLY)
configure_file(key.jks key.jks COPYONLY)
