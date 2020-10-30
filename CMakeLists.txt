cmake_minimum_required(VERSION 3.0)
project(dstu-engine LANGUAGES C VERSION 0.0.1)

add_subdirectory(src)

add_custom_target(cppcheck COMMAND cppcheck --enable=all ${CMAKE_SOURCE_DIR}/src)
