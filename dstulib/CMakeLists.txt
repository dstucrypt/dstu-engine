add_library(dstulib OBJECT params.c)
target_include_directories(dstulib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(dstulib PROPERTIES POSITION_INDEPENDENT_CODE ON)

add_subdirectory(gost)
