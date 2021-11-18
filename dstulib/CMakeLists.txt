add_library(dstulib OBJECT key.c asn1.c compress.c params.c)
target_include_directories(dstulib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(dstulib PROPERTIES POSITION_INDEPENDENT_CODE ON)

if ( CLANG_TIDY_EXE )
        set_target_properties ( dstulib PROPERTIES C_CLANG_TIDY "${DO_CLANG_TIDY}" )
endif ()
if ( INCLUDE_WHAT_YOU_USE_EXE )
        set_target_properties ( dstulib PROPERTIES C_INCLUDE_WHAT_YOU_USE "${DO_INCLUDE_WHAT_YOU_USE}" )
endif ()

if(ENABLE_CODECOV AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    # Add required flags (GCC & LLVM/Clang)
    target_compile_options(dstulib PUBLIC
        -O0        # no optimization
        -g         # generate debug info
        --coverage # sets all required flags
    )
else(ENABLE_CODECOV AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    if(ENABLE_CODECOV)
        message(FATAL_ERROR "Unknown compiler id: ${CMAKE_C_COMPILER_ID}")
    endif(ENABLE_CODECOV)
endif(ENABLE_CODECOV AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")

add_subdirectory(gost)
