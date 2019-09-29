# SEOS KeyStoreLibrary

project(seos_keystore C)

add_library(
    ${PROJECT_NAME} STATIC

    "src/SeosKeyStore.c"
    "src/SeosKeyStoreApi.c"
    "src/SeosKeyStoreClient.c"
    "src/SeosKeyStoreRpc.c"
    "src/KeyNameMap.c"
    "src/KeyStoreCtxRegister.c"
)
if (ENABLE_LINT)
        set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
        set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

if(NO_KERNEL_BUILD)
    # when building for the x64 architecture, some warnings are
    # reported (i.e. printf formatting) that the code is full of,
    # and that are otherwise not reported, so as a quick fix we
    # remove the -Werror in this build situation
    target_compile_options(${PROJECT_NAME}
        PUBLIC
            -Wall
    )

    # since PAGE_SIZE is normally defined as part of musllibc
    # (which is missing here) we have to define it
    target_compile_definitions(${PROJECT_NAME} PRIVATE PAGE_SIZE=${PAGE_SIZE_VALUE})
else()
    target_compile_options(${PROJECT_NAME}
        PUBLIC
            -Wall
            -Werror
    )
endif(NO_KERNEL_BUILD)

if (KEYSTORE_CONFIG_H_FILE)
    list(APPEND PUBLIC_TARGET_COMPILE_DEFINITIONS
        "KEYSTORE_CONFIG_H_FILE=${KEYSTORE_CONFIG_H_FILE}")
endif()

if (DEBUG_CONFIG_H_FILE)
    list(APPEND PUBLIC_TARGET_COMPILE_DEFINITIONS
        "DEBUG_CONFIG_H_FILE=${DEBUG_CONFIG_H_FILE}"
    )
endif()

if (MEMORY_CONFIG_H_FILE)
    list(APPEND PUBLIC_TARGET_COMPILE_DEFINITIONS
        "MEMORY_CONFIG_H_FILE=${MEMORY_CONFIG_H_FILE}"
    )
endif()

list(APPEND PRIVATE_TARGET_COMPILE_DEFINITIONS
    MBEDTLS_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/configs/MbedTLS_Config.h"
)
target_include_directories(${PROJECT_NAME}
    PUBLIC
    "3rdParty/mbedtls/include"
)
target_sources(${PROJECT_NAME}
    PRIVATE
    "3rdParty/mbedtls/library/base64.c"
)

target_compile_definitions(${PROJECT_NAME}
    PUBLIC
        ${PUBLIC_TARGET_COMPILE_DEFINITIONS}
    PRIVATE
        ${PRIVATE_TARGET_COMPILE_DEFINITIONS}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "include"
)

target_link_libraries(${PROJECT_NAME}
    seos_libs
    seos_crypto
    seos_core_api
)

get_target_property(SEOS_CORE_API_INCLUDES seos_core_api INTERFACE_INCLUDE_DIRECTORIES)
find_file(SEOS_KEY_STORE_API_HEADER SeosKeyStoreApi.h PATHS ${SEOS_CORE_API_INCLUDES} CMAKE_FIND_ROOT_PATH_BOTH)

find_package(Doxygen)
if (DOXYGEN_FOUND AND DOXYGEN_DOT_FOUND)
    add_custom_target( seos_keystore_doc
        COMMAND
            export DOXYGEN_OUTPUT_DIR=${CMAKE_CURRENT_BINARY_DIR}
            # link the API file SeosKeyStoreApi.h from seos_core_api in order to produce a complete doxygen documentation
            && ln -sf ${SEOS_KEY_STORE_API_HEADER} ${CMAKE_CURRENT_SOURCE_DIR}/include
            # run doxygen
            && ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
            # remove the link to SeosKeyStoreApi.h
            && rm -f ${CMAKE_CURRENT_SOURCE_DIR}/include/SeosKeyStoreApi.h
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation for seos_keystore with Doxygen"
        VERBATIM )
else(DOXYGEN_FOUND AND DOXYGEN_DOT_FOUND)
    message("Doxygen needs to be installed to generate the doxygen documentation")
endif(DOXYGEN_FOUND AND DOXYGEN_DOT_FOUND)
