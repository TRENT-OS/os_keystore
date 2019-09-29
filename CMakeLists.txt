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

# if invoked from the SOES sandbox, provide a documentation build target
if (COMMAND seos_create_doxygen_target)

    get_target_property(
        SEOS_CORE_API_INCLUDES
        seos_core_api
        INTERFACE_INCLUDE_DIRECTORIES)

    find_file(
        SEOS_KEYSTORE_API_HEADER
        SeosKeyStoreApi.h
        PATHS ${SEOS_CORE_API_INCLUDES}
        CMAKE_FIND_ROOT_PATH_BOTH)

    seos_create_doxygen_target( seos_keystore_doc
        # pre-step: link the API file SeosKeyStoreApi.h from seos_core_api in
        #           order to produce a complete doxygen documentation
        "ln -sf ${SEOS_KEYSTORE_API_HEADER} ${CMAKE_CURRENT_SOURCE_DIR}/include"
        # post-step: remove the link to SeosCryptoApi.h
        "rm -f ${CMAKE_CURRENT_SOURCE_DIR}/include/SeosKeyStoreApi.h"
    )

endif()
