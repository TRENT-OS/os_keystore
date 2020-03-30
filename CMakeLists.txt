# SEOS KeyStoreLibrary

project(seos_keystore C)

add_library(${PROJECT_NAME} STATIC
    "src/SeosKeyStore.c"
    "src/SeosKeyStoreApi.c"
    "src/KeyNameMap.c"
    "src/AesNvm.c")

if(KEYSTORE_AS_COMPONENT)

    target_sources(${PROJECT_NAME}
        PRIVATE
            "src/SeosKeyStoreClient.c"
            "src/SeosKeyStoreRpc.c")

endif()

if (ENABLE_LINT)
        set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
        set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

if(NO_KERNEL_BUILD)

    # since PAGE_SIZE is normally defined as part of musllibc
    # (which is missing here) we have to define it
    target_compile_definitions(${PROJECT_NAME}
        PRIVATE
            PAGE_SIZE=${PAGE_SIZE_VALUE})

endif(NO_KERNEL_BUILD)

if (KEYSTORE_CONFIG_H_FILE)

    target_compile_definitions(${PROJECT_NAME}
        PUBLIC
            "KEYSTORE_CONFIG_H_FILE=${KEYSTORE_CONFIG_H_FILE}"
    )

endif()

target_include_directories(${PROJECT_NAME}
    PUBLIC
        "include"
)

target_link_libraries(${PROJECT_NAME}
    seos_core_api
    seos_crypto
)

# if invoked from the SEOS sandbox, provide a documentation build target
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
        # post-step: remove the link to OS_Crypto.h
        "rm -f ${CMAKE_CURRENT_SOURCE_DIR}/include/SeosKeyStoreApi.h"
    )

endif()
