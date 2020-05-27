# OS KeyStoreLibrary

project(seos_keystore C)

add_library(${PROJECT_NAME} STATIC
    "src/OS_Keystore.c"
    "src/KeystoreLib.c"
    "src/KeyNameMap.c"
    "src/AesNvm.c")

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

# if invoked from the OS sandbox, provide a documentation build target
if (COMMAND seos_create_doxygen_target)

    get_target_property(
        OS_CORE_API_INCLUDES
        seos_core_api
        INTERFACE_INCLUDE_DIRECTORIES)

    find_file(
        OS_KEYSTORE_API_HEADER
        SeosKeyStoreApi.h
        PATHS ${OS_CORE_API_INCLUDES}
        CMAKE_FIND_ROOT_PATH_BOTH)

    seos_create_doxygen_target( seos_keystore_doc
        # pre-step: link the API file SeosKeyStoreApi.h from seos_core_api in
        #           order to produce a complete doxygen documentation
        "ln -sf ${OS_KEYSTORE_API_HEADER} ${CMAKE_CURRENT_SOURCE_DIR}/include"
        # post-step: remove the link to OS_Crypto.h
        "rm -f ${CMAKE_CURRENT_SOURCE_DIR}/include/SeosKeyStoreApi.h"
    )

endif()
