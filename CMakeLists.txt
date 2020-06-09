# OS KeyStoreLibrary

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


#-------------------------------------------------------------------------------
project(os_keystore C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/OS_Keystore.c"
        "src/KeystoreLib.c"
        "src/KeyNameMap.c"
        "src/AesNvm.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "include"
)


if (KEYSTORE_CONFIG_H_FILE)

    target_compile_definitions(${PROJECT_NAME}
        INTERFACE
            "KEYSTORE_CONFIG_H_FILE=${KEYSTORE_CONFIG_H_FILE}"
    )

endif()


target_link_libraries(${PROJECT_NAME}
    INTERFACE
        os_core_api
        os_libs
        os_crypto
)


#-------------------------------------------------------------------------------
# if invoked from the OS sandbox, provide a documentation build target
if (COMMAND os_create_doxygen_target)

    get_target_property(
        OS_CORE_API_INCLUDES
        os_core_api
        INTERFACE_INCLUDE_DIRECTORIES)

    find_file(
        OS_KEYSTORE_API_HEADER
        SeosKeyStoreApi.h
        PATHS ${OS_CORE_API_INCLUDES}
        CMAKE_FIND_ROOT_PATH_BOTH)

    os_create_doxygen_target( os_keystore_doc
        # pre-step: link the API file OS_Keystore.h from os_core_api in
        #           order to produce a complete doxygen documentation
        "ln -sf ${OS_KEYSTORE_API_HEADER} ${CMAKE_CURRENT_SOURCE_DIR}/include"
        # post-step: remove the link to OS_Keystore.h
        "rm -f ${CMAKE_CURRENT_SOURCE_DIR}/include/OS_Keystore.h"
    )

endif()
