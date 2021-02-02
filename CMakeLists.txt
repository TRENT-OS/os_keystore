# OS KeyStore library

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


target_link_libraries(${PROJECT_NAME}
    INTERFACE
        os_core_api
        lib_mem
        lib_utils
        os_crypto
)
