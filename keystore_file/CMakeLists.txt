# OS KeystoreFile library

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


#-------------------------------------------------------------------------------
project(os_keystore_file C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/KeySize.c"
        "src/KeyName.c"
        "src/KeyNameMap.c"
        "src/KeystoreFile.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "include"
)


target_link_libraries(${PROJECT_NAME}
    INTERFACE
        os_keystore_common
        lib_utils
)
