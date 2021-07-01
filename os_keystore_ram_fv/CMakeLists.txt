# OS KeystoreRamFV library

cmake_minimum_required(VERSION 3.13.0)

# enable new behavior introduced in CMake 3.13, where relative paths will be
# converted into absolute paths in target_sources(INTERFACE ....)
cmake_policy(SET CMP0076 NEW)


#-------------------------------------------------------------------------------
project(os_keystore_ram_fv C)

add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "keystore_ram_fv/KeystoreRamFV.c"
        "keystore_ram_fv/stdlib_fv/stdlib_fv.c"
        "src/OS_KeystoreRamFV.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "keystore_ram_fv"
        "keystore_ram_fv/stdlib_fv"
        "include"
)
