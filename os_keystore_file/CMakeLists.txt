#
# OS KeystoreFile
#
# Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
#

cmake_minimum_required(VERSION 3.18)

#-------------------------------------------------------------------------------
project(os_keystore_file C)

#-------------------------------------------------------------------------------
# LIBRARY
#-------------------------------------------------------------------------------
add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/OS_KeystoreFile_KeySize.c"
        "src/OS_KeystoreFile_KeyName.c"
        "src/OS_KeystoreFile_KeyNameMap.c"
        "src/OS_KeystoreFile.c"
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
