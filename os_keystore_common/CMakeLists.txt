#
# OS Keystore common library
#
# Copyright (C) 2021, HENSOLDT Cyber GmbH
# SPDX-License-Identifier: BSD-3-Clause
#

cmake_minimum_required(VERSION 3.18)

#-------------------------------------------------------------------------------
project(os_keystore_common C)

#-------------------------------------------------------------------------------
# LIBRARY
#-------------------------------------------------------------------------------
add_library(${PROJECT_NAME} INTERFACE)

target_sources(${PROJECT_NAME}
    INTERFACE
        "src/OS_Keystore.c"
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        "include"
)

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        os_core_api
)
