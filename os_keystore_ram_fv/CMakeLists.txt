#
# OS KeystoreRamFV
#
# Copyright (C) 2021-2024, HENSOLDT Cyber GmbH
# 
# SPDX-License-Identifier: GPL-2.0-or-later
#
# For commercial licensing, contact: info.cyber@hensoldt.net
#

cmake_minimum_required(VERSION 3.18)

#-------------------------------------------------------------------------------
project(os_keystore_ram_fv C)

#-------------------------------------------------------------------------------
# LIBRARY
#-------------------------------------------------------------------------------
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

target_link_libraries(${PROJECT_NAME}
    INTERFACE
        os_keystore_common
)
