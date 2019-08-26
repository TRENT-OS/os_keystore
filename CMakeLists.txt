# SEOS KeyStoreLibrary

project(seos_keystore C)

add_library(
    ${PROJECT_NAME} STATIC

    "src/SeosKeyStore.c"
    "src/SeosKeyStoreApi.c"
    "src/SeosKeyStoreClient.c"
    "src/SeosKeyStoreRpc.c"
)
if (ENABLE_LINT)
        set(CMAKE_C_CPPCHECK "cppcheck;--enable=warning;--inline-suppr")
        set(CMAKE_C_CLANG_TIDY "clang-tidy;-checks=*")
endif()

target_compile_options(${PROJECT_NAME}
    PUBLIC
        -Wall
        -Werror
)

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

get_target_property(SEOS_CORE_API_INCLUDES seos_core_api INTERFACE_INCLUDE_DIRECTORIES)
find_file(SEOS_KEY_STORE_API_HEADER SeosKeyStoreApi.h PATHS ${SEOS_CORE_API_INCLUDES} CMAKE_FIND_ROOT_PATH_BOTH)
if (SEOS_KEY_STORE_API_HEADER)
    execute_process(COMMAND ln -sf ${SEOS_KEY_STORE_API_HEADER} ${CMAKE_CURRENT_SOURCE_DIR}/include)
endif(SEOS_KEY_STORE_API_HEADER)

find_package(Doxygen
             REQUIRED dot
             OPTIONAL_COMPONENTS mscgen dia)
if (DOXYGEN_FOUND)
    # note the option ALL which allows to build the docs together with the application
    add_custom_target( seos_keystore_doc
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile && ln -sf ${CMAKE_CURRENT_SOURCE_DIR}/html ${CMAKE_CURRENT_BINARY_DIR}/seos_keystore_doc
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )
else(DOXYGEN_FOUND)
    message("Doxygen needs to be installed to generate the doxygen documentation")
endif(DOXYGEN_FOUND)
