/*
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 */

/**
 * @file
 *
 * OS_KeystoreRamFV is a formally verified implementation of the OS_Keystore API
 * that performs storage of keys in a RAM buffer.
 *
 * The implementation expects to receive a pointer to a memory buffer and the
 * buffer size. The macro OS_KeystoreRamFV_SIZE_OF_BUFFER(num_elements) helps to
 * convert the desired number of keys to the appropriate buffer size.
 *
 * NOTE: This module is a wrapper of KeystoreRamFV to adapt it to the TRENTOS-M
 * API architecture. KeystoreRamFV is the formally verified module which
 * contains all the real business logic.
 *
 * NOTE: This implementation stores the keys without additional hashing.
 *
 * NOTE: There is no persistence of the keys after a power-cycle or after an
 * init()-free()-cycle.
 */

#pragma once

#include "OS_Keystore.int.h"

#include <stdint.h>

//! Maximum size of a key.
#define OS_KeystoreRamFV_MAX_KEY_SIZE 2048

typedef struct __attribute__((packed))
{
    uint32_t    keySize;
    uint8_t     keyData[OS_KeystoreRamFV_MAX_KEY_SIZE];
}
OS_KeystoreRamFV_DataSubRecord;

//! Override the default definition of KeystoreRamFV_KEY_DATA_SIZE with the size
//! required to store key size and key data.
#define KeystoreRamFV_KEY_DATA_SIZE \
    OS_KeystoreRamFV_MAX_KEY_SIZE + \
    offsetof(OS_KeystoreRamFV_DataSubRecord, keyData)

// Including the module after the definition of KeystoreRamFV_KEY_DATA_SIZE in
// order to override its default definition.
#include "KeystoreRamFV.h"

//! Maximum length of a key name.
#define OS_KeystoreRamFV_MAX_NAME_LEN \
    (KeystoreRamFV_KEY_NAME_SIZE - 1)

//! Macro to translate an amount of key elements into the needed amount of bytes
//! in memory to store them.
#define OS_KeystoreRamFV_SIZE_OF_BUFFER(num_elements) \
    ((num_elements) * sizeof(KeystoreRamFV_ElementRecord_t))

//! Macro to translate an amount of bytes in memory into the amount of key
//! elements that could be stored in that memory.
#define OS_KeystoreRamFV_NUM_ELEMENTS_BUFFER(size_of_buffer) \
    ((size_of_buffer) / sizeof(KeystoreRamFV_ElementRecord_t))

//! Macro to get the pointer to the parent struct OS_Keystore_t.
#define OS_KeystoreRamFV_TO_OS_KEYSTORE(self)   (&((self)->parent))


typedef struct
{
    OS_Keystore_t               parent;
    KeystoreRamFV_t             fvKeystore;
    KeystoreRamFV_KeyRecord_t   keyRecord;
}
OS_KeystoreRamFV_t;

/**
 * Allocates space for a new OS_KeystoreRamFV_t context and initialises it.
 *
 * It returns an OS_Keystore_Handle_t to be used with the OS Keystore API.
 *
 * @retval OS_SUCCESS                   Operation was successful.
 * @retval OS_ERROR_INSUFFICIENT_SPACE  Failed to allocate space for the
 *                                      OS_KeystoreRamFV_t context.
 * @retval OS_ERROR_INVALID_PARAMETER   Some of the needed parameters are not
 *                                      valid for some reason.
 *
 * @param[out] pHandle  Pointer to the variable of the caller supposed to hold
 *                      the OS_Keystore_Handle_t return value.
 * @param[in]  buf      The pointer to the memory area that will hold the keys.
 * @param[in]  bufSize  The capacity, in bytes, of the memory area that will
 *                      hold the keys.
 */
OS_Error_t
OS_KeystoreRamFV_init(
    OS_Keystore_Handle_t*   pHandle,
    void*                   buf,
    size_t                  bufSize);
