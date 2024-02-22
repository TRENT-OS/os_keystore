/*
 * Copyright (C) 2021-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
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
 * NOTE: This module is a wrapper of KeystoreRamFV to adapt it to the TRENTOS
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
#include "KeystoreRamFV.h"

#include "lib_debug/Debug.h"

#include <stdint.h>


/**
 * This defines the maximum size of struct OS_CryptoKey_Data_t, which consists of
 *  - an element of type struct OS_CryptoKey_Type_t (size 4 bytes)
 *  - an element of type struct OS_CryptoKey_Attrib_t (size 8 bytes)
 *  - a struct that holds respective key information (size depends on the selected encryption algorithm)
 *
 * The maximum value is therefore defined by the size of the largest struct that holds
 * respective key information. Currently, this is given by the struct OS_CryptoKey_RsaRrv_t (size 2068 bytes).
 *
 * In a total, this results in a value of 2080 bytes.
 */
#define OS_KeystoreRamFV_MAX_KEY_SIZE 2080

/**
 * This struct defines the memory layout of a key record.
 * It is used as payload for KeystoreRamFV_KeyRecord_t in order to store the key
 * data together with the used size, as it needs to be returned by the loadKey()
 * function.
 */
typedef struct __attribute__((packed))
{
    uint32_t    keySize; //!< Size of the used key data.
    uint8_t     keyData[OS_KeystoreRamFV_MAX_KEY_SIZE]; //!< Key data.
}
OS_KeystoreRamFV_DataSubRecord;

// Make sure that KeystoreRamFV is configured in a compatible way.
Debug_STATIC_ASSERT(
    sizeof(OS_KeystoreRamFV_DataSubRecord) == KeystoreRamFV_KEY_DATA_SIZE);

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


/**
 * OS_KeystoreRamFV context.
 */
typedef struct
{
    //! Parent struct which holds the vTable immplemented by this module.
    OS_Keystore_t               parent;
    //! KeystoreRamFV_t context which implements the kernel functions.
    KeystoreRamFV_t             fvKeystore;
    //! Temporary support record for operations.
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
