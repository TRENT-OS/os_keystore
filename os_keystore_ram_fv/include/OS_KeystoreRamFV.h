/*
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 */

/**
 * @file
 *
 * OS_KeystoreRamFV is a formally verified implementation that performs storage
 * of keys in a RAM buffer.
 *
 * The implementation expects to receive a pointer to a memory buffer
 * and the buffer size. The macro OS_KeystoreRamFV_SIZE_OF_BUFFER(num_elements)
 * helps to convert the desired number of keys to the appropriate buffer size.
 *
 * Info: This module is a wrapper of KeystoreRamFV to adapt that to the
 * TRENTOS-M API implementation architecture. KeystoreRamFV is the formally
 * verified module which contains all the real business logic.
 *
 * Info: This implementation stores the keys without additional hashing.
 *
 * Info: There is no persistence of the keys after a power cycle or after an
 * init() - free() cycle.
 */

#pragma once

#include "OS_Keystore.int.h"
#include "KeystoreRamFV.h"

/**
 * Maximum length of a key name.
 */
#define OS_KeystoreRamFV_MAX_NAME_LEN \
    (KeystoreRamFV_KEY_NAME_SIZE - 1)
/**
 * Maximum size of a key.
 */
#define OS_KeystoreRamFV_MAX_KEY_SIZE \
    (KeystoreRamFV_KEY_DATA_SIZE)
/**
 * Macro to translate an amount of key elements into needed bytes in memory to
 * store that amount.
 */
#define OS_KeystoreRamFV_SIZE_OF_BUFFER(num_elements) \
    ((num_elements) * sizeof(KeystoreRamFV_ElementRecord_t))
/**
 * Macro to translate an amount of bytes in memory to an amount of key elements
 * that could be stored in that that memory.
 */
#define OS_KeystoreRamFV_NUM_ELEMENTS_BUFFER(size_of_buffer) \
    ((size_of_buffer) / sizeof(KeystoreRamFV_ElementRecord_t))
/**
 * Macro to get the pointer to the parent struct (in this case it would a be an
 * OS_Keystore_t).
 */
#define OS_KeystoreRamFV_TO_OS_KEYSTORE(self)   (&((self)->parent))


typedef struct
{
    OS_Keystore_t               parent;
    KeystoreRamFV_t             fvKeystore;
    KeystoreRamFV_KeyRecord_t   keyRecord;
}
OS_KeystoreRamFV_t;

/**
 * Allocates space for a new OS_KeystoreRamFV_t context and initialises it
 * returning back a reference to it as an OS_Keystore_Handle.
 *
 * @retval OS_SUCCESS                   Operation was successful.
 * @retval OS_ERROR_INSUFFICIENT_SPACE  Failed to allocate space for the
 *                                      OS_KeystoreFile_t context.
 * @retval OS_ERROR_INVALID_PARAMETER   Some of the needed parameters is not
 *                                      valid for some reason.
 *
 * @param[out] pHandle  Pointer to the variable of the caller supposed to hold
 *                      the OS_Keystore_Handle return value.
 * @param[in]  buf      The pointer to the memory area that will hold the keys.
 * @param[in]  bufSize  The capacity, in bytes, of the memory area that will
 *                      hold the keys.
 */
OS_Error_t
OS_KeystoreRamFV_init(
    OS_Keystore_Handle_t*   pHandle,
    void*                   buf,
    size_t                  bufSize);
