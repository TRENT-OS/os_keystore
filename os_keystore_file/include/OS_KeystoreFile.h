/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

/**
 * @file
 *
 * OS_KeystoreFile is an implementation of the OS_Keystore API that performs
 * storage of keys by using an instance of the TRENTOS FileSystem API to write
 * in files.
 *
 * OS_KeystoreFile writes opaque buffers of cryptographic material (keys, as
 * exported from the TRENTOS Crypto API) into a file, for which the
 * KeystoreFile needs a handle to a mounted file system. Conversely, it can also
 * load keys back into memory.
 * Every OS_KeystoreFile instance has an "instance name" (set during the
 * initialization), which allows having several instances of the KeystoreFile on
 * the same file system. Each key is stored in its own file and the file name is
 * constructed from a Keystore's "instance name" and the respective "key name".
 *
 * NOTE: Using different instances of the KeystoreFile with the same file system
 * requires each instance to have a unique instance name. Otherwise, these
 * instances might interfere with each other.
 *
 * NOTE: The isolation between two KeystoreFile instances using the same piece
 * of storage and the same file system is weak. If one instance needs to be
 * separated from another instance, each instance should have its own piece of
 * storage (separate ranges of storage can be assigned via the StorageServer).
 */

#pragma once

#include "OS_Crypto.h"
#include "OS_FileSystem.h"
#include "OS_Keystore.int.h"
#include "OS_KeystoreFile_KeyNameMap.h"

//! Maximum length of a key name.
#define OS_KeystoreFile_MAX_INSTANCE_NAME_LEN   15

//! Maximum size of a key.
#define OS_KeystoreFile_MAX_KEY_SIZE            2048

//! Maximum length of a file name. A file names is a combination of instance and
//! key name in the format "<instancename>_<keyname>.key" and needs 5 more chars
//! for separator and file extension (excluding the null terminator).
#define OS_KeystoreFile_MAX_FILE_NAME_LEN \
    (OS_KeystoreFile_MAX_INSTANCE_NAME_LEN + 1 + \
    OS_KeystoreFile_KeyName_MAX_NAME_LEN + 4)

//! Macro to get the pointer to the parent struct OS_Keystore_t.
#define OS_KeystoreFile_TO_OS_KEYSTORE(self)    (&((self)->parent))


typedef struct
{
    OS_Keystore_t               parent;
    OS_FileSystem_Handle_t      hFs;
    OS_Crypto_Handle_t          hCrypto;
    // null terminated string
    char                        name[OS_KeystoreFile_MAX_INSTANCE_NAME_LEN + 1];
    OS_KeystoreFile_KeyNameMap  keyNameMap;
    unsigned char               buffer[OS_KeystoreFile_MAX_KEY_SIZE];
}
OS_KeystoreFile_t;


/**
 * Allocates space for a new OS_KeystoreFile_t context and initialises it.
 *
 * It returns an OS_Keystore_Handle_t to be used with the OS Keystore API.
 *
 * @retval OS_SUCCESS                   Operation was successful.
 * @retval OS_ERROR_INSUFFICIENT_SPACE  Failed to allocate space for the
 *                                      OS_KeystoreFile_t context.
 * @retval OS_ERROR_INVALID_PARAMETER   Some of the needed parameters are not
 *                                      valid for some reason.
 * @retval OS_ERROR_ABORTED             Some of the internal initialisations
 *                                      failed.
 *
 * @param[out] pHandle  Pointer to the variable of the caller supposed to hold
 *                      the OS_Keystore_Handle_t return value.
 * @param[in]  hFs      Handle that references the mounted FileSystems context
 *                      to be used to store / load the keys when using the API
 *                      functions with the created context.
 * @param[in]  hCrypto  Handle that references the Crypto context to be used to
 *                      hash the keys.
 * @param[in]  name     Unique name (ID) for the created context.
 */
OS_Error_t
OS_KeystoreFile_init(
    OS_Keystore_Handle_t*   pHandle,
    OS_FileSystem_Handle_t  hFs,
    OS_Crypto_Handle_t      hCrypto,
    const char*             name);
