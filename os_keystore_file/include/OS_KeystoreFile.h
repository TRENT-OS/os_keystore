/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"
#include "OS_FileSystem.h"
#include "OS_Keystore_Vtable.h"
#include "KeyNameMap.h"

#define OS_KeystoreFile_MAX_INSTANCE_NAME_LEN   16
#define OS_KeystoreFile_MAX_KEY_SIZE            2048
// Maximum length of a file name. A file names is a combination of instance and
// key name in the format "<instancename>_<keyname>.key" and needs 5 more chars
// for separator and file extension (excluding the null terminator).
#define OS_KeystoreFile_MAX_FILE_NAME_LEN \
    (OS_KeystoreFile_MAX_INSTANCE_NAME_LEN + 1 + MAX_KEY_NAME_LEN + 4)

#define OS_KeystoreFile_TO_OS_KEYSTORE(self)    ((OS_Keystore_t*) (self))
#define OS_KeystoreFile_TO_HANDLE(self)         ((OS_Keystore_Handle_t) (self))


typedef struct
{
    const OS_Keystore_Vtable_t* vtable;
    OS_FileSystem_Handle_t      hFs;
    OS_Crypto_Handle_t          hCrypto;
    char                        name[OS_KeystoreFile_MAX_INSTANCE_NAME_LEN +
                                                                           1]; // null terminated string
    KeyNameMap                  keyNameMap;
    unsigned char               buffer[OS_KeystoreFile_MAX_KEY_SIZE];
}
OS_KeystoreFile_t;


OS_Error_t
OS_KeystoreFile_init(
    OS_KeystoreFile_t* self,
    OS_FileSystem_t*   fs,
    OS_Crypto_Handle_t hCrypto,
    const char*        name);

OS_Error_t
OS_KeystoreFile_new(
    OS_KeystoreFile_t** pSelf,
    OS_FileSystem_t*    fs,
    OS_Crypto_Handle_t  hCrypto,
    const char*         name);

OS_Error_t
OS_KeystoreFile_del(
    OS_KeystoreFile_t* pSelf);
