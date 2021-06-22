/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"
#include "OS_FileSystem.h"
#include "OS_Keystore.h"
#include "KeyNameMap.h"

#define KeystoreFile_MAX_INSTANCE_NAME_LEN   16
#define KeystoreFile_MAX_KEY_SIZE            2048
// Maximum length of a file name. A file names is a combination of instance and
// key name in the format "<instancename>_<keyname>.key" and needs 5 more chars
// for separator and file extension (excluding the null terminator).
#define KeystoreFile_MAX_FILE_NAME_LEN \
    (KeystoreFile_MAX_INSTANCE_NAME_LEN + 1 + MAX_KEY_NAME_LEN + 4)

typedef struct
{
    OS_FileSystem_Handle_t  hFs;
    OS_Crypto_Handle_t      hCrypto;
    char                    name[KeystoreFile_MAX_INSTANCE_NAME_LEN +
                                                                    1]; // null terminated string
    KeyNameMap              keyNameMap;
    unsigned char           buffer[KeystoreFile_MAX_KEY_SIZE];
}
KeystoreFile_t;
