/*
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Keystore.int.h"
#include "KeystoreRamFV.h"

#define OS_KeystoreRamFV_MAX_NAME_LEN \
    (KeystoreRamFV_KEY_NAME_SIZE - 1)

#define OS_KeystoreRamFV_MAX_KEY_SIZE \
    (KeystoreRamFV_KEY_DATA_SIZE)

#define OS_KeystoreRamFV_SIZE_OF_BUFFER(num_elements) \
    ((num_elements) * sizeof(KeystoreRamFV_ElementRecord_t))

#define OS_KeystoreRamFV_NUM_ELEMENTS_BUFFER(size_of_buffer) \
    ((size_of_buffer) / sizeof(KeystoreRamFV_ElementRecord_t))

#define OS_KeystoreRamFV_TO_OS_KEYSTORE(self)   (&((self)->parent))


typedef struct
{
    OS_Keystore_t               parent;
    KeystoreRamFV_t             fvKeystore;
    KeystoreRamFV_KeyRecord_t   keyRecord;
}
OS_KeystoreRamFV_t;


OS_Error_t
OS_KeystoreRamFV_init(
    OS_Keystore_Handle_t*   pHandle,
    void*                   buf,
    unsigned                numElements);
