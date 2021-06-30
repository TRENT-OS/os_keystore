/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_Keystore.h"

#include <stddef.h>

typedef OS_Error_t
(*OS_Keystore_Vtable_Free)(
    OS_Keystore_t*  self);

typedef OS_Error_t
(*OS_Keystore_Vtable_StoreKey)(
    OS_Keystore_t*  self,
    const char*     name,
    void const*     keyData,
    size_t          keySize);

typedef OS_Error_t
(*OS_Keystore_Vtable_LoadKey)(
    OS_Keystore_t*  self,
    const char*     name,
    void*           keyData,
    size_t*         keySize);

typedef OS_Error_t
(*OS_Keystore_Vtable_DeleteKey)(
    OS_Keystore_t*  self,
    const char*     name);

typedef OS_Error_t
(*OS_Keystore_Vtable_CopyKey)(
    OS_Keystore_t*  self,
    const char*     name,
    OS_Keystore_t*  destKeyStore);

typedef OS_Error_t
(*OS_Keystore_Vtable_MoveKey)(
    OS_Keystore_t*  self,
    const char*     name,
    OS_Keystore_t*  destKeyStore);

typedef OS_Error_t
(*OS_Keystore_Vtable_WipeKeystore)(
    OS_Keystore_t*  self);

typedef struct
{
    OS_Keystore_Vtable_Free           free;
    OS_Keystore_Vtable_StoreKey       storeKey;
    OS_Keystore_Vtable_LoadKey        loadKey;
    OS_Keystore_Vtable_DeleteKey      deleteKey;
    OS_Keystore_Vtable_CopyKey        copyKey;
    OS_Keystore_Vtable_MoveKey        moveKey;
    OS_Keystore_Vtable_WipeKeystore   wipeKeystore;
}
OS_Keystore_Vtable_t;
