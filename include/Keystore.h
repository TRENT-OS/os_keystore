/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Error.h"

#include <stddef.h>

typedef struct OS_Keystore Keystore_t;

typedef OS_Error_t
(*Keystore_Vtable_StoreKey)(
    Keystore_t* self,
    const char* name,
    void const* keyData,
    size_t      keySize);

typedef OS_Error_t
(*Keystore_Vtable_LoadKey)(
    Keystore_t* self,
    const char* name,
    void*       keyData,
    size_t*     keySize);

typedef OS_Error_t
(*Keystore_Vtable_DeleteKey)(
    Keystore_t* self,
    const char* name);

typedef OS_Error_t
(*Keystore_Vtable_CopyKey)(
    Keystore_t* self,
    const char* name,
    Keystore_t* destKeyStore);

typedef OS_Error_t
(*Keystore_Vtable_MoveKey)(
    Keystore_t* self,
    const char* name,
    Keystore_t* destKeyStore);

typedef OS_Error_t
(*Keystore_Vtable_WipeKeystore)(
    Keystore_t* self);

typedef OS_Error_t
(*Keystore_Vtable_Free)(
    Keystore_t* self);

typedef struct
{
    Keystore_Vtable_StoreKey       storeKey;
    Keystore_Vtable_LoadKey        loadKey;
    Keystore_Vtable_DeleteKey      deleteKey;
    Keystore_Vtable_CopyKey        copyKey;
    Keystore_Vtable_MoveKey        moveKey;
    Keystore_Vtable_WipeKeystore   wipeKeystore;
    Keystore_Vtable_Free           free;
}
Keystore_Vtable_t;

struct OS_Keystore
{
    const Keystore_Vtable_t* vtable;
};
