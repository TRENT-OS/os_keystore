/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Error.h"

#include <stddef.h>

typedef OS_Error_t
(*Keystore_Vtable_StoreKey)(
    void*       self,
    const char* name,
    void const* keyData,
    size_t      keySize);

typedef OS_Error_t
(*Keystore_Vtable_LoadKey)(
    void*       self,
    const char* name,
    void*       keyData,
    size_t*     keySize);

typedef OS_Error_t
(*Keystore_Vtable_DeleteKey)(
    void*       self,
    const char* name);

typedef OS_Error_t
(*Keystore_Vtable_CopyKey)(
    void*       self,
    const char* name,
    void*       destKeyStore);

typedef OS_Error_t
(*Keystore_Vtable_MoveKey)(
    void*       self,
    const char* name,
    void*       destKeyStore);

typedef OS_Error_t
(*Keystore_Vtable_WipeKeystore)(
    void* self);

typedef OS_Error_t
(*Keystore_Vtable_Free)(
    void* self);

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

typedef struct
{
    const Keystore_Vtable_t* vtable;
    void* context;
} Keystore_t;
