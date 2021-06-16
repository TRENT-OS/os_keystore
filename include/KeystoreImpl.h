/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Error.h"

#include <stddef.h>

typedef OS_Error_t
(*KeystoreImpl_StoreKey)(
    void*       self,
    const char* name,
    void const* keyData,
    size_t      keySize);

typedef OS_Error_t
(*KeystoreImpl_LoadKey)(
    void*       self,
    const char* name,
    void*       keyData,
    size_t*     keySize);

typedef OS_Error_t
(*KeystoreImpl_DeleteKey)(
    void*       self,
    const char* name);

typedef OS_Error_t
(*KeystoreImpl_CopyKey)(
    void*       self,
    const char* name,
    void*       destKeyStore);

typedef OS_Error_t
(*KeystoreImpl_MoveKey)(
    void*       self,
    const char* name,
    void*       destKeyStore);

typedef OS_Error_t
(*KeystoreImpl_WipeKeystore)(
    void* self);

typedef OS_Error_t
(*KeystoreImpl_Free)(
    void* self);

typedef struct
{
    KeystoreImpl_StoreKey       storeKey;
    KeystoreImpl_LoadKey        loadKey;
    KeystoreImpl_DeleteKey      deleteKey;
    KeystoreImpl_CopyKey        copyKey;
    KeystoreImpl_MoveKey        moveKey;
    KeystoreImpl_WipeKeystore   wipeKeystore;
    KeystoreImpl_Free           free;
}
KeystoreImpl_Vtable_t;

typedef struct
{
    const KeystoreImpl_Vtable_t* vtable;
    void* context;
} KeystoreImpl_t;
