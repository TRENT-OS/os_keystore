/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Error.h"

#include <stddef.h>

typedef OS_Error_t
(*KeystoreImpl_storeKey)(
    void*       self,
    const char* name,
    void const* keyData,
    size_t      keySize);

typedef OS_Error_t
(*KeystoreImpl_loadKey)(
    void*       self,
    const char* name,
    void*       keyData,
    size_t*     keySize);

typedef OS_Error_t
(*KeystoreImpl_deleteKey)(
    void*       self,
    const char* name);

typedef OS_Error_t
(*KeystoreImpl_copyKey)(
    void*       self,
    const char* name,
    void*       destKeyStore);

typedef OS_Error_t
(*KeystoreImpl_moveKey)(
    void*       self,
    const char* name,
    void*       destKeyStore);

typedef OS_Error_t
(*KeystoreImpl_wipeKeystore)(
    void* self);

typedef OS_Error_t
(*KeystoreImpl_free)(
    void* self);

typedef struct
{
    KeystoreImpl_storeKey storeKey;
    KeystoreImpl_loadKey loadKey;
    KeystoreImpl_deleteKey deleteKey;
    KeystoreImpl_copyKey copyKey;
    KeystoreImpl_moveKey moveKey;
    KeystoreImpl_wipeKeystore wipeKeystore;
    KeystoreImpl_free free;
} KeystoreImpl_Vtable_t;

typedef struct
{
    const KeystoreImpl_Vtable_t* vtable;
    void* context;
} KeystoreImpl_t;
