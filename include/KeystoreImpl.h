/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosError.h"
#include <stddef.h>

typedef seos_err_t
(*KeystoreImpl_storeKey)(
    void*       self,
    const char* name,
    void const* keyData,
    size_t      keySize);

typedef seos_err_t
(*KeystoreImpl_loadKey)(
    void*       self,
    const char* name,
    void*       keyData,
    size_t*     keySize);

typedef seos_err_t
(*KeystoreImpl_deleteKey)(
    void*       self,
    const char* name);

typedef seos_err_t
(*KeystoreImpl_copyKey)(
    void*       self,
    const char* name,
    void*       destKeyStore);

typedef seos_err_t
(*KeystoreImpl_moveKey)(
    void*       self,
    const char* name,
    void*       destKeyStore);

typedef seos_err_t
(*KeystoreImpl_wipeKeystore)(
    void* self);

typedef struct
{
    KeystoreImpl_storeKey storeKey;
    KeystoreImpl_loadKey loadKey;
    KeystoreImpl_deleteKey deleteKey;
    KeystoreImpl_copyKey copyKey;
    KeystoreImpl_moveKey moveKey;
    KeystoreImpl_wipeKeystore wipeKeystore;
} KeystoreImpl_Vtable_t;

typedef struct
{
    const KeystoreImpl_Vtable_t* vtable;
    void* context;
} KeystoreImpl_t;