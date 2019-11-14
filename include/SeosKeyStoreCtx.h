/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosKeyStoreCtx.h
 *
 * @brief SEOS KeyStore API interface context
 *
 */

#pragma once

#include "SeosError.h"
#include "SeosCrypto_Handles.h"

typedef struct SeosKeyStoreCtx SeosKeyStoreCtx;

typedef seos_err_t
(*SeosKeyStoreCtx_importKeyT)(SeosKeyStoreCtx*          keyStoreCtx,
                              const char*               name,
                              void const*               keyData,
                              size_t                    keySize);

typedef seos_err_t
(*SeosKeyStoreCtx_getKeyT)(SeosKeyStoreCtx*         keyStoreCtx,
                           const char*              name,
                           void*                    keyData,
                           size_t*                  keySize);

typedef seos_err_t
(*SeosKeyStoreCtx_deleteKeyT)(SeosKeyStoreCtx*      self,
                              const char*           name);

typedef seos_err_t
(*SeosKeyStoreCtx_copyKeyT)(SeosKeyStoreCtx*        self,
                            const char*             name,
                            SeosKeyStoreCtx*        destKeyStore);

typedef seos_err_t
(*SeosKeyStoreCtx_moveKeyT)(SeosKeyStoreCtx*        self,
                            const char*             name,
                            SeosKeyStoreCtx*        destKeyStore);

typedef seos_err_t
(*SeosKeyStoreCtx_wipeKeyStoreT)(SeosKeyStoreCtx*   self);

typedef void
(*SeosKeyStoreCtx_deInitT)(SeosKeyStoreCtx*         self);

typedef struct
{
    SeosKeyStoreCtx_importKeyT      importKey;
    SeosKeyStoreCtx_getKeyT         getKey;
    SeosKeyStoreCtx_deleteKeyT      deleteKey;
    SeosKeyStoreCtx_copyKeyT        copyKey;
    SeosKeyStoreCtx_moveKeyT        moveKey;
    SeosKeyStoreCtx_wipeKeyStoreT   wipeKeyStore;

    SeosKeyStoreCtx_deInitT         deInit;
}
SeosKeyStoreCtx_Vtable;

struct SeosKeyStoreCtx
{
    const SeosKeyStoreCtx_Vtable* vtable;
};

/** @} */