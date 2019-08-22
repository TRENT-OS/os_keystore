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

#include "seos_err.h"
#include "SeosCrypto_Handles.h"

typedef struct SeosKeyStoreCtx SeosKeyStoreCtx;

typedef seos_err_t
(*SeosKeyStoreCtx_importKeyT)(SeosKeyStoreCtx*          self,
                              SeosCrypto_KeyHandle*     keyHandle,
                              const char*               name,
                              void const*               keyBytesBuffer,
                              unsigned int              algorithm,
                              unsigned int              flags,
                              size_t                    lenBits);

typedef seos_err_t
(*SeosKeyStoreCtx_getKeyT)(SeosKeyStoreCtx*         self,
                           SeosCrypto_KeyHandle*    keyHandle,
                           const char*              name);

typedef seos_err_t
(*SeosKeyStoreCtx_deleteKeyT)(SeosKeyStoreCtx*          self,
                              SeosCrypto_KeyHandle      keyHandle,
                              const char*               name);

typedef seos_err_t
(*SeosKeyStoreCtx_closeKeyT)(SeosKeyStoreCtx*          self,
                             SeosCrypto_KeyHandle      keyHandle);

typedef seos_err_t
(*SeosKeyStoreCtx_copyKeyT)(SeosKeyStoreCtx*        self,
                            SeosCrypto_KeyHandle    keyHandle,
                            const char*             name,
                            SeosKeyStoreCtx*        destKeyStore);

typedef seos_err_t
(*SeosKeyStoreCtx_moveKeyT)(SeosKeyStoreCtx*        self,
                            SeosCrypto_KeyHandle    keyHandle,
                            const char*             name,
                            SeosKeyStoreCtx*        destKeyStore);

typedef seos_err_t
(*SeosKeyStoreCtx_generateKeyT)(SeosKeyStoreCtx*            self,
                                SeosCrypto_KeyHandle*       keyHandle,
                                const char*                 name,
                                unsigned int                algorithm,
                                unsigned int                flags,
                                size_t                      lenBits);

typedef void
(*SeosKeyStoreCtx_deInitT)(SeosKeyStoreCtx* self);

typedef struct
{
    SeosKeyStoreCtx_importKeyT      importKey;
    SeosKeyStoreCtx_getKeyT         getKey;
    SeosKeyStoreCtx_deleteKeyT      deleteKey;
    SeosKeyStoreCtx_closeKeyT       closeKey;
    SeosKeyStoreCtx_copyKeyT        copyKey;
    SeosKeyStoreCtx_moveKeyT        moveKey;
    SeosKeyStoreCtx_generateKeyT    generateKey;

    SeosKeyStoreCtx_deInitT         deInit;
}
SeosKeyStoreCtx_Vtable;

struct SeosKeyStoreCtx
{
    const SeosKeyStoreCtx_Vtable* vtable;
};

/** @} */