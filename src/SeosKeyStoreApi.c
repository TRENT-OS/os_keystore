/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreCtx.h"
#include "SeosKeyStoreApi.h"

/* Public functions ----------------------------------------------------------*/
seos_err_t
SeosKeyStoreApi_importKey(SeosKeyStoreCtx*          keyStoreCtx,
                          SeosCrypto_KeyHandle*     keyHandle,
                          const char*               name,
                          void const*               keyBytesBuffer,
                          unsigned int              algorithm,
                          unsigned int              flags,
                          size_t                    lenBits)
{
    Debug_ASSERT_SELF(keyStoreCtx);
    return keyStoreCtx->vtable->importKey(keyStoreCtx,
                                          keyHandle,
                                          name,
                                          keyBytesBuffer,
                                          algorithm,
                                          flags,
                                          lenBits);
}

seos_err_t
SeosKeyStoreApi_getKey(SeosKeyStoreCtx*         keyStoreCtx,
                       SeosCrypto_KeyHandle*    keyHandle,
                       const char*              name)
{
    Debug_ASSERT_SELF(keyStoreCtx);
    return keyStoreCtx->vtable->getKey(keyStoreCtx,
                                       keyHandle,
                                       name);
}

seos_err_t
SeosKeyStoreApi_deleteKey(SeosKeyStoreCtx*          keyStoreCtx,
                          SeosCrypto_KeyHandle      keyHandle,
                          const char*               name)
{
    Debug_ASSERT_SELF(keyStoreCtx);
    return keyStoreCtx->vtable->deleteKey(keyStoreCtx,
                                          keyHandle,
                                          name);
}

seos_err_t
SeosKeyStoreApi_copyKey(SeosKeyStoreCtx*        keyStoreCtx,
                        SeosCrypto_KeyHandle    keyHandle,
                        const char*             name,
                        SeosKeyStoreCtx*        destKeyStore)
{
    Debug_ASSERT_SELF(keyStoreCtx);
    return keyStoreCtx->vtable->copyKey(keyStoreCtx,
                                        keyHandle,
                                        name,
                                        destKeyStore);
}

seos_err_t
SeosKeyStoreApi_moveKey(SeosKeyStoreCtx*        keyStoreCtx,
                        SeosCrypto_KeyHandle    keyHandle,
                        const char*             name,
                        SeosKeyStoreCtx*        destKeyStore)
{
    Debug_ASSERT_SELF(keyStoreCtx);
    return keyStoreCtx->vtable->moveKey(keyStoreCtx,
                                        keyHandle,
                                        name,
                                        destKeyStore);
}

seos_err_t
SeosKeyStoreApi_generateKey(SeosKeyStoreCtx*            keyStoreCtx,
                            SeosCrypto_KeyHandle*       keyHandle,
                            const char*                 name,
                            unsigned int                algorithm,
                            unsigned int                flags,
                            size_t                      lenBits)
{
    Debug_ASSERT_SELF(keyStoreCtx);
    return keyStoreCtx->vtable->generateKey(keyStoreCtx,
                                            keyHandle,
                                            name,
                                            algorithm,
                                            flags,
                                            lenBits);
}

