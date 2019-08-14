/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreApi.h"
#include "SeosKeyStore.h"
#include "SeosKeyStoreRpc.h"

/* Public functions ----------------------------------------------------------*/
seos_err_t
SeosKeyStoreApi_importKey(SeosKeyStoreApi*          self,
                          SeosCrypto_KeyHandle*     keyHandle,
                          const char*               name,
                          void const*               keyBytesBuffer,
                          unsigned int              algorithm,
                          unsigned int              flags,
                          size_t                    lenBits)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->importKey(self,
                                   keyHandle,
                                   name,
                                   keyBytesBuffer,
                                   algorithm,
                                   flags,
                                   lenBits);
}

seos_err_t
SeosKeyStoreApi_getKey(SeosKeyStoreApi*         self,
                       SeosCrypto_KeyHandle*    keyHandle,
                       const char*              name)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->getKey(self,
                                keyHandle,
                                name);
}

seos_err_t
SeosKeyStoreApi_deleteKey(SeosKeyStoreApi*          self,
                          SeosCrypto_KeyHandle      keyHandle,
                          const char*               name)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->deleteKey(self,
                                   keyHandle,
                                   name);
}

seos_err_t
SeosKeyStoreApi_copyKey(SeosKeyStoreApi*        self,
                        SeosCrypto_KeyHandle    keyHandle,
                        const char*             name,
                        SeosKeyStoreApi*        destKeyStore)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->copyKey(self,
                                 keyHandle,
                                 name,
                                 destKeyStore);
}

seos_err_t
SeosKeyStoreApi_moveKey(SeosKeyStoreApi*        self,
                        SeosCrypto_KeyHandle    keyHandle,
                        const char*             name,
                        SeosKeyStoreApi*        destKeyStore)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->moveKey(self,
                                 keyHandle,
                                 name,
                                 destKeyStore);
}

seos_err_t
SeosKeyStoreApi_generateKey(SeosKeyStoreApi*            self,
                            SeosCrypto_KeyHandle*       keyHandle,
                            const char*                 name,
                            unsigned int                algorithm,
                            unsigned int                flags,
                            size_t                      lenBits)
{
    Debug_ASSERT_SELF(self);
    return self->vtable->generateKey(self,
                                     keyHandle,
                                     name,
                                     algorithm,
                                     flags,
                                     lenBits);
}

