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
SeosKeyStoreApi_initAsLocal(SeosKeyStoreApi* self, SeosKeyStore* keyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    if (keyStore == NULL)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        Debug_LOG_ERROR("%s: Invalid parameters! keyStore == NULL", __func__);
    }
    else
    {
        self->isLocalConnection         = true;
        self->connector.local.keyStore  = keyStore;
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_initAsRpc(SeosKeyStoreApi* self, SeosKeyStoreClient* client)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    if (client == NULL)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        Debug_LOG_ERROR("%s: Invalid parameters! client == NULL", __func__);
    }
    else
    {
        self->isLocalConnection    = false;
        self->connector.rpc.client = client;
    }
    return retval;
}

void
SeosKeyStoreApi_deInit(SeosKeyStoreApi* self)
{
    Debug_ASSERT_SELF(self);
    return;
}

seos_err_t
SeosKeyStoreApi_importKey(SeosKeyStoreApi*          self,
                          SeosCrypto_KeyHandle*   keyHandle,
                          const char*             name,
                          void const*             keyBytesBuffer,
                          unsigned int            algorithm,
                          unsigned int            flags,
                          size_t                  lenBits)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosCrypto_keyImport(self->connector.local.keyStore->cryptoCore,
                                      keyHandle,
                                      algorithm,
                                      flags,
                                      keyBytesBuffer,
                                      lenBits);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosCryptoApi_keyImport failed with err %d!", __func__,
                            retval);
        }
        retval = SeosKeyStore_importKey(self->connector.local.keyStore, name,
                                        *keyHandle);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_importKey failed with err %d!", __func__,
                            retval);
        }
    }
    else
    {
        //retval = SeosKeyStoreClient_importKey(self->connector.rpc.client, name, key);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_getKey(SeosKeyStoreApi* self, SeosCrypto_KeyHandle* keyHandle,
                       const char* name)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_getKey(self->connector.local.keyStore, name, keyHandle);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_getKey failed with err %d!", __func__,
                            retval);
        }
    }
    else
    {
        //retval = SeosKeyStoreClient_getKey(self->connector.rpc.client, name, key, keyBytes, keyType);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_deleteKey(SeosKeyStoreApi* self, SeosCrypto_KeyHandle keyHandle,
                          const char* name)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_deleteKey(self->connector.local.keyStore, name);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_deleteKey failed with err %d!", __func__,
                            retval);
        }
    }
    else
    {
        //retval = SeosKeyStoreClient_deleteKey(self->connector.rpc.client, name);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_copyKey(SeosKeyStoreApi* self, SeosCrypto_KeyHandle keyHandle,
                        const char* name, SeosKeyStoreApi* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_copyKey(self->connector.local.keyStore, name,
                                      destKeyStore->connector.local.keyStore);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_copyKey failed with err %d!", __func__,
                            retval);
        }
    }
    else
    {
        //retval = SeosKeyStoreClient_copyKey(self->connector.rpc.client, name, destKeyStore->connector.rpc.client);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_moveKey(SeosKeyStoreApi* self, SeosCrypto_KeyHandle keyHandle,
                        const char* name, SeosKeyStoreApi* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_moveKey(self->connector.local.keyStore, name,
                                      destKeyStore->connector.local.keyStore);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_moveKey failed with err %d!", __func__,
                            retval);
        }
    }
    else
    {
        //retval = SeosKeyStoreClient_moveKey(self->connector.rpc.client, name, destKeyStore->connector.rpc.client);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_generateKey(SeosKeyStoreApi*        self,
                            SeosCrypto_KeyHandle*   keyHandle,
                            const char*             name,
                            unsigned int            algorithm,
                            unsigned int            flags,
                            size_t                  lenBits)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_generateKey(self->connector.local.keyStore, keyHandle,
                                          name, algorithm, flags, lenBits);
    }
    else
    {
        //retval = SeosKeyStoreClient_generateKey(self->connector.rpc.client, key, name, keyBytes, keyType);
    }
    return retval;
}

