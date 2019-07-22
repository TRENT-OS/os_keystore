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
SeosKeyStoreApi_importKey(SeosKeyStoreApi* self, const char* name, SeosCryptoKey*  key)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_importKey(self->connector.local.keyStore, name, key);
    }
    else
    {
        retval = SeosKeyStoreClient_importKey(self->connector.rpc.client, name, key);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_getKey(SeosKeyStoreApi* self, const char* name, SeosCryptoKey* key, char* keyBytes, SeosKeyStore_KeyType* keyType)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_getKey(self->connector.local.keyStore, name, key, keyBytes, keyType);
    }
    else
    {
        retval = SeosKeyStoreClient_getKey(self->connector.rpc.client, name, key, keyBytes, keyType);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_getKeySizeBytes(SeosKeyStoreApi* self, const char* name, size_t* keySize)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_getKeySizeBytes(self->connector.local.keyStore, name, keySize);
    }
    else
    {
        retval = SeosKeyStoreClient_getKeySizeBytes(self->connector.rpc.client, name, keySize);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_deleteKey(SeosKeyStoreApi* self, const char* name)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_deleteKey(self->connector.local.keyStore, name);
    }
    else
    {
        retval = SeosKeyStoreClient_deleteKey(self->connector.rpc.client, name);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_copyKey(SeosKeyStoreApi* self, const char* name, SeosKeyStoreApi* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_copyKey(self->connector.local.keyStore, name, destKeyStore->connector.local.keyStore);
    }
    else
    {
        retval = SeosKeyStoreClient_copyKey(self->connector.rpc.client, name, destKeyStore->connector.rpc.client);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_moveKey(SeosKeyStoreApi* self, const char* name, SeosKeyStoreApi* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_moveKey(self->connector.local.keyStore, name, destKeyStore->connector.local.keyStore);
    }
    else
    {
        retval = SeosKeyStoreClient_moveKey(self->connector.rpc.client, name, destKeyStore->connector.rpc.client);
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_generateKey(SeosKeyStoreApi* self, SeosCryptoKey* key, const char* name, char* keyBytes, SeosKeyStore_KeyType* keyType)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (self->isLocalConnection)
    {
        retval = SeosKeyStore_generateKey(self->connector.local.keyStore, key, name, keyBytes, keyType);
    }
    else
    {
        retval = SeosKeyStoreClient_generateKey(self->connector.rpc.client, key, name, keyBytes, keyType);
    }
    return retval;
}

