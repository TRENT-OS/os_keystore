/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreClient.h"
#include "LibDebug/Debug.h"

/* Public functions ----------------------------------------------------------*/
seos_err_t
SeosKeyStoreClient_init(SeosKeyStoreClient* self, SeosKeyStoreRpc_Handle rpcHandle, void* dataport)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    memset(self, 0, sizeof(*self));

    if (NULL == rpcHandle || NULL == dataport)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }

    self->clientDataport    = dataport;
    self->rpcHandle         = rpcHandle;
    retval                  = SEOS_SUCCESS;

exit:
    return retval;
}

void
SeosKeyStoreClient_deInit(SeosKeyStoreClient* self)
{
    Debug_ASSERT_SELF(self);
}

seos_err_t
SeosKeyStoreClient_importKey(SeosKeyStoreClient* self, const char* name, SeosCryptoKey*  key)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name || strlen(name) > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // load data from the dataport
        // calculation
        // store data to the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreClient_getKey(SeosKeyStoreClient* self, const char* name, SeosCryptoKey* key, char* keyBytes, SeosKeyStore_KeyType* keyType)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name || strlen(name) > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // load data from the dataport
        // calculation
        // store data to the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreClient_getKeySizeBytes(SeosKeyStoreClient* self, const char* name, size_t* keySize)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name || strlen(name) > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // load data from the dataport
        // calculation
        // store data to the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreClient_deleteKey(SeosKeyStoreClient* self, const char* name)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name || strlen(name) > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // load data from the dataport
        // calculation
        // store data to the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreClient_copyKey(SeosKeyStoreClient* self, const char* name, SeosKeyStoreClient* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name || strlen(name) > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // load data from the dataport
        // calculation
        // store data to the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreClient_moveKey(SeosKeyStoreClient* self, const char* name, SeosKeyStoreClient* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name || strlen(name) > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // load data from the dataport
        // calculation
        // store data to the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreClient_generateKey(SeosKeyStoreClient* self, SeosCryptoKey* key, const char* name, char* keyBytes, SeosKeyStore_KeyType* keyType)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name || strlen(name) > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // load data from the dataport
        // calculation
        // store data to the dataport
    }
    
    return retval;
}