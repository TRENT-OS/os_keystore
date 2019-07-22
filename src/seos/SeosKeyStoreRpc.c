/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreRpc.h"
#include "SeosKeyStore.h"
#include "LibDebug/Debug.h"

/* Private functions prototypes ----------------------------------------------*/
static bool registerHandle(SeosKeyStoreRpc* self);
static bool isValidHandle(SeosKeyStoreRpc* self);

/* Private variables ---------------------------------------------------------*/
SeosKeyStoreRpc* handle = NULL;

/* Public functions ----------------------------------------------------------*/
seos_err_t
SeosKeyStoreRpc_init(SeosKeyStoreRpc*   self,
                    SeosKeyStore*       SeosKeyStoreApiCtx,
                    void*               serverDataport)
{
    Debug_ASSERT_SELF(self);
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == SeosKeyStoreApiCtx || NULL == serverDataport)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    memset(self, 0, sizeof(*self));
    self->seosKeyStoreCtx   = SeosKeyStoreApiCtx;
    self->serverDataport    = serverDataport;
    retval                  = SEOS_SUCCESS;

    if (!registerHandle(self))
    {
        SeosKeyStoreRpc_deInit(self);
        retval = SEOS_ERROR_INSUFFICIENT_SPACE;
    }
exit:
    return retval;
}

void
SeosKeyStoreRpc_deInit(SeosKeyStoreRpc* self)
{
    Debug_ASSERT_SELF(self);
    return;
}

seos_err_t
SeosKeyStoreRpc_importKey(SeosKeyStoreRpc* self)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // save to the dataport
        // call rpc
        // read from the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreRpc_getKey(SeosKeyStoreRpc* self, SeosCrypto_KeyHandle* key)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // save to the dataport
        // call rpc
        // read from the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreRpc_getKeySizeBytes(SeosKeyStoreRpc* self)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // save to the dataport
        // call rpc
        // read from the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreRpc_deleteKey(SeosKeyStoreRpc* self)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // save to the dataport
        // call rpc
        // read from the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreRpc_copyKey(SeosKeyStoreRpc* self, SeosKeyStoreRpc* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // save to the dataport
        // call rpc
        // read from the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreRpc_moveKey(SeosKeyStoreRpc* self, SeosKeyStoreRpc* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // save to the dataport
        // call rpc
        // read from the dataport
    }
    
    return retval;
}

seos_err_t
SeosKeyStoreRpc_generateKey(SeosKeyStoreRpc*            self,
                            SeosCryptoCipher_Algorithm  algorithm,
                            unsigned int                flags,
                            size_t                      lenBits,
                            SeosCrypto_KeyHandle*       key)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        // save to the dataport
        // call rpc
        // read from the dataport
    }
    
    return retval;
}

/* Private functions ---------------------------------------------------------*/
static inline bool
registerHandle(SeosKeyStoreRpc* self)
{
    bool retval = true;

    if (handle != NULL)
    {
        retval = false;
    }
    else
    {
        handle = self;
    }
    return retval;
}

static inline bool
isValidHandle(SeosKeyStoreRpc* self)
{
    return handle != NULL && self == handle;
}