/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreRpc.h"
#include "SeosKeyStore.h"
#include "LibDebug/Debug.h"

/* Macros --------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)  (lenBits / CHAR_BIT + ((lenBits % CHAR_BIT) ? 1 : 0))

/* Private functions prototypes ----------------------------------------------*/
static bool registerHandle(SeosKeyStoreRpc* self);
static bool isValidHandle(SeosKeyStoreRpc* self);

/* Private variables ---------------------------------------------------------*/
static SeosKeyStoreRpc* handle = NULL;

/* Public functions ----------------------------------------------------------*/
seos_err_t
SeosKeyStoreRpc_init(SeosKeyStoreRpc*   self,
                     SeosKeyStoreCtx*   keyStoreCtx,
                     void*              serverDataport)
{
    Debug_ASSERT_SELF(self);
    Debug_LOG_TRACE("%s", __func__);

    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == self || NULL == keyStoreCtx || NULL == serverDataport)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
        goto exit;
    }
    memset(self, 0, sizeof(*self));
    self->seosKeyStoreCtx   = keyStoreCtx;
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
SeosKeyStoreRpc_importKey(SeosKeyStoreRpc*          self,
                          SeosCrypto_KeyHandle*     keyHandle,
                          unsigned int              algorithm,
                          unsigned int              flags,
                          size_t                    lenBits)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosKeyStore_importKey(self->seosKeyStoreCtx,
                                        keyHandle,
                                        (self->serverDataport + LEN_BITS_TO_BYTES(lenBits)),
                                        self->serverDataport,
                                        algorithm,
                                        flags,
                                        lenBits);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_importKey failed, err %d!", __func__, retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreRpc_getKey(SeosKeyStoreRpc*         self,
                       SeosCrypto_KeyHandle*   keyHandle)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosKeyStore_getKey(self->seosKeyStoreCtx,
                                     keyHandle,
                                     self->serverDataport);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_getKey failed, err %d!", __func__, retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreRpc_deleteKey(SeosKeyStoreRpc*          self,
                          SeosCrypto_KeyHandle    keyHandle)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosKeyStore_deleteKey(self->seosKeyStoreCtx,
                                        keyHandle,
                                        self->serverDataport);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_deleteKey failed, err %d!", __func__, retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreRpc_closeKey(SeosKeyStoreRpc*       self,
                         SeosCrypto_KeyHandle   keyHandle)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosKeyStore_closeKey(self->seosKeyStoreCtx,
                                       keyHandle);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_closeKey failed, err %d!", __func__, retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreRpc_copyKey(SeosKeyStoreRpc*        self,
                        SeosCrypto_KeyHandle    keyHandle,
                        SeosKeyStoreRpc*        destKeyStore)
{
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStore);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosKeyStore_copyKey(self->seosKeyStoreCtx,
                                      keyHandle,
                                      self->serverDataport,
                                      destKeyStore->seosKeyStoreCtx);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_copyKey failed, err %d!", __func__, retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreRpc_moveKey(SeosKeyStoreRpc*        self,
                        SeosCrypto_KeyHandle    keyHandle,
                        SeosKeyStoreRpc*        destKeyStore)
{
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStore);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosKeyStore_moveKey(self->seosKeyStoreCtx,
                                      keyHandle,
                                      self->serverDataport,
                                      destKeyStore->seosKeyStoreCtx);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_moveKey failed, err %d!", __func__, retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreRpc_generateKey(SeosKeyStoreRpc*            self,
                            SeosCrypto_KeyHandle*       keyHandle,
                            unsigned int                algorithm,
                            unsigned int                flags,
                            size_t                      lenBits)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosKeyStore_generateKey(self->seosKeyStoreCtx,
                                          keyHandle,
                                          self->serverDataport,
                                          algorithm,
                                          flags,
                                          lenBits);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_generateKey failed, err %d!", __func__,
                            retval);
        }
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