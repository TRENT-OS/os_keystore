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
                          size_t                    keySize)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        ((char*)(self->serverDataport))[PAGE_SIZE - 1] = 0;
        retval = SeosKeyStore_importKey(self->seosKeyStoreCtx,
                                        (self->serverDataport + keySize),
                                        self->serverDataport,
                                        keySize);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_importKey failed, err %d!", __func__, retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreRpc_getKey(SeosKeyStoreRpc* self,
                       size_t* keysize)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        char keyData[MAX_KEY_LEN] = {0};
        ((char*)(self->serverDataport))[PAGE_SIZE - 1] = 0;

        retval = SeosKeyStore_getKey(self->seosKeyStoreCtx,
                                     self->serverDataport,
                                     keyData,
                                     keysize);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_getKey failed, err %d!", __func__, retval);
        }

        memcpy(self->serverDataport, keyData, *keysize);
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
        retval = SeosKeyStore_deleteKey(self->seosKeyStoreCtx,
                                        self->serverDataport);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_deleteKey failed, err %d!", __func__, retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreRpc_copyKey(SeosKeyStoreRpc*        self,
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
        ((char*)(self->serverDataport))[PAGE_SIZE - 1] = 0;
        retval = SeosKeyStore_copyKey(self->seosKeyStoreCtx,
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
        ((char*)(self->serverDataport))[PAGE_SIZE - 1] = 0;
        retval = SeosKeyStore_moveKey(self->seosKeyStoreCtx,
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
SeosKeyStoreRpc_wipeKeyStore(SeosKeyStoreRpc* self)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (!isValidHandle(self))
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        retval = SeosKeyStore_wipeKeyStore(self->seosKeyStoreCtx);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStore_wipeKeyStore failed, err %d!", __func__,
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