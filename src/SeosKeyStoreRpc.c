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

    if (NULL == self || NULL == keyStoreCtx || NULL == serverDataport)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));
    self->seosKeyStoreCtx   = keyStoreCtx;
    self->serverDataport    = serverDataport;

    if (!registerHandle(self))
    {
        SeosKeyStoreRpc_deInit(self);
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return SEOS_SUCCESS;
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

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    ((char*)(self->serverDataport))[PAGE_SIZE - 1] = 0;

    return SeosKeyStore_importKey(self->seosKeyStoreCtx,
                                    (self->serverDataport + keySize),
                                    self->serverDataport,
                                    keySize);
}

seos_err_t
SeosKeyStoreRpc_getKey(SeosKeyStoreRpc* self,
                       size_t* keysize)
{
    Debug_ASSERT_SELF(self);

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    char keyData[MAX_KEY_LEN] = {0};
    ((char*)(self->serverDataport))[PAGE_SIZE - 1] = 0;

    seos_err_t retval = SeosKeyStore_getKey(self->seosKeyStoreCtx,
                                            self->serverDataport,
                                            keyData,
                                            keysize);
    if (retval == SEOS_SUCCESS)
    {
        memcpy(self->serverDataport, keyData, *keysize);
    }

    return retval;
}

seos_err_t
SeosKeyStoreRpc_deleteKey(SeosKeyStoreRpc* self)
{
    Debug_ASSERT_SELF(self);

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    return SeosKeyStore_deleteKey(self->seosKeyStoreCtx,
                                    self->serverDataport);
}

seos_err_t
SeosKeyStoreRpc_copyKey(SeosKeyStoreRpc*        self,
                        SeosKeyStoreRpc*        destKeyStore)
{
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStore);

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    ((char*)(self->serverDataport))[PAGE_SIZE - 1] = 0;

    return SeosKeyStore_copyKey(self->seosKeyStoreCtx,
                                self->serverDataport,
                                destKeyStore->seosKeyStoreCtx);
}

seos_err_t
SeosKeyStoreRpc_moveKey(SeosKeyStoreRpc*        self,
                        SeosKeyStoreRpc*        destKeyStore)
{
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStore);

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    ((char*)(self->serverDataport))[PAGE_SIZE - 1] = 0;

    return SeosKeyStore_moveKey(self->seosKeyStoreCtx,
                                self->serverDataport,
                                destKeyStore->seosKeyStoreCtx);
}

seos_err_t
SeosKeyStoreRpc_wipeKeyStore(SeosKeyStoreRpc* self)
{
    Debug_ASSERT_SELF(self);

    if (!isValidHandle(self))
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    return SeosKeyStore_wipeKeyStore(self->seosKeyStoreCtx);
}

/* Private functions ---------------------------------------------------------*/
static inline bool
registerHandle(SeosKeyStoreRpc* self)
{
    if (handle != NULL)
    {
        return false;
    }

    handle = self;
    return true;
}

static inline bool
isValidHandle(SeosKeyStoreRpc* self)
{
    return handle != NULL && self == handle;
}