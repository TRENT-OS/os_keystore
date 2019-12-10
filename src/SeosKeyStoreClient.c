/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreClient.h"
#include "LibDebug/Debug.h"
#include <string.h>
#include <limits.h>

/* Macros --------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)  (lenBits / CHAR_BIT + ((lenBits % CHAR_BIT) ? 1 : 0))

/* Private variables ----------------------------------------------------------*/
static const SeosKeyStoreCtx_Vtable SeosKeyStoreClient_vtable =
{
    .importKey      = SeosKeyStoreClient_importKey,
    .getKey         = SeosKeyStoreClient_getKey,
    .deleteKey      = SeosKeyStoreClient_deleteKey,
    .copyKey        = SeosKeyStoreClient_copyKey,
    .moveKey        = SeosKeyStoreClient_moveKey,
    .wipeKeyStore   = SeosKeyStoreClient_wipeKeyStore,
    .deInit         = SeosKeyStoreClient_deInit,
};

/* Public functions ----------------------------------------------------------*/
seos_err_t
SeosKeyStoreClient_init(SeosKeyStoreClient*         self,
                        SeosKeyStoreRpc_Handle      rpcHandle,
                        void*                       dataport)
{
    Debug_ASSERT_SELF(self);

    if (NULL == rpcHandle
        || NULL == dataport)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    self->clientDataport    = dataport;
    self->rpcHandle         = rpcHandle;
    self->parent.vtable     = &SeosKeyStoreClient_vtable;

    return SEOS_SUCCESS;
}

void
SeosKeyStoreClient_deInit(SeosKeyStoreCtx* keyStoreCtx)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
}

seos_err_t
SeosKeyStoreClient_importKey(SeosKeyStoreCtx*   keyStoreCtx,
                             const char*        name,
                             void const*        keyData,
                             size_t             keySize)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);

    if (NULL == name || NULL == keyData)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((strlen(name) + keySize) > PAGE_SIZE)
    {
        Debug_LOG_ERROR("%s: the length of the name and the key data is larger than the dataport!",
                        __func__);
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(self->clientDataport, keyData, keySize);
    strncpy(self->clientDataport + keySize, name, PAGE_SIZE - keySize);

    return SeosKeyStoreRpc_importKey(self->rpcHandle, keySize);
}

seos_err_t
SeosKeyStoreClient_getKey(SeosKeyStoreCtx*  keyStoreCtx,
                          const char*       name,
                          void*             keyData,
                          size_t*           keySize)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);

    if (NULL == name || NULL == keyData || NULL == keySize)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    strncpy(self->clientDataport, name, PAGE_SIZE);
    seos_err_t retval = SeosKeyStoreRpc_getKey(self->rpcHandle, keySize);

    if (retval == SEOS_SUCCESS)
    {
        memcpy(keyData, self->clientDataport, *keySize);
    }

    return retval;
}

seos_err_t
SeosKeyStoreClient_deleteKey(SeosKeyStoreCtx*   keyStoreCtx,
                             const char*        name)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);

    if (NULL == name)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    strncpy(self->clientDataport, name, PAGE_SIZE);
    return SeosKeyStoreRpc_deleteKey(self->rpcHandle);
}

seos_err_t
SeosKeyStoreClient_copyKey(SeosKeyStoreCtx* keyStoreCtx,
                           const char*      name,
                           SeosKeyStoreCtx* destKeyStore)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    SeosKeyStoreClient* destKeyStoreRpc = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStoreRpc);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);

    if (NULL == name)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    strncpy(self->clientDataport, name, PAGE_SIZE);
    return SeosKeyStoreRpc_copyKey(self->rpcHandle, destKeyStoreRpc->rpcHandle);
}

seos_err_t
SeosKeyStoreClient_moveKey(SeosKeyStoreCtx* keyStoreCtx,
                           const char*      name,
                           SeosKeyStoreCtx* destKeyStore)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    SeosKeyStoreClient* destKeyStoreRpc = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStoreRpc);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);

    if (NULL == name)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    strncpy(self->clientDataport, name, PAGE_SIZE);
    return SeosKeyStoreRpc_moveKey(self->rpcHandle, destKeyStoreRpc->rpcHandle);
}

seos_err_t
SeosKeyStoreClient_wipeKeyStore(SeosKeyStoreCtx* keyStoreCtx)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);

    return SeosKeyStoreRpc_wipeKeyStore(self->rpcHandle);
}