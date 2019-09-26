/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreClient.h"
#include "LibDebug/Debug.h"
#include <string.h>

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
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name || NULL == keyData)
    {
        Debug_LOG_ERROR("%s: keyData and name of the key can't be NULL!", __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if ((strlen(name) + keySize) > PAGE_SIZE)
    {
        Debug_LOG_ERROR("%s: keyData and name of the key can't be NULL!", __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memcpy(self->clientDataport, keyData, keySize);
    strncpy(self->clientDataport + keySize, name, PAGE_SIZE - keySize);

    retval = SeosKeyStoreRpc_importKey(self->rpcHandle, keySize);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_importKey failed, err %d!", __func__,
                        retval);
    }

    return retval;
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
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name || NULL == keyData || NULL == keySize)
    {
        Debug_LOG_ERROR("%s: keyData, keySize and name of the key can't be NULL!",
                        __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    strncpy(self->clientDataport, name, PAGE_SIZE);
    retval = SeosKeyStoreRpc_getKey(self->rpcHandle, keySize);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_getKey failed, err %d!", __func__,
                        retval);
    }

    memcpy(keyData, self->clientDataport, *keySize);

    return retval;
}

seos_err_t
SeosKeyStoreClient_deleteKey(SeosKeyStoreCtx*   keyStoreCtx,
                             const char*        name)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name)
    {
        Debug_LOG_ERROR("%s: name of the key can't be NULL!", __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    strncpy(self->clientDataport, name, PAGE_SIZE);
    retval = SeosKeyStoreRpc_deleteKey(self->rpcHandle);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_deleteKey failed, err %d!", __func__,
                        retval);
    }

    return retval;
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
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name)
    {
        Debug_LOG_ERROR("%s: name of the key can't be NULL!", __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    strncpy(self->clientDataport, name, PAGE_SIZE);
    retval = SeosKeyStoreRpc_copyKey(self->rpcHandle, destKeyStoreRpc->rpcHandle);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_copyKey failed, err %d!", __func__,
                        retval);
    }

    return retval;
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
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == name)
    {
        Debug_LOG_ERROR("%s: name of the key can't be NULL!", __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    strncpy(self->clientDataport, name, PAGE_SIZE);
    retval = SeosKeyStoreRpc_moveKey(self->rpcHandle, destKeyStoreRpc->rpcHandle);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_moveKey failed, err %d!", __func__,
                        retval);
    }

    return retval;
}

seos_err_t
SeosKeyStoreClient_wipeKeyStore(SeosKeyStoreCtx* keyStoreCtx)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    retval = SeosKeyStoreRpc_wipeKeyStore(self->rpcHandle);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_wipeKeyStore failed, err %d!", __func__,
                        retval);
    }

    return retval;
}