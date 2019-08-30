/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */
/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreClient.h"
#include "LibDebug/Debug.h"

/* Macros --------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)  (lenBits / CHAR_BIT + ((lenBits % CHAR_BIT) ? 1 : 0))

/* Private variables ----------------------------------------------------------*/
static const SeosKeyStoreCtx_Vtable SeosKeyStoreClient_vtable =
{
    .importKey      = SeosKeyStoreClient_importKey,
    .getKey         = SeosKeyStoreClient_getKey,
    .deleteKey      = SeosKeyStoreClient_deleteKey,
    .closeKey       = SeosKeyStoreClient_closeKey,
    .copyKey        = SeosKeyStoreClient_copyKey,
    .moveKey        = SeosKeyStoreClient_moveKey,
    .generateKey    = SeosKeyStoreClient_generateKey,
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
SeosKeyStoreClient_importKey(SeosKeyStoreCtx*            keyStoreCtx,
                             SeosCrypto_KeyHandle*       keyHandle,
                             const char*                 name,
                             void const*                 keyBytesBuffer,
                             unsigned int                algorithm,
                             unsigned int                flags,
                             size_t                      lenBits)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
    seos_err_t retval = SEOS_ERROR_GENERIC;
    size_t nameLen = strlen(name);

    if (NULL == name || (nameLen + LEN_BITS_TO_BYTES(lenBits)) > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        memcpy(self->clientDataport, keyBytesBuffer, LEN_BITS_TO_BYTES(lenBits));
        strncpy(self->clientDataport + LEN_BITS_TO_BYTES(lenBits), name,
                PAGE_SIZE - LEN_BITS_TO_BYTES(lenBits));

        retval = SeosKeyStoreRpc_importKey(self->rpcHandle, keyHandle, algorithm, flags,
                                           lenBits);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStoreRpc_importKey failed, err %d!", __func__,
                            retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreClient_getKey(SeosKeyStoreCtx*            keyStoreCtx,
                          SeosCrypto_KeyHandle*       keyHandle,
                          const char*                 name)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
    seos_err_t retval = SEOS_ERROR_GENERIC;
    size_t nameLen = strlen(name);

    if (NULL == name || nameLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        strncpy(self->clientDataport, name, PAGE_SIZE);
        retval = SeosKeyStoreRpc_getKey(self->rpcHandle, keyHandle);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStoreRpc_getKey failed, err %d!", __func__,
                            retval);
        }
    }

    return retval;
}

seos_err_t
SeosKeyStoreClient_deleteKey(SeosKeyStoreCtx*        keyStoreCtx,
                             SeosCrypto_KeyHandle    keyHandle)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    retval = SeosKeyStoreRpc_deleteKey(self->rpcHandle, keyHandle);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_deleteKey failed, err %d!", __func__,
                        retval);
    }

    return retval;
}

seos_err_t
SeosKeyStoreClient_closeKey(SeosKeyStoreCtx*        keyStoreCtx,
                            SeosCrypto_KeyHandle    keyHandle)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    retval = SeosKeyStoreRpc_closeKey(self->rpcHandle, keyHandle);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_closeKey failed, err %d!", __func__,
                        retval);
    }

    return retval;
}

seos_err_t
SeosKeyStoreClient_copyKey(SeosKeyStoreCtx*        keyStoreCtx,
                           SeosCrypto_KeyHandle    keyHandle,
                           SeosKeyStoreCtx*        destKeyStore)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    SeosKeyStoreClient* destKeyStoreRpc = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStoreRpc);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    retval = SeosKeyStoreRpc_copyKey(self->rpcHandle, keyHandle,
                                     destKeyStoreRpc->rpcHandle);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_copyKey failed, err %d!", __func__,
                        retval);
    }


    return retval;
}

seos_err_t
SeosKeyStoreClient_moveKey(SeosKeyStoreCtx*        keyStoreCtx,
                           SeosCrypto_KeyHandle    keyHandle,
                           SeosKeyStoreCtx*        destKeyStore)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    SeosKeyStoreClient* destKeyStoreRpc = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStoreRpc);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    retval = SeosKeyStoreRpc_moveKey(self->rpcHandle, keyHandle,
                                     destKeyStoreRpc->rpcHandle);
    if (retval != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosKeyStoreRpc_moveKey failed, err %d!", __func__,
                        retval);
    }

    return retval;
}

seos_err_t
SeosKeyStoreClient_generateKey(SeosKeyStoreCtx*            keyStoreCtx,
                               SeosCrypto_KeyHandle*       keyHandle,
                               const char*                 name,
                               unsigned int                algorithm,
                               unsigned int                flags,
                               size_t                      lenBits)
{
    SeosKeyStoreClient* self = (SeosKeyStoreClient*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStoreClient_vtable);
    seos_err_t retval = SEOS_ERROR_GENERIC;
    size_t nameLen = strlen(name);

    if (NULL == name || nameLen > PAGE_SIZE)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        strncpy(self->clientDataport, name, PAGE_SIZE);
        retval = SeosKeyStoreRpc_generateKey(self->rpcHandle, keyHandle, algorithm,
                                             flags, lenBits);
        if (retval != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: SeosKeyStoreRpc_generateKey failed, err %d!", __func__,
                            retval);
        }
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