/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreCtx.h"
#include "SeosKeyStoreApi.h"
#include "KeyStoreCtxRegister.h"

/* Private variables ---------------------------------------------------------*/
static KeyStoreCtxRegister ctxRegisterInstance;
static KeyStoreCtxRegister* ctxRegisterHandle = NULL;

/* Private function prototypes -----------------------------------------------*/
static KeyStoreCtxRegister* KeyStoreCtxRegister_getInstance();
static seos_err_t registerContext(SeosKeyStoreCtxHandle* keyStoreCtx,
                                  SeosCrypto_KeyHandle* keyHandle);
static SeosKeyStoreCtx* retreiveContext(SeosCrypto_KeyHandle* keyHandle);
static void deregisterContext(SeosCrypto_KeyHandle keyHandle);

/* Public functions ----------------------------------------------------------*/
seos_err_t
SeosKeyStoreApi_importKey(SeosKeyStoreCtx*          keyStoreCtx,
                          SeosCrypto_KeyHandle*     keyHandle,
                          const char*               name,
                          void const*               keyBytesBuffer,
                          unsigned int              algorithm,
                          unsigned int              flags,
                          size_t                    lenBits)
{
    seos_err_t retval = keyStoreCtx->vtable->importKey(keyStoreCtx,
                                                       keyHandle,
                                                       name,
                                                       keyBytesBuffer,
                                                       algorithm,
                                                       flags,
                                                       lenBits);
    if (retval == SEOS_SUCCESS)
    {
        retval = registerContext(&keyStoreCtx, keyHandle);
    }
    else
    {
        retval = keyStoreCtx->vtable->deleteKey(keyStoreCtx,
                                                *keyHandle);
    }

    return retval;
}

seos_err_t
SeosKeyStoreApi_getKey(SeosKeyStoreCtx*         keyStoreCtx,
                       SeosCrypto_KeyHandle*    keyHandle,
                       const char*              name)
{
    seos_err_t retval = keyStoreCtx->vtable->getKey(keyStoreCtx,
                                                    keyHandle,
                                                    name);
    if (retval == SEOS_SUCCESS)
    {
        retval = registerContext(&keyStoreCtx, keyHandle);
    }
    else
    {
        retval = keyStoreCtx->vtable->closeKey(keyStoreCtx,
                                               *keyHandle);
    }

    return retval;
}

seos_err_t
SeosKeyStoreApi_deleteKey(SeosCrypto_KeyHandle keyHandle)
{
    SeosKeyStoreCtx* keyStoreCtx = retreiveContext(&keyHandle);
    if (keyStoreCtx == NULL)
    {
        Debug_LOG_ERROR("Failed to retreive the context!");
        return SEOS_ERROR_NOT_FOUND;
    }

    seos_err_t retval = keyStoreCtx->vtable->deleteKey(keyStoreCtx,
                                                       keyHandle);
    if (retval == SEOS_SUCCESS)
    {
        deregisterContext(keyHandle);
    }

    return retval;
}

seos_err_t SeosKeyStoreApi_closeKey(SeosCrypto_KeyHandle keyHandle)
{
    SeosKeyStoreCtx* keyStoreCtx = retreiveContext(&keyHandle);
    if (keyStoreCtx == NULL)
    {
        Debug_LOG_ERROR("Failed to retreive the context!");
        return SEOS_ERROR_NOT_FOUND;
    }

    seos_err_t retval = keyStoreCtx->vtable->closeKey(keyStoreCtx,
                                                      keyHandle);
    if (retval == SEOS_SUCCESS)
    {
        deregisterContext(keyHandle);
    }

    return retval;
}

seos_err_t
SeosKeyStoreApi_copyKey(SeosCrypto_KeyHandle    keyHandle,
                        SeosKeyStoreCtx*        destKeyStore)
{
    SeosKeyStoreCtx* keyStoreCtx = retreiveContext(&keyHandle);
    if (keyStoreCtx == NULL)
    {
        Debug_LOG_ERROR("Failed to retreive the context!");
        return SEOS_ERROR_NOT_FOUND;
    }

    return keyStoreCtx->vtable->copyKey(keyStoreCtx,
                                        keyHandle,
                                        destKeyStore);
}

seos_err_t
SeosKeyStoreApi_moveKey(SeosCrypto_KeyHandle    keyHandle,
                        SeosKeyStoreCtx*        destKeyStore)
{
    SeosKeyStoreCtx* keyStoreCtx = retreiveContext(&keyHandle);
    if (keyStoreCtx == NULL)
    {
        Debug_LOG_ERROR("Failed to retreive the context!");
        return SEOS_ERROR_NOT_FOUND;
    }

    seos_err_t retval = keyStoreCtx->vtable->moveKey(keyStoreCtx,
                                                     keyHandle,
                                                     destKeyStore);
    if (retval == SEOS_SUCCESS)
    {
        deregisterContext(keyHandle);
    }

    return retval;
}

seos_err_t
SeosKeyStoreApi_generateKey(SeosKeyStoreCtx*            keyStoreCtx,
                            SeosCrypto_KeyHandle*       keyHandle,
                            const char*                 name,
                            unsigned int                algorithm,
                            unsigned int                flags,
                            size_t                      lenBits)
{
    seos_err_t retval = keyStoreCtx->vtable->generateKey(keyStoreCtx,
                                                         keyHandle,
                                                         name,
                                                         algorithm,
                                                         flags,
                                                         lenBits);
    if (retval == SEOS_SUCCESS)
    {
        retval = registerContext(&keyStoreCtx, keyHandle);
    }
    else
    {
        retval = keyStoreCtx->vtable->deleteKey(keyStoreCtx,
                                                *keyHandle);
    }

    return retval;
}

/* Private functions ----------------------------------------------------------*/
static KeyStoreCtxRegister* KeyStoreCtxRegister_getInstance()
{
    if (ctxRegisterHandle == NULL)
    {
        if (!KeyStoreCtxRegister_ctor(&ctxRegisterInstance, 1))
        {
            Debug_LOG_ERROR("Failed to construct the key store context register!");
            return NULL;
        }

        ctxRegisterHandle = &ctxRegisterInstance;
    }

    return ctxRegisterHandle;
}

static seos_err_t registerContext(SeosKeyStoreCtxHandle*    keyStoreCtx,
                                  SeosCrypto_KeyHandle*   keyHandle)
{
    KeyStoreCtxRegister* ctxRegister = KeyStoreCtxRegister_getInstance();
    if (!KeyStoreCtxRegister_insert(ctxRegister, keyHandle, keyStoreCtx))
    {
        Debug_LOG_ERROR("%s: Failed to save the context!", __func__);
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }
    return SEOS_SUCCESS;
}

static SeosKeyStoreCtx* retreiveContext(SeosCrypto_KeyHandle* keyHandle)
{
    KeyStoreCtxRegister* ctxRegister = KeyStoreCtxRegister_getInstance();
    int index = KeyStoreCtxRegister_getIndexOf(ctxRegister, keyHandle);
    if (index < 0)
    {
        Debug_LOG_ERROR("%s: Key corresponding to the passed key handle not found!",
                        __func__);
        return NULL;
    }
    //the cast is necessary here because of the const qualifier
    //(so the context doesn't have to have const everywhere)
    SeosKeyStoreCtxHandle* ctxHandle = (SeosKeyStoreCtxHandle*)
                                       KeyStoreCtxRegister_getValueAt(ctxRegister, index);

    return *ctxHandle;
}

static void deregisterContext(SeosCrypto_KeyHandle keyHandle)
{
    KeyStoreCtxRegister* ctxRegister = KeyStoreCtxRegister_getInstance();
    Debug_ASSERT(KeyStoreCtxRegister_remove(ctxRegister, &keyHandle));
}

