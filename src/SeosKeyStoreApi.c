/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */


/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStoreCtx.h"
#include "SeosKeyStoreApi.h"


/* Public functions ----------------------------------------------------------*/

//------------------------------------------------------------------------------
seos_err_t
SeosKeyStoreApi_importKey(
    SeosKeyStoreCtx*  keyStoreCtx,
    const char*       name,
    void const*       keyData,
    size_t            keySize)
{
    return keyStoreCtx->vtable->importKey(
               keyStoreCtx,
               name,
               keyData,
               keySize);
}

//------------------------------------------------------------------------------
seos_err_t
SeosKeyStoreApi_getKey(
    SeosKeyStoreCtx*  keyStoreCtx,
    const char*       name,
    void*             keyData,
    size_t*           keySize)
{
    return keyStoreCtx->vtable->getKey(
               keyStoreCtx,
               name,
               keyData,
               keySize);
}


//------------------------------------------------------------------------------
seos_err_t
SeosKeyStoreApi_deleteKey(
    SeosKeyStoreCtx*  keyStoreCtx,
    const char*       name)
{
    return keyStoreCtx->vtable->deleteKey(
               keyStoreCtx,
               name);
}


//------------------------------------------------------------------------------
seos_err_t
SeosKeyStoreApi_copyKey(
    SeosKeyStoreCtx*  keyStoreCtx,
    const char*       name,
    SeosKeyStoreCtx*  destKeyStore)
{
    return keyStoreCtx->vtable->copyKey(
               keyStoreCtx,
               name,
               destKeyStore);
}


//------------------------------------------------------------------------------
seos_err_t
SeosKeyStoreApi_moveKey(
    SeosKeyStoreCtx*  keyStoreCtx,
    const char*       name,
    SeosKeyStoreCtx*  destKeyStore)
{
    return keyStoreCtx->vtable->moveKey(
               keyStoreCtx,
               name,
               destKeyStore);
}


//------------------------------------------------------------------------------
seos_err_t
SeosKeyStoreApi_wipeKeyStore(
    SeosKeyStoreCtx* keyStoreCtx)
{
    return keyStoreCtx->vtable->wipeKeyStore(
               keyStoreCtx);
}
