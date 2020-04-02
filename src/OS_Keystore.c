/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Keystore.h"
#include "OS_Crypto.h"

#include "KeystoreImpl.h"
#include "KeystoreLib.h"

#include <stdlib.h>

// For now, we only have the LIB so lets use just that; later we may have other
// implementations below this API level..
struct OS_Keystore
{
    KeystoreImpl_t impl;
};

seos_err_t
OS_Keystore_storeKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    void const*          keyData,
    size_t               keySize)
{
    return (NULL == hKeystore) ?
           SEOS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->storeKey(hKeystore->impl.context, name,
                                            keyData, keySize);
}

seos_err_t
OS_Keystore_loadKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    void*                keyData,
    size_t*              keySize)
{
    return (NULL == hKeystore) ?
           SEOS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->loadKey(hKeystore->impl.context, name, keyData,
                                           keySize);
}

seos_err_t
OS_Keystore_deleteKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name)
{
    return (NULL == hKeystore) ?
           SEOS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->deleteKey(hKeystore->impl.context, name);
}

seos_err_t
OS_Keystore_copyKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    OS_Keystore_Handle_t hDestKeystore)
{
    return (NULL == hKeystore || NULL == hDestKeystore) ?
           SEOS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->copyKey(hKeystore->impl.context, name,
                                           hDestKeystore->impl.context);
}

seos_err_t
OS_Keystore_moveKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    OS_Keystore_Handle_t hDestKeystore)
{
    return (NULL == hKeystore || NULL == hDestKeystore) ?
           SEOS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->moveKey(hKeystore->impl.context, name,
                                           hDestKeystore->impl.context);
}

seos_err_t
OS_Keystore_wipeKeystore(
    OS_Keystore_Handle_t hKeystore)
{
    return (NULL == hKeystore) ?
           SEOS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->wipeKeystore(hKeystore->impl.context);
}

seos_err_t
OS_Keystore_init(
    OS_Keystore_Handle_t* hKeystore,
    FileStreamFactory*    fileStreamFactory,
    OS_Crypto_Handle_t    hCrypto,
    const char*           name)
{
    seos_err_t err;

    if (NULL == hKeystore)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    if ((*hKeystore = malloc(sizeof(OS_Keystore_t))) == NULL)
    {
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    if ((err = KeystoreLib_init(&((*hKeystore)->impl), fileStreamFactory, hCrypto,
                                name)) != SEOS_SUCCESS)
    {
        free(*hKeystore);
    }

    return err;
}

seos_err_t
OS_Keystore_free(
    OS_Keystore_Handle_t hKeystore)
{
    seos_err_t err;

    if (NULL == hKeystore)
    {
        return SEOS_ERROR_INVALID_HANDLE;
    }

    err = KeystoreLib_free(&hKeystore->impl);
    free(hKeystore);

    return err;
}