/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Keystore.h"
#include "OS_Crypto.h"

#include "KeystoreImpl.h"

#include <stdlib.h>

// For now, we only have the LIB so lets use just that; later we may have other
// implementations below this API level..
struct OS_Keystore
{
    KeystoreImpl_t impl;
};

OS_Error_t
OS_Keystore_storeKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    void const*          keyData,
    size_t               keySize)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->storeKey(hKeystore->impl.context, name,
                                            keyData, keySize);
}

OS_Error_t
OS_Keystore_loadKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    void*                keyData,
    size_t*              keySize)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->loadKey(hKeystore->impl.context, name, keyData,
                                           keySize);
}

OS_Error_t
OS_Keystore_deleteKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->deleteKey(hKeystore->impl.context, name);
}

OS_Error_t
OS_Keystore_copyKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    OS_Keystore_Handle_t hDestKeystore)
{
    return (NULL == hKeystore || NULL == hDestKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->copyKey(hKeystore->impl.context, name,
                                           hDestKeystore->impl.context);
}

OS_Error_t
OS_Keystore_moveKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    OS_Keystore_Handle_t hDestKeystore)
{
    return (NULL == hKeystore || NULL == hDestKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->moveKey(hKeystore->impl.context, name,
                                           hDestKeystore->impl.context);
}

OS_Error_t
OS_Keystore_wipeKeystore(
    OS_Keystore_Handle_t hKeystore)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->wipeKeystore(hKeystore->impl.context);
}

OS_Error_t
OS_Keystore_free(
    OS_Keystore_Handle_t hKeystore)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->impl.vtable->free(hKeystore->impl.context);
}
