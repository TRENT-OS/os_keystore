/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Keystore.h"
#include "OS_Keystore_Vtable.h"
#include "OS_Crypto.h"

#include <stdlib.h>

OS_Error_t
OS_Keystore_storeKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    void const*          keyData,
    size_t               keySize)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->vtable->storeKey(hKeystore, name, keyData, keySize);
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
           hKeystore->vtable->loadKey(hKeystore, name, keyData, keySize);
}

OS_Error_t
OS_Keystore_deleteKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->vtable->deleteKey(hKeystore, name);
}

OS_Error_t
OS_Keystore_copyKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    OS_Keystore_Handle_t hDestKeystore)
{
    return (NULL == hKeystore || NULL == hDestKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->vtable->copyKey(hKeystore, name, hDestKeystore);
}

OS_Error_t
OS_Keystore_moveKey(
    OS_Keystore_Handle_t hKeystore,
    const char*          name,
    OS_Keystore_Handle_t hDestKeystore)
{
    return (NULL == hKeystore || NULL == hDestKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->vtable->moveKey(hKeystore, name, hDestKeystore);
}

OS_Error_t
OS_Keystore_wipeKeystore(
    OS_Keystore_Handle_t hKeystore)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->vtable->wipeKeystore(hKeystore);
}

OS_Error_t
OS_Keystore_free(
    OS_Keystore_Handle_t hKeystore)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->vtable->free(hKeystore);
}
