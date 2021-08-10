/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

/**
 * @file
 *
 * Common part of the OS_Keystore API implementation.
 *
 * Its aim is to:
 * - dereference the Vtable when calling the functions of the API,
 * - define the 'default' implementations of those functions (when provided).
 */

#include "OS_Keystore.int.h"
#include "lib_debug/Debug.h"

#include <string.h>

OS_Error_t
OS_Keystore_free(
    OS_Keystore_Handle_t hKeystore)
{
    return (NULL == hKeystore) ?
           OS_ERROR_INVALID_HANDLE :
           hKeystore->vtable->free(hKeystore);
}

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


// Non virtual functions -------------------------------------------------------

OS_Error_t
OS_Keystore_copyKeyImpl(
    OS_Keystore_t*  srcPtr,
    const char*     name,
    OS_Keystore_t*  dstPtr,
    void*           keyBuffer,
    size_t          keyBufferSize)
{
    OS_Error_t err = OS_Keystore_loadKey(
                         srcPtr,
                         name,
                         keyBuffer,
                         &keyBufferSize);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: loadKey failed with err %d!", __func__, err);
        return err;
    }

    err = OS_Keystore_storeKey(dstPtr, name, keyBuffer, keyBufferSize);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: storeKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}

OS_Error_t
OS_Keystore_moveKeyImpl(
    OS_Keystore_t*  srcPtr,
    const char*     name,
    OS_Keystore_t*  dstPtr)
{
    OS_Error_t err = OS_Keystore_copyKey(srcPtr, name, dstPtr);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: copyKey failed with err %d!", __func__, err);
        return err;
    }

    err = OS_Keystore_deleteKey(srcPtr, name);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: deleteKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}
