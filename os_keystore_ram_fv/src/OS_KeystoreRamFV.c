/*
 * Copyright (C) 2021, HENSOLDT Cyber GmbH
 */

#include "OS_KeystoreRamFV.h"

#include "lib_debug/Debug.h"

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

// The formally verified keystore offers the chance to map a key by the pair
// name-appId. We are interested only in name, therefore we will always use the
// same appId here defined.
#define APP_ID 0


// Vtable definition -----------------------------------------------------------

static OS_Error_t
OS_KeystoreRamFV_free(
    OS_Keystore_t* ptr);

static OS_Error_t
OS_KeystoreRamFV_storeKey(
    OS_Keystore_t*  ptr,
    const char*     name,
    void const*     keyData,
    size_t          keySize);

static OS_Error_t
OS_KeystoreRamFV_loadKey(
    OS_Keystore_t*  ptr,
    const char*     name,
    void*           keyData,
    size_t*         keySize);

static OS_Error_t
OS_KeystoreRamFV_deleteKey(
    OS_Keystore_t*  ptr,
    const char*     name);

static OS_Error_t
OS_KeystoreRamFV_copyKey(
    OS_Keystore_t*  srcPtr,
    const char*     name,
    OS_Keystore_t*  dstPtr);

static OS_Error_t
OS_KeystoreRamFV_wipeKeystore(
    OS_Keystore_t*  ptr);

static const OS_Keystore_Vtable_t OS_KeystoreRamFV_vtable =
{
    .free           = OS_KeystoreRamFV_free,
    .storeKey       = OS_KeystoreRamFV_storeKey,
    .loadKey        = OS_KeystoreRamFV_loadKey,
    .deleteKey      = OS_KeystoreRamFV_deleteKey,
    .copyKey        = OS_KeystoreRamFV_copyKey,
    .moveKey        = OS_Keystore_moveKeyImpl,
    .wipeKeystore   = OS_KeystoreRamFV_wipeKeystore
};


// Private functions -----------------------------------------------------------

static inline bool
isLoadKeyParametersOk(
    OS_KeystoreRamFV_t* self,
    const char*         name,
    void*               keyData,
    size_t*             keySize)
{
    if (NULL == self || NULL == keySize || NULL == keyData || NULL == name)
    {
        return false;
    }

    size_t nameLen = strlen(name);

    if (nameLen > OS_KeystoreRamFV_MAX_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__, nameLen, OS_KeystoreRamFV_MAX_NAME_LEN);
        return false;
    }

    size_t my_keysize = *keySize;

    if (my_keysize > OS_KeystoreRamFV_MAX_KEY_SIZE)
    {
        Debug_LOG_ERROR("%s: The length of the passed key data %zu is invalid, must be in the range [1;%d]!",
                        __func__, my_keysize, OS_KeystoreRamFV_MAX_KEY_SIZE);
        return false;
    }

    return true;
}

static inline bool
isStoreKeyParametersOk(
    OS_KeystoreRamFV_t* self,
    const char*         name,
    void const*         keyData,
    size_t              keySize)
{
    if (NULL == self || NULL == keyData || NULL == name)
    {
        return false;
    }

    size_t nameLen = strlen(name);

    if (nameLen > OS_KeystoreRamFV_MAX_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__,
                        nameLen,
                        OS_KeystoreRamFV_MAX_NAME_LEN);
        return false;
    }

    if (keySize > OS_KeystoreRamFV_MAX_KEY_SIZE || keySize == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key data %zu is invalid, must be in the range [1;%d]!",
                        __func__, keySize, OS_KeystoreRamFV_MAX_KEY_SIZE);
        return false;
    }

    return true;
}

static OS_Error_t
ctor(
    OS_KeystoreRamFV_t* self,
    void*               buf,
    size_t              bufSize)
{
    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(OS_KeystoreRamFV_t));

    KeystoreRamFV_init(
        &self->fvKeystore,
        OS_KeystoreRamFV_NUM_ELEMENTS_BUFFER(bufSize),
        buf);

    OS_KeystoreRamFV_TO_OS_KEYSTORE(self)->vtable = &OS_KeystoreRamFV_vtable;

    return OS_SUCCESS;
}

static OS_Error_t
dtor(
    OS_KeystoreRamFV_t* self)
{
    if (self == NULL)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    return OS_SUCCESS;
}


// Exported via Vtable ---------------------------------------------------------

static OS_Error_t
OS_KeystoreRamFV_free(
    OS_Keystore_t*  ptr)
{
    OS_KeystoreRamFV_t* self = (OS_KeystoreRamFV_t*) ptr;

    OS_Error_t err = dtor(self);
    if (OS_SUCCESS == err)
    {
        free(self);
    }

    return err;
}

static OS_Error_t
OS_KeystoreRamFV_storeKey(
    OS_Keystore_t*  ptr,
    const char*     name,
    void const*     keyData,
    size_t          keySize)
{
    OS_KeystoreRamFV_t* self = (OS_KeystoreRamFV_t*) ptr;

    if (!isStoreKeyParametersOk(self, name, keyData, keySize))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    memset(&self->keyRecord, 0, sizeof(self->keyRecord));

    strncpy(self->keyRecord.name, name, sizeof(self->keyRecord.name) - 1);
    memcpy(self->keyRecord.data, keyData, keySize);

    KeystoreRamFV_Result_t result = KeystoreRamFV_add(
                                        &self->fvKeystore,
                                        APP_ID,
                                        &self->keyRecord);
    if (result.error)
    {
        Debug_LOG_ERROR("%s: key_store_add() failed, err %d!",
                        __func__,
                        result.error);
        return result.error == KeystoreRamFV_ERR_OUT_OF_SPACE ?
               OS_ERROR_INSUFFICIENT_SPACE : OS_ERROR_INVALID_PARAMETER;
    }

    return OS_SUCCESS;
}

static OS_Error_t
OS_KeystoreRamFV_loadKey(
    OS_Keystore_t*  ptr,
    const char*     name,
    void*           keyData,
    size_t*         keySize)
{
    OS_KeystoreRamFV_t* self = (OS_KeystoreRamFV_t*) ptr;

    if (!isLoadKeyParametersOk(self, name, keyData, keySize))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    // NOTE: The formally verified keystore does not support null-terminated
    // strings but always compares the whole char-array. For adaption a char
    // array of max size needs to be filled with 0 after the name.
    char cleanName[KeystoreRamFV_KEY_NAME_SIZE] = { 0 };
    strncpy(cleanName, name, sizeof(cleanName) - 1);

    KeystoreRamFV_Result_t result = KeystoreRamFV_get(
                                        &self->fvKeystore,
                                        APP_ID,
                                        cleanName,
                                        &self->keyRecord);
    if (result.error)
    {
        *keySize = 0;
        Debug_LOG_ERROR("%s: key_store_add() failed, err %d!",
                        __func__,
                        result.error);
        return result.error == KeystoreRamFV_ERR_NOT_FOUND ?
               OS_ERROR_NOT_FOUND : OS_ERROR_INVALID_PARAMETER;
    }

    if (*keySize == 0)
    {
        return OS_ERROR_BUFFER_TOO_SMALL;
    }

    *keySize =
        *keySize < sizeof(self->keyRecord.data) ?
        *keySize : sizeof(self->keyRecord.data);

    if (keyData != self->keyRecord.data)
    {
        memcpy(keyData, self->keyRecord.data, *keySize);
    }

    return OS_SUCCESS;
}

static OS_Error_t
OS_KeystoreRamFV_deleteKey(
    OS_Keystore_t*  ptr,
    const char*     name)
{
    OS_KeystoreRamFV_t* self = (OS_KeystoreRamFV_t*) ptr;

    if (NULL == self || NULL == name)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);

    if (nameLen > OS_KeystoreRamFV_MAX_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__,
                        nameLen,
                        OS_KeystoreRamFV_MAX_NAME_LEN);
        return OS_ERROR_INVALID_PARAMETER;
    }

    // NOTE: The formally verified keystore does not support null-terminated
    // strings but always compares the whole char-array. For adaption a char
    // array of max size needs to be filled with 0 after the name.
    char cleanName[KeystoreRamFV_KEY_NAME_SIZE] = { 0 };
    strncpy(cleanName, name, sizeof(cleanName) - 1);

    unsigned int err = KeystoreRamFV_delete(
                           &self->fvKeystore,
                           APP_ID,
                           cleanName);
    if (err)
    {
        return err == KeystoreRamFV_ERR_NOT_FOUND ?
               OS_ERROR_NOT_FOUND : OS_ERROR_INVALID_PARAMETER;
    }

    return OS_SUCCESS;
}

static OS_Error_t
OS_KeystoreRamFV_copyKey(
    OS_Keystore_t*  srcPtr,
    const char*     name,
    OS_Keystore_t*  dstPtr)
{
    OS_KeystoreRamFV_t* self = (OS_KeystoreRamFV_t*) srcPtr;
    return OS_Keystore_copyKeyImpl(
               srcPtr,
               name,
               dstPtr,
               self->keyRecord.data,
               sizeof(self->keyRecord.data));
}

static OS_Error_t
OS_KeystoreRamFV_wipeKeystore(
    OS_Keystore_t*  ptr)
{
    OS_KeystoreRamFV_t* self = (OS_KeystoreRamFV_t*) ptr;

    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    KeystoreRamFV_wipe(&self->fvKeystore);

    return OS_SUCCESS;
}


// Public functions ------------------------------------------------------------

OS_Error_t
OS_KeystoreRamFV_init(
    OS_Keystore_Handle_t*   pHandle,
    void*                   buf,
    unsigned                bufSize)
{
    OS_Error_t err = OS_ERROR_GENERIC;
    OS_KeystoreRamFV_t* self = malloc(sizeof(OS_KeystoreRamFV_t));

    if (NULL == self)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    err = ctor(self, buf, bufSize);

    if (err != OS_SUCCESS)
    {
        free(self);
    }
    else
    {
        *pHandle = OS_KeystoreRamFV_TO_OS_KEYSTORE(self);
    }

    return err;
}
