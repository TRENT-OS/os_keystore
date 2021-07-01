/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "OS_KeystoreFile.h"
#include "OS_Keystore.h"
#include "lib_utils/BitConverter.h"

#include <string.h>

#define KEY_LEN_SIZE          (sizeof(uint32_t))
#define KEY_HASH_SIZE         32


// Private functions -----------------------------------------------------------

static OS_Error_t
createKeyHash(
    OS_Crypto_Handle_t hCrypto,
    const void*        keyData,
    size_t             keyDataSize,
    void*              output)
{
    OS_Error_t err = OS_SUCCESS;
    OS_CryptoDigest_Handle_t hDigest;

    err = OS_CryptoDigest_init(
              &hDigest,
              hCrypto,
              OS_CryptoDigest_ALG_SHA256);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoDigest_init() failed with error code %d!",
                        __func__, err);
        goto ERR_EXIT;
    }

    err = OS_CryptoDigest_process(hDigest, keyData, keyDataSize);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoDigest_process() failed with error code %d!",
                        __func__, err);
        goto ERR_DESTRUCT;
    }

    size_t digestSize = KEY_HASH_SIZE;
    err = OS_CryptoDigest_finalize(hDigest, output, &digestSize);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoDigest_finalize() failed with error code %d!",
                        __func__, err);
        goto ERR_DESTRUCT;
    }

ERR_DESTRUCT:
    OS_CryptoDigest_free(hDigest);

ERR_EXIT:
    return err;
}

static void
getFileName(
    const char*  instName,
    const char*  keyName,
    const size_t sz,
    char*        fileName)
{
    // Todo: Eventually we would like to have each instance have its own
    //       directory, but right now we don't support that.

    // Create file name in the format "<instancename>_<keyname>.key".
    snprintf(fileName, sz, "%s_%s.key", instName, keyName);
}

static OS_Error_t
fs_writeKey(
    OS_FileSystem_Handle_t hFs,
    const void*            keyData,
    const void*            keyDataHash,
    size_t                 keySize,
    const char*            instName,
    const char*            keyName)
{
    uint8_t keySizeBuffer[KEY_LEN_SIZE];
    OS_Error_t err = OS_SUCCESS;
    OS_FileSystemFile_Handle_t hFile;
    char fileName[OS_KeystoreFile_MAX_FILE_NAME_LEN + 1]; // null terminated string
    size_t offs;

    getFileName(instName, keyName, sizeof(fileName), fileName);

    err = OS_FileSystemFile_open(
              hFs,
              &hFile,
              fileName,
              OS_FileSystem_OpenMode_RDWR,
              OS_FileSystem_OpenFlags_CREATE);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_open() failed on '%s' with %d",
                        fileName, err);
        return OS_ERROR_OPERATION_DENIED;
    }

    err  = OS_ERROR_OPERATION_DENIED;
    offs = 0;

    err = OS_FileSystemFile_write(
              hFs,
              hFile,
              offs,
              KEY_HASH_SIZE,
              keyDataHash);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_write() failed on '%s' with %d",
                        fileName, err);
        goto err0;
    }

    offs += KEY_HASH_SIZE;

    BitConverter_putUint32BE((uint32_t) keySize, keySizeBuffer);

    err = OS_FileSystemFile_write(
              hFs,
              hFile,
              offs,
              KEY_LEN_SIZE,
              keySizeBuffer);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_write() failed on '%s' with %d",
                        fileName, err);
        goto err0;
    }

    offs += KEY_LEN_SIZE;

    if ((err = OS_FileSystemFile_write(hFs, hFile, offs,
                                       keySize,
                                       keyData)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_write() failed on '%s' with %d",
                        fileName, err);
        goto err0;
    }

err0:
    if ((err = OS_FileSystemFile_close(hFs, hFile)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_close() failed on '%s' with %d",
                        fileName, err);
    }

    return err;
}

static OS_Error_t
fs_readKey(
    OS_FileSystem_Handle_t hFs,
    void*                  keyData,
    void*                  keyDataHash,
    size_t                 keySize,
    const char*            instName,
    const char*            keyName)
{
    uint8_t keySizeBuffer[KEY_LEN_SIZE];
    OS_Error_t err = OS_SUCCESS;
    OS_FileSystemFile_Handle_t hFile;
    char fileName[OS_KeystoreFile_MAX_FILE_NAME_LEN + 1]; // null terminated string
    size_t offs, realKeySize;

    getFileName(instName, keyName, sizeof(fileName), fileName);

    err = OS_FileSystemFile_open(
              hFs,
              &hFile,
              fileName,
              OS_FileSystem_OpenMode_RDONLY,
              OS_FileSystem_OpenFlags_NONE);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_open() failed on '%s' with %d",
                        fileName, err);
        return OS_ERROR_OPERATION_DENIED;
    }

    err  = OS_ERROR_OPERATION_DENIED;
    offs = 0;

    err = OS_FileSystemFile_read(
              hFs,
              hFile,
              offs,
              KEY_HASH_SIZE,
              keyDataHash);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_read() failed on '%s' with %d",
                        fileName, err);
        goto err0;
    }

    offs += KEY_HASH_SIZE;

    err = OS_FileSystemFile_read(
              hFs,
              hFile,
              offs,
              KEY_LEN_SIZE,
              keySizeBuffer);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_read() failed on '%s' with %d",
                        fileName, err);
        goto err0;
    }

    realKeySize = BitConverter_getUint32BE(keySizeBuffer);

    if (realKeySize != keySize)
    {
        Debug_LOG_ERROR("Key size in map (%zu bytes) does not match the size of "
                        "the key data (%zu bytes) found in '%s'",
                        keySize, realKeySize, fileName);
        goto err0;
    }

    offs += KEY_LEN_SIZE;

    err = OS_FileSystemFile_read(
              hFs,
              hFile,
              offs,
              keySize,
              keyData);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_read() failed on '%s' with %d",
                        fileName, err);
        goto err0;
    }

err0:
    if ((err = OS_FileSystemFile_close(hFs, hFile)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_close() failed on '%s' with %d",
                        fileName, err);
    }

    return err;
}

static OS_Error_t
fs_deleteKey(
    OS_FileSystem_Handle_t hFs,
    const char*            instName,
    const char*            keyName)
{
    OS_Error_t err;
    char fileName[OS_KeystoreFile_MAX_FILE_NAME_LEN + 1]; // null terminated string

    getFileName(instName, keyName, sizeof(fileName), fileName);

    if ((err = OS_FileSystemFile_delete(hFs, fileName)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_delete() failed on '%s' with %d",
                        fileName, err);
    }

    return err;
}

static OS_Error_t
map_registerKey(
    OS_KeystoreFile_t*  self,
    const char*         name,
    size_t              keySize)
{
    OS_KeystoreFile_KeyName keyName;

    strncpy(keyName.buffer, name, sizeof(keyName.buffer) - 1);
    keyName.buffer[sizeof(keyName.buffer) - 1] = '\0';

    if (!OS_KeystoreFile_KeyNameMap_insert(
            &self->keyNameMap,
            &keyName,
            &keySize))
    {
        Debug_LOG_ERROR("%s: Failed to save the key name!", __func__);
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    return OS_SUCCESS;
}

static bool
map_checkKeyExists(
    OS_KeystoreFile_t*  self,
    const char*         name)
{
    OS_KeystoreFile_KeyName keyName;

    strncpy(keyName.buffer, name, sizeof(keyName.buffer) - 1);
    keyName.buffer[sizeof(keyName.buffer) - 1] = '\0';

    return OS_KeystoreFile_KeyNameMap_getIndexOf(&self->keyNameMap, &keyName)
           >= 0 ? true : false;
}

static size_t
map_getKeySize(
    OS_KeystoreFile_t*  self,
    const char*         name)
{
    int keyIndex;

    keyIndex = OS_KeystoreFile_KeyNameMap_getIndexOf(
                   &self->keyNameMap,
                   (OS_KeystoreFile_KeyName*) name);

    if (keyIndex < 0)
    {
        return 0;
    }

    return *OS_KeystoreFile_KeyNameMap_getValueAt(&self->keyNameMap, keyIndex);
}

static OS_Error_t
map_deregisterKey(
    OS_KeystoreFile_t*  self,
    const char*         name)
{
    OS_KeystoreFile_KeyName keyName;

    strncpy(keyName.buffer, name, sizeof(keyName.buffer) - 1);
    keyName.buffer[sizeof(keyName.buffer) - 1] = '\0';

    if (!OS_KeystoreFile_KeyNameMap_remove(&self->keyNameMap, &keyName))
    {
        Debug_LOG_ERROR("%s: Failed to remove the key name!", __func__);
        return OS_ERROR_ABORTED;
    }

    return OS_SUCCESS;
}

static inline bool
isStoreKeyParametersOk(
    OS_KeystoreFile_t*  self,
    const char*         name,
    void const*         keyData,
    size_t              keySize)
{
    if (NULL == self || NULL == keyData || NULL == name)
    {
        return false;
    }

    size_t nameLen = strlen(name);

    if (nameLen > OS_KeystoreFile_KeyName_MAX_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__,
                        nameLen,
                        OS_KeystoreFile_KeyName_MAX_NAME_LEN);
        return false;
    }

    if (keySize > OS_KeystoreFile_MAX_KEY_SIZE || keySize == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key data %zu is invalid, must be in the range [1;%d]!",
                        __func__, keySize, OS_KeystoreFile_MAX_KEY_SIZE);
        return false;
    }

    if (map_checkKeyExists(self, name))
    {
        Debug_LOG_ERROR("%s: The key with the name %s already exists!",
                        __func__, name);
        return false;
    }

    return true;
}

static inline bool
isLoadKeyParametersOk(
    OS_KeystoreFile_t*  self,
    const char*         name,
    void*               keyData,
    size_t*             keySize)
{
    if (NULL == self || NULL == keySize || NULL == keyData || NULL == name)
    {
        return false;
    }

    size_t nameLen = strlen(name);

    if (nameLen > OS_KeystoreFile_KeyName_MAX_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__, nameLen, OS_KeystoreFile_KeyName_MAX_NAME_LEN);
        return false;
    }

    size_t my_keysize = *keySize;

    if (my_keysize > OS_KeystoreFile_MAX_KEY_SIZE)
    {
        Debug_LOG_ERROR("%s: The length of the passed key data %zu is invalid, must be in the range [1;%d]!",
                        __func__, my_keysize, OS_KeystoreFile_MAX_KEY_SIZE);
        return false;
    }

    return true;
}


// Exported via VTABLE ---------------------------------------------------------

static OS_Error_t
OS_KeystoreFile_free(
    OS_Keystore_t*  ptr)
{
    if (ptr == NULL)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    OS_KeystoreFile_t* self = (OS_KeystoreFile_t*) ptr;
    OS_KeystoreFile_KeyNameMap_dtor(&self->keyNameMap);

    return OS_SUCCESS;
}

static OS_Error_t
OS_KeystoreFile_storeKey(
    OS_Keystore_t*  ptr,
    const char*     name,
    void const*     keyData,
    size_t          keySize)
{
    OS_Error_t err;
    OS_KeystoreFile_t*  self = (OS_KeystoreFile_t*) ptr;
    char keyDataHash[KEY_HASH_SIZE] = {0};

    if (!isStoreKeyParametersOk(self, name, keyData, keySize))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    err = createKeyHash(
              self->hCrypto,
              keyData,
              keySize,
              keyDataHash);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not hash the key data, err %d!",
                        __func__, err);
        return err;
    }

    err = fs_writeKey(
              self->hFs,
              keyData,
              keyDataHash,
              keySize,
              self->name,
              name);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not write the key data to the file, err %d!",
                        __func__, err);
        return err;
    }

    err = map_registerKey(self, name, keySize);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Failed to register the key name, error code %d!",
                        __func__, err);
        goto err0;
    }

    return OS_SUCCESS;

err0:
    fs_deleteKey(self->hFs, self->name, name);
    return err;
}

static OS_Error_t
OS_KeystoreFile_loadKey(
    OS_Keystore_t*  ptr,
    const char*     name,
    void*           keyData,
    size_t*         keySize)
{
    OS_Error_t err;
    OS_KeystoreFile_t*  self = (OS_KeystoreFile_t*) ptr;
    unsigned char calculatedHash[KEY_HASH_SIZE];
    unsigned char readHash[KEY_HASH_SIZE];

    if (!isLoadKeyParametersOk(self, name, keyData, keySize))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if (!map_checkKeyExists(self, name))
    {
        Debug_LOG_ERROR("%s: The key with the name %s does not exist!",
                        __func__, name);
        return OS_ERROR_NOT_FOUND;
    }

    // Get the size of the written key data from the map and check that the
    // provided buffer is large enough
    size_t savedKeySize = map_getKeySize(self, name);

    if (savedKeySize > *keySize)
    {
        Debug_LOG_ERROR("%s: The actual amount of key data (%zu bytes) is bigger "
                        "than the expected size (%zu byes)",
                        __func__, savedKeySize, *keySize);
        return OS_ERROR_BUFFER_TOO_SMALL;
    }

    err = fs_readKey(
              self->hFs,
              keyData,
              readHash,
              savedKeySize,
              self->name,
              name);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not read the key data from the file, err %d!",
                        __func__, err);
        return err;
    }

    err = createKeyHash(
              self->hCrypto,
              keyData,
              savedKeySize,
              calculatedHash);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not hash the key data, err %d!",
                        __func__, err);
        return err;
    }

    if (memcmp(readHash, calculatedHash, KEY_HASH_SIZE) != 0)
    {
        Debug_LOG_ERROR("%s: The key is corrupted - hash value does not correspond to the data!",
                        __func__);
        err = OS_ERROR_GENERIC;
        return err;
    }

    *keySize = savedKeySize;

    return err;
}

static OS_Error_t
OS_KeystoreFile_deleteKey(
    OS_Keystore_t*  ptr,
    const char*     name)
{
    OS_Error_t err;
    OS_KeystoreFile_t*  self = (OS_KeystoreFile_t*) ptr;

    if (NULL == self || NULL == name)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);

    if (nameLen > OS_KeystoreFile_KeyName_MAX_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__,
                        nameLen,
                        OS_KeystoreFile_KeyName_MAX_NAME_LEN);
        return OS_ERROR_INVALID_PARAMETER;
    }

    if (!map_checkKeyExists(self, name))
    {
        Debug_LOG_ERROR("%s: The key with the name %s does not exist!",
                        __func__, name);
        return OS_ERROR_NOT_FOUND;
    }

    err = map_deregisterKey(self, name);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Failed to deregister the key name, error code %d!",
                        __func__, err);
        return err;
    }

    err = fs_deleteKey(self->hFs, self->name, name);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: fs_deleteKey failed with error code %d!",
                        __func__, err);
        return err;
    }

    return err;
}

static OS_Error_t
OS_KeystoreFile_copyKey(
    OS_Keystore_t*  srcPtr,
    const char*     name,
    OS_Keystore_t*  dstPtr)
{
    OS_Error_t err;
    OS_KeystoreFile_t* self = (OS_KeystoreFile_t*) srcPtr;
    size_t keySize = OS_KeystoreFile_MAX_KEY_SIZE;

    if (NULL == self || NULL == name || NULL == dstPtr)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);

    if (nameLen > OS_KeystoreFile_KeyName_MAX_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__,
                        nameLen,
                        OS_KeystoreFile_KeyName_MAX_NAME_LEN);
        return OS_ERROR_INVALID_PARAMETER;
    }

    err = OS_KeystoreFile_loadKey(srcPtr, name, self->buffer, &keySize);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: loadKey failed with err %d!", __func__, err);
        return err;
    }

    err = OS_KeystoreFile_storeKey(dstPtr, name, self->buffer, keySize);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: storeKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}

static OS_Error_t
OS_KeystoreFile_moveKey(
    OS_Keystore_t*  srcPtr,
    const char*     name,
    OS_Keystore_t*  dstPtr)
{
    OS_Error_t err;

    if (NULL == srcPtr || NULL  == name || NULL == dstPtr)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);

    if (nameLen > OS_KeystoreFile_KeyName_MAX_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__,
                        nameLen,
                        OS_KeystoreFile_KeyName_MAX_NAME_LEN);
        return OS_ERROR_INVALID_PARAMETER;
    }

    err = OS_KeystoreFile_copyKey(srcPtr, name, dstPtr);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: copyKey failed with err %d!", __func__, err);
        return err;
    }

    err = OS_KeystoreFile_deleteKey(srcPtr, name);

    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: deleteKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}

static OS_Error_t
OS_KeystoreFile_wipeKeystore(
    OS_Keystore_t*  ptr)
{
    OS_Error_t err;
    OS_KeystoreFile_t*  self = (OS_KeystoreFile_t*) ptr;

    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    int registerSize = OS_KeystoreFile_KeyNameMap_getSize(&self->keyNameMap);

    if (registerSize < 0)
    {
        Debug_LOG_ERROR("%s: Failed to read the key name register size!",
                        __func__);
        return OS_ERROR_ABORTED;
    }

    if (registerSize == 0)
    {
        Debug_LOG_INFO("%s: Trying to wipe an empty keystore! Returning...",
                       __func__);
        return OS_SUCCESS;
    }

    for (int i = registerSize - 1; i >= 0; i--)
    {
        OS_KeystoreFile_KeyName const* keyName =
            OS_KeystoreFile_KeyNameMap_getKeyAt(&self->keyNameMap, i);
        err = OS_KeystoreFile_deleteKey(ptr, keyName->buffer);

        if (err != OS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: Failed to delete the key %s!",
                            __func__, keyName->buffer);
            return err;
        }
    }

    return err;
}


// Public functions ------------------------------------------------------------

static const OS_Keystore_Vtable_t OS_KeystoreFile_vtable =
{
    .free           = OS_KeystoreFile_free,
    .storeKey       = OS_KeystoreFile_storeKey,
    .loadKey        = OS_KeystoreFile_loadKey,
    .deleteKey      = OS_KeystoreFile_deleteKey,
    .copyKey        = OS_KeystoreFile_copyKey,
    .moveKey        = OS_KeystoreFile_moveKey,
    .wipeKeystore   = OS_KeystoreFile_wipeKeystore
};

OS_Error_t
OS_KeystoreFile_init(
    OS_KeystoreFile_t*     self,
    OS_FileSystem_Handle_t hFs,
    OS_Crypto_Handle_t     hCrypto,
    const char*            name)
{
    if (NULL == self || NULL == hFs || NULL == name)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (strlen(name) > OS_KeystoreFile_MAX_INSTANCE_NAME_LEN)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(OS_KeystoreFile_t));

    if (!OS_KeystoreFile_KeyNameMap_ctor(&self->keyNameMap, 1))
    {
        return OS_ERROR_ABORTED;
    }

    strncpy(self->name, name, sizeof(self->name) - 1);
    self->name[sizeof(self->name) - 1] = '\0';

    self->hFs     = hFs;
    self->hCrypto = hCrypto;

    self->vtable = &OS_KeystoreFile_vtable;

    return OS_SUCCESS;
}

OS_Error_t
OS_KeystoreFile_new(
    OS_KeystoreFile_t**    pSelf,
    OS_FileSystem_Handle_t hFs,
    OS_Crypto_Handle_t     hCrypto,
    const char*            name)
{
    OS_Error_t err      = OS_ERROR_GENERIC;
    *pSelf              = malloc(sizeof(OS_KeystoreFile_t));

    if (NULL == *pSelf)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    err = OS_KeystoreFile_init(
              *pSelf,
              hFs,
              hCrypto,
              name);
    if (err != OS_SUCCESS)
    {
        free(*pSelf);
    }

    return err;
}

OS_Error_t
OS_KeystoreFile_del(
    OS_KeystoreFile_t* self)
{
    OS_Error_t err = OS_Keystore_free(OS_KeystoreFile_TO_OS_KEYSTORE(self));
    if (OS_SUCCESS == err)
    {
        free(self);
    }

    return err;
}
