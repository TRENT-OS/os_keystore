/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "OS_Crypto.h"
#include "OS_Keystore.h"
#include "OS_FileSystem.h"

#include "KeystoreLib.h"
#include "KeyNameMap.h"

#include "lib_utils/BitConverter.h"

#include <string.h>

#define KEY_LEN_SIZE          (sizeof(uint32_t))
#define KEY_HASH_SIZE         32
#define MAX_INSTANCE_NAME_LEN 16
#define MAX_KEY_SIZE          2048

// Maximum length of a file name. A file names is a combination of instance and
// key name in the format "<instancename>_<keyname>.key" and needs 5 more chars
// for separator and file extension (excluding the null terminator).
#define MAX_FILE_NAME_LEN     (MAX_INSTANCE_NAME_LEN + 1 + MAX_KEY_NAME_LEN + 4)

typedef struct
{
    OS_FileSystem_Handle_t hFs;
    OS_Crypto_Handle_t hCrypto;
    char name[MAX_INSTANCE_NAME_LEN + 1];
    KeyNameMap keyNameMap;
    unsigned char buffer[MAX_KEY_SIZE];
} KeystoreLib_t;

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

    err = OS_CryptoDigest_init(&hDigest, hCrypto,
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
    char fileName[MAX_FILE_NAME_LEN + 1];
    size_t offs;

    getFileName(instName, keyName, sizeof(fileName), fileName);
    if ((err = OS_FileSystemFile_open(hFs, &hFile, fileName,
                                      OS_FileSystem_OpenMode_RDWR,
                                      OS_FileSystem_OpenFlags_CREATE)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_open() failed on '%s' with %d",
                        fileName, err);
        return OS_ERROR_OPERATION_DENIED;
    }

    err  = OS_ERROR_OPERATION_DENIED;
    offs = 0;

    if ((err = OS_FileSystemFile_write(hFs, hFile, offs,
                                       KEY_HASH_SIZE,
                                       keyDataHash)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_write() failed on '%s' with %d",
                        fileName, err);
        goto err0;
    }

    offs += KEY_HASH_SIZE;

    BitConverter_putUint32BE((uint32_t) keySize, keySizeBuffer);
    if ((err = OS_FileSystemFile_write(hFs, hFile, offs,
                                       KEY_LEN_SIZE,
                                       keySizeBuffer)) != OS_SUCCESS)
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
    char fileName[MAX_FILE_NAME_LEN + 1];
    size_t offs, realKeySize;

    getFileName(instName, keyName, sizeof(fileName), fileName);
    if ((err = OS_FileSystemFile_open(hFs, &hFile, fileName,
                                      OS_FileSystem_OpenMode_RDONLY,
                                      OS_FileSystem_OpenFlags_NONE)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_open() failed on '%s' with %d",
                        fileName, err);
        return OS_ERROR_OPERATION_DENIED;
    }

    err  = OS_ERROR_OPERATION_DENIED;
    offs = 0;

    if ((err = OS_FileSystemFile_read(hFs, hFile, offs,
                                      KEY_HASH_SIZE,
                                      keyDataHash)) != OS_SUCCESS)
    {
        Debug_LOG_ERROR("OS_FileSystemFile_read() failed on '%s' with %d",
                        fileName, err);
        goto err0;
    }

    offs += KEY_HASH_SIZE;

    if ((err = OS_FileSystemFile_read(hFs, hFile, offs,
                                      KEY_LEN_SIZE,
                                      keySizeBuffer)) != OS_SUCCESS)
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

    if ((err = OS_FileSystemFile_read(hFs, hFile, offs,
                                      keySize,
                                      keyData)) != OS_SUCCESS)
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
    char fileName[MAX_FILE_NAME_LEN + 1];

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
    KeystoreLib_t* self,
    const char*    name,
    size_t         keySize)
{
    KeyNameMap_t keyName;

    strncpy(keyName.buffer, name, sizeof(keyName.buffer) - 1);
    keyName.buffer[sizeof(keyName.buffer) - 1] = '\0';

    if (!KeyNameMap_insert(&self->keyNameMap, &keyName, &keySize))
    {
        Debug_LOG_ERROR("%s: Failed to save the key name!", __func__);
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    return OS_SUCCESS;
}

static bool
map_checkKeyExists(
    KeystoreLib_t* self,
    const char*    name)
{
    KeyNameMap_t keyName;

    strncpy(keyName.buffer, name, sizeof(keyName.buffer) - 1);
    keyName.buffer[sizeof(keyName.buffer) - 1] = '\0';

    return KeyNameMap_getIndexOf(&self->keyNameMap, &keyName) >= 0 ? true : false;
}

static size_t
map_getKeySize(
    KeystoreLib_t* self,
    const char*    name)
{
    int keyIndex;

    keyIndex = KeyNameMap_getIndexOf(&self->keyNameMap, (KeyNameMap_t*)name);
    if (keyIndex < 0)
    {
        return 0;
    }

    return *KeyNameMap_getValueAt(&self->keyNameMap, keyIndex);
}

static OS_Error_t
map_deregisterKey(
    KeystoreLib_t* self,
    const char*    name)
{
    KeyNameMap_t keyName;

    strncpy(keyName.buffer, name, sizeof(keyName.buffer) - 1);
    keyName.buffer[sizeof(keyName.buffer) - 1] = '\0';

    if (!KeyNameMap_remove(&self->keyNameMap, &keyName))
    {
        Debug_LOG_ERROR("%s: Failed to remove the key name!", __func__);
        return OS_ERROR_ABORTED;
    }

    return OS_SUCCESS;
}

static inline bool
isStoreKeyParametersOk(
    KeystoreLib_t*  self,
    const char*     name,
    void const*     keyData,
    size_t          keySize)
{
    if (NULL == self || NULL == keyData || NULL == name)
    {
        return false;
    }

    size_t nameLen = strlen(name);
    if (nameLen > MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return false;
    }
    if (keySize > MAX_KEY_SIZE || keySize == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key data %zu is invalid, must be in the range [1;%d]!",
                        __func__, keySize, MAX_KEY_SIZE);
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
    KeystoreLib_t*  self,
    const char*     name,
    void*           keyData,
    size_t*         keySize)
{
    if (NULL == self || NULL == keySize || NULL == keyData || NULL == name)
    {
        return false;
    }

    size_t nameLen = strlen(name);
    if (nameLen > MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return false;
    }

    size_t my_keysize = *keySize;
    if (my_keysize > MAX_KEY_SIZE)
    {
        Debug_LOG_ERROR("%s: The length of the passed key data %zu is invalid, must be in the range [1;%d]!",
                        __func__, my_keysize, MAX_KEY_SIZE);
        return false;
    }

    return true;
}


// Exported via VTABLE ---------------------------------------------------------

static OS_Error_t
KeystoreLib_storeKey(
    void*       ptr,
    const char* name,
    void const* keyData,
    size_t      keySize)
{
    OS_Error_t err;
    KeystoreLib_t*  self = (KeystoreLib_t*) ptr;
    char keyDataHash[KEY_HASH_SIZE] = {0};

    if (!isStoreKeyParametersOk(ptr, name, keyData, keySize))
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    err = createKeyHash(self->hCrypto,
                        keyData,
                        keySize,
                        keyDataHash);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not hash the key data, err %d!", __func__, err);
        return err;
    }

    err = fs_writeKey(self->hFs, keyData, keyDataHash, keySize, self->name, name);
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
KeystoreLib_loadKey(
    void*       ptr,
    const char* name,
    void*       keyData,
    size_t*     keySize)
{
    OS_Error_t err;
    KeystoreLib_t*  self = (KeystoreLib_t*) ptr;
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

    // Get the size of the written key data from the map and check that the provided
    // buffer is large enough
    size_t savedKeySize = map_getKeySize(self, name);
    if (savedKeySize > *keySize)
    {
        Debug_LOG_ERROR("%s: The actual amount of key data (%zu bytes) is bigger "
                        "than the expected size (%zu byes)",
                        __func__, savedKeySize, *keySize);
        return OS_ERROR_BUFFER_TOO_SMALL;
    }

    err = fs_readKey(self->hFs, keyData, readHash, savedKeySize, self->name, name);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not read the key data from the file, err %d!",
                        __func__, err);
        return err;
    }

    err = createKeyHash(self->hCrypto,
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
KeystoreLib_deleteKey(
    void*       ptr,
    const char* name)
{
    OS_Error_t err;
    KeystoreLib_t*  self = (KeystoreLib_t*) ptr;

    if (NULL == self || NULL == name)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);
    if (nameLen > MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
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
KeystoreLib_copyKey(
    void*       srcPtr,
    const char* name,
    void*       dstPtr)
{
    OS_Error_t err;
    KeystoreLib_t*  self = (KeystoreLib_t*) srcPtr;
    KeystoreLib_t*  destKeyStore = (KeystoreLib_t*) dstPtr;
    size_t keySize = MAX_KEY_SIZE;

    if (NULL == self || NULL == name || NULL == destKeyStore)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);
    if (nameLen > MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return OS_ERROR_INVALID_PARAMETER;
    }

    err = KeystoreLib_loadKey(self, name, self->buffer, &keySize);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: loadKey failed with err %d!", __func__, err);
        return err;
    }

    err = KeystoreLib_storeKey(destKeyStore, name, self->buffer, keySize);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: storeKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}

static OS_Error_t
KeystoreLib_moveKey(
    void*       srcPtr,
    const char* name,
    void*       dstPtr)
{
    OS_Error_t err;
    KeystoreLib_t*  self = (KeystoreLib_t*) srcPtr;
    KeystoreLib_t*  destKeyStore = (KeystoreLib_t*) dstPtr;

    if (NULL == self || NULL  == name || NULL == destKeyStore)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);
    if (nameLen > MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range [1;%d]!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return OS_ERROR_INVALID_PARAMETER;
    }

    err = KeystoreLib_copyKey(self, name, destKeyStore);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: copyKey failed with err %d!", __func__, err);
        return err;
    }

    err = KeystoreLib_deleteKey(self, name);
    if (err != OS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: deleteKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}

static OS_Error_t
KeystoreLib_wipeKeystore(
    void* ptr)
{
    OS_Error_t err;
    KeystoreLib_t*  self = (KeystoreLib_t*) ptr;

    if (NULL == self)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    int registerSize = KeyNameMap_getSize(&self->keyNameMap);
    if (registerSize < 0)
    {
        Debug_LOG_ERROR("%s: Failed to read the key name register size!", __func__);
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
        KeyNameMap_t* keyName = (KeyNameMap_t*)KeyNameMap_getKeyAt(
                                    &self->keyNameMap, i);
        err = KeystoreLib_deleteKey(self, keyName->buffer);
        if (err != OS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: Failed to delete the key %s!", __func__, keyName->buffer);
            return err;
        }
    }

    return err;
}

// Public functions ------------------------------------------------------------

static const KeystoreImpl_Vtable_t KeystoreLib_vtable =
{
    .storeKey       = KeystoreLib_storeKey,
    .loadKey        = KeystoreLib_loadKey,
    .deleteKey      = KeystoreLib_deleteKey,
    .copyKey        = KeystoreLib_copyKey,
    .moveKey        = KeystoreLib_moveKey,
    .wipeKeystore   = KeystoreLib_wipeKeystore,
};

OS_Error_t
KeystoreLib_init(
    KeystoreImpl_t*        impl,
    OS_FileSystem_Handle_t hFs,
    OS_Crypto_Handle_t     hCrypto,
    const char*            name)
{
    KeystoreLib_t* self;
    OS_Error_t err;

    if (NULL == impl || NULL == hFs || NULL == name)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }
    else if (strlen(name) > MAX_INSTANCE_NAME_LEN)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    if ((self = malloc(sizeof(KeystoreLib_t))) == NULL)
    {
        return OS_ERROR_INSUFFICIENT_SPACE;
    }

    memset(self, 0, sizeof(KeystoreLib_t));
    if (!KeyNameMap_ctor(&self->keyNameMap, 1))
    {
        err = OS_ERROR_ABORTED;
        goto err0;
    }

    strncpy(self->name, name, sizeof(self->name) - 1);
    self->name[sizeof(self->name) - 1] = '\0';

    self->hFs     = hFs;
    self->hCrypto = hCrypto;

    impl->vtable  = &KeystoreLib_vtable;
    impl->context = self;

    return OS_SUCCESS;

err0:
    free(self);

    return err;
}

OS_Error_t
KeystoreLib_free(
    KeystoreImpl_t* impl)
{
    if (impl == NULL || impl->context == NULL)
    {
        return OS_ERROR_INVALID_PARAMETER;
    }

    free(impl->context);

    return OS_SUCCESS;
}
