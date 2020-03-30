/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStore.h"
#include "OS_Crypto.h"
#include "SeosKeyStoreApi.h"

/* Defines -------------------------------------------------------------------*/
#define KEY_DATA_HASH_LEN   32  /* length of the checksum produced by hashing the key data
                                (len, bytes, algorithm and flags) */

/* Macros -------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)          (lenBits / CHAR_BIT + ((lenBits % CHAR_BIT) ? 1 : 0))

/* Private functions prototypes ----------------------------------------------*/
static seos_err_t createKeyHash(OS_Crypto_Handle_t hCrypto,
                                const void* keyData,
                                size_t keyDataSize,
                                void* output);

static seos_err_t writeKeyToFile(FileStreamFactory* fsFactory,
                                 const void* keyData,
                                 const void* keyDataHash,
                                 size_t keySize,
                                 const char* name);

static seos_err_t readKeyFromFile(SeosKeyStore* self,
                                  void* keyData,
                                  void* keyDataHash,
                                  size_t* keySize,
                                  const char* name);

static seos_err_t deleteKeyFromFile(FileStreamFactory* fsFactory,
                                    const char* name);

static seos_err_t registerKeyName(SeosKeyStore* self,
                                  const char* name,
                                  size_t keySize);

static seos_err_t deRegisterKeyName(SeosKeyStore* self,
                                    const char* name);

static bool checkIfKeyNameExists(SeosKeyStore* self,
                                 const char* name);

static void cpyIntToBuf(uint32_t integer,
                        unsigned char* buf);

static size_t cpyBufToInt(const char* buf);

/* Private variables ----------------------------------------------------------*/
static const SeosKeyStoreCtx_Vtable SeosKeyStore_vtable =
{
    .importKey      = SeosKeyStore_importKey,
    .getKey         = SeosKeyStore_getKey,
    .deleteKey      = SeosKeyStore_deleteKey,
    .copyKey        = SeosKeyStore_copyKey,
    .moveKey        = SeosKeyStore_moveKey,
    .wipeKeyStore   = SeosKeyStore_wipeKeyStore,
    .deInit         = SeosKeyStore_deInit,
};
/* Public functions ----------------------------------------------------------*/
seos_err_t SeosKeyStore_init(SeosKeyStore*              self,
                             FileStreamFactory*         fileStreamFactory,
                             OS_Crypto_Handle_t         hCrypto,
                             const char*                name)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    // We do not check hCrypto, as that will be done by the Crypto API layer
    if (NULL == fileStreamFactory
        || NULL == name)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);
    if (nameLen > SeosKeyStore_MAX_KEYSTORE_NAME_LEN)
    {
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    memset(self, 0, sizeof(*self));

    if (!KeyNameMap_ctor(&self->keyNameMap, 1))
    {
        retval = SEOS_ERROR_ABORTED;
    }
    else
    {
        self->fsFactory     = fileStreamFactory;
        self->hCrypto       = hCrypto;
        self->parent.vtable = &SeosKeyStore_vtable;

        memcpy(self->name, name, nameLen);

        retval = SEOS_SUCCESS;
    }

    return retval;
}

void SeosKeyStore_deInit(SeosKeyStoreCtx* keyStoreCtx)
{
    SeosKeyStore* self = (SeosKeyStore*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStore_vtable);
    FileStreamFactory_dtor(self->fsFactory);
}

seos_err_t SeosKeyStore_importKey(SeosKeyStoreCtx*          keyStoreCtx,
                                  const char*               name,
                                  void const*               keyData,
                                  size_t                    keySize)
{
    SeosKeyStore* self = (SeosKeyStore*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStore_vtable);
    seos_err_t err = SEOS_SUCCESS;
    char keyDataHash[KEY_DATA_HASH_LEN] = {0};

    if (keyData == NULL || name == NULL)
    {
        Debug_LOG_ERROR("%s: keyData, keySize and name of the key can't be NULL!",
                        __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);
    if (nameLen >= MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %d!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if (keySize > MAX_KEY_LEN || keySize == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key data %zu is invalid, must be in the range 0 - %d!",
                        __func__, keySize, MAX_KEY_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (checkIfKeyNameExists(self, name))
    {
        Debug_LOG_ERROR("%s: The key with the name %s already exists!",
                        __func__, name);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = createKeyHash(self->hCrypto,
                        keyData,
                        keySize,
                        keyDataHash);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not hash the key data, err %d!", __func__, err);
        goto exit;
    }

    err = writeKeyToFile(self->fsFactory, keyData, keyDataHash, keySize, name);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not write the key data to the file, err %d!",
                        __func__, err);
        goto exit;
    }

    err = registerKeyName(self, name, keySize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Failed to register the key name, error code %d!",
                        __func__, err);
        goto err0;
    }

    goto exit;

err0:
    deleteKeyFromFile(self->fsFactory, name);

exit:
    return err;
}

seos_err_t SeosKeyStore_getKey(SeosKeyStoreCtx*         keyStoreCtx,
                               const char*              name,
                               void*                    keyData,
                               size_t*                  keySize)
{
    SeosKeyStore* self = (SeosKeyStore*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStore_vtable);
    seos_err_t err = SEOS_SUCCESS;
    unsigned char calculatedHash[KEY_DATA_HASH_LEN];
    unsigned char readHash[KEY_DATA_HASH_LEN];

    if (keySize == NULL || keyData == NULL || name == NULL)
    {
        Debug_LOG_ERROR("%s: keyData, keySize and name of the key can't be NULL!",
                        __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    size_t requestedKeysize = *keySize;

    size_t nameLen = strlen(name);
    if (nameLen >= MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %d!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if (requestedKeysize > MAX_KEY_LEN)
    {
        Debug_LOG_ERROR("%s: The length of the passed key data %zu is invalid, must be in the range 0 - %d!",
                        __func__, requestedKeysize, MAX_KEY_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    err = readKeyFromFile(self, keyData, readHash, &requestedKeysize, name);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not read the key data from the file, err %d!",
                        __func__, err);
        return err;
    }

    err = createKeyHash(self->hCrypto,
                        keyData,
                        requestedKeysize,
                        calculatedHash);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not hash the key data, err %d!",
                        __func__, err);
        return err;
    }

    if (memcmp(readHash, calculatedHash, KEY_DATA_HASH_LEN) != 0)
    {
        Debug_LOG_ERROR("%s: The key is corrupted - hash value does not correspond to the data!",
                        __func__);
        err = SEOS_ERROR_GENERIC;
        return err;
    }

    *keySize = requestedKeysize;

    return err;
}

seos_err_t SeosKeyStore_deleteKey(SeosKeyStoreCtx*          keyStoreCtx,
                                  const char*               name)
{
    SeosKeyStore* self = (SeosKeyStore*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStore_vtable);
    seos_err_t err = SEOS_ERROR_GENERIC;

    if (name == NULL)
    {
        Debug_LOG_ERROR("%s: name of the key can't be NULL!", __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);
    if (nameLen >= MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %d!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (!checkIfKeyNameExists(self, name))
    {
        Debug_LOG_ERROR("%s: The key with the name %s does not exist!",
                        __func__, name);
        return SEOS_ERROR_NOT_FOUND;
    }

    err = deRegisterKeyName(self, name);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Failed to deregister the key name, error code %d!",
                        __func__, err);
        return err;
    }

    err = deleteKeyFromFile(self->fsFactory, name);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: deleteKeyFromFile failed with error code %d!",
                        __func__, err);
        return err;
    }

    return err;
}

seos_err_t SeosKeyStore_copyKey(SeosKeyStoreCtx*        keyStoreCtx,
                                const char*             name,
                                SeosKeyStoreCtx*        destKeyStore)
{
    SeosKeyStore* self = (SeosKeyStore*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStore_vtable);
    Debug_ASSERT_SELF(destKeyStore);
    seos_err_t err = SEOS_SUCCESS;
    size_t keySize = MAX_KEY_LEN;

    if (name == NULL)
    {
        Debug_LOG_ERROR("%s: name of the key can't be NULL!", __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);
    if (nameLen >= MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %d!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = SeosKeyStore_getKey(keyStoreCtx, name, self->buffer, &keySize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: getKey failed with err %d!", __func__, err);
        return err;
    }

    err = SeosKeyStoreApi_importKey(destKeyStore, name, self->buffer, keySize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: importKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}

seos_err_t SeosKeyStore_moveKey(SeosKeyStoreCtx*        keyStoreCtx,
                                const char*             name,
                                SeosKeyStoreCtx*        destKeyStore)
{
    SeosKeyStore* self = (SeosKeyStore*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStore_vtable);
    Debug_ASSERT_SELF(destKeyStore);
    seos_err_t err = SEOS_SUCCESS;

    if (name == NULL)
    {
        Debug_LOG_ERROR("%s: name of the key can't be NULL!", __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);
    if (nameLen >= MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %d!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = SeosKeyStore_copyKey(keyStoreCtx, name, destKeyStore);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: copyKey failed with err %d!", __func__, err);
        return err;
    }

    err = SeosKeyStore_deleteKey(keyStoreCtx, name);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: deleteKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}

seos_err_t
SeosKeyStore_wipeKeyStore(SeosKeyStoreCtx* keyStoreCtx)
{
    SeosKeyStore* self = (SeosKeyStore*)keyStoreCtx;
    Debug_ASSERT_SELF(self);
    Debug_ASSERT(self->parent.vtable == &SeosKeyStore_vtable);
    seos_err_t err = SEOS_ERROR_GENERIC;

    int registerSize = KeyNameMap_getSize(&self->keyNameMap);
    if (registerSize < 0)
    {
        Debug_LOG_ERROR("%s: Failed to read the key name register size!", __func__);
        return SEOS_ERROR_ABORTED;
    }

    if (registerSize == 0)
    {
        Debug_LOG_INFO("%s: Trying to wipe an empty keystore! Returning...",
                       __func__);
        return SEOS_SUCCESS;
    }

    for (int i = registerSize - 1; i >= 0; i--)
    {
        SeosKeyStore_KeyName* keyName = (SeosKeyStore_KeyName*)KeyNameMap_getKeyAt(
                                            &self->keyNameMap, i);
        err = SeosKeyStore_deleteKey(keyStoreCtx, keyName->buffer);
        if (err != SEOS_SUCCESS)
        {
            Debug_LOG_ERROR("%s: Failed to delete the key %s!", __func__, keyName->buffer);
            return err;
        }
    }

    return err;
}

/* Private functions ---------------------------------------------------------*/
static seos_err_t createKeyHash(OS_Crypto_Handle_t      hCrypto,
                                const void*             keyData,
                                size_t                  keyDataSize,
                                void*                   output)
{
    seos_err_t err = SEOS_SUCCESS;
    OS_CryptoDigest_Handle_t hDigest;

    err = OS_CryptoDigest_init(&hDigest, hCrypto,
                               OS_CryptoDigest_ALG_SHA256);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoLibDigest_init failed with error code %d!",
                        __func__, err);
        goto ERR_EXIT;
    }

    err = OS_CryptoDigest_process(hDigest, keyData, keyDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoLibDigest_update failed with error code %d!",
                        __func__, err);
        goto ERR_DESTRUCT;
    }

    size_t digestSize = KEY_DATA_HASH_LEN;
    err = OS_CryptoDigest_finalize(hDigest, output, &digestSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: OS_CryptoLibDigest_finalizeNoData2 failed with error code %d!",
                        __func__, err);
        goto ERR_DESTRUCT;
    }

ERR_DESTRUCT:
    OS_CryptoDigest_free(hDigest);

ERR_EXIT:
    return err;
}

static seos_err_t writeKeyToFile(FileStreamFactory* fsFactory,
                                 const void* keyData,
                                 const void* keyDataHash,
                                 size_t keySize,
                                 const char* name)
{
    Debug_ASSERT_SELF(fsFactory);
    uint8_t keySizeBuffer[KEY_INT_PROPERTY_LEN] = {0};
    BitMap16 flags = 0;
    seos_err_t err = SEOS_SUCCESS;

    cpyIntToBuf(keySize, keySizeBuffer);

    // create a file
    FileStream* file = FileStreamFactory_create(fsFactory, name,
                                                FileStream_OpenMode_W);
    if (file == NULL)
    {
        Debug_LOG_ERROR("%s: Failed to open the file stream with a path '%s'!",
                        __func__, name);
        return SEOS_ERROR_OPERATION_DENIED;
    }

    // write the hash to the file
    if (Stream_write(FileStream_TO_STREAM(file), (char*)keyDataHash,
                     KEY_DATA_HASH_LEN) != KEY_DATA_HASH_LEN)
    {
        Debug_LOG_ERROR("%s: Stream_write failed while writing the hash!", __func__);
        err = SEOS_ERROR_OPERATION_DENIED;
        goto ERROR;
    }

    // write the size of the key data to the file
    if (Stream_write(FileStream_TO_STREAM(file), (char*)keySizeBuffer,
                     KEY_INT_PROPERTY_LEN) != KEY_INT_PROPERTY_LEN)
    {
        Debug_LOG_ERROR("%s: Stream_write failed while writing the key size!",
                        __func__);
        err = SEOS_ERROR_OPERATION_DENIED;
        goto ERROR;
    }

    // write the key data to the file
    if (Stream_write(FileStream_TO_STREAM(file), (char*)keyData,
                     keySize) != keySize)
    {
        Debug_LOG_ERROR("%s: Stream_write failed while writing the key data!",
                        __func__);
        err = SEOS_ERROR_OPERATION_DENIED;
        goto ERROR;
    }

ERROR:
    // destroy (close) the file
    BitMap_SET_BIT(flags, FileStream_DeleteFlags_CLOSE);
    FileStreamFactory_destroy(fsFactory, file, flags);

    return err;
}

static seos_err_t readKeyFromFile(SeosKeyStore* self,
                                  void* keyData,
                                  void* keyDataHash,
                                  size_t* keySize,
                                  const char* name)
{
    Debug_ASSERT_SELF(self);
    int readBytes = 0;
    uint8_t keySizeBuffer[KEY_INT_PROPERTY_LEN] = {0};
    BitMap16 flags = 0;
    seos_err_t err = SEOS_SUCCESS;

    size_t requestedKeySize = *keySize;

    /* get the size of the written key data from the map
       and check that the provided buffer is large enough */
    int keyIndex = KeyNameMap_getIndexOf(&self->keyNameMap,
                                         (SeosKeyStore_KeyName*)name);
    size_t savedKeySize = keyIndex >= 0 ?
                          *KeyNameMap_getValueAt(&self->keyNameMap, keyIndex)
                          : requestedKeySize;

    if (requestedKeySize < savedKeySize)
    {
        Debug_LOG_ERROR("%s: The requested size of the key data: %zu is smaller than the amount of saved bytes: %zu!",
                        __func__, requestedKeySize, savedKeySize);
        return SEOS_ERROR_BUFFER_TOO_SMALL;
    }

    // create a file stream
    FileStream* file = FileStreamFactory_create(self->fsFactory, name,
                                                FileStream_OpenMode_r);
    if (file == NULL)
    {
        Debug_LOG_ERROR("%s: Failed to open the file stream with a path '%s'!",
                        __func__, name);
        return SEOS_ERROR_NOT_FOUND;
    }

    // read the key data hash
    readBytes = Stream_read(FileStream_TO_STREAM(file), (char*)keyDataHash,
                            KEY_DATA_HASH_LEN);
    if (readBytes <= 0)
    {
        Debug_LOG_ERROR("%s: Stream_read failed while reading the hash! Return value = %d",
                        __func__,
                        readBytes);
        err = SEOS_ERROR_OPERATION_DENIED;
        goto ERROR;
    }

    // read the key data size
    readBytes = Stream_read(FileStream_TO_STREAM(file), (char*)keySizeBuffer,
                            KEY_INT_PROPERTY_LEN);
    if (readBytes <= 0)
    {
        Debug_LOG_ERROR("%s: Stream_read failed while reading the key size! Return value = %d",
                        __func__,
                        readBytes);
        err = SEOS_ERROR_OPERATION_DENIED;
        goto ERROR;
    }
    requestedKeySize = cpyBufToInt((char*)keySizeBuffer);

    readBytes = Stream_read(FileStream_TO_STREAM(file), (char*)keyData,
                            savedKeySize);
    if (readBytes <= 0)
    {
        Debug_LOG_ERROR("%s: Stream_read failed while reading the key data! Return value = %d",
                        __func__,
                        readBytes);
        err = SEOS_ERROR_OPERATION_DENIED;
        goto ERROR;
    }

    // returning the successfully read key size
    *keySize = requestedKeySize;

ERROR:
    // destroy (close) the file
    BitMap_SET_BIT(flags, FileStream_DeleteFlags_CLOSE);
    FileStreamFactory_destroy(self->fsFactory, file, flags);

    return err;
}

static seos_err_t deleteKeyFromFile(FileStreamFactory* fsFactory,
                                    const char* name)
{
    FileStream* file = FileStreamFactory_create(fsFactory, name,
                                                FileStream_OpenMode_r);
    BitMap16 flags = 0;

    if (file == NULL)
    {
        Debug_LOG_ERROR("%s: Failed to open the file stream with a path '%s'!",
                        __func__, name);
        return SEOS_ERROR_NOT_FOUND;
    }

    BitMap_SET_BIT(flags, FileStream_DeleteFlags_CLOSE);
    BitMap_SET_BIT(flags, FileStream_DeleteFlags_DELETE);
    FileStreamFactory_destroy(fsFactory, file, flags);

    return SEOS_SUCCESS;
}

static seos_err_t registerKeyName(SeosKeyStore*               self,
                                  const char*                 name,
                                  size_t                      keySize)
{
    SeosKeyStore_KeyName keyName;
    size_t nameLen = strlen(name);

    strncpy(keyName.buffer, name, nameLen);
    keyName.buffer[nameLen] = 0;

    if (!KeyNameMap_insert(&self->keyNameMap, &keyName, &keySize))
    {
        Debug_LOG_ERROR("%s: Failed to save the key name!", __func__);
        return SEOS_ERROR_INSUFFICIENT_SPACE;
    }

    return SEOS_SUCCESS;
}

static bool checkIfKeyNameExists(SeosKeyStore*    self,
                                 const char*      name)
{
    SeosKeyStore_KeyName keyName;
    size_t nameLen = strlen(name);

    strncpy(keyName.buffer, name, nameLen);
    keyName.buffer[nameLen] = 0;

    return KeyNameMap_getIndexOf(&self->keyNameMap, &keyName) >= 0 ? true : false;
}

static seos_err_t deRegisterKeyName(SeosKeyStore* self,
                                    const char* name)
{
    SeosKeyStore_KeyName keyName;
    size_t nameLen = strlen(name);

    strncpy(keyName.buffer, name, nameLen);
    keyName.buffer[nameLen] = 0;

    if (!KeyNameMap_remove(&self->keyNameMap, &keyName))
    {
        Debug_LOG_ERROR("%s: Failed to remove the key name!", __func__);
        return SEOS_ERROR_ABORTED;
    }

    return SEOS_SUCCESS;
}

static void cpyIntToBuf(uint32_t integer, unsigned char* buf)
{
    buf[0] = (integer >> 24) & 0xFF;
    buf[1] = (integer >> 16) & 0xFF;
    buf[2] = (integer >> 8) & 0xFF;
    buf[3] = integer & 0xFF;
}

static size_t cpyBufToInt(const char* buf)
{
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | (buf[3]);
}
