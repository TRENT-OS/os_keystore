/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStore.h"
#include "SeosCryptoApi.h"
#include "mbedtls/base64.h"
/* Defines -------------------------------------------------------------------*/
#define KEY_DATA_HASH_LEN   32  /* length of the checksum produced by hashing the key data
                                (len, bytes, algorithm and flags) */

#define DELIMITER_STRING    "," /* Delimiter used for separating the serialized key parameters inside 
                                a file when saving a key (i.e. keyLen, keyBytes, algorithm, flags) */

// we round up the MAX_KEY_LEN / B64_KEY_DATA_HASH_LEN to the first
// value divisible by 3 and multiply it ny 4/3 (overhead for base64)
#define MAX_B64_KEY_LEN                     ((MAX_KEY_LEN + 2) / 3 * 4)
#define B64_KEY_DATA_HASH_LEN               ((KEY_DATA_HASH_LEN + 2) / 3 * 4)
#define B64_KEY_INT_PROPERTY_LEN            ((KEY_INT_PROPERTY_LEN + 2) / 3 * 4)

#define MAX_KEY_DATA_LEN                    (MAX_B64_KEY_LEN + B64_KEY_INT_PROPERTY_LEN + B64_KEY_DATA_HASH_LEN + 2)

/* Macros -------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)          (lenBits / CHAR_BIT + ((lenBits % CHAR_BIT) ? 1 : 0))

#define KEY_SIZE_INDEX                      0
#define KEY_DATA_INDEX                      (B64_KEY_INT_PROPERTY_LEN + 1)
#define KEY_HASH_INDEX(keyDataLen)          (KEY_DATA_INDEX + keyDataLen + 1)

#define KEY_DATA_TOTAL_LEN(keyDataLen)      (B64_KEY_INT_PROPERTY_LEN + keyDataLen + 2 + B64_KEY_DATA_HASH_LEN)

/* Private variables ----------------------------------------------*/
static unsigned char buffer[MAX_KEY_DATA_LEN];

/* Private functions prototypes ----------------------------------------------*/
static seos_err_t createKeyHash(SeosCryptoCtx* cryptoCtx,
                                const void* keyData,
                                size_t keyDataSize,
                                void* output);

static seos_err_t writeKeyToFile(FileStreamFactory* fsFactory,
                                 const void* keyData,
                                 const void* keyDataHash,
                                 size_t keySize,
                                 const char* name,
                                 unsigned char* buffer);

static seos_err_t readKeyFromFile(FileStreamFactory* fsFactory,
                                  void* keyData,
                                  void* keyDataHash,
                                  size_t* keySize,
                                  const char* name,
                                  unsigned char* buffer);

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
/* Private variables ---------------------------------------------------------*/
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
                             SeosCrypto*                cryptoCore,
                             char*                      name)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_ERROR_GENERIC;

    if (NULL == fileStreamFactory
        || NULL == cryptoCore
        || NULL == name)
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
        self->name          = name;
        self->cryptoCore    = cryptoCore;
        self->parent.vtable = &SeosKeyStore_vtable;

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
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %zu!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    if (keySize >= MAX_KEY_LEN || keySize == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key data %zu is invalid, must be in the range 0 - %zu!",
                        __func__, keySize, MAX_KEY_DATA_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    if (checkIfKeyNameExists(self, name))
    {
        Debug_LOG_ERROR("%s: The key with the name %s already exists!",
                        __func__, name);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = createKeyHash(SeosCrypto_TO_SEOS_CRYPTO_CTX(self->cryptoCore),
                        keyData,
                        keySize,
                        keyDataHash);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not hash the key data, err %d!", __func__, err);
        goto exit;
    }

    err = writeKeyToFile(self->fsFactory, keyData, keyDataHash, keySize, name,
                         buffer);
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

    size_t nameLen = strlen(name);
    if (nameLen >= MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %zu!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }
    err = readKeyFromFile(self->fsFactory, keyData, readHash, keySize, name,
                          buffer);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not read the key data from the file, err %d!",
                        __func__, err);
        return err;
    }

    err = createKeyHash(SeosCrypto_TO_SEOS_CRYPTO_CTX(self->cryptoCore),
                        keyData,
                        *keySize,
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
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %zu!",
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
    size_t keySize = 0;

    if (name == NULL)
    {
        Debug_LOG_ERROR("%s: name of the key can't be NULL!", __func__);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    size_t nameLen = strlen(name);
    if (nameLen >= MAX_KEY_NAME_LEN || nameLen == 0)
    {
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %zu!",
                        __func__, nameLen, MAX_KEY_NAME_LEN);
        return SEOS_ERROR_INVALID_PARAMETER;
    }

    err = SeosKeyStore_getKey(keyStoreCtx, name, buffer, &keySize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: getKey failed with err %d!", __func__, err);
        return err;
    }

    err = SeosKeyStore_importKey(destKeyStore, name, buffer, keySize);
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
        Debug_LOG_ERROR("%s: The length of the passed key name %zu is invalid, must be in the range 0 - %zu!",
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
static seos_err_t createKeyHash(SeosCryptoCtx*  cryptoCtx,
                                const void*     keyData,
                                size_t          keyDataSize,
                                void*           output)
{
    seos_err_t err = SEOS_SUCCESS;
    SeosCrypto_DigestHandle scDigestHandle;

    err = SeosCryptoApi_digestInit(cryptoCtx, &scDigestHandle,
                                   SeosCryptoDigest_Algorithm_SHA256, NULL, 0);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoDigest_init failed with error code %d!",
                        __func__, err);
        goto ERR_EXIT;
    }

    err = SeosCryptoApi_digestUpdate(cryptoCtx, scDigestHandle, keyData,
                                     keyDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoDigest_update failed with error code %d!",
                        __func__, err);
        goto ERR_DESTRUCT;
    }

    size_t digestSize = KEY_DATA_HASH_LEN;
    err = SeosCryptoApi_digestFinalize(cryptoCtx, scDigestHandle, NULL, 0, &output,
                                       &digestSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoDigest_finalizeNoData2 failed with error code %d!",
                        __func__, err);
        goto ERR_DESTRUCT;
    }

ERR_DESTRUCT:
    SeosCryptoApi_digestClose(cryptoCtx, scDigestHandle);

ERR_EXIT:
    return err;
}

static seos_err_t writeKeyToFile(FileStreamFactory* fsFactory,
                                 const void* keyData,
                                 const void* keyDataHash,
                                 size_t keySize,
                                 const char* name,
                                 unsigned char* buffer)
{
    Debug_ASSERT_SELF(fsFactory);
    //unsigned char keyDataBuffer[MAX_KEY_DATA_LEN + 1] = {0};
    size_t encodedBytes = 0;
    size_t encodedSize = 0;
    size_t encodedKeySize = 0;
    uint8_t keySizeBuffer[KEY_INT_PROPERTY_LEN] = {0};
    seos_err_t err = SEOS_SUCCESS;

    cpyIntToBuf(keySize, keySizeBuffer);

    // encode the key size to base64 and write it to the buffer
    // + 1 is added to B64_KEY_INT_PROPERTY_LEN because the function adds the '\0' char at the end
    err = mbedtls_base64_encode(&buffer[KEY_SIZE_INDEX],
                                B64_KEY_INT_PROPERTY_LEN + 1,
                                &encodedBytes,
                                keySizeBuffer,
                                KEY_INT_PROPERTY_LEN);
    if (err != SEOS_SUCCESS || encodedBytes != B64_KEY_INT_PROPERTY_LEN)
    {
        Debug_LOG_ERROR("%s: Could not base64 encode the key property, err %d, encoded bytes = %d, expected size = %d!",
                        __func__, err, encodedBytes, B64_KEY_INT_PROPERTY_LEN);
        err = err == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL ?
              SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_ERROR_INVALID_PARAMETER;
        return err;
    }

    // add a delimiter between the key size and the key bytes
    buffer[KEY_DATA_INDEX - 1] = DELIMITER_STRING[0];

    // get the length of the base64 encoded key
    err = mbedtls_base64_encode(NULL,
                                0,
                                &encodedKeySize,
                                keyData,
                                keySize);
    // encode the key bytes to base64 and write it to the buffer
    err = mbedtls_base64_encode(&buffer[KEY_DATA_INDEX],
                                encodedKeySize,
                                &encodedBytes,
                                keyData,
                                keySize);
    // encodedKeySize represents the length of the key bytes + '\0'
    encodedKeySize--;
    if (err != SEOS_SUCCESS || encodedBytes != encodedKeySize)
    {
        Debug_LOG_ERROR("%s: Could not base64 encode the key, err %d, encoded bytes = %d, expected size = %d!",
                        __func__, err, encodedBytes, encodedKeySize);
        err = err == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL ?
              SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_ERROR_INVALID_PARAMETER;
        return err;
    }

    // add a delimiter between the key bytes and the hash
    buffer[KEY_HASH_INDEX(encodedKeySize) - 1] = DELIMITER_STRING[0];

    // get the length of the base64 encoded hash
    err = mbedtls_base64_encode(NULL,
                                0,
                                &encodedSize,
                                keyDataHash,
                                KEY_DATA_HASH_LEN);
    // encode the hash to base64 and write it to the buffer
    err = mbedtls_base64_encode(&buffer[KEY_HASH_INDEX(encodedKeySize)],
                                encodedSize,
                                &encodedBytes,
                                keyDataHash,
                                KEY_DATA_HASH_LEN);
    if (err != SEOS_SUCCESS || encodedBytes != encodedSize - 1)
    {
        Debug_LOG_ERROR("%s: Could not base64 encode the hash, err %d, encoded bytes = %d, expected size = %d!",
                        __func__, err, encodedBytes, encodedSize);
        err = err == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL ?
              SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_ERROR_INVALID_PARAMETER;
        return err;
    }

    // create a file
    FileStream* file = FileStreamFactory_create(fsFactory, name,
                                                FileStream_OpenMode_W);
    if (file == NULL)
    {
        Debug_LOG_ERROR("%s: Failed to open the file stream with a path '%s'!",
                        __func__, name);
        return SEOS_ERROR_OPERATION_DENIED;
    }

    // write the prepared buffer to the file
    if (Stream_write(FileStream_TO_STREAM(file), (char*)buffer,
                     KEY_DATA_TOTAL_LEN(encodedKeySize)) != KEY_DATA_TOTAL_LEN(encodedKeySize))
    {
        Debug_LOG_ERROR("%s: Stream_write failed!", __func__);
        err = SEOS_ERROR_OPERATION_DENIED;
    }
    // destroy (close) the file
    BitMap16 flags = 0;
    BitMap_SET_BIT(flags, FileStream_DeleteFlags_CLOSE);
    FileStreamFactory_destroy(fsFactory, file, flags);

    return err;
}

static seos_err_t readKeyFromFile(FileStreamFactory* fsFactory,
                                  void* keyData,
                                  void* keyDataHash,
                                  size_t* keySize,
                                  const char* name,
                                  unsigned char* buffer)
{
    Debug_ASSERT_SELF(fsFactory);
    size_t decodedBytes = 0;
    size_t decodedSize = 0;
    int readBytes = 0;
    uint8_t keySizeBuffer[KEY_INT_PROPERTY_LEN] = {0};
    seos_err_t err = SEOS_SUCCESS;
    BitMap16 flags = 0;
    BitMap_SET_BIT(flags, FileStream_DeleteFlags_CLOSE);

    // create a file stream
    FileStream* file = FileStreamFactory_create(fsFactory, name,
                                                FileStream_OpenMode_r);
    if (file == NULL)
    {
        Debug_LOG_ERROR("%s: Failed to open the file stream with a path '%s'!",
                        __func__, name);
        return SEOS_ERROR_NOT_FOUND;
    }

    // read and decode the key length and store it into the keyEntry object
    // + 1 is added to B64_KEY_INT_PROPERTY_LEN to read past the first delimiter
    readBytes = Stream_get(FileStream_TO_STREAM(file),
                           (char*)buffer, B64_KEY_INT_PROPERTY_LEN + 1, DELIMITER_STRING, 0);
    if (readBytes <= 0)
    {
        Debug_LOG_ERROR("%s: Stream_get failed, for property! Return value = %d",
                        __func__,
                        readBytes);
        err = SEOS_ERROR_OPERATION_DENIED;
        goto ERROR;
    }

    err = mbedtls_base64_decode(keySizeBuffer,
                                KEY_INT_PROPERTY_LEN,
                                &decodedBytes,
                                buffer,
                                readBytes);
    if (err != SEOS_SUCCESS || decodedBytes != KEY_INT_PROPERTY_LEN)
    {
        Debug_LOG_ERROR("%s: Could not base64 decode the key property, err = %d, decoded bytes = %d, expected size = %d!",
                        __func__, err, decodedBytes, KEY_INT_PROPERTY_LEN);
        err = err == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL ?
              SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_ERROR_INVALID_PARAMETER;
        goto ERROR;
    }
    *keySize = cpyBufToInt((char*)keySizeBuffer);

    // read and decode the key bytes and store it into the keyEntry object
    // + 1 is added to B64_KEY_INT_PROPERTY_LEN to read past the first delimiter
    readBytes = Stream_get(FileStream_TO_STREAM(file),
                           (char*)buffer, MAX_B64_KEY_LEN + 1, DELIMITER_STRING, 0);
    if (readBytes <= 0)
    {
        Debug_LOG_ERROR("%s: Stream_get failed! Return value = %d", __func__,
                        readBytes);
        err = SEOS_ERROR_OPERATION_DENIED;
        goto ERROR;
    }
    //when the *dst = NULL the function returns the decoded size inside *olen
    err = mbedtls_base64_decode(NULL,
                                0,
                                &decodedSize,
                                buffer,
                                readBytes);
    err = mbedtls_base64_decode(keyData,
                                decodedSize,
                                &decodedBytes,
                                buffer,
                                readBytes);
    if (err != SEOS_SUCCESS || decodedBytes != decodedSize)
    {
        Debug_LOG_ERROR("%s: Could not base64 decode the key, err %d, decoded bytes = %d, expected size = %d!",
                        __func__, err, decodedBytes, decodedSize);
        err = err == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL ?
              SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_ERROR_INVALID_PARAMETER;
        goto ERROR;
    }

    // read and decode the hash and store it into the keyEntry object
    readBytes = Stream_get(FileStream_TO_STREAM(file),
                           (char*)buffer, B64_KEY_DATA_HASH_LEN, DELIMITER_STRING, 0);
    if (readBytes <= 0)
    {
        Debug_LOG_ERROR("%s: Stream_get failed! Return value = %d", __func__,
                        readBytes);
        err = SEOS_ERROR_OPERATION_DENIED;
        goto ERROR;
    }
    err = mbedtls_base64_decode(keyDataHash,
                                KEY_DATA_HASH_LEN,
                                &decodedBytes,
                                buffer,
                                readBytes);
    if (err != SEOS_SUCCESS || decodedBytes != KEY_DATA_HASH_LEN)
    {
        Debug_LOG_ERROR("%s: Could not base64 decode the hash, err %d, decoded bytes = %d, expected size = %d!",
                        __func__, err, decodedBytes, KEY_DATA_HASH_LEN);
        err = err == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL ?
              SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_ERROR_INVALID_PARAMETER;
        goto ERROR;
    }

ERROR:
    // destroy (close) the file
    FileStreamFactory_destroy(fsFactory, file, flags);

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
