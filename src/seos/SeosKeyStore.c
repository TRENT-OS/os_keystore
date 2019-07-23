/*
 *  Copyright (C) 2019, Hensoldt Cyber GmbH
 */

/* Includes ------------------------------------------------------------------*/
#include "SeosKeyStore.h"
#include "seos/SeosCryptoDigest.h"
#include "seos/SeosCryptoCipher.h"
#include "seos/seos_rng.h"
#include "mbedtls/base64.h"
#include "LibMem/BitmapAllocator.h"
/* Defines -------------------------------------------------------------------*/
#define MAX_KEY_LEN                         256

#define KEY_INT_PROPERTY_LEN                4
#define KEY_DATA_HASH_LEN                   32

#define NUM_OF_PROPERTIES                   3

/* Memory allocation ---------------------------------------------------------*/
#define ELEMENT_SIZE                        (MAX_KEY_LEN)

// we round up the MAX_KEY_LEN / B64_KEY_DATA_HASH_LEN to the first
// value divisible by 3 and multiply it ny 4/3 (overhead for base64)
#define MAX_B64_KEY_LEN                     ((MAX_KEY_LEN + 2) / 3 * 4)
#define B64_KEY_DATA_HASH_LEN               ((KEY_DATA_HASH_LEN + 2) / 3 * 4)
#define B64_KEY_INT_PROPERTY_LEN            ((KEY_INT_PROPERTY_LEN + 2) / 3 * 4)

#define MAX_KEY_DATA_LEN                    (MAX_B64_KEY_LEN + NUM_OF_PROPERTIES*B64_KEY_INT_PROPERTY_LEN + B64_KEY_DATA_HASH_LEN + 4)

#define KEY_BYTES_INDEX                     (NUM_OF_PROPERTIES*B64_KEY_INT_PROPERTY_LEN + 3)

#define DELIMITER_STRING                    ","

#define RNG_SEED                            "9f19a9b95fea4d3419f39697ed54fd32"

/* Macros -------------------------------------------------------------------*/
#define LEN_BITS_TO_BYTES(lenBits)          (lenBits/8)

#define FOURTH_DELIM_INDEX(keyLen)          (KEY_BYTES_INDEX + keyLen)
#define HASH_INDEX(keyLen)                  (FOURTH_DELIM_INDEX(keyLen) + 1)
#define KEY_DATA_TOTAL_LEN(keyLen)          (B64_KEY_INT_PROPERTY_LEN*3 + keyLen + 4 + B64_KEY_DATA_HASH_LEN)

/* Private types ---------------------------------------------------------*/
typedef struct KeyEntry
{
    unsigned char keyProperties[NUM_OF_PROPERTIES][KEY_INT_PROPERTY_LEN];
    unsigned char keyBytes[MAX_KEY_LEN];
    unsigned char hash[KEY_DATA_HASH_LEN];
} KeyEntry;
/* Private functions prototypes ----------------------------------------------*/
static seos_err_t createKeyHash(const void* keyData, size_t keyDataSize,
                                void* output);
static seos_err_t writeKeyToFile(FileStreamFactory* fsFactory,
                                 KeyEntry* keyEntry, size_t keySize, const char* name);
static seos_err_t readKeyFromFile(FileStreamFactory* fsFactory,
                                  KeyEntry* keyEntry, const char* name);
static void cpyIntToBuf(uint32_t integer, unsigned char* buf);
static size_t cpyBufToInt(const char* buf);
/* Private variables ---------------------------------------------------------*/
static BitmapAllocator bmAllocator;

/* Public functions ----------------------------------------------------------*/
bool SeosKeyStore_ctor(SeosKeyStore* self, FileStreamFactory* fileStreamFactory,
                       char* name)
{
    Debug_ASSERT_SELF(self);
    self->fsFactory = fileStreamFactory;
    self->name = name;

    BitmapAllocator_ctor(&bmAllocator, ELEMENT_SIZE, SeosKeyStore_MAX_NUM_FILES);
    return true;
}

void SeosKeyStore_dtor(SeosKeyStore* self)
{
    Debug_ASSERT_SELF(self);
    FileStreamFactory_dtor(self->fsFactory);
}

seos_err_t SeosKeyStore_importKey(SeosKeyStore* self, const char* name,
                                  SeosCryptoKey* key)
{
    Debug_ASSERT_SELF(self);
    KeyEntry newKeyEntry;
    seos_err_t err = SEOS_SUCCESS;

    memcpy(newKeyEntry.keyBytes, key->bytes, LEN_BITS_TO_BYTES(key->lenBits));
    cpyIntToBuf(key->lenBits, newKeyEntry.keyProperties[0]);
    cpyIntToBuf(key->algorithm, newKeyEntry.keyProperties[1]);
    cpyIntToBuf(key->flags, newKeyEntry.keyProperties[2]);

    err = createKeyHash(&newKeyEntry,
                        (KEY_INT_PROPERTY_LEN * NUM_OF_PROPERTIES) + LEN_BITS_TO_BYTES(key->lenBits),
                        newKeyEntry.hash);

    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not hash the key data, err %d!", __func__, err);
        return err;
    }

    err = writeKeyToFile(self->fsFactory, &newKeyEntry,
                         LEN_BITS_TO_BYTES(key->lenBits), name);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not write the key data to the file, err %d!",
                        __func__, err);
        return err;
    }

    return err;
}

seos_err_t SeosKeyStore_getKey(SeosKeyStore* self, const char* name,
                               SeosCryptoKey* key)
{
    KeyEntry newKeyEntry;
    seos_err_t err = SEOS_SUCCESS;
    unsigned char calculatedHash[KEY_DATA_HASH_LEN];

    err = readKeyFromFile(self->fsFactory, &newKeyEntry, name);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not read the key data from the file, err %d!",
                        __func__, err);
        return err;
    }

    size_t readKeySize      = cpyBufToInt((char*)newKeyEntry.keyProperties[0]);
    size_t readKeyAlgorithm = cpyBufToInt((char*)newKeyEntry.keyProperties[1]);
    size_t readKeyFlags     = cpyBufToInt((char*)newKeyEntry.keyProperties[2]);

    err = createKeyHash(&newKeyEntry,
                        (KEY_INT_PROPERTY_LEN * NUM_OF_PROPERTIES) + LEN_BITS_TO_BYTES(readKeySize),
                        calculatedHash);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not hash the key data, err %d!",
                        __func__, err);
        return err;
    }

    if (memcmp(newKeyEntry.hash, calculatedHash, KEY_DATA_HASH_LEN) != 0)
    {
        Debug_LOG_ERROR("%s: The key is corrupted - hash value does not correspond to the data!",
                        __func__);
        return SEOS_ERROR_GENERIC;
    }

    char* keyBytes = Allocator_alloc(BitmapAllocator_TO_ALLOCATOR(&bmAllocator),
                                     ELEMENT_SIZE);
    memcpy(keyBytes, newKeyEntry.keyBytes, LEN_BITS_TO_BYTES(readKeySize));
    err = SeosCryptoKey_init(key,
                             NULL,
                             readKeyAlgorithm,
                             readKeyFlags,
                             keyBytes,
                             readKeySize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoKey_init failed to construct the key with error code %d!",
                        __func__, err);
        return err;
    }

    return err;
}

seos_err_t SeosKeyStore_getKeySizeBytes(SeosKeyStore* self, const char* name,
                                        size_t* keySize)
{
    KeyEntry newKeyEntry;
    seos_err_t err = SEOS_SUCCESS;
    unsigned char calculatedHash[KEY_DATA_HASH_LEN];

    err = readKeyFromFile(self->fsFactory, &newKeyEntry, name);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not read the key data from the file, err %d!",
                        __func__, err);
        return err;
    }

    size_t readKeySize = cpyBufToInt((char*)newKeyEntry.keyProperties[0]);

    err = createKeyHash(&newKeyEntry,
                        (KEY_INT_PROPERTY_LEN * NUM_OF_PROPERTIES) + LEN_BITS_TO_BYTES(readKeySize),
                        calculatedHash);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: Could not hash the key data, err %d!",
                        __func__, err);
        return err;
    }

    if (memcmp(newKeyEntry.hash, calculatedHash, KEY_DATA_HASH_LEN) != 0)
    {
        Debug_LOG_ERROR("%s: The key is corrupted - hash value does not correspond to the data!",
                        __func__);
        return SEOS_ERROR_GENERIC;
    }
    *keySize = LEN_BITS_TO_BYTES(readKeySize);


    return err;
}

seos_err_t SeosKeyStore_deleteKey(SeosKeyStore* self, SeosCryptoKey* key,
                                  const char* name)
{
    Debug_ASSERT_SELF(self);
    BitMap16 flags = 0;

    FileStream* file = FileStreamFactory_create(self->fsFactory, name,
                                                FileStream_OpenMode_r);
    if (file == NULL)
    {
        Debug_LOG_ERROR("%s: Failed to open the file stream with a path '%s'!",
                        __func__, name);
        return SEOS_ERROR_NOT_FOUND;
    }

    BitMap_SET_BIT(flags, FileStream_DeleteFlags_CLOSE);
    BitMap_SET_BIT(flags, FileStream_DeleteFlags_DELETE);
    FileStreamFactory_destroy(self->fsFactory, file, flags);

    Allocator_free(BitmapAllocator_TO_ALLOCATOR(&bmAllocator), key->bytes);

    return SEOS_SUCCESS;
}

seos_err_t SeosKeyStore_closeKey(SeosKeyStore* self, SeosCryptoKey* key)
{
    Debug_ASSERT_SELF(self);
    Allocator_free(BitmapAllocator_TO_ALLOCATOR(&bmAllocator), key->bytes);

    return SEOS_SUCCESS;
}

seos_err_t SeosKeyStore_copyKey(SeosKeyStore* self, const char* name,
                                SeosKeyStore* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStore);
    SeosCryptoKey key;
    seos_err_t err = SEOS_SUCCESS;

    err = SeosKeyStore_getKey(self, name, &key);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: getKey failed with err %d!", __func__, err);
        return err;
    }

    err = SeosKeyStore_importKey(destKeyStore, name, &key);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: importKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}

seos_err_t SeosKeyStore_moveKey(SeosKeyStore* self,
                                const char* name,
                                SeosCryptoKey* key,
                                SeosKeyStore* destKeyStore)
{
    Debug_ASSERT_SELF(self);
    Debug_ASSERT_SELF(destKeyStore);
    seos_err_t err = SEOS_SUCCESS;

    err = SeosKeyStore_copyKey(self, name, destKeyStore);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: copyKey failed with err %d!", __func__, err);
        return err;
    }

    err = SeosKeyStore_deleteKey(self, key, name);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: deleteKey failed with err %d!", __func__, err);
        return err;
    }

    return err;
}

seos_err_t SeosKeyStore_generateKey(SeosKeyStore*   self,
                                    SeosCryptoKey*  key,
                                    const char*     name,
                                    unsigned int    algorithm,
                                    unsigned int    flags,
                                    size_t          lenBits)
{
    Debug_ASSERT_SELF(self);
    seos_err_t err = SEOS_SUCCESS;
    seos_rng_t seosRng;

    err = seos_rng_init(&seosRng, RNG_SEED, strlen(RNG_SEED));
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: seos_rng_init failed with error code %d!", __func__, err);
        return err;
    }

    char* keyBytes = Allocator_alloc(BitmapAllocator_TO_ALLOCATOR(&bmAllocator),
                                     ELEMENT_SIZE);
    err = seos_rng_get_prng_bytes(&seosRng, keyBytes, MAX_KEY_LEN);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: seos_rng_get_prng_bytes failed with error code %d!",
                        __func__, err);
        goto ERROR;
    }

    err = SeosCryptoKey_init(key,
                             NULL,
                             algorithm,
                             flags,
                             keyBytes,
                             lenBits);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoKey_init failed to construct the key with error code %d!",
                        __func__, err);
        goto ERROR;
    }

    err = SeosKeyStore_importKey(self, name, key);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: importKey failed with err %d!", __func__, err);
        goto ERROR;
    }

ERROR:
    seos_rng_free(&seosRng);

    return err;
}

/* Private functions ---------------------------------------------------------*/
static seos_err_t createKeyHash(const void* keyData, size_t keyDataSize,
                                void* output)
{
    seos_err_t err = SEOS_SUCCESS;
    SeosCryptoDigest scDigest;

    err = SeosCryptoDigest_init(&scDigest, SeosCryptoDigest_Algorithm_SHA256, NULL,
                                0);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoDigest_init failed with error code %d!",
                        __func__, err);
        goto ERR_EXIT;
    }

    err = SeosCryptoDigest_update(&scDigest, keyData, keyDataSize);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoDigest_update failed with error code %d!",
                        __func__, err);
        goto ERR_DESTRUCT;
    }

    err = SeosCryptoDigest_finalizeNoData2(&scDigest, output,
                                           KEY_DATA_HASH_LEN);
    if (err != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("%s: SeosCryptoDigest_finalizeNoData2 failed with error code %d!",
                        __func__, err);
        goto ERR_DESTRUCT;
    }

ERR_DESTRUCT:
    SeosCryptoDigest_deInit(&scDigest);

ERR_EXIT:
    return err;
}

static seos_err_t writeKeyToFile(FileStreamFactory* fsFactory,
                                 KeyEntry* keyEntry, size_t keySize, const char* name)
{
    Debug_ASSERT_SELF(fsFactory);
    unsigned char keyData[MAX_KEY_DATA_LEN + 1] = {0};
    size_t encodedBytes = 0;
    size_t encodedSize = 0;
    size_t encodedKeySize = 0;
    seos_err_t err = SEOS_SUCCESS;

    for (size_t i = 0; i < NUM_OF_PROPERTIES; i++)
    {
        // encode the key size to base64 and write it to the buffer
        // + 1 is added to B64_KEY_INT_PROPERTY_LEN because the function adds the '\0' char at the end
        err = mbedtls_base64_encode(&keyData[i * (B64_KEY_INT_PROPERTY_LEN + 1)],
                                    B64_KEY_INT_PROPERTY_LEN + 1,
                                    &encodedBytes,
                                    keyEntry->keyProperties[i],
                                    KEY_INT_PROPERTY_LEN);
        if (err != SEOS_SUCCESS || encodedBytes != B64_KEY_INT_PROPERTY_LEN)
        {
            Debug_LOG_ERROR("%s: Could not base64 encode the key property %d, err %d, encoded bytes = %d, expected size = %d!",
                            __func__, i, err, encodedBytes, B64_KEY_INT_PROPERTY_LEN);
            err = err == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL ?
                  SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_ERROR_INVALID_PARAMETER;
            return err;
        }

        // add a delimiter between the key size and the key bytes
        keyData[(i + 1) * B64_KEY_INT_PROPERTY_LEN + i * 1] = DELIMITER_STRING[0];
    }

    // get the length of the base64 encoded key
    err = mbedtls_base64_encode(NULL,
                                0,
                                &encodedKeySize,
                                keyEntry->keyBytes,
                                keySize);
    // encode the key bytes to base64 and write it to the buffer
    err = mbedtls_base64_encode(&keyData[KEY_BYTES_INDEX],
                                encodedKeySize,
                                &encodedBytes,
                                keyEntry->keyBytes,
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
    keyData[FOURTH_DELIM_INDEX(encodedKeySize)] = DELIMITER_STRING[0];

    // get the length of the base64 encoded hash
    err = mbedtls_base64_encode(NULL,
                                0,
                                &encodedSize,
                                keyEntry->hash,
                                KEY_DATA_HASH_LEN);
    // encode the hash to base64 and write it to the buffer
    err = mbedtls_base64_encode(&keyData[HASH_INDEX(encodedKeySize)],
                                encodedSize,
                                &encodedBytes,
                                keyEntry->hash,
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
    if (Stream_write(FileStream_TO_STREAM(file), (char*)keyData,
                     KEY_DATA_TOTAL_LEN(encodedKeySize)) != KEY_DATA_TOTAL_LEN(
            encodedKeySize))
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
                                  KeyEntry* keyEntry, const char* name)
{
    Debug_ASSERT_SELF(fsFactory);
    unsigned char buffer[MAX_KEY_DATA_LEN] = {0};
    size_t decodedBytes = 0;
    size_t decodedSize = 0;
    int readBytes = 0;
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

    for (size_t i = 0; i < NUM_OF_PROPERTIES; i++)
    {
        // read and decode the key length and store it into the keyEntry object
        // + 1 is added to B64_KEY_INT_PROPERTY_LEN to read past the first delimiter
        readBytes = Stream_get(FileStream_TO_STREAM(file),
                               (char*)buffer, B64_KEY_INT_PROPERTY_LEN + 1, DELIMITER_STRING, 0);
        if (readBytes <= 0)
        {
            Debug_LOG_ERROR("%s: Stream_get failed, for property %d! Return value = %d",
                            __func__, i,
                            readBytes);
            err = SEOS_ERROR_OPERATION_DENIED;
            goto ERROR;
        }

        err = mbedtls_base64_decode(keyEntry->keyProperties[i],
                                    KEY_INT_PROPERTY_LEN,
                                    &decodedBytes,
                                    buffer,
                                    readBytes);
        if (err != SEOS_SUCCESS || decodedBytes != KEY_INT_PROPERTY_LEN)
        {
            Debug_LOG_ERROR("%s: Could not base64 decode the key property %d, err = %d, decoded bytes = %d, expected size = %d!",
                            __func__, i, err, decodedBytes, KEY_INT_PROPERTY_LEN);
            err = err == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL ?
                  SEOS_ERROR_INSUFFICIENT_SPACE : SEOS_ERROR_INVALID_PARAMETER;
            goto ERROR;
        }
    }

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
    err = mbedtls_base64_decode(keyEntry->keyBytes,
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
    err = mbedtls_base64_decode(keyEntry->hash,
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
