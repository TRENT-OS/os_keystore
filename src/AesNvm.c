/*
 *  Copyright (C) 2018, Hensoldt Cyber GmbH
 */

#include "AesNvm.h"

#include <stdlib.h>
#include <string.h>


#define KEY_LENGTH_IN_BYTES         32
#define KEY_LENGTH_IN_BITS          (KEY_LENGTH_IN_BYTES*8)
#define IV_LENGTH_IN_BYTES          16
#define ENCRYPTION_PAGE_LEN         1024

#define AesNvm_KEY_LENGTH_IN_BYTES  KEY_LENGTH_IN_BYTES

static const Nvm_Vtable AesNvm_vtable =
{
    .read       = AesNvm_read,
    .erase      = AesNvm_erase,
    .getSize    = AesNvm_getSize,
    .write      = AesNvm_write,
    .dtor       = AesNvm_dtor
};


//------------------------------------------------------------------------------
static void
createIV(
    AesNvm*      self,
    uint32_t     addr,
    const void*  startIv,
    void*        newIV)
{
    seos_err_t ret;
    char addressArray[IV_LENGTH_IN_BYTES] = {0};
    size_t outputSize = IV_LENGTH_IN_BYTES;
    SeosCryptoApi_CipherH hCipher;

    addressArray[0] = (addr >> 24) & 0xFF;
    addressArray[1] = (addr >> 16) & 0xFF;
    addressArray[2] = (addr >> 8) & 0xFF;
    addressArray[3] = addr & 0xFF;

    // Encrypt the address using the hashed master key and use the encrypted
    // address as new IV
    ret = SeosCryptoApi_Cipher_init(
              &hCipher,
              self->hCrypto,
              self->hHashedKey,
              SeosCryptoApi_Cipher_ALG_AES_CBC_ENC,
              startIv,
              IV_LENGTH_IN_BYTES);

    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_Cipher_init failed, code %d", ret);
        return;
    }

    ret = SeosCryptoApi_Cipher_process(
              hCipher,
              addressArray,
              IV_LENGTH_IN_BYTES,
              newIV,
              &outputSize);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_Cipher_process failed, code %d", ret);
    }

    if (outputSize != IV_LENGTH_IN_BYTES)
    {
        Debug_LOG_ERROR("length %zu invalid for calculated IV, expected %d",
                        outputSize, IV_LENGTH_IN_BYTES);
    }

    SeosCryptoApi_Cipher_free(hCipher);
}


//------------------------------------------------------------------------------
static void
cryptoCalculateBlock(
    AesNvm*      self,
    size_t       addr,
    const void*  input,
    void*        output,
    const void*  startIv,
    uint8_t      operation)
{
    seos_err_t ret;
    char iv_temp[IV_LENGTH_IN_BYTES] = {0};
    size_t outputSize = ENCRYPTION_PAGE_LEN;
    SeosCryptoApi_CipherH hCipher;

    createIV(self, addr, startIv, iv_temp);

    ret = SeosCryptoApi_Cipher_init(
              &hCipher,
              self->hCrypto,
              self->hKey,
              operation,
              iv_temp,
              IV_LENGTH_IN_BYTES);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_Cipher_init failed, code %d", ret);
        return;
    }

    ret = SeosCryptoApi_Cipher_process(hCipher, input, ENCRYPTION_PAGE_LEN,
                                       output, &outputSize);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_Cipher_process failed, code %d", ret);
    }

    if (outputSize != ENCRYPTION_PAGE_LEN)
    {
        Debug_LOG_ERROR("length %zu invalid for block, expected %d",
                        outputSize, ENCRYPTION_PAGE_LEN);
    }

    SeosCryptoApi_Cipher_free(hCipher);
}


//------------------------------------------------------------------------------
static void
decryptBlock(
    AesNvm*      self,
    size_t       addr,
    const void*  input,
    void*        output)
{
    Debug_ASSERT_SELF(self);

    cryptoCalculateBlock(
        self,
        addr,
        input,
        output,
        self->startIv,
        SeosCryptoApi_Cipher_ALG_AES_CBC_DEC);
}


//------------------------------------------------------------------------------
static void
encryptBlock(
    AesNvm*      self,
    size_t       addr,
    const void*  input,
    void*        output)
{
    Debug_ASSERT_SELF(self);

    cryptoCalculateBlock(
        self,
        addr,
        input,
        output,
        self->startIv,
        SeosCryptoApi_Cipher_ALG_AES_CBC_ENC);
}


//------------------------------------------------------------------------------
static int
entropy(
    void*          ctx,
    unsigned char* buf,
    size_t         len)
{
    // This would be the platform specific function to obtain entropy
    memset(buf, 0, len);
    return 0;
}


//------------------------------------------------------------------------------
static seos_err_t
init_crypto(
    AesNvm*      self)
{
    Debug_ASSERT_SELF(self);

    static SeosCryptoApi_Config cfgLib =
    {
        .mode = SeosCryptoApi_Mode_LIBRARY,
        .mem = {
            .malloc = malloc,
            .free = free,
        },
        .impl.lib.rng.entropy = entropy,
    };

    seos_err_t ret = SeosCryptoApi_init(&(self->hCrypto), &cfgLib);

    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_init failed, code %d", ret);
        return ret;
    }

    return SEOS_SUCCESS;

}


//------------------------------------------------------------------------------
// Public functions
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
bool
AesNvm_ctor(
    AesNvm*      self,
    Nvm*         nvm,
    const void*  startIv,
    const SeosCryptoApi_Key_Data* masterKeyData)
{
    Debug_ASSERT_SELF(self);
    seos_err_t ret;

    self->parent.vtable = &AesNvm_vtable;
    self->underlyingNvm = nvm;
    self->startIv = startIv;

    ret = init_crypto(self);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("init_crypto failed, code %d", ret);
        return false;
    }

    // Setup key data
    ret = SeosCryptoApi_Key_import(
              &self->hKey,
              self->hCrypto,
              masterKeyData);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_Key_import failed for master key, code %d", ret);
        goto err0;
    }

    // Hash the master key
    SeosCryptoApi_DigestH hDigest;
    ret = SeosCryptoApi_Digest_init(
              &hDigest,
              self->hCrypto,
              SeosCryptoApi_Digest_ALG_SHA256);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_Digest_init failed, code %d", ret);
        goto err1;
    }

    ret = SeosCryptoApi_Digest_process(
              hDigest,
              masterKeyData->data.aes.bytes,
              masterKeyData->data.aes.len);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_Digest_process failed, code %d", ret);
        goto err2;
    }

    static SeosCryptoApi_Key_Data hHashedKeyData =
    {
        .type = SeosCryptoApi_Key_TYPE_AES,
        .data.aes.len = KEY_LENGTH_IN_BYTES
    };

    size_t len = sizeof(hHashedKeyData.data.aes.bytes);
    ret = SeosCryptoApi_Digest_finalize(
              hDigest,
              hHashedKeyData.data.aes.bytes,
              &len);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_Digest_finalize failed, code %d",
                        ret);
        goto err2;
    }

    ret = SeosCryptoApi_Key_import(
              &self->hHashedKey,
              self->hCrypto,
              &hHashedKeyData);
    if (ret != SEOS_SUCCESS)
    {
        Debug_LOG_ERROR("SeosCryptoApi_Key_import failed for hashed key, code %d",
                        ret);
        goto err2;
    }

    SeosCryptoApi_Digest_free(hDigest);

    return true;

err2:
    SeosCryptoApi_Digest_free(hDigest);
err1:
    SeosCryptoApi_Key_free(self->hKey);
err0:
    SeosCryptoApi_free(self->hCrypto);

    return false;
}


//------------------------------------------------------------------------------
void
AesNvm_dtor(
    Nvm* nvm)
{
    DECL_UNUSED_VAR(AesNvm * self) = (AesNvm*) nvm;
    Debug_ASSERT_SELF(self);

    SeosCryptoApi_Key_free(self->hHashedKey);
    SeosCryptoApi_Key_free(self->hKey);
    SeosCryptoApi_free(self->hCrypto);
}


//------------------------------------------------------------------------------
size_t
AesNvm_read(
    Nvm*    nvm,
    size_t  addr,
    void*   buffer,
    size_t  size)
{
    AesNvm* self = (AesNvm*) nvm;
    Debug_ASSERT_SELF(self);
    uint32_t pageOffset = addr % ENCRYPTION_PAGE_LEN;
    uint32_t allignedAddr = addr - pageOffset;
    size_t totalRead = 0, retValue = 0;
    char memoryBlock[ENCRYPTION_PAGE_LEN] = {0};

    while ((int32_t)size > 0)
    {
        retValue = Nvm_read(self->underlyingNvm,
                            allignedAddr,
                            memoryBlock,
                            ENCRYPTION_PAGE_LEN);
        if (retValue != ENCRYPTION_PAGE_LEN)
        {
            Debug_LOG_WARNING("%s: Tried to read %d bytes, but read %zu bytes, from address %u!",
                              __func__, ENCRYPTION_PAGE_LEN, retValue, allignedAddr);
            return totalRead;
        }

        decryptBlock(self, allignedAddr, memoryBlock, memoryBlock);

        //If the size of the buffer is larger that the remaining space in the current block
        //we have to read the data to the end of the current block, adjust the address and
        //the pageOffset and repeat for the next block
        size_t sizeInCurrentBlock = size > (ENCRYPTION_PAGE_LEN - pageOffset) ?
                                    (ENCRYPTION_PAGE_LEN - pageOffset) : size;

        memcpy(buffer, &memoryBlock[pageOffset], sizeInCurrentBlock);

        //move the address and the page offset to the begining of the next block
        allignedAddr += ENCRYPTION_PAGE_LEN;
        pageOffset = 0;

        //decrease the size by already read length
        size -= (ENCRYPTION_PAGE_LEN - pageOffset);

        //change the position in the read buffer and add
        //the num of bytes to the total byte counter
        buffer += (ENCRYPTION_PAGE_LEN - pageOffset);
        totalRead += sizeInCurrentBlock;
    }

    return totalRead;
}


//------------------------------------------------------------------------------
size_t
AesNvm_write(
    Nvm*         nvm,
    size_t       addr,
    void const*  buffer,
    size_t       size)
{
    AesNvm* self = (AesNvm*) nvm;
    Debug_ASSERT_SELF(self);
    uint32_t pageOffset = addr % ENCRYPTION_PAGE_LEN;
    uint32_t allignedAddr = addr - pageOffset;
    size_t totalWritten = 0, retValue = 0;
    char memoryBlock[ENCRYPTION_PAGE_LEN] = {0};

    while ((int32_t)size > 0)
    {
        retValue = Nvm_read(self->underlyingNvm, allignedAddr, memoryBlock,
                            ENCRYPTION_PAGE_LEN);
        if (retValue != ENCRYPTION_PAGE_LEN)
        {
            Debug_LOG_WARNING("%s: Tried to read %d bytes, but read %zu bytes, from address: %u",
                              __func__, ENCRYPTION_PAGE_LEN, retValue, allignedAddr);
            return totalWritten;
        }

        decryptBlock(self, allignedAddr, memoryBlock, memoryBlock);

        //If the size of the buffer is larger that the remaining space in the current block
        //we have to write the data to the end of the current block, adjust the address and
        //the pageOffset and repeat for the next block
        size_t sizeInCurrentBlock = size > (ENCRYPTION_PAGE_LEN - pageOffset) ?
                                    (ENCRYPTION_PAGE_LEN - pageOffset) : size;
        memcpy(&memoryBlock[pageOffset], buffer, sizeInCurrentBlock);

        encryptBlock(self, allignedAddr, memoryBlock, memoryBlock);

        retValue = Nvm_write(self->underlyingNvm, allignedAddr, memoryBlock,
                             ENCRYPTION_PAGE_LEN);
        if (retValue != ENCRYPTION_PAGE_LEN)
        {
            Debug_LOG_WARNING("%s: Tried to write %d bytes, but written %zu bytes, to address %u!",
                              __func__, ENCRYPTION_PAGE_LEN, retValue, allignedAddr);
            return totalWritten;
        }

        //move the address and the page offset to the begining of the next block
        allignedAddr += ENCRYPTION_PAGE_LEN;
        pageOffset = 0;

        //decrease the size by already read length
        size -= (ENCRYPTION_PAGE_LEN - pageOffset);

        //change the position in the read buffer and add
        //the num of bytes to the total byte counter
        buffer += (ENCRYPTION_PAGE_LEN - pageOffset);
        totalWritten += sizeInCurrentBlock;
    }

    return totalWritten;
}


//------------------------------------------------------------------------------
size_t
AesNvm_erase(
    Nvm*    nvm,
    size_t  addr,
    size_t  size)
{
    AesNvm* self = (AesNvm*) nvm;
    Debug_ASSERT_SELF(self);
    size_t retValue = 0, totalErased = 0;
    char memoryBlock[ENCRYPTION_PAGE_LEN] = {0};

    for (unsigned int i = 0; i < (size / ENCRYPTION_PAGE_LEN); i++)
    {
        memset(memoryBlock, 0xFF, ENCRYPTION_PAGE_LEN);

        encryptBlock(self, addr + (i * ENCRYPTION_PAGE_LEN), memoryBlock, memoryBlock);

        retValue = Nvm_write(self->underlyingNvm, addr + (ENCRYPTION_PAGE_LEN * i),
                             memoryBlock, ENCRYPTION_PAGE_LEN);
        if (retValue != ENCRYPTION_PAGE_LEN)
        {
            Debug_LOG_WARNING("%s: Tried to write %d bytes, but written %zu bytes, to address %zu!",
                              __func__, ENCRYPTION_PAGE_LEN, retValue, addr + (ENCRYPTION_PAGE_LEN * i));
            return totalErased;
        }
        totalErased += retValue;
    }

    return totalErased;
}


//------------------------------------------------------------------------------
size_t
AesNvm_getSize(
    Nvm* nvm)
{
    return nvm->vtable->getSize(nvm);
}