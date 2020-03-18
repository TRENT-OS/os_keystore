/**
 * @addtogroup API
 * @{
 *
 * @file SeosKeyStore.h
 *
 * @brief a library that implements core key storage functions for SEOS.
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#pragma once

/* Includes ------------------------------------------------------------------*/
#include "SeosError.h"
#include "LibIO/FileStream.h"
#include "LibIO/FileStreamFactory.h"
#include "KeyNameMap.h"
#include "SeosKeyStoreCtx.h"
#include "SeosCryptoApi.h"

/* Exported macro ------------------------------------------------------------*/
#define SeosKeyStore_TO_SEOS_KEY_STORE_CTX(self) (&(self)->parent)

/* Exported defines ------------------------------------------------------------*/
#define SeosKeyStore_MAX_KEYSTORE_NAME_LEN MAX_KEY_NAME_LEN

/* Exported types ------------------------------------------------------------*/
typedef struct SeosKeyStore SeosKeyStore;
typedef void* (SeosKeyStore_MallocFunc)(size_t size);
typedef void  (SeosKeyStore_FreeFunc)(void* ptr);

typedef struct
{
    SeosKeyStore_MallocFunc*   malloc;
    SeosKeyStore_FreeFunc*     free;
}
SeosKeyStore_MemIf;

typedef struct
{
    void*   buf;
    size_t  len;
}
SeosKeyStore_StaticBuf;

struct SeosKeyStore
{
    SeosKeyStoreCtx parent;
    FileStreamFactory* fsFactory;
    SeosCryptoApiH hCrypto;
    char name[SeosKeyStore_MAX_KEYSTORE_NAME_LEN];
    union
    {
        SeosKeyStore_MemIf        memIf;
        SeosKeyStore_StaticBuf    staticBuf;
    }
    mem;
    KeyNameMap keyNameMap;
    unsigned char buffer[MAX_KEY_LEN];
};

/* Exported constants --------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
/**
 * @brief Constructor
 *
 * @param self                  pointer to self
 * @param fileStreamFactory     pointer to the fileStreamFactory which takes care
 *                              of the filestream creation/destruction
 * @param name                  name of the keystore
 *
 * @return seos_err_t
 *
 */
seos_err_t
SeosKeyStore_init(SeosKeyStore*         self,
                  FileStreamFactory*    fileStreamFactory,
                  SeosCryptoApiH        hCrypto,
                  const char*           name);
/**
 * @brief Destructor
 *
 */
void
SeosKeyStore_deInit(SeosKeyStoreCtx* keyStoreCtx);
/**
 * @brief Imports a SeosCryptoLib_Key object into the keystore
 *
 * @param keyStoreCtx       pointer to keyStoreCtx
 * @param name              name of the key to import
 * @param keyData           buffer containing the key data
 * @param keySize           size of the key data in bytes
 *
 * @return seos_err_t
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER     One of the handles is NULL,
 *                                          one of the parameters exceeds
 *                                          the maximum allowed length or the
 *                                          key with the same name already exists
 *
 * @retval SEOS_ERROR_OPERATION_DENIED      Underlying filesytsem operation failed
 *
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE    Not enough space in the internal key
 *                                          name register
 *
 */
seos_err_t SeosKeyStore_importKey(SeosKeyStoreCtx*          keyStoreCtx,
                                  const char*               name,
                                  void const*               keyData,
                                  size_t                    keySize);
/**
 * @brief Retreives the key with a given name from the keystore
 *
 * @param       keyStoreCtx     pointer to keyStoreCtx
 * @param       name            name of the key to get
 * @param[out]  keyData         address of the buffer which will be filled
 *                              with key data
 * @param[out]  keySize         address of the variable which will be filled
 *                              with key data size
 *
 * @return seos_err_t
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER     One of the handles is NULL,
 *                                          one of the parameters exceeds
 *                                          the maximum allowed length
 *
 * @retval SEOS_ERROR_BUFFER_TOO_SMALL      The requested size of the key data is
 *                                          smaller than the amount of saved bytes
 *
 * @retval SEOS_ERROR_NOT_FOUND             There is no saved key with the passed name
 *
 * @retval SEOS_ERROR_OPERATION_DENIED      Underlying filesytsem operation failed
 *
 */
seos_err_t
SeosKeyStore_getKey(SeosKeyStoreCtx*         keyStoreCtx,
                    const char*              name,
                    void*                    keyData,
                    size_t*                  keySize);
/**
 * @brief Deletes a key with a given name from the keystore
 *
 * @param keyStoreCtx   pointer to keyStoreCtx
 * @param name          name of the key to delete
 *
 * @return seos_err_t
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER     One of the handles is NULL,
 *                                          one of the parameters exceeds
 *                                          the maximum allowed length
 *
 * @retval SEOS_ERROR_ABORTED               Failed to retreive the key name from the
 *                                          internal register
 *
 * @retval SEOS_ERROR_NOT_FOUND             There is no saved key with the passed name
 *
 */
seos_err_t
SeosKeyStore_deleteKey(SeosKeyStoreCtx*         keyStoreCtx,
                       const char*              name);
/**
 * @brief Copies the key from the current key store to the destination key store
 *
 * @param keyStoreCtx   pointer to keyStoreCtx
 * @param name          name of the key to copy
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err_t
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER     One of the handles is NULL,
 *                                          one of the parameters exceeds
 *                                          the maximum allowed length
 *
 */
seos_err_t
SeosKeyStore_copyKey(SeosKeyStoreCtx*           keyStoreCtx,
                     const char*                name,
                     SeosKeyStoreCtx*           destKeyStore);
/**
 * @brief Moves the key from the current key store to
 * the destination key store (after the operation the key is no longer in the
 * current key store)
 *
 * @param keyStoreCtx   pointer to keyStoreCtx
 * @param name          name of the key to move
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err_t
 *
 * @retval SEOS_ERROR_INVALID_PARAMETER     One of the handles is NULL,
 *                                          one of the parameters exceeds
 *                                          the maximum allowed length
 *
 */
seos_err_t
SeosKeyStore_moveKey(SeosKeyStoreCtx*           keyStoreCtx,
                     const char*                name,
                     SeosKeyStoreCtx*           destKeyStore);
/**
 * @brief Deletes all the keys from the keystore
 *
 * @param keyStoreCtx   pointer to keyStoreCtx
 *
 * @retval SEOS_ERROR_ABORTED               Failed to retreive the size of the
 *                                          internal register
 *
 */
seos_err_t
SeosKeyStore_wipeKeyStore(SeosKeyStoreCtx* keyStoreCtx);
///@}