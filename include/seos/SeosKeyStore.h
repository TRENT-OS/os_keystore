/**
 * @addtogroup SEOS
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
#include "seos_err.h"
#include "SeosCryptoKey.h"
#include "SeosCryptoCipher.h"
#include "SeosCryptoApi.h"
#include "LibIO/FileStream.h"
#include "LibIO/FileStreamFactory.h"

/* Exported macro ------------------------------------------------------------*/

/* Exported types ------------------------------------------------------------*/
typedef struct SeosKeyStore SeosKeyStore;

struct SeosKeyStore
{
    FileStreamFactory* fsFactory;
    SeosCrypto* cryptoCore;
    char* name;
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
 * @return true if success
 *
 */
bool
SeosKeyStore_ctor(SeosKeyStore* self,
                  FileStreamFactory* fileStreamFactory,
                  SeosCrypto* cryptoCore,
                  char* name);
/**
 * @brief Destructor
 *
 */
void
SeosKeyStore_dtor(SeosKeyStore* self);
/**
 * @brief Imports a SeosCrypto_Key object into the keystore
 *
 * @param self          pointer to self
 * @param name          name of the key to import
 * @param key           key object to import
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStore_importKey(SeosKeyStore* self, const char* name,
                       SeosCryptoKey* key);
/**
 * @brief Retreives the key with a given name from the keystore
 *
 * @param self          pointer to self
 * @param name          name of the key to get
 * @param key[out]      the returned key
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStore_getKey(SeosKeyStore* self, const char* name, SeosCryptoKey** key);
/**
 * @brief Reads the key data from the key specified by the passed name and
 * stores the key size in the output parameter keySize
 *
 * @param self          pointer to self
 * @param name          name of the key we want to get the size of
 * @param keySize[out]  the size of the key in bytes
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStore_getKeySizeBytes(SeosKeyStore* self, const char* name,
                             size_t* keySize);
/**
 * @brief Deletes a key with a given name from the keystore
 *
 * @param self          pointer to self
 * @param name          key name
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStore_deleteKey(SeosKeyStore* self, const char* name);
/**
 * @brief Frees the resources of the passed key (dtor) but the key remains
 * in the non volatile storage
 *
 * @param self          pointer to self
 * @param key           key handle
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStore_closeKey(SeosKeyStore* self, SeosCryptoKey* key);
/**
 * @brief Copies the key with a selected name from the current key store to
 * the destination key store
 *
 * @param self          pointer to self
 * @param name          name of the key we want to copy
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStore_copyKey(SeosKeyStore* self, const char* name,
                     SeosKeyStore* destKeyStore);
/**
 * @brief Moves the key with a selected name from the current key store to
 * the destination key store (after the operation the key is no longer in the
 * current key store)
 *
 * @param self          pointer to self
 * @param name          name of the key we want to move
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStore_moveKey(SeosKeyStore* self, const char* name,
                     SeosKeyStore* destKeyStore);
/**
 * @brief Generates a key with a given name using an RNG, stores the key into the key store
 * and returns the key data in the key object.
 *
 * @param self          pointer to self
 * @param key[out]      the returned key
 * @param name          name of the key we want to generate
 * @param algorithm     algorithm that uses the key
 * @param flags         flags
 * @param lenBits       length of the key in bits
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStore_generateKey(SeosKeyStore*   self,
                         SeosCryptoKey** key,
                         const char*     name,
                         unsigned int    algorithm,
                         unsigned int    flags,
                         size_t          lenBits);
///@}