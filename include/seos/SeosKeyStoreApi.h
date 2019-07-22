/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosKeyStoreApi.h
 *
 * @brief SEOS KeyStore API library
 *
 */
#pragma once

#include "SeosKeyStore.h"
#include "SeosKeyStoreClient.h"

typedef struct
{
    SeosKeyStore* keyStore;
}
SeosKeyStoreApi_LocalConnector;

typedef struct
{
    SeosKeyStoreClient* client;
}
SeosKeyStoreApi_RpcConnector;

typedef struct
{
    union
    {
        SeosKeyStoreApi_LocalConnector  local;
        SeosKeyStoreApi_RpcConnector    rpc;
    }
    connector;
    bool isLocalConnection;
}
SeosKeyStoreApi;

seos_err_t
SeosKeyStoreApi_initAsLocal(SeosKeyStoreApi* self, SeosKeyStore* keyStore);

seos_err_t
SeosKeyStoreApi_initAsRpc(SeosKeyStoreApi* self, SeosKeyStoreClient* client);

void
SeosKeyStoreApi_deInit(SeosKeyStoreApi* self);

/***************************** KeyStore functions *******************************/
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
SeosKeyStoreApi_importKey(SeosKeyStoreApi*  self,
                            const char*     name,
                            SeosCryptoKey*  key);
/**
 * @brief Retreives the key with a given name from the keystore
 *
 * @param self          pointer to self
 * @param name          name of the key to get
 * @param keyBytes      pointer to the allocated chunk of memory for the keyBytes
 * @param keyBytes      pointer to the key type
 * @param key[out]      the returned key
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_getKey(SeosKeyStoreApi*         self,
                        const char*             name,
                        SeosCryptoKey*          key,
                        char*                   keyBytes,
                        SeosKeyStore_KeyType*   keyType);
/**
 * @brief Reads the key data from the key specified by the passed name and
 * stores the key size in the output parameter keySize
 *
 * @param self          pointer to self
 * @param name          name of the key we want to get
 * @param keySize[out]  the size of the key in bytes
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_getKeySizeBytes(SeosKeyStoreApi*    self,
                                const char*         name,
                                size_t*             keySize);
/**
 * @brief Deletes a key with a given name from the keystore
 *
 * @param self          pointer to self
 * @param name          name of the key we want to delete
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_deleteKey(SeosKeyStoreApi*      self,
                            const char*         name);
/**
 * @brief Copies the key with a selected name from the current key store to
 * the destination key store
 *
 * @param self          pointer to self
 * @param name          name of the key we want to delete
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_copyKey(SeosKeyStoreApi*    self,
                        const char*         name,
                        SeosKeyStoreApi*    destKeyStore);
/**
 * @brief Moves the key with a selected name from the current key store to
 * the destination key store (after the operation the key is no longer in the
 * current key store)
 *
 * @param self          pointer to self
 * @param name          name of the key we want to delete
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_moveKey(SeosKeyStoreApi*    self,
                        const char*         name,
                        SeosKeyStoreApi*    destKeyStore);
/**
 * @brief Generates a key with a given name using an RNG, stores the key into the key store
 * and returns the key data in the key object.
 *
 * @param self          pointer to self
 * @param name          name of the key we want to delete
 * @param keyBytes      pointer to the allocated chunk of memory for the keyBytes
 * @param keyBytes      pointer to the key type
 * @param key[out]      the returned key
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_generateKey(SeosKeyStoreApi*        self,
                            SeosCryptoKey*          key,
                            const char*             name, 
                            char*                   keyBytes, 
                            SeosKeyStore_KeyType*   keyType);

/** @} */
