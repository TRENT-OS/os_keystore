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
 * @param self              pointer to self
 * @param key               key object to import
 * @param keyBytesBuffer    buffer containing the key bytes
 * @param name              name of the key to import
 * @param algorithm         algorithm that uses the key
 * @param flags             flags
 * @param lenBits           length of the key in bits
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_importKey(SeosKeyStoreApi*          self,
                            SeosCrypto_KeyHandle*   key,
                            const char*             name
                            void const*             keyBytesBuffer,
                            unsigned int            algorithm,
                            unsigned int            flags,
                            size_t                  lenBits));
/**
 * @brief Retreives the key with a given name from the keystore
 *
 * @param self          pointer to self
 * @param key           key handle
 * @param name          name of the key to get
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_getKey(SeosKeyStoreApi*         self,
                        SeosCrypto_KeyHandle    key,
                        const char*             name);
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
SeosKeyStoreApi_deleteKey(SeosKeyStoreApi*          self,
                            SeosCrypto_KeyHandle    key);
/**
 * @brief Copies the key with a selected name from the current key store to
 * the destination key store
 *
 * @param self          pointer to self
 * @param key           key handle
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_copyKey(SeosKeyStoreApi*        self,
                        SeosCrypto_KeyHandle    key,
                        SeosKeyStoreApi*        destKeyStore);
/**
 * @brief Moves the key with a selected name from the current key store to
 * the destination key store (after the operation the key is no longer in the
 * current key store)
 *
 * @param self          pointer to self
 * @param key           key handle
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_moveKey(SeosKeyStoreApi*        self,
                        SeosCrypto_KeyHandle    key,
                        SeosKeyStoreApi*        destKeyStore);
/**
 * @brief Generates a key with a given name using an RNG, stores the key into the key store
 * and returns the key data in the key object.
 *
 * @param self          pointer to self
 * @param key           key handle
 * @param name          name of the key to get
 * @param algorithm     algorithm that uses the key
 * @param flags         flags
 * @param lenBits       length of the key in bits
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreApi_generateKey(SeosKeyStoreApi*        self,
                            SeosCrypto_KeyHandle*   key,
                            const char*             name, 
                            unsigned int            algorithm,
                            unsigned int            flags,
                            size_t                  lenBits);

/** @} */
