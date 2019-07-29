/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup Server
 * @{
 *
 * @file SeosKeyStoreRpc.h
 *
 * @brief RPC object and functions to handle the requests of a SEOS KeyStore
 *  client on the server's side
 *
 */
#pragma once

#include "SeosKeyStore.h"

typedef struct
{
    SeosKeyStore*
    seosKeyStoreCtx;  ///< KeyStore context to be used by the RPC object
    void*
    serverDataport;     ///< the server's address of the dataport shared with the client
}
SeosKeyStoreRpc;

typedef SeosKeyStoreRpc* SeosKeyStoreRpc_Handle;

/**
 * @brief constructor of a seos KeyStore RPC object
 *
 * @param self (required) pointer to the seos KeyStore rpc object to be
 *  constructed
 * @param SeosKeyStoreRpcCtx the SeosKeyStore context needed to allocate the
 *  resources
 * @param serverDataport pointer to the dataport connected to the client
 *
 * @return an error code.
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or wrong
 * @retval SEOS_ERROR_ABORTED if there is no way to allocate needed resources
 *
 */
seos_err_t
SeosKeyStoreRpc_init(SeosKeyStoreRpc* self,
                   SeosKeyStore* SeosKeyStoreRpcCtx,
                   void* serverDataport);
/**
 * @brief destructor of a seos KeyStore RPC object
 *
 * @param self (required) pointer to the seos KeyStore rpc object to be
 *  destructed
 *
 */
void
SeosKeyStoreRpc_deInit(SeosKeyStoreRpc* self);

/***************************** KeyStore functions *******************************/
/**
 * @brief Imports a SeosCrypto_Key object into the keystore
 *
 * @param self          pointer to self
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_importKey(SeosKeyStoreRpc* self);
/**
 * @brief Retreives the key with a given name from the keystore
 *
 * @param self          pointer to self
 * @param key[out]      the returned key
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_getKey(SeosKeyStoreRpc* self, SeosCryptoApi_KeyHandle* key);
/**
 * @brief Reads the key data from the key specified by the passed name and
 * stores the key size in the output parameter keySize
 *
 * @param self          pointer to self
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_getKeySizeBytes(SeosKeyStoreRpc* self);
/**
 * @brief Deletes a key with a given name from the keystore
 *
 * @param self          pointer to self
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_deleteKey(SeosKeyStoreRpc* self);
/**
 * @brief Copies the key with a selected name from the current key store to
 * the destination key store
 *
 * @param self          pointer to self
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_copyKey(SeosKeyStoreRpc* self, SeosKeyStoreRpc* destKeyStore);
/**
 * @brief Moves the key with a selected name from the current key store to
 * the destination key store (after the operation the key is no longer in the
 * current key store)
 *
 * @param self          pointer to self
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_moveKey(SeosKeyStoreRpc* self, SeosKeyStoreRpc* destKeyStore);
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
SeosKeyStoreRpc_generateKey(SeosKeyStoreRpc*            self,
                            SeosCryptoCipher_Algorithm  algorithm,
                            unsigned int                flags,
                            size_t                      lenBits,
                            SeosCryptoApi_KeyHandle*       key);

/** @} */
