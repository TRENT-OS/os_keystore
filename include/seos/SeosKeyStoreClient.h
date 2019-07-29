/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 * @addtogroup API
 * @{
 *
 * @file SeosKeyStoreClient.h
 *
 * @brief Client object and functions to access the SEOS KeyStore API running on
 *  a camkes server. Many of the functions here are just a wrapper of the
 *  SeosKeyStoreRpc functions running on the server and called by the client via
 *  RPC calls.
 *
 */
#pragma once

#include "seos/seos_err.h"
#include "SeosKeyStoreRpc.h"

typedef struct
{
    SeosKeyStoreRpc_Handle
    rpcHandle;      ///< pointer to be used in the rpc call, this pointer is not valid in our address space but will be used as a handle to tell the server which is the correct object in his address space
    void*
    clientDataport; ///< the client's address of the dataport shared with the server
}
SeosKeyStoreClient;

/**
 * @brief constructor of a seos KeyStore client
 *
 * @param self (required) pointer to the seos KeyStore client object to be constructed
 * @params rpcHandle handle to point the remote RPC context
 * @params dataport pointer to the dataport connected to the server
 *
 * @return an error code
 * @retval SEOS_SUCCESS if all right
 * @retval SEOS_ERROR_INVALID_PARAMETER if any of the required parameters is
 *  missing or if any parameter is invalid
 *
 */
seos_err_t
SeosKeyStoreClient_init(SeosKeyStoreClient* self,
                        SeosKeyStoreRpc_Handle rpcHandle,
                        void* dataport);
/**
 * @brief destructor of a seos KeyStore client
 *
 * @param self (required) pointer to the seos KeyStore client object to be
 *  destructed
 *
 */
void
SeosKeyStoreClient_deInit(SeosKeyStoreClient* self);

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
SeosKeyStoreClient_importKey(SeosKeyStoreClient*    self,
                            const char*             name,
                            SeosCryptoKey*          key);
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
SeosKeyStoreClient_getKey(SeosKeyStoreClient*   self,
                        const char*             name,
                        SeosCryptoKey*          key,
                        char*                   keyBytes);
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
SeosKeyStoreClient_getKeySizeBytes(SeosKeyStoreClient*  self,
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
SeosKeyStoreClient_deleteKey(SeosKeyStoreClient*    self,
                            const char*             name);
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
SeosKeyStoreClient_copyKey(SeosKeyStoreClient*  self,
                            const char*         name,
                            SeosKeyStoreClient* destKeyStore);
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
SeosKeyStoreClient_moveKey(SeosKeyStoreClient*  self,
                        const char*             name,
                        SeosKeyStoreClient*     destKeyStore);
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
SeosKeyStoreClient_generateKey(SeosKeyStoreClient*  self,
                            SeosCryptoKey*          key,
                            const char*             name, 
                            char*                   keyBytes);

/** @} */
