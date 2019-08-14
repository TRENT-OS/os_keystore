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
/* Defines ------------------------------------------------------------------*/
#include "seos/seos_err.h"
#include "SeosKeyStoreApi.h"
#include "SeosKeyStoreRpc.h"

/* Exported macro ------------------------------------------------------------*/
#define SeosKeyStoreClient_TO_SEOS_KEY_STORE_API(self) ((&(self))->parent)

/* Exported types ------------------------------------------------------------*/
typedef struct
{
    SeosKeyStoreApi   parent;
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
SeosKeyStoreClient_init(SeosKeyStoreClient*     self,
                        SeosKeyStoreRpc_Handle  rpcHandle,
                        void*                   dataport);
/**
 * @brief destructor of a seos KeyStore client
 *
 * @param api (required) pointer to the seos KeyStore client object to be
 *  destructed
 *
 */
void
SeosKeyStoreClient_deInit(SeosKeyStoreApi* api);

/***************************** KeyStore functions *******************************/
/**
 * @brief Imports a SeosCrypto_Key object into the keystore
 *
 * @param api              pointer to api
 * @param keyHandle         key handle
 * @param name              name of the key to import
 * @param keyBytesBuffer    buffer containing the key bytes
 * @param algorithm         algorithm that uses the key
 * @param flags             flags
 * @param lenBits           length of the key in bits
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreClient_importKey(SeosKeyStoreApi*       api,
                             SeosCrypto_KeyHandle*  keyHandle,
                             const char*            name,
                             void const*            keyBytesBuffer,
                             unsigned int           algorithm,
                             unsigned int           flags,
                             size_t                 lenBits);
/**
 * @brief Retreives the key with a given name from the keystore
 *
 * @param api          pointer to api
 * @param keyHandle     key handle
 * @param name          name of the key to get
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreClient_getKey(SeosKeyStoreApi*      api,
                          SeosCrypto_KeyHandle* keyHandle,
                          const char*           name);
/**
 * @brief Deletes a key with from the keystore
 *
 * @param api          pointer to api
 * @param keyHandle     key handle
 * @param name          name of the keyHandle we want to delete
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreClient_deleteKey(SeosKeyStoreApi*       api,
                             SeosCrypto_KeyHandle   keyHandle,
                             const char*            name);
/**
 * @brief Copies the key from the current key store to the destination key store
 *
 * @param api          pointer to api
 * @param keyHandle     key handle
 * @param name          name of the key to be copied
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreClient_copyKey(SeosKeyStoreApi*     api,
                           SeosCrypto_KeyHandle keyHandle,
                           const char*          name,
                           SeosKeyStoreApi*     destKeyStore);
/**
 * @brief Moves the key from the current key store to
 * the destination key store (after the operation the key is no longer in the
 * current key store)
 *
 * @param api          pointer to api
 * @param keyHandle     key handle
 * @param name          name of the key to be moved
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreClient_moveKey(SeosKeyStoreApi*     api,
                           SeosCrypto_KeyHandle keyHandle,
                           const char*          name,
                           SeosKeyStoreApi*     destKeyStore);
/**
 * @brief Generates a key with a given name using an RNG, stores the key into the key store
 * and returns the key data in the key object.
 *
 * @param api          pointer to api
 * @param keyHandle     key handle
 * @param name          name of the key to get
 * @param algorithm     algorithm that uses the key
 * @param flags         flags
 * @param lenBits       length of the key in bits
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreClient_generateKey(SeosKeyStoreApi*         api,
                               SeosCrypto_KeyHandle*    keyHandle,
                               const char*              name,
                               unsigned int             algorithm,
                               unsigned int             flags,
                               size_t                   lenBits);

/** @} */
