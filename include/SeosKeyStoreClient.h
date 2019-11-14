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
#include "SeosError.h"
#include "SeosKeyStoreRpc.h"
#include "SeosKeyStoreCtx.h"

/* Exported macro ------------------------------------------------------------*/
#define SeosKeyStoreClient_TO_SEOS_KEY_STORE_CTX(self) (&(self)->parent)

/* Exported types ------------------------------------------------------------*/
typedef struct
{
    SeosKeyStoreCtx   parent;
    SeosKeyStoreRpc_Handle
    rpcHandle;      ///< pointer to be used in the rpc call, this pointer is not valid in our address space but will be used as a handle to tell the server which is the correct object in his address space
    void*
    clientDataport; ///< the client's address of the dataport shared with the server
}
SeosKeyStoreClient;

/**
 * @brief constructor of a seos KeyStore client
 *
 * @param self          (required) pointer to the seos KeyStore client object to be constructed
 * @param rpcHandle     handle to point the remote RPC context
 * @param dataport      pointer to the dataport connected to the server
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
 * @param keyStoreCtx   (required) pointer to the seos KeyStore client object to be
 *                      destructed
 *
 */
void
SeosKeyStoreClient_deInit(SeosKeyStoreCtx* keyStoreCtx);

/***************************** KeyStore functions *******************************/
/**
 * @brief Imports a SeosCrypto_Key object into the keystore
 *
 * @param keyStoreCtx       pointer to keyStoreCtx
 * @param name              name of the key to import
 * @param keyData           buffer containing the key data
 * @param keySize           size of the key data in bytes
 *
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE
 * @retval SEOS_ERROR_INVALID_PARAMETER
 * @retval SEOS_ERROR_OPERATION_DENIED
 *
 */
seos_err_t
SeosKeyStoreClient_importKey(SeosKeyStoreCtx*   keyStoreCtx,
                             const char*        name,
                             void const*        keyData,
                             size_t             keySize);
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
 * @return SEOS_ERROR_GENERIC
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE
 * @retval SEOS_ERROR_INVALID_PARAMETER
 * @retval SEOS_ERROR_OPERATION_DENIED
 *
 */
seos_err_t
SeosKeyStoreClient_getKey(SeosKeyStoreCtx*  keyStoreCtx,
                          const char*       name,
                          void*             keyData,
                          size_t*           keySize);
/**
 * @brief Deletes a key with a given name from the keystore
 *
 * @param keyStoreCtx   pointer to keyStoreCtx
 * @param name          name of the key to delete
 *
 * @return SEOS_ERROR_NOT_FOUND
 *
 */
seos_err_t
SeosKeyStoreClient_deleteKey(SeosKeyStoreCtx*   keyStoreCtx,
                             const char*        name);
/**
 * @brief Copies the key from the current key store to the destination key store
 *
 * @param keyStoreCtx   pointer to keyStoreCtx
 * @param name          name of the key to copy
 * @param destKeyStore  pointer to the destination key store
 *
 * @return SEOS_ERROR_GENERIC
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE
 * @retval SEOS_ERROR_INVALID_PARAMETER
 * @retval SEOS_ERROR_OPERATION_DENIED
 *
 */
seos_err_t
SeosKeyStoreClient_copyKey(SeosKeyStoreCtx* keyStoreCtx,
                           const char*      name,
                           SeosKeyStoreCtx* destKeyStore);
/**
 * @brief Moves the key from the current key store to
 * the destination key store (after the operation the key is no longer in the
 * current key store)
 *
 * @param keyStoreCtx   pointer to keyStoreCtx
 * @param name          name of the key to move
 * @param destKeyStore  pointer to the destination key store
 *
 * @return SEOS_ERROR_GENERIC
 * @retval SEOS_ERROR_INSUFFICIENT_SPACE
 * @retval SEOS_ERROR_INVALID_PARAMETER
 * @retval SEOS_ERROR_OPERATION_DENIED
 *
 */
seos_err_t
SeosKeyStoreClient_moveKey(SeosKeyStoreCtx* keyStoreCtx,
                           const char*      name,
                           SeosKeyStoreCtx* destKeyStore);
/**
 * @brief Deletes all the keys from the keystore
 *
 * @param keyStoreCtx   pointer to keyStoreCtx
 *
 * @retval SEOS_ERROR_NOT_FOUND
 *
 */
seos_err_t
SeosKeyStoreClient_wipeKeyStore(SeosKeyStoreCtx* keyStoreCtx);

/** @} */
