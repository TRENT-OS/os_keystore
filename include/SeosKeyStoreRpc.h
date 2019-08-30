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
/* Defines -------------------------------------------------------------------*/
#include "SeosCrypto_Handles.h"
#include "SeosKeyStoreCtx.h"

/* Exported types ------------------------------------------------------------*/
typedef struct
{
    SeosKeyStoreCtx*
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
SeosKeyStoreRpc_init(SeosKeyStoreRpc*   self,
                     SeosKeyStoreCtx*   SeosKeyStoreRpcCtx,
                     void*              serverDataport);
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
 * @param self              pointer to self
 * @param keyHandle         key handle
 * @param algorithm         algorithm that uses the key
 * @param flags             flags
 * @param lenBits           length of the key in bits
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_importKey(SeosKeyStoreRpc*      self,
                          SeosCrypto_KeyHandle* keyHandle,
                          unsigned int          algorithm,
                          unsigned int          flags,
                          size_t                lenBits);
/**
 * @brief Retreives the key with a given name from the keystore
 *
 * @param self          pointer to self
 * @param keyHandle     key handle
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_getKey(SeosKeyStoreRpc*         self,
                       SeosCrypto_KeyHandle*    keyHandle);
/**
 * @brief Deletes a key with a given name from the keystore
 *
 * @param self          pointer to self
 * @param keyHandle     key handle
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_deleteKey(SeosKeyStoreRpc*      self,
                          SeosCrypto_KeyHandle  keyHandle);
/**
 * @brief Closes a key with a given handle
 *
 * @param self          pointer to self
 * @param keyHandle     key handle
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_closeKey(SeosKeyStoreRpc*       self,
                         SeosCrypto_KeyHandle   keyHandle);
/**
 * @brief Copies the key with a selected name from the current key store to
 * the destination key store
 *
 * @param self          pointer to self
 * @param keyHandle     key handle
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_copyKey(SeosKeyStoreRpc*        self,
                        SeosCrypto_KeyHandle    keyHandle,
                        SeosKeyStoreRpc*        destKeyStore);
/**
 * @brief Moves the key with a selected name from the current key store to
 * the destination key store (after the operation the key is no longer in the
 * current key store)
 *
 * @param self          pointer to self
 * @param keyHandle     key handle
 * @param destKeyStore  pointer to the destination key store
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_moveKey(SeosKeyStoreRpc*        self,
                        SeosCrypto_KeyHandle    keyHandle,
                        SeosKeyStoreRpc*        destKeyStore);
/**
 * @brief Generates a key with a given name using an RNG, stores the key into the key store
 * and returns the key data in the key object.
 *
 * @param self          pointer to self
 * @param keyHandle     key handle
 * @param algorithm     algorithm that uses the key
 * @param flags         flags
 * @param lenBits       length of the key in bits
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_generateKey(SeosKeyStoreRpc*        self,
                            SeosCrypto_KeyHandle*   keyHandle,
                            unsigned int            algorithm,
                            unsigned int            flags,
                            size_t                  lenBits);
/**
 * @brief Deletes all the keys from the keystore
 *
 * @param self          pointer to self
 *
 * @return seos_err
 *
 */
seos_err_t
SeosKeyStoreRpc_wipeKeyStore(SeosKeyStoreRpc* self);

/** @} */
