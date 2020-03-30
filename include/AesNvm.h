/**
 * @addtogroup SEOS
 * @{
 *
 * @file AesNvm.h
 *
 * @brief a implementation of the AES block encryption on top of an NVM interface.
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#pragma once

/* Includes ------------------------------------------------------------------*/
#include "LibMem/Nvm.h"
#include "OS_Crypto.h"

/* Exported macro ------------------------------------------------------------*/
#define AesNvm_TO_NVM(self)             (&(self)->parent)


/* Exported types ------------------------------------------------------------*/
typedef struct AesNvm AesNvm;

struct AesNvm
{
    Nvm                        parent;
    Nvm*                       underlyingNvm;
    const uint8_t*             startIv;
    OS_Crypto_Handle_t         hCrypto;
    OS_CryptoKey_Handle_t      hKey;
    OS_CryptoKey_Handle_t      hHashedKey;
};

/* Exported constants --------------------------------------------------------*/
/* Exported functions ------------------------------------------------------- */
/**
 * @brief Constructor that receives the nvm contex and NVM_write,
 * NVM_read and NVM_erase functions.
 *
 * @return true if success
 *
 */
bool
AesNvm_ctor(
    AesNvm*                     self,
    Nvm*                        parent,
    const void*                 startIv,
    const OS_CryptoKey_Data_t*  masterKeyData);


void
AesNvm_dtor(
    Nvm* nvm);


/**
 * @brief static implementation of the write method that encrypts
 * the data in blocks and passes it on to the NVM_write function
 * passed in the constructor. The max write length is equal to
 * the encryption block length.
 *
 * @return number of succesfully written bytes
 *
 */
size_t
AesNvm_write(
    Nvm*         nvm,
    size_t       addr,
    void const*  buffer,
    size_t       length);


/**
 * @brief static implementation of the read method that decrypts
 * the data from the NVM_read function passed in the constructor.
 * The max read length is equal to the encryption block length.
 *
 * @return number of succesfully read bytes
 *
 */
size_t
AesNvm_read(
    Nvm*    nvm,
    size_t  addr,
    void*   buffer,
    size_t  length);


/**
 * @brief static implementation of the erase method that is required
 * when working with flash. It writes the encrypted version of the
 * empty block (0xFF) using the NVM_write function passed in the constructor.
 *
 * @return number of succesfully erased bytes
 *
 */
size_t
AesNvm_erase(
    Nvm*    nvm,
    size_t  addr,
    size_t  length);


/**
 * @brief static implementation of the get_size method that simply calls
 * the NVM_getSize passed in the constructor
 *
 * @return number of succesfully mempory size in bytes
 *
 */
size_t
AesNvm_getSize(
    Nvm* nvm);

///@}
