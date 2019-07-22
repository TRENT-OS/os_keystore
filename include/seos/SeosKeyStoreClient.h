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

/** @} */
