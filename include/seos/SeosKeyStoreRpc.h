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

/** @} */
