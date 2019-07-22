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

/** @} */
