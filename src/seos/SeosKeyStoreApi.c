/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 *
 */
#include "SeosKeyStoreApi.h"
#include "SeosKeyStore.h"
#include "SeosKeyStoreRpc.h"

// Private static functions ----------------------------------------------------

// Public functions ------------------------------------------------------------

seos_err_t
SeosKeyStoreApi_initAsLocal(SeosKeyStoreApi* self, SeosKeyStore* keyStore)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    if (keyStore == NULL)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        self->isLocalConnection         = true;
        self->connector.local.keyStore  = keyStore;
    }
    return retval;
}

seos_err_t
SeosKeyStoreApi_initAsRpc(SeosKeyStoreApi* self, SeosKeyStoreClient* client)
{
    Debug_ASSERT_SELF(self);
    seos_err_t retval = SEOS_SUCCESS;

    if (client == NULL)
    {
        retval = SEOS_ERROR_INVALID_PARAMETER;
    }
    else
    {
        self->isLocalConnection    = false;
        self->connector.rpc.client = client;
    }
    return retval;
}

void
SeosKeyStoreApi_deInit(SeosKeyStoreApi* self)
{
    return;
}
