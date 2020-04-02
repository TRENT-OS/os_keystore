/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "SeosError.h"
#include "OS_Crypto.h"

#include "LibIO/FileStreamFactory.h"

#include "KeystoreImpl.h"

seos_err_t
KeystoreLib_init(
    KeystoreImpl_t*    self,
    FileStreamFactory* fileStreamFactory,
    OS_Crypto_Handle_t hCrypto,
    const char*        name);

seos_err_t
KeystoreLib_free(
    KeystoreImpl_t* self);