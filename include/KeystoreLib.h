/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"
#include "OS_FileSystem.h"

#include "KeystoreImpl.h"

OS_Error_t
KeystoreLib_init(
    KeystoreImpl_t*    self,
    OS_FileSystem_t*   fs,
    OS_Crypto_Handle_t hCrypto,
    const char*        name);

OS_Error_t
KeystoreLib_free(
    KeystoreImpl_t* self);