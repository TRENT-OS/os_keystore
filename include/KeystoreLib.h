/**
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#pragma once

#include "OS_Crypto.h"
#include "OS_FileSystem.h"

#include "Keystore.h"

OS_Error_t
KeystoreLib_init(
    Keystore_t*        self,
    OS_FileSystem_t*   fs,
    OS_Crypto_Handle_t hCrypto,
    const char*        name);
