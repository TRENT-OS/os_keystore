/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "OS_KeystoreFile_KeySize.h"
#include "OS_KeystoreFile_KeyName.h"
#include "lib_utils/MapT.h"

MapT_DECLARE(
    OS_KeystoreFile_KeyName,
    OS_KeystoreFile_KeySize,
    OS_KeystoreFile_KeyNameMap);
