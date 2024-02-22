/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include "OS_KeystoreFile_KeySize.h"
#include "OS_KeystoreFile_KeyName.h"
#include "lib_utils/MapT.h"

MapT_DECLARE(
    OS_KeystoreFile_KeyName,
    OS_KeystoreFile_KeySize,
    OS_KeystoreFile_KeyNameMap);
