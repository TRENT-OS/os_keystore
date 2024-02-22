/*
 * Copyright (C) 2019-2024, HENSOLDT Cyber GmbH
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For commercial licensing, contact: info.cyber@hensoldt.net
 */

#pragma once

#include <stddef.h>
#include <stdbool.h>


typedef size_t OS_KeystoreFile_KeySize;


/* Public functions ----------------------------------------------------------*/

bool
OS_KeystoreFile_KeySize_ctorCopy(
    OS_KeystoreFile_KeySize*       dst,
    OS_KeystoreFile_KeySize const* src);

bool
OS_KeystoreFile_KeySize_ctorMove(
    OS_KeystoreFile_KeySize*       dst,
    OS_KeystoreFile_KeySize const* src);

bool
OS_KeystoreFile_KeySize_assign(
    OS_KeystoreFile_KeySize*       dst,
    OS_KeystoreFile_KeySize const* src);

void
OS_KeystoreFile_KeySize_dtor(
    OS_KeystoreFile_KeySize* el);
