/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
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
