/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include <stdbool.h>


#define OS_KeystoreFile_KeyName_MAX_NAME_LEN    16

typedef struct OS_KeystoreFile_KeyName
{
    char buffer[OS_KeystoreFile_KeyName_MAX_NAME_LEN + 1]; // null terminated string
}
OS_KeystoreFile_KeyName;


/* Public functions ----------------------------------------------------------*/

bool
OS_KeystoreFile_KeyName_ctorCopy(
    OS_KeystoreFile_KeyName*       dst,
    OS_KeystoreFile_KeyName const* src);
bool
OS_KeystoreFile_KeyName_ctorMove(
    OS_KeystoreFile_KeyName*       dst,
    OS_KeystoreFile_KeyName const* src);
bool
OS_KeystoreFile_KeyName_assign(
    OS_KeystoreFile_KeyName*       dst,
    OS_KeystoreFile_KeyName const* src);
void
OS_KeystoreFile_KeyName_dtor(
    OS_KeystoreFile_KeyName* el);

bool
OS_KeystoreFile_KeyName_isEqual(
    OS_KeystoreFile_KeyName const* a,
    OS_KeystoreFile_KeyName const* b);
