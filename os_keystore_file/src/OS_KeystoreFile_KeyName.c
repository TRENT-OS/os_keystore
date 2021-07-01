/*
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "OS_KeystoreFile_KeyName.h"

#include <string.h>


bool
OS_KeystoreFile_KeyName_ctorCopy(
    OS_KeystoreFile_KeyName*       dst,
    OS_KeystoreFile_KeyName const* src)
{
    return OS_KeystoreFile_KeyName_assign(dst, src);
}

bool
OS_KeystoreFile_KeyName_ctorMove(
    OS_KeystoreFile_KeyName*       dst,
    OS_KeystoreFile_KeyName const* src)
{
    return OS_KeystoreFile_KeyName_assign(dst, src);
}

bool
OS_KeystoreFile_KeyName_assign(
    OS_KeystoreFile_KeyName*       dst,
    OS_KeystoreFile_KeyName const* src)
{
    strncpy(dst->buffer, src->buffer, sizeof(dst->buffer) - 1);
    dst->buffer[sizeof(dst->buffer) - 1] = '\0';

    return true;
}

void
OS_KeystoreFile_KeyName_dtor(
    OS_KeystoreFile_KeyName* el)
{
    return;
}

bool
OS_KeystoreFile_KeyName_isEqual(
    OS_KeystoreFile_KeyName const* a,
    OS_KeystoreFile_KeyName const* b)
{
    return !strncmp(a->buffer, b->buffer, sizeof(a->buffer));
}
