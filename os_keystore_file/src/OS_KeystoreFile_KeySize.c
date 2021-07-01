/*
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "OS_KeystoreFile_KeySize.h"


bool
OS_KeystoreFile_KeySize_ctorCopy(
    OS_KeystoreFile_KeySize*       dst,
    OS_KeystoreFile_KeySize const* src)
{
    return OS_KeystoreFile_KeySize_assign(dst, src);
}

bool
OS_KeystoreFile_KeySize_ctorMove(
    OS_KeystoreFile_KeySize*       dst,
    OS_KeystoreFile_KeySize const* src)
{
    return OS_KeystoreFile_KeySize_assign(dst, src);
}

bool
OS_KeystoreFile_KeySize_assign(
    OS_KeystoreFile_KeySize*       dst,
    OS_KeystoreFile_KeySize const* src)
{
    *dst = *src;
    return true;
}

void
OS_KeystoreFile_KeySize_dtor(
    OS_KeystoreFile_KeySize* el)
{
    return;
}
