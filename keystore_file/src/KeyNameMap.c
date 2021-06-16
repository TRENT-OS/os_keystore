/**
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "KeyNameMap.h"
#include <string.h>

MapT_DEFINE(KeystoreFile_KeyName, size_t, KeyNameMap);

/* Key functions ----------------------------------------------------------*/
bool
size_t_ctorCopy(
    size_t*       dst,
    size_t const* src)
{
    return size_t_assign(dst, src);
}

bool
size_t_ctorMove(
    size_t*       dst,
    size_t const* src)
{
    return size_t_assign(dst, src);
}

bool
size_t_assign(
    size_t*       dst,
    size_t const* src)
{
    *dst = *src;
    return true;
}

void
size_t_dtor(
    size_t* el)
{
    return;
}

/* Value functions ----------------------------------------------------------*/
bool
KeystoreFile_KeyName_ctorCopy(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src)
{
    return KeystoreFile_KeyName_assign(dst, src);
}

bool
KeystoreFile_KeyName_ctorMove(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src)
{
    return KeystoreFile_KeyName_assign(dst, src);
}

bool
KeystoreFile_KeyName_assign(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src)
{
    strncpy(dst->buffer, src->buffer, sizeof(dst->buffer) - 1);
    dst->buffer[sizeof(dst->buffer) - 1] = '\0';

    return true;
}

void
KeystoreFile_KeyName_dtor(
    KeyNameMap_t* el)
{
    return;
}

bool
KeystoreFile_KeyName_isEqual(
    KeyNameMap_t const* a,
    KeyNameMap_t const* b)
{
    return !strncmp(a->buffer, b->buffer, sizeof(a->buffer));
}
