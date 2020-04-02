/**
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "KeyNameMap.h"
#include <string.h>

MapT_DEFINE(KeystoreLib_KeyName, size_t, KeyNameMap);

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
KeystoreLib_KeyName_ctorCopy(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src)
{
    return KeystoreLib_KeyName_assign(dst, src);
}

bool
KeystoreLib_KeyName_ctorMove(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src)
{
    return KeystoreLib_KeyName_assign(dst, src);
}

bool
KeystoreLib_KeyName_assign(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src)
{
    memcpy(dst, src, MAX_KEY_NAME_LEN);
    return true;
}

void
KeystoreLib_KeyName_dtor(
    KeyNameMap_t* el)
{
    return;
}

bool
KeystoreLib_KeyName_isEqual(
    KeyNameMap_t const* a,
    KeyNameMap_t const* b)
{
    return !strncmp(a->buffer, b->buffer, MAX_KEY_NAME_LEN);
}