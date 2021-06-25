/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "KeyNameMap.h"
#include <string.h>

MapT_DEFINE(KeyName, KeySize, KeyNameMap);

/* Key functions ----------------------------------------------------------*/
bool
KeySize_ctorCopy(
    KeySize*       dst,
    KeySize const* src)
{
    return KeySize_assign(dst, src);
}

bool
KeySize_ctorMove(
    KeySize*       dst,
    KeySize const* src)
{
    return KeySize_assign(dst, src);
}

bool
KeySize_assign(
    KeySize*       dst,
    KeySize const* src)
{
    *dst = *src;
    return true;
}

void
KeySize_dtor(
    KeySize* el)
{
    return;
}

/* Value functions ----------------------------------------------------------*/
bool
KeyName_ctorCopy(
    KeyName*       dst,
    KeyName const* src)
{
    return KeyName_assign(dst, src);
}

bool
KeyName_ctorMove(
    KeyName*       dst,
    KeyName const* src)
{
    return KeyName_assign(dst, src);
}

bool
KeyName_assign(
    KeyName*       dst,
    KeyName const* src)
{
    strncpy(dst->buffer, src->buffer, sizeof(dst->buffer) - 1);
    dst->buffer[sizeof(dst->buffer) - 1] = '\0';

    return true;
}

void
KeyName_dtor(
    KeyName* el)
{
    return;
}

bool
KeyName_isEqual(
    KeyName const* a,
    KeyName const* b)
{
    return !strncmp(a->buffer, b->buffer, sizeof(a->buffer));
}
