/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "KeyNameMap.h"
#include <string.h>

MapT_DEFINE(KeyName, size_t, KeyNameMap);

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
