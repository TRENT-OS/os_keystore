/*
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "KeyName.h"

#include <string.h>


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
