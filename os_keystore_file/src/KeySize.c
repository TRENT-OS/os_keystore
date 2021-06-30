/*
 *
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#include "KeySize.h"


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
