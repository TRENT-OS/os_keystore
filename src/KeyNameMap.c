/**
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "KeyNameMap.h"
#include <string.h>

MapT_DEFINE(SeosKeyStore_KeyName, size_t, KeyNameMap);

/* Key functions ----------------------------------------------------------*/
bool
size_t_ctorCopy(size_t* dst, size_t const* src)
{
    return size_t_assign(dst, src);
}

bool
size_t_ctorMove(size_t* dst, size_t const* src)
{
    return size_t_assign(dst, src);
}

bool
size_t_assign(size_t* dst, size_t const* src)
{
    *dst = *src;
    return true;
}

void
size_t_dtor(size_t* el)
{
    return;
}

/* Value functions ----------------------------------------------------------*/
bool
SeosKeyStore_KeyName_ctorCopy(SeosKeyStore_KeyName* dst,
                              SeosKeyStore_KeyName const* src)
{
    return SeosKeyStore_KeyName_assign(dst, src);
}

bool
SeosKeyStore_KeyName_ctorMove(SeosKeyStore_KeyName* dst,
                              SeosKeyStore_KeyName const* src)
{
    return SeosKeyStore_KeyName_assign(dst, src);
}

bool
SeosKeyStore_KeyName_assign(SeosKeyStore_KeyName* dst,
                            SeosKeyStore_KeyName const* src)
{
    memcpy(dst, src, MAX_KEY_NAME_LEN);
    return true;
}

void
SeosKeyStore_KeyName_dtor(SeosKeyStore_KeyName* el)
{
    return;
}

bool
SeosKeyStore_KeyName_isEqual(SeosKeyStore_KeyName const* a,
                             SeosKeyStore_KeyName const* b)
{
    return !strncmp(a->buffer, b->buffer, MAX_KEY_NAME_LEN);
}

