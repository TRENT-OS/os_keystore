/**
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "KeyNameMap.h"

MapT_DEFINE(SeosCrypto_KeyHandle, SeosKeyStore_KeyName, KeyNameMap);

/* Key functions ----------------------------------------------------------*/
bool
SeosCrypto_KeyHandle_ctorCopy(SeosCrypto_KeyHandle* dst,
                              SeosCrypto_KeyHandle const* src)
{
    return SeosCrypto_KeyHandle_assign(dst, src);
}

bool
SeosCrypto_KeyHandle_ctorMove(SeosCrypto_KeyHandle* dst,
                              SeosCrypto_KeyHandle const* src)
{
    return SeosCrypto_KeyHandle_assign(dst, src);
}

bool
SeosCrypto_KeyHandle_assign(SeosCrypto_KeyHandle* dst,
                            SeosCrypto_KeyHandle const* src)
{
    *dst = *src;
    return true;
}

void
SeosCrypto_KeyHandle_dtor(SeosCrypto_KeyHandle* el)
{
    return;
}

bool
SeosCrypto_KeyHandle_isEqual(SeosCrypto_KeyHandle const* a,
                             SeosCrypto_KeyHandle const* b)
{
    return *a == *b;
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

