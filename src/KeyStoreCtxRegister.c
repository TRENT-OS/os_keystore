/**
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */

#include "KeyStoreCtxRegister.h"

MapT_DEFINE(SeosCrypto_KeyHandle, SeosKeyStoreCtxHandle, KeyStoreCtxRegister);

/* Value functions ----------------------------------------------------------*/
bool
SeosKeyStoreCtxHandle_ctorCopy(SeosKeyStoreCtxHandle* dst,
                              SeosKeyStoreCtxHandle const* src)
{
    return SeosKeyStoreCtxHandle_assign(dst, src);
}

bool
SeosKeyStoreCtxHandle_ctorMove(SeosKeyStoreCtxHandle* dst,
                              SeosKeyStoreCtxHandle const* src)
{
    return SeosKeyStoreCtxHandle_assign(dst, src);
}

bool
SeosKeyStoreCtxHandle_assign(SeosKeyStoreCtxHandle* dst,
                            SeosKeyStoreCtxHandle const* src)
{
    *dst = *src;
    return true;
}

void
SeosKeyStoreCtxHandle_dtor(SeosKeyStoreCtxHandle* el)
{
    return;
}

