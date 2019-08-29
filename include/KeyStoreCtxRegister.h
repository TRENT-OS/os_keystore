/**
 * @addtogroup UTIL
 * @{
 *
 * @file KeyStoreCtxRegister.h
 *
 * @brief register that saves the key store context for 
 * each key handle in use
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#pragma once

#include "LibUtil/MapT.h"
#include "KeyNameMap.h"
#include "SeosCrypto_Handles.h"
#include "SeosKeyStoreCtx.h"

typedef SeosKeyStoreCtx* SeosKeyStoreCtxHandle;

MapT_DECLARE(SeosCrypto_KeyHandle, SeosKeyStoreCtxHandle, KeyStoreCtxRegister);

/* Value functions ----------------------------------------------------------*/
bool
SeosKeyStoreCtxHandle_ctorCopy(SeosKeyStoreCtxHandle* dst,
                              SeosKeyStoreCtxHandle const* src);
bool
SeosKeyStoreCtxHandle_ctorMove(SeosKeyStoreCtxHandle* dst,
                              SeosKeyStoreCtxHandle const* src);
bool
SeosKeyStoreCtxHandle_assign(SeosKeyStoreCtxHandle* dst,
                            SeosKeyStoreCtxHandle const* src);
void
SeosKeyStoreCtxHandle_dtor(SeosKeyStoreCtxHandle* el);

///@}