/**
 * @addtogroup UTIL
 * @{
 *
 * @file KeyNameMap.h
 *
 * @brief key store key name map definition
 *
 * Copyright (C) 2019, Hensoldt Cyber GmbH
 */
#pragma once

#include "LibUtil/MapT.h"
#include "SeosCrypto_Handles.h"

#if !defined(KEYSTORE_CONFIG_H_FILE)
#   error a configuration file must be provided! See KeyStore_Config.h.example
#else
#   define  KeyStore_XSTR(d)    KeyStore_STR(d)
#   define  KeyStore_STR(d)     #d
#   include KeyStore_XSTR(KEYSTORE_CONFIG_H_FILE)
#endif

typedef struct SeosKeyStore_KeyName
{
    char buffer[MAX_KEY_NAME_LEN];
}
SeosKeyStore_KeyName;

MapT_DECLARE(SeosCrypto_KeyHandle, SeosKeyStore_KeyName, KeyNameMap);

/* Key functions ----------------------------------------------------------*/
bool
SeosCrypto_KeyHandle_ctorCopy(SeosCrypto_KeyHandle* dst,
                              SeosCrypto_KeyHandle const* src);
bool
SeosCrypto_KeyHandle_ctorMove(SeosCrypto_KeyHandle* dst,
                              SeosCrypto_KeyHandle const* src);
bool
SeosCrypto_KeyHandle_assign(SeosCrypto_KeyHandle* dst,
                            SeosCrypto_KeyHandle const* src);
void
SeosCrypto_KeyHandle_dtor(SeosCrypto_KeyHandle* el);
bool
SeosCrypto_KeyHandle_isEqual(SeosCrypto_KeyHandle const* a,
                             SeosCrypto_KeyHandle const* b);

/* Value functions ----------------------------------------------------------*/
bool
SeosKeyStore_KeyName_ctorCopy(SeosKeyStore_KeyName* dst,
                              SeosKeyStore_KeyName const* src);
bool
SeosKeyStore_KeyName_ctorMove(SeosKeyStore_KeyName* dst,
                              SeosKeyStore_KeyName const* src);
bool
SeosKeyStore_KeyName_assign(SeosKeyStore_KeyName* dst,
                            SeosKeyStore_KeyName const* src);
void
SeosKeyStore_KeyName_dtor(SeosKeyStore_KeyName* el);

///@}