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

MapT_DECLARE(SeosKeyStore_KeyName, size_t, KeyNameMap);

/* Key functions ----------------------------------------------------------*/
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

bool
SeosKeyStore_KeyName_isEqual(SeosKeyStore_KeyName const* a,
                             SeosKeyStore_KeyName const* b);

/* Value functions ----------------------------------------------------------*/
bool
size_t_ctorCopy(size_t* dst, size_t const* src);
bool
size_t_ctorMove(size_t* dst, size_t const* src);
bool
size_t_assign(size_t* dst, size_t const* src);
void
size_t_dtor(size_t* el);

///@}