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

#include "lib_utils/MapT.h"

#define MAX_KEY_NAME_LEN    16

typedef struct KeystoreLib_KeyName
{
    char buffer[MAX_KEY_NAME_LEN + 1];
} KeystoreLib_KeyName;

// So we can use our convention
typedef KeystoreLib_KeyName KeyNameMap_t;

MapT_DECLARE(KeystoreLib_KeyName, size_t, KeyNameMap);

/* Key functions ----------------------------------------------------------*/
bool
KeystoreLib_KeyName_ctorCopy(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src);
bool
KeystoreLib_KeyName_ctorMove(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src);
bool
KeystoreLib_KeyName_assign(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src);
void
KeystoreLib_KeyName_dtor(
    KeyNameMap_t* el);

bool
KeystoreLib_KeyName_isEqual(
    KeyNameMap_t const* a,
    KeyNameMap_t const* b);

/* Value functions ----------------------------------------------------------*/
bool
size_t_ctorCopy(
    size_t*       dst,
    size_t const* src);

bool
size_t_ctorMove(
    size_t*       dst,
    size_t const* src);

bool
size_t_assign(
    size_t*       dst,
    size_t const* src);

void
size_t_dtor(
    size_t* el);

///@}