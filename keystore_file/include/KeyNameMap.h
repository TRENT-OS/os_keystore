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

typedef struct KeystoreFile_KeyName
{
    char buffer[MAX_KEY_NAME_LEN + 1]; // null terminated string
} KeystoreFile_KeyName;

// So we can use our convention
typedef KeystoreFile_KeyName KeyNameMap_t;

MapT_DECLARE(KeystoreFile_KeyName, size_t, KeyNameMap);

/* Key functions ----------------------------------------------------------*/
bool
KeystoreFile_KeyName_ctorCopy(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src);
bool
KeystoreFile_KeyName_ctorMove(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src);
bool
KeystoreFile_KeyName_assign(
    KeyNameMap_t*       dst,
    KeyNameMap_t const* src);
void
KeystoreFile_KeyName_dtor(
    KeyNameMap_t* el);

bool
KeystoreFile_KeyName_isEqual(
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
