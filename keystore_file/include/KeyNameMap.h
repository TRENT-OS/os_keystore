/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include "lib_utils/MapT.h"

#define MAX_KEY_NAME_LEN    16

typedef size_t KeySize;

typedef struct KeyName
{
    char buffer[MAX_KEY_NAME_LEN + 1]; // null terminated string
} KeyName;

MapT_DECLARE(KeyName, KeySize, KeyNameMap);

/* Key functions ----------------------------------------------------------*/
bool
KeyName_ctorCopy(
    KeyName*       dst,
    KeyName const* src);
bool
KeyName_ctorMove(
    KeyName*       dst,
    KeyName const* src);
bool
KeyName_assign(
    KeyName*       dst,
    KeyName const* src);
void
KeyName_dtor(
    KeyName* el);

bool
KeyName_isEqual(
    KeyName const* a,
    KeyName const* b);

/* Value functions ----------------------------------------------------------*/
bool
KeySize_ctorCopy(
    KeySize*       dst,
    KeySize const* src);

bool
KeySize_ctorMove(
    KeySize*       dst,
    KeySize const* src);

bool
KeySize_assign(
    KeySize*       dst,
    KeySize const* src);

void
KeySize_dtor(
    KeySize* el);
