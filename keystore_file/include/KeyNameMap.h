/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */
#pragma once

#include "lib_utils/MapT.h"

#define MAX_KEY_NAME_LEN    16

typedef struct KeyName
{
    char buffer[MAX_KEY_NAME_LEN + 1]; // null terminated string
} KeyName;

MapT_DECLARE(KeyName, size_t, KeyNameMap);

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

