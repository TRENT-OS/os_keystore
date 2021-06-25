/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include <stddef.h>
#include <stdbool.h>


typedef size_t KeySize;


/* Public functions ----------------------------------------------------------*/

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
