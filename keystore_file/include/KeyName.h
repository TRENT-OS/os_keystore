/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

#pragma once

#include <stdbool.h>


#define MAX_KEY_NAME_LEN    16

typedef struct KeyName
{
    char buffer[MAX_KEY_NAME_LEN + 1]; // null terminated string
}
KeyName;


/* Public functions ----------------------------------------------------------*/

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
