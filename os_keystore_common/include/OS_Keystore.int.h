/*
 * Copyright (C) 2019-2021, HENSOLDT Cyber GmbH
 */

/**
 * @file
 *
 * Internal part of OS_Keystore.h
 *
 * This file provides the definition of the type OS_Keystore_t and the Vtable
 * types (function pointers and Vtable struct) needed for the TRENTOS-M
 * internal interface implementation mechanism.
 *
 * Moreover the file offers some interface function implementation as well as a
 * 'default' implementation that can be (or not) used by the modules that
 * will implement OS_Keystore.
 */

#pragma once

#include "OS_Keystore.h"

typedef OS_Error_t
(*OS_Keystore_Vtable_Free)(
    OS_Keystore_t*  self);

typedef OS_Error_t
(*OS_Keystore_Vtable_StoreKey)(
    OS_Keystore_t*  self,
    const char*     name,
    void const*     keyData,
    size_t          keySize);

typedef OS_Error_t
(*OS_Keystore_Vtable_LoadKey)(
    OS_Keystore_t*  self,
    const char*     name,
    void*           keyData,
    size_t*         keySize);

typedef OS_Error_t
(*OS_Keystore_Vtable_DeleteKey)(
    OS_Keystore_t*  self,
    const char*     name);

typedef OS_Error_t
(*OS_Keystore_Vtable_CopyKey)(
    OS_Keystore_t*  self,
    const char*     name,
    OS_Keystore_t*  destKeyStore);

typedef OS_Error_t
(*OS_Keystore_Vtable_MoveKey)(
    OS_Keystore_t*  self,
    const char*     name,
    OS_Keystore_t*  destKeyStore);

typedef OS_Error_t
(*OS_Keystore_Vtable_WipeKeystore)(
    OS_Keystore_t*  self);

typedef struct
{
    OS_Keystore_Vtable_Free           free;
    OS_Keystore_Vtable_StoreKey       storeKey;
    OS_Keystore_Vtable_LoadKey        loadKey;
    OS_Keystore_Vtable_DeleteKey      deleteKey;
    OS_Keystore_Vtable_CopyKey        copyKey;
    OS_Keystore_Vtable_MoveKey        moveKey;
    OS_Keystore_Vtable_WipeKeystore   wipeKeystore;
}
OS_Keystore_Vtable_t;

struct OS_Keystore
{
    const OS_Keystore_Vtable_t* vtable;
};


// Non virtual functions -------------------------------------------------------

/**
 * An implementation of the OS_Keystore_copyKey() function provided as a
 * standard implementation that performs OS_Keystore_loadKey() and then
 * OS_Keystore_storeKey().
 *
 * A designer of an implementation of OS_Keystore may decide or not to use it
 * (putting it in its Vtable).
 *
 * See OS_Keystore_copyKey().
 *
 */
OS_Error_t
OS_Keystore_copyKeyImpl(
    OS_Keystore_t*  srcPtr,
    const char*     name,
    OS_Keystore_t*  dstPtr,
    void*           keyBuffer,
    size_t          keyBufferSize);

/**
 * An implementation of the OS_Keystore_moveKey() function provided as a
 * standard implementation that performs the OS_Keystore_copyKey() and then
 * OS_Keystore_deleteKey().
 *
 * A designer of an implementation of OS_Keystore may decide or not to use it
 * (putting it in its Vtable).
 *
 * See OS_Keystore_moveKey().
 *
 */
OS_Error_t
OS_Keystore_moveKeyImpl(
    OS_Keystore_t*  srcPtr,
    const char*     name,
    OS_Keystore_t*  dstPtr);
