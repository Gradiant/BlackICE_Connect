/*******************************************************************************
 *
 *                                   GRADIANT
 *
 *     Galician Research And Development center In AdvaNced Telecommunication
 *
 *
 * Copyright (c) 2019 by Gradiant. All rights reserved.
 * Licensed under the Mozilla Public License v2.0 (the "LICENSE").
 * https://github.com/Gradiant/BlackICE_Connect/LICENSE
 *******************************************************************************/

#ifndef _PKCS11_INTERFACE_H_
#define _PKCS11_INTERFACE_H_

#ifdef _WIN32
	#include <windows.h> // HMODULE and used functions:  LoadLibrary(), GetProcAddress(), FreeLibrary()
#endif

#include <stdio.h>         
#include <stdlib.h>
#include <string.h>
#include "cryptoki/cryptoki.h"

#ifdef _WIN32
	typedef HMODULE blackIce_handle;
#else
	typedef void* blackIce_handle;
#endif

blackIce_handle blackIce_LoadLibrary(const char* const libName);
int blackIce_FreeLibrary(blackIce_handle libHandle);
void* blackIce_LoadProc(blackIce_handle libHandle, const char* const procName);

int Initialize(CK_FUNCTION_LIST_PTR_PTR  ppFunctions,
	blackIce_handle           *phModule,
	char                      *libraryPath);
int InitPin(CK_FUNCTION_LIST_PTR  pFunctions,
	char                  *userPIN);
int ChangePin(CK_FUNCTION_LIST_PTR  pFunctions,
	char                  *userPIN,
	char				  *newPIN);

#endif //!_PKCS11_INTERFACE_H_