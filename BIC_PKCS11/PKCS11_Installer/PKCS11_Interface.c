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

#include "PKCS11_Interface.h"
#ifndef _WIN32
	#include "dlfcn.h"
#endif //_WIN32

blackIce_handle blackIce_LoadLibrary(const char* const libName)
{
#ifdef _WIN32
	return LoadLibrary(libName);
#else //!_WIN32
	return dlopen(libName, RTLD_LAZY);
#endif //_WIN32
}

int blackIce_FreeLibrary(blackIce_handle libHandle)
{
#ifdef _WIN32
	return FreeLibrary(libHandle);
#else //!_WIN32
	return dlclose(libHandle);
#endif //_WIN32
}

void* blackIce_LoadProc(blackIce_handle libHandle, const char* const procName)
{
# ifdef _WIN32
	return GetProcAddress(libHandle, procName);
# else //!_WIN32
	return dlsym(libHandle, procName);
# endif //_WIN32
}

/******************************************************************************
*
* Initialize: load library, get function list, initialize
*
******************************************************************************/

int Initialize(CK_FUNCTION_LIST_PTR_PTR  ppFunctions,
	blackIce_handle           *phModule,
	char                      *libraryPath)
{
	CK_C_GetFunctionList  pC_GetFunctionList = NULL;
	int                   err = CKR_OK;

	// load PKCS#11 library
	if ((*phModule = blackIce_LoadLibrary(libraryPath)) == NULL)
	{
#ifdef _WIN32
		err = GetLastError();
#else //!_WIN32
		/* GetLastError() is WinAPI-specific. The closest thing in Linux is dlerror(),
		but it returns a char* instead of an int. */
		err = -1;
#endif //_WIN32
		printf("[Initialize]: unable to load library '%s'\n", libraryPath);
		return err;
	}

	// get the address of the C_GetFunctionList function
	if ((pC_GetFunctionList = (CK_C_GetFunctionList)blackIce_LoadProc((*phModule), "C_GetFunctionList")) == NULL)
	{
		printf("[Initialize]: C_GetFunctionList not found\n");
		return err;
	}

	// get addresses of all the remaining PKCS#11 functions
	err = pC_GetFunctionList(ppFunctions);
	if (err != CKR_OK)
	{
		printf("[Initialize]: pC_GetFunctionList returned 0x%08x\n", err);
		return err;
	}

	// initialize token
	err = (*ppFunctions)->C_Initialize(NULL);
	if (err != CKR_OK)
	{
		printf("[Initialize]: C_Initialize returned 0x%08x\n", err);
		return err;
	}
	return err;
}


/******************************************************************************
*
* Init user PIN
*
******************************************************************************/
int InitPin(CK_FUNCTION_LIST_PTR  pFunctions,
	char                  *userPIN)
{
	CK_SESSION_HANDLE     hSession = 0;
	char                  *soPIN = "1234";
	int                   err = 0;
	err = pFunctions->C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
	if (err != CKR_OK)
	{
		printf("[InitPin]: C_OpenSession returned 0x%08x\n", err);
		return err;
	}
	err = pFunctions->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)soPIN, (CK_ULONG)strlen(soPIN));
	if (err != CKR_OK)
	{
		printf("[InitPin]: C_Login (ADMIN) returned 0x%08x\n", err);
		return err;
	}
	err = pFunctions->C_InitPIN(hSession, (CK_UTF8CHAR_PTR)userPIN, (CK_ULONG)strlen(userPIN));
	if (err != CKR_OK)
	{
		printf("[InitPin]: C_InitPIN returned 0x%08x\n", err);
		return err;
	}
	err = pFunctions->C_CloseSession(hSession);
	return CKR_OK;
}

/******************************************************************************
*
* Init user PIN
*
******************************************************************************/
int ChangePin(CK_FUNCTION_LIST_PTR  pFunctions,
	char                  *userPIN,
	char				  *newPIN)
{
	CK_SESSION_HANDLE     hSession = 0;
	int                   err = 0;
	err = pFunctions->C_OpenSession(1, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
	if (err != CKR_OK)
	{
		printf("[InitPin]: C_OpenSession returned 0x%08x\n", err);
		return err;
	}
	err = pFunctions->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, (CK_ULONG)strlen(userPIN));
	if (err != CKR_OK)
	{
		printf("[InitPin]: C_Login (User) returned 0x%08x\n", err);
		return err;
	}
	err = pFunctions->C_SetPIN(hSession, (CK_UTF8CHAR_PTR)userPIN, (CK_ULONG)strlen(userPIN), (CK_UTF8CHAR_PTR)newPIN, (CK_ULONG)strlen(newPIN));
	if (err != CKR_OK)
	{
		printf("[InitPin]: C_InitPIN returned 0x%08x\n", err);
		return err;
	}
	err = pFunctions->C_CloseSession(hSession);
	return CKR_OK;
}