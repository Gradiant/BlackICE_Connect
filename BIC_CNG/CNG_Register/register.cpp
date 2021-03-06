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

#include "register.h"

////
//// An array of algorithm names, all belonging to the
//// same algorithm class...
////
PWSTR AlgorithmNames[1] = {
	(PWSTR)NCRYPT_KEY_STORAGE_ALGORITHM
};

//
// Definition of ONE class of algorithms supported
// by the provider...
////
CRYPT_INTERFACE_REG AlgorithmClass = {
	NCRYPT_KEY_STORAGE_INTERFACE,       // ncrypt key storage interface
	CRYPT_LOCAL,                        // Scope: local system only
	1,                                  // One algorithm in the class
	AlgorithmNames                      // The name(s) of the algorithm(s) in the class
};

//
// An array of ALL the algorithm classes supported
// by the provider...
//
PCRYPT_INTERFACE_REG AlgorithmClasses[1] = {
	&AlgorithmClass
};

//
// Definition of the provider's user-mode binary...
////
CRYPT_IMAGE_REG KspImage = {
	(PWSTR)KSP_BINARY,                   // File name of the sample KSP binary
	1,                                  // Number of algorithm classes the binary supports
	AlgorithmClasses                    // List of all algorithm classes available
};

//
// Definition of the overall provider...
//
CRYPT_PROVIDER_REG KSPProvider = {
	0,
	NULL,
	&KspImage,  // Image that provides user-mode support
	NULL              // Image that provides kernel-mode support (*MUST* be NULL)
};

void
EnumProviders(void)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	DWORD cbBuffer = 0;
	PCRYPT_PROVIDERS pBuffer = NULL;
	DWORD i = 0;

	ntStatus = BCryptEnumRegisteredProviders(&cbBuffer, &pBuffer);

	if (NT_SUCCESS(ntStatus))
	{
		if (pBuffer == NULL)
		{
			wprintf(L"BCryptEnumRegisteredProviders returned a NULL ptr\n");
		}
		else
		{
			for (i = 0; i < pBuffer->cProviders; i++)
			{
				wprintf(L"%s\n", pBuffer->rgpszProviders[i]);
			}
		}
	}
	else
	{
		wprintf(L"BCryptEnumRegisteredProviders failed with error code 0x%08x\n", ntStatus);
	}

	if (pBuffer != NULL)
	{
		BCryptFreeBuffer(pBuffer);
	}
	return;
}
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////

NTSTATUS
RegisterProvider(
	void
)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	//
	// Make CNG aware that our provider
	// exists...
	//
	ntStatus = BCryptRegisterProvider(
		GRADIANT_KSP_PROVIDER_NAME,
		0,                          // Flags: fail if provider is already registered
		&KSPProvider
	);
	if (!NT_SUCCESS(ntStatus))
	{
		wprintf(L"BCryptRegisterProvider failed with error code 0x%08x\n", ntStatus);
		return ntStatus;
	}

	//
	// Add the algorithm name to the priority list of the
	// symmetric cipher algorithm class. (This makes it
	// visible to BCryptResolveProviders.)
	//
	ntStatus = BCryptAddContextFunction(
		CRYPT_LOCAL,                    // Scope: local machine only
		NULL,                           // Application context: default
		NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
		NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
		CRYPT_PRIORITY_TOP				// highest priority
	);
	if (!NT_SUCCESS(ntStatus))
	{
		wprintf(L"BCryptAddContextFunction failed with error code 0x%08x\n", ntStatus);
		return ntStatus;
	}

	//
	// Identify our new provider as someone who exposes
	// an implementation of the new algorithm.
	//
	ntStatus = BCryptAddContextFunctionProvider(
		CRYPT_LOCAL,                    // Scope: local machine only
		NULL,                           // Application context: default
		NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
		NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
		GRADIANT_KSP_PROVIDER_NAME,        // Provider name
		CRYPT_PRIORITY_TOP           // Lowest priority
	);
	if (!NT_SUCCESS(ntStatus))
	{
		wprintf(L"BCryptAddContextFunctionProvider failed with error code 0x%08x\n", ntStatus);
	}
	return ntStatus;
}
///////////////////////////////////////////////////////////////////////////////

NTSTATUS
UnRegisterProvider()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;

	//
	// Tell CNG that this provider no longer supports
	// this algorithm.
	//
	ntStatus = BCryptRemoveContextFunctionProvider(
		CRYPT_LOCAL,                    // Scope: local machine only
		NULL,                           // Application context: default
		NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
		NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
		GRADIANT_KSP_PROVIDER_NAME         // Provider
	);
	if (!NT_SUCCESS(ntStatus))
	{
		wprintf(L"BCryptRemoveContextFunctionProvider failed with error code 0x%08x\n", ntStatus);
		return ntStatus;
	}


	//
	// Tell CNG to forget about our provider component.
	//
	ntStatus = BCryptUnregisterProvider(GRADIANT_KSP_PROVIDER_NAME);
	if (!NT_SUCCESS(ntStatus))
	{
		wprintf(L"BCryptUnregisterProvider failed with error code 0x%08x\n", ntStatus);
	}
	return ntStatus;
}
///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
void
DisplayUsage(void)
{
	wprintf(L"Usage: CNG_Register -enum | -register | -unregister\n");
	exit(1);
}
///////////////////////////////////////////////////////////////////////////////

