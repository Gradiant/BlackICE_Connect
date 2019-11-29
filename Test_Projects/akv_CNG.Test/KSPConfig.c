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


///////////////////////////////////////////////////////////////////////////////
//
// Headers...
//
///////////////////////////////////////////////////////////////////////////////
#include "KSPConfig.h"

////
//// An array of algorithm names, all belonging to the
//// same algorithm class...
////
PWSTR AlgorithmNames[1] = {
	NCRYPT_KEY_STORAGE_ALGORITHM
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
	KSP_BINARY,                   // File name of the sample KSP binary
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
///////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////

void
DisplayUsage()
{
	wprintf(L"Usage: SampleKSPconfig -enum | -register | -unregister\n");
	exit(1);
}
///////////////////////////////////////////////////////////////////////////////


NTSTATUS EnumerateProviders(unsigned long *numProv, PWSTR provider)
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
			return ntStatus;
		}
		else
		{
			*numProv = pBuffer->cProviders;
			if (provider != NULL) {
				ntStatus = STATUS_INTERNAL_ERROR;
				for (i = 0; i < pBuffer->cProviders; i++)
				{
					if (wcscmp(pBuffer->rgpszProviders[i], provider) == 0) {
						ntStatus = STATUS_SUCCESS;
						break;
					}
				}
			}
		}
	}
	else
	{
		return ntStatus;
	}

	if (pBuffer != NULL)
	{
		BCryptFreeBuffer(pBuffer);
	}
	return ntStatus;
}
///////////////////////////////////////////////////////////////////////////////



NTSTATUS OpenProvider(LPCWSTR providerName, NCRYPT_PROV_HANDLE **phProviderResult) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	NCRYPT_PROV_HANDLE phProvider = 0;
	DWORD              dwFlags = 0;
	
	ntStatus = NCryptOpenStorageProvider(
		&phProvider,
		providerName,
		dwFlags
	);
	if (!NT_SUCCESS(ntStatus))
	{
		wprintf(L"NCryptOpenStorageProvider failed with error code 0x%08x\n", ntStatus);
	}
	*phProviderResult = phProvider;
	return ntStatus;
}

NTSTATUS FreeOpenProvider(NCRYPT_PROV_HANDLE ** phProvider) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ntStatus = NCryptFreeObject(
		*phProvider
	);
	if (!NT_SUCCESS(ntStatus))
	{
		wprintf(L"NCryptOpenStorageProvider failed with error code 0x%08x\n", ntStatus);
	}
	return ntStatus;
}

NTSTATUS EnumKeys(NCRYPT_PROV_HANDLE * phProvider, NCryptKeyName **ppKeyName, void **ppEnumState, DWORD dwFlags) {
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ntStatus = NCryptEnumKeys(
		phProvider,
		NULL,
		&ppKeyName,
		&ppEnumState,
		dwFlags
	);
	return ntStatus;
}

///////////////////////////////////////////////////////////////////////////////
