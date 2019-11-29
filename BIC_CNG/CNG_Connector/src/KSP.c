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
// Headers
//
///////////////////////////////////////////////////////////////////////////////
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include "KSP.h"
#include <wchar.h>
#include <src/Debug.h>
#include <src/interface.h>
#include "../resource.h"


///////////////////////////////////////////////////////////////////////////////
//
// Ncrypt key storage provider function table
//
///////////////////////////////////////////////////////////////////////////////
NCRYPT_KEY_STORAGE_FUNCTION_TABLE KSPFunctionTable =
{
	KSP_INTERFACE_VERSION,
	KSPOpenProvider,
	KSPOpenKey,
	KSPCreatePersistedKey,
	KSPGetProviderProperty,
	KSPGetKeyProperty,
	KSPSetProviderProperty,
	KSPSetKeyProperty,
	KSPFinalizeKey,
	KSPDeleteKey,
	KSPFreeProvider,
	KSPFreeKey,
	KSPFreeBuffer,
	KSPEncrypt,
	KSPDecrypt,
	KSPIsAlgSupported,
	KSPEnumAlgorithms,
	KSPEnumKeys,
	KSPImportKey,
	KSPExportKey,
	KSPSignHash,
	KSPVerifySignature,
	KSPPromptUser,
	KSPNotifyChangeKey,
	KSPSecretAgreement,
	KSPDeriveKey,
	KSPFreeSecret
};

///////////////////////////////////////////////////////////////////////////////
//
// Variables
//
///////////////////////////////////////////////////////////////////////////////
HINSTANCE g_hInstance;
//List of keys/providers
LIST_ENTRY g_KspEnumStateList;
//KSP_KEY tokenKeys = NULL;
//char* token = NULL;

///////////////////////////////////////////////////////////////////////////////
//
// Dll entry
//
///////////////////////////////////////////////////////////////////////////////

BOOL
WINAPI
DllMain(
	HMODULE hInstDLL,
	DWORD dwReason,
	LPVOID lpvReserved)
{
	UNREFERENCED_PARAMETER(lpvReserved);
	g_hInstance = (HINSTANCE)hInstDLL;

	if (dwReason == DLL_PROCESS_ATTACH)
	{
		InitializeListHead(&g_KspEnumStateList);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		if (g_hRSAProvider)
		{
			BCryptCloseAlgorithmProvider(g_hRSAProvider, 0);
		}
	}
	return TRUE;
}


///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
* DESCRIPTION :     Get the KSP key storage Interface function
*                   dispatch table
*
* INPUTS :
*            LPCWSTR pszProviderName        Name of the provider (unused)
*            DWORD   dwFlags                Flags (unused)
* OUTPUTS :
*            char    **ppFunctionTable      The key storage interface function
*                                           dispatch table
* RETURN :
*            ERROR_SUCCESS                  The function was successful.
*/
NTSTATUS
WINAPI
GetKeyStorageInterface(
	__in   LPCWSTR pszProviderName,
	__out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
	__in   DWORD dwFlags)
{

	UNREFERENCED_PARAMETER(pszProviderName);
	UNREFERENCED_PARAMETER(dwFlags);

	*ppFunctionTable = &KSPFunctionTable;

	return ERROR_SUCCESS;
}

/*******************************************************************
* DESCRIPTION :     Load and initialize the KSP provider
*
* INPUTS :
*            LPCWSTR pszProviderName         Name of the provider
*            DWORD   dwFlags                 Flags (unused)
* OUTPUTS :
*            NCRYPT_PROV_HANDLE *phProvider  The provider handle
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPOpenProvider(
	__out   NCRYPT_PROV_HANDLE	*phProvider,
	__in    LPCWSTR				pszProviderName,
	__in    DWORD				dwFlags)
{
	int resultado = ConfigureApplication();
	InitializeLogs(LOG_CONTEXT);
	context context;
	Context_Initialization("OpenProvider", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		status = NTE_INTERNAL_ERROR;
	NTSTATUS			result = ERROR_SUCCESS;
	KSP_PROVIDER		*pProvider = NULL;
	DWORD				cbLength = 0;
	size_t				cbProviderName = 0;
	UNREFERENCED_PARAMETER(dwFlags);

	if (resultado < 0) {
		if (resultado == BAD_CONF_FILE) {
			status = NTE_INVALID_PARAMETER;
			goto cleanup;
		}
		else if (resultado == HOST_MEMORY) {
			status = NTE_NO_MEMORY;
			goto cleanup;
		}
		else {
			status = NTE_FAIL;
			goto cleanup;
		}
	}
	// Validate input parameters.
	if (phProvider == NULL) {
		status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}
	if (pszProviderName == NULL) {
		status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}
	if (strcmp(AUTH_METHOD, WINDOWS_AUTH) != 0)
	{
		char pin[MAXPINLEN * 2] = "";
		status = AuthDisplay(g_hInstance, &pin);
		if (ERROR_SUCCESS != status) {
			status = NTE_INVALID_PARAMETER;
			goto cleanup;
		}
		result = (NTSTATUS)DecryptAllConfigurationData(pin, strlen(pin));
		ZeroMemory(pin, MAXPINLEN * 2);
		status = NormalizeNteStatus(result);
		if (ERROR_SUCCESS != status) {
			goto cleanup;
		}
	}
	result = GetAccesToken((char **)&TOKEN);
	status = NormalizeNteStatus(result);
	if (ERROR_SUCCESS != status) {
		status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	//The size of the provider name should be limited.
	cbProviderName = (wcslen(pszProviderName) + 1) * sizeof(WCHAR);
	if (cbProviderName > MAXUSHORT) {
		status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	// Allocate memory for provider object.
	cbLength = sizeof(KSP_PROVIDER) + (DWORD)cbProviderName;
	pProvider = (KSP_PROVIDER*)HeapAlloc(GetProcessHeap(), 0, cbLength);
	if (NULL == pProvider) {
		status = NTE_NO_MEMORY;
		goto cleanup;
	}
	ZeroMemory(pProvider, cbLength);
	//Assign values to fields of the provider handle.
	pProvider->cbLength = cbLength;
	pProvider->dwMagic = KSP_PROVIDER_MAGIC;
	pProvider->dwFlags = 0;
	pProvider->pszName = (LPWSTR)(pProvider + 1);
	CopyMemory(pProvider->pszName, pszProviderName, cbProviderName);
	pProvider->pszContext = NULL;

	//Assign the output value.
	*phProvider = (NCRYPT_PROV_HANDLE)pProvider;
	pProvider = NULL;
	status = ERROR_SUCCESS;
cleanup:
	if (pProvider) {
		HeapFree(GetProcessHeap(), 0, pProvider);
	}
	Error_Writter(&context, status);
	Write_DebugData(context, LOG_CONTEXT);
	if (status != ERROR_SUCCESS) {
		ClearGlobalData();
	}
	return status;
}



/******************************************************************************
* DESCRIPTION :     Release a handle to the KSP provider
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*/
SECURITY_STATUS
WINAPI
KSPFreeProvider(
	__in    NCRYPT_PROV_HANDLE hProvider)
{
	context context;
	Context_Initialization("FreeProvider", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;
	KSP_PROVIDER		*pProvider = NULL;

	// Validate input parameters.
	pProvider = KspValidateProvHandle(hProvider);
	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	};
	// Free context.
	if (pProvider->pszContext)
	{
		HeapFree(GetProcessHeap(), 0, pProvider->pszContext);
		pProvider->pszContext = NULL;
	}
	// Release token and provider credentials
	if (TOKEN != NULL) {
		free(TOKEN);
		TOKEN = NULL;
	}
	Remove_all_key_list();
	ZeroMemory(pProvider, pProvider->cbLength);
	HeapFree(GetProcessHeap(), 0, pProvider);
	Status = ERROR_SUCCESS;
cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	ClearGlobalData();
	return Status;
}


/******************************************************************************
* DESCRIPTION :     Open a key in the key storage provider
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            LPCWSTR pszKeyName              Name of the key
			 DWORD  dwLegacyKeySpec          Flags for legacy key support (unused)
*            DWORD   dwFlags                 Flags (unused)
* OUTPUTS:
*            NCRYPT_KEY_HANDLE               A handle to the opened key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPOpenKey(
	__inout NCRYPT_PROV_HANDLE hProvider,
	__out   NCRYPT_KEY_HANDLE *phKey,
	__in    LPCWSTR pszKeyName,
	__in_opt DWORD  dwLegacyKeySpec,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("OpenKey", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;
	KSP_PROVIDER		*pProvider = NULL;
	KSP_KEY				*pKey = NULL;
	AKV_KEY				*currentKey = NULL;

	//
	// Validate input parameters.
	//
	UNREFERENCED_PARAMETER(dwLegacyKeySpec);
	UNREFERENCED_PARAMETER(dwFlags);
	pProvider = KspValidateProvHandle(hProvider);
	if (pProvider == NULL) {
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}
	if ((phKey == NULL) || (pszKeyName == NULL)) {
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}
	currentKey = Find_Key_By_Name(pszKeyName);
	if (currentKey == NULL) {
		Status = FindKeyInKeyStore(pszKeyName, &currentKey);
		if (Status != ERROR_SUCCESS) {
			goto cleanup;
		}
	}
	//Initialize the key object.
	Status = CreateNewKeyObject(pszKeyName, &pKey);
	if (Status != ERROR_SUCCESS) {
		goto cleanup;
	};
	//Parse key.
	Status = ParseMemoryKey(pKey, currentKey);
	if (Status != ERROR_SUCCESS) {
		goto cleanup;
	}

	pKey->fFinished = TRUE;
	*phKey = (NCRYPT_KEY_HANDLE)pKey;
	pKey = NULL;
	Status = ERROR_SUCCESS;

cleanup:
	if (pKey) {
		DeleteKeyObject(pKey);
	}
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}


/******************************************************************************
* DESCRIPTION :     Create a new key and stored it into the user profile
*                   key storage area
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            LPCWSTR pszAlgId                Cryptographic algorithm to create the key
*            LPCWSTR pszKeyName              Name of the key
*            DWORD  dwLegacyKeySpec          Flags for legacy key support (unused)
*            DWORD   dwFlags                 0|NCRYPT_OVERWRITE_KEY_FLAG
* OUTPUTS:
*            NCRYPT_KEY_HANDLE               A handle to the opened key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_EXISTS                      The key already exists.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_NOT_SUPPORTED               The algorithm is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPCreatePersistedKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__out   NCRYPT_KEY_HANDLE *phKey,
	__in    LPCWSTR pszAlgId,
	__in_opt LPCWSTR pszKeyName,
	__in    DWORD   dwLegacyKeySpec,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("CreatePersistedKey", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;
	NTSTATUS			ntStatus = STATUS_INTERNAL_ERROR;
	DWORD				dwBitLength = 0;
	KSP_PROVIDER		*pProvider = NULL;
	KSP_KEY				*pKey = NULL;
	AKV_KEY				*currentKey = NULL;

	Write_Free_Text(pszKeyName, LOG_CONTEXT);
	//
	// Validate input parameters.
	//
	UNREFERENCED_PARAMETER(dwLegacyKeySpec);

	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if ((phKey == NULL) || (pszAlgId == NULL))
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	/*if ((dwFlags & ~(NCRYPT_SILENT_FLAG | NCRYPT_OVERWRITE_KEY_FLAG)) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}*/

	if (wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) != 0)
	{
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}

	//Create the key object.
	//Initialize the key object.
	Status = CreateNewKeyObject(pszKeyName, &pKey);
	if (Status != ERROR_SUCCESS) {
		goto cleanup;
	};

	// If the overwrite flag is not set then check to
	// make sure the key doesn't already exist.
	if (pszKeyName != NULL) {
		currentKey = Find_Key_By_Name(pszKeyName);
		if (currentKey == NULL) {
			Status = FindKeyInKeyStore(pszKeyName, &currentKey);
		}
	}

	if (currentKey != NULL && ((dwFlags & NCRYPT_OVERWRITE_KEY_FLAG) == 0))
	{
		Status = NTE_EXISTS;
		goto cleanup;
	}

	//Set the key length to the default length.
	pKey->dwKeyBitLength = KSP_DEFAULT_KEY_LENGTH;

	//Set finalize flag to false.
	pKey->fFinished == FALSE;
	//
	// Set return values.
	//

	*phKey = (NCRYPT_KEY_HANDLE)pKey;
	pKey = NULL;

	Status = ERROR_SUCCESS;

cleanup:
	if (pKey)
	{
		DeleteKeyObject(pKey);
	}
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Retrieves the value of a named property for a key storage
*                provider object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            LPCWSTR pszProperty             Name of the property
*            DWORD   cbOutput                Size of the output buffer
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing the value
*                                            of the property.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_NOT_FOUND                   Cannot find such a property.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPGetProviderProperty(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    LPCWSTR pszProperty,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("GetProviderProperty", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;
	KSP_PROVIDER		*pProvider = NULL;
	DWORD				cbResult = 0;
	DWORD				dwProperty = 0;
	// DEBUG
	char type[MAX_SMALL_DEBUG_BUFFER] = "";
	char staticValue[MAX_SMALL_DEBUG_BUFFER] = "";
	wcstombs(staticValue, pszProperty, wcslen(pszProperty));
	Write_Debug_Template(context, type, staticValue, NULL, LOG_CONTEXT);
	//
	// Validate input parameters.
	//
	wprintf(L" %0ls", pszProperty);
	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if ((pszProperty == NULL) || (pcbResult == NULL))
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}


	if ((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}

	//
	//Determine the size of the properties.
	//

	if (wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
	{
		dwProperty = KSP_IMPL_TYPE_PROPERTY;
		cbResult = sizeof(DWORD);
	}
	else if (wcscmp(pszProperty, NCRYPT_MAX_NAME_LENGTH_PROPERTY) == 0)
	{
		dwProperty = KSP_MAX_NAME_LEN_PROPERTY;
		cbResult = sizeof(DWORD);
	}
	else if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
	{
		dwProperty = KSP_NAME_PROPERTY;
		cbResult = (DWORD)((wcslen(pProvider->pszName) + 1) * sizeof(WCHAR));
	}
	else if (wcscmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0)
	{
		dwProperty = KSP_VERSION_PROPERTY;
		cbResult = sizeof(DWORD);
	}
	else if (wcscmp(pszProperty, NCRYPT_USE_CONTEXT_PROPERTY) == 0)
	{
		dwProperty = KSP_USE_CONTEXT_PROPERTY;
		cbResult = 0;

		if (pProvider->pszContext)
		{
			cbResult =
				(DWORD)(wcslen(pProvider->pszContext) + 1) * sizeof(WCHAR);
		}

		if (cbResult == 0)
		{
			goto cleanup;
		}
	}
	else if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY) == 0)
	{
		dwProperty = NTE_NOT_SUPPORTED;
		cbResult = sizeof(DWORD);
	}
	else
	{
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}

	*pcbResult = cbResult;

	//Output buffer is empty, this is a property length query, and we can exit early.
	if (pbOutput == NULL)
	{
		Status = ERROR_SUCCESS;
		goto cleanup;
	}

	//Otherwise, validate the size.
	if (cbOutput < *pcbResult)
	{
		Status = NTE_BUFFER_TOO_SMALL;
		goto cleanup;
	}

	//
	//Retrieve the requested property data
	//if the property is not supported, we have already returned NTE_NOT_SUPPORTED.
	//
	switch (dwProperty)
	{
	case KSP_IMPL_TYPE_PROPERTY:
		*(DWORD *)pbOutput = NCRYPT_IMPL_HARDWARE_FLAG; //Hardware provider
		break;

	case KSP_MAX_NAME_LEN_PROPERTY:
		*(DWORD *)pbOutput = MAX_PATH;
		break;

	case KSP_NAME_PROPERTY:
		CopyMemory(pbOutput, pProvider->pszName, cbResult);
		break;

	case KSP_VERSION_PROPERTY:
		*(DWORD *)pbOutput = KSP_VERSION;
		break;

	case KSP_USE_CONTEXT_PROPERTY:
		CopyMemory(pbOutput, pProvider->pszContext, cbResult);
		break;

	case KSP_SECURITY_DESCR_SUPPORT_PROPERTY:
		*(DWORD *)pbOutput = KSP_SUPPORT_SECURITY_DESCRIPTOR;
		break;
	}

	Status = ERROR_SUCCESS;

cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Retrieves the value of a named property for a key storage
*                key object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object
*            LPCWSTR pszProperty             Name of the property
*            DWORD   cbOutput                Size of the output buffer
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing the value
*                                            of the property.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_NOT_FOUND                   Cannot find such a property.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPGetKeyProperty(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in    LPCWSTR pszProperty,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("GetKeyProperty", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;
	KSP_PROVIDER		*pProvider = NULL;
	KSP_KEY				*pKey = NULL;
	KSP_PROPERTY	*pProperty = NULL;
	DWORD				dwProperty = 0;
	DWORD				cbResult = 0;
	LPWSTR				pszAlgorithm = NULL;
	LPWSTR				pszAlgorithmGroup = NULL;
	PBYTE				pbSecurityInfo = NULL;
	DWORD				cbSecurityInfo = 0;
	DWORD				cbTmp = 0;
	char				type[MAX_SMALL_DEBUG_BUFFER] = "";
	char				staticValue[MAX_SMALL_DEBUG_BUFFER] = "";
	wcstombs(type, pszProperty, wcslen(pszProperty));
	Write_Debug_Template(context, type, staticValue, NULL, LOG_CONTEXT);
	// Do something with lpszDynamic

	//
	// Validate input parameters.
	//

	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	pKey = KspValidateKeyHandle(hKey);

	if (pKey == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if ((pszProperty == NULL) ||
		(wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME) ||
		(pcbResult == NULL))
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	//NCRYPT_SILENT_FLAG is ignored in this KSP.
	dwFlags &= ~NCRYPT_SILENT_FLAG;

	//If this is to get the security descriptor, the flags
	//must be one of the OWNER_SECURITY_INFORMATION |GROUP_SECURITY_INFORMATION |
	//DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION.
	if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
	{
		if (dwFlags & OWNER_SECURITY_INFORMATION) {
			Write_Free_Text("OWNER_SECURITY_INFORMATION", LOG_CONTEXT);
		}
		else if (dwFlags & GROUP_SECURITY_INFORMATION) {
			Write_Free_Text("GROUP_SECURITY_INFORMATION", LOG_CONTEXT);
		}
		else if (dwFlags & DACL_SECURITY_INFORMATION) {
			Write_Free_Text("DACL_SECURITY_INFORMATION", LOG_CONTEXT);
		}
		else if (dwFlags & LABEL_SECURITY_INFORMATION) {
			Write_Free_Text("LABEL_SECURITY_INFORMATION", LOG_CONTEXT);
		}
		else if (dwFlags & SACL_SECURITY_INFORMATION) {
			Write_Free_Text("SACL_SECURITY_INFORMATION", LOG_CONTEXT);
		}
		if ((dwFlags == 0) || ((dwFlags & ~(OWNER_SECURITY_INFORMATION |
			GROUP_SECURITY_INFORMATION |
			DACL_SECURITY_INFORMATION |
			LABEL_SECURITY_INFORMATION |
			SACL_SECURITY_INFORMATION)) != 0))
		{
			Status = NTE_BAD_FLAGS;
			goto cleanup;
		}
	}
	else
	{
		//Otherwise,Only NCRYPT_PERSIST_ONLY_FLAG is a valid flag.
		if (dwFlags & ~NCRYPT_PERSIST_ONLY_FLAG)
		{
			Status = NTE_BAD_FLAGS;
			goto cleanup;
		}
	}

	//If NCRYPT_PERSIST_ONLY_FLAG is supported, properties must
	//be read from the property list.
	if (dwFlags & NCRYPT_PERSIST_ONLY_FLAG)
	{   //@@Critical section code would need to be added here for
		//multi-threaded support@@.
		// Lookup property.
		Status = LookupExistingKeyProperty(
			pKey,
			pszProperty,
			&pProperty);
		if (Status != ERROR_SUCCESS)
		{
			goto cleanup;
		}

		// Validate the size of the output buffer.
		cbResult = pProperty->cbPropertyData;

		*pcbResult = cbResult;
		if (pbOutput == NULL)
		{
			Status = ERROR_SUCCESS;
			goto cleanup;
		}
		if (cbOutput < *pcbResult)
		{
			Status = NTE_BUFFER_TOO_SMALL;
			goto cleanup;
		}

		// Copy the property data to the output buffer.
		CopyMemory(pbOutput, (PBYTE)(pProperty + 1), cbResult);

		Status = ERROR_SUCCESS;
		goto cleanup;

	}

	//
	//Determine length of requested property.
	//
	if (wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
	{
		dwProperty = KSP_ALGORITHM_PROPERTY;
		/*Status = BcryptAlgorithmTranscriptor(pKey->dwAlgID, &pszAlgorithm);*/

		switch (pKey->dwAlgID) {
		case KSP_RSA_ALGID:
			pszAlgorithm = BCRYPT_RSA_ALGORITHM;
			break;
		default:
			Status = NTE_BAD_KEY;
			goto cleanup;
		}
		/*if (Status != ERROR_SUCCESS)
			goto cleanup;*/
		cbResult = (DWORD)(wcslen(pszAlgorithm) + 1) * sizeof(WCHAR);
	}
	else if (wcscmp(pszProperty, NCRYPT_BLOCK_LENGTH_PROPERTY) == 0)
	{
		dwProperty = KSP_BLOCK_LENGTH_PROPERTY;
		cbResult = sizeof(DWORD);
	}
	else if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
	{
		dwProperty = KSP_EXPORT_POLICY_PROPERTY;
		cbResult = sizeof(DWORD);
	}
	else if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
	{
		dwProperty = KSP_KEY_USAGE_PROPERTY;
		cbResult = sizeof(DWORD);
	}
	else if (wcscmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0)
	{
		dwProperty = KSP_KEY_TYPE_PROPERTY;
		cbResult = sizeof(DWORD);
	}
	else if (wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
	{
		dwProperty = KSP_LENGTH_PROPERTY;
		cbResult = sizeof(DWORD);
	}
	else if (wcscmp(pszProperty, NCRYPT_LENGTHS_PROPERTY) == 0)
	{
		dwProperty = KSP_LENGTHS_PROPERTY;
		cbResult = sizeof(NCRYPT_SUPPORTED_LENGTHS);
	}
	else if (wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
	{
		dwProperty = KSP_NAME_PROPERTY;
		if (pKey->pszKeyName == NULL)
		{
			// This should only happen if this is an ephemeral key.
			Status = NTE_NOT_SUPPORTED;
			goto cleanup;
		}
		cbResult = (DWORD)(wcslen(pKey->pszKeyName) + 1) * sizeof(WCHAR);
	}
	else if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
	{
		//@@Synchronization schemes would need to be added here for
		//multi-threaded support@@.
		dwProperty = KSP_SECURITY_DESCR_PROPERTY;
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
		(PSECURITY_DESCRIPTOR*)pbSecurityInfo = pKey->pbSecurityDescr;
		cbSecurityInfo = pKey->cbSecurityDescr;
		cbResult = cbSecurityInfo;
	}
	else if (wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0)
	{
		dwProperty = KSP_ALGORITHM_GROUP_PROPERTY;
		pszAlgorithmGroup = NCRYPT_RSA_ALGORITHM_GROUP;
		cbResult = (DWORD)(wcslen(pszAlgorithmGroup) + 1) * sizeof(WCHAR);
	}
	else if (wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0)
	{
		//For this, the unique name property and the name property are
		//the same, which is the name of the key file.
		dwProperty = KSP_UNIQUE_NAME_PROPERTY;

		if (pKey->pszKeyName == NULL)
		{
			// This should only happen if this is a public key object.
			Status = NTE_NOT_SUPPORTED;
			goto cleanup;
		}

		cbResult = (DWORD)(wcslen(pKey->pszKeyName) + 1) * sizeof(WCHAR);
	}
	else
	{
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}


	//
	// Validate the size of the output buffer.
	//

	*pcbResult = cbResult;

	if (pbOutput == NULL)
	{
		Status = ERROR_SUCCESS;
		goto cleanup;
	}

	if (cbOutput < *pcbResult)
	{
		Status = NTE_BUFFER_TOO_SMALL;
		goto cleanup;
	}

	//
	// Retrieve the requested property data.
	//
	switch (dwProperty)
	{
	case KSP_ALGORITHM_PROPERTY:
		CopyMemory(pbOutput, pszAlgorithm, cbResult);
		break;

	case KSP_BLOCK_LENGTH_PROPERTY:
		*(DWORD *)pbOutput = (pKey->dwKeyBitLength + 7) / 8;
		break;

	case KSP_EXPORT_POLICY_PROPERTY:
		*(DWORD *)pbOutput = pKey->dwExportPolicy;
		break;

	case KSP_KEY_USAGE_PROPERTY:
		*(DWORD *)pbOutput = pKey->dwKeyUsagePolicy;
		break;

	case KSP_KEY_TYPE_PROPERTY:
		*(DWORD *)pbOutput = 0; // current user //NCRYPT_MACHINE_KEY_FLAG;
		break;

	case KSP_LENGTH_PROPERTY:
		*(DWORD *)pbOutput = pKey->dwKeyBitLength;
		break;

	case KSP_LENGTHS_PROPERTY:
	{
		NCRYPT_SUPPORTED_LENGTHS pLengths;
		if (pKey->dwAlgID == KSP_RSA_ALGID) {
			pLengths.dwDefaultLength = KSP_DEFAULT_KEY_LENGTH;
			pLengths.dwIncrement = KSP_RSA_INCREMENT;
			pLengths.dwMaxLength = KSP_RSA_MAX_LENGTH;
			pLengths.dwMinLength = KSP_RSA_MIN_LENGTH;
		}
		else {
			Status = NTE_INTERNAL_ERROR;
			goto cleanup;
		}
		CopyMemory(pbOutput, &pLengths, sizeof(NCRYPT_SUPPORTED_LENGTHS));
		break;
	}

	case KSP_NAME_PROPERTY:
		CopyMemory(pbOutput, pKey->pszKeyName, cbResult);
		break;

	case KSP_UNIQUE_NAME_PROPERTY:
		CopyMemory(pbOutput, pKey->pszKeyName, cbResult);
		break;

	case KSP_SECURITY_DESCR_PROPERTY:
		CopyMemory(pbOutput, pbSecurityInfo, cbResult);
		break;

	case KSP_ALGORITHM_GROUP_PROPERTY:
		CopyMemory(pbOutput, pszAlgorithmGroup, cbResult);
		break;

	}
	//wcstombs(staticValue, pbOutput, wcslen(pbOutput));
	//Write_Debug_Template(context, type, staticValue, NULL);
	Status = ERROR_SUCCESS;

cleanup:

	if (pbSecurityInfo)
	{
		HeapFree(GetProcessHeap(), 0, pbSecurityInfo);
	}
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Sets the value for a named property for a CNG key storage
*                provider object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            LPCWSTR pszProperty             Name of the property
*            PBYTE   pbInput                 Input buffer containing the value
*                                            of the property
*            DWORD   cbOutput                Size of the input buffer
*            DWORD   dwFlags                 Flags
*
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPSetProviderProperty(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    LPCWSTR pszProperty,
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("SetProviderProperty", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;
	KSP_PROVIDER		*pProvider = NULL;


	// Validate input parameters.
	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if ((pszProperty == NULL) ||
		(wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME) ||
		(pbInput == NULL))
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if ((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}

	//Update the property.
	if (wcscmp(pszProperty, NCRYPT_USE_CONTEXT_PROPERTY) == 0)
	{

		if (pProvider->pszContext)
		{
			HeapFree(GetProcessHeap(), 0, pProvider->pszContext);
		}

		pProvider->pszContext = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cbInput);
		if (pProvider->pszContext == NULL)
		{
			Status = NTE_NO_MEMORY;
			goto cleanup;
		}

		CopyMemory(pProvider->pszContext, pbInput, cbInput);

	}
	else
	{
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}


	Status = ERROR_SUCCESS;

cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Set the value of a named property for a key storage
*                key object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object
*            LPCWSTR pszProperty             Name of the property
*            PBYTE   pbInput                 Input buffer containing the value
*                                            of the property
*            DWORD   cbOutput                Size of the input buffer
*            DWORD   dwFlags                 Flags
*
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle or a valid key handle
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPSetKeyProperty(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__inout NCRYPT_KEY_HANDLE hKey,
	__in    LPCWSTR pszProperty,
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("SetKeyProperty", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS         Status = NTE_INTERNAL_ERROR;
	KSP_PROVIDER			*pProvider = NULL;
	KSP_KEY				    *pKey = NULL;
	KSP_PROPERTY      *pProperty = NULL;
	KSP_PROPERTY      *pExistingProperty = NULL;
	DWORD                   dwTempFlags = dwFlags;
	//DEBUG
	char					type[MAX_SMALL_DEBUG_BUFFER] = "";
	char					staticValue[MAX_SMALL_DEBUG_BUFFER] = "";
	wcstombs(type, pszProperty, wcslen(pszProperty));
	Write_Debug_Template(context, type, staticValue, NULL, LOG_CONTEXT);

	// Validate input parameters.
	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	pKey = KspValidateKeyHandle(hKey);

	if (pKey == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if ((pszProperty == NULL) ||
		(wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME) ||
		(pbInput == NULL))
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}


	if (wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
	{
		pKey->dwKeyUsagePolicy = *(DWORD*)pbInput;
		return STATUS_SUCCESS;
	}
	if (wcscmp(pszProperty, NCRYPT_UI_POLICY_PROPERTY) == 0)
	{
		return STATUS_SUCCESS;
	}
	if (wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
	{
		if (*(DWORD*)pbInput != 0)
		{
			return NTE_NOT_SUPPORTED;
		}
	}
	// Ignore the silent flag if it is turned on.
	dwTempFlags &= ~NCRYPT_SILENT_FLAG;
	if (wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
	{
		// At least one flag must be set.
		if (dwTempFlags == 0)
		{
			Status = NTE_BAD_FLAGS;
			goto cleanup;
		}

		// Reject flags *not* in the list below.
		if ((dwTempFlags & ~(OWNER_SECURITY_INFORMATION |
			GROUP_SECURITY_INFORMATION |
			DACL_SECURITY_INFORMATION |
			LABEL_SECURITY_INFORMATION |
			SACL_SECURITY_INFORMATION |
			NCRYPT_PERSIST_FLAG)) != 0)
		{
			Status = NTE_BAD_FLAGS;
			goto cleanup;
		}
	}
	else
	{
		if ((dwTempFlags & ~(NCRYPT_PERSIST_FLAG |
			NCRYPT_PERSIST_ONLY_FLAG)) != 0)
		{
			Status = NTE_BAD_FLAGS;
			goto cleanup;
		}
	}

	if ((dwTempFlags & NCRYPT_PERSIST_ONLY_FLAG) == 0)
	{
		//The property is one of the built-in key properties.
		Status = SetBuildinKeyProperty(pKey,
			pszProperty,
			pbInput,
			cbInput,
			&dwTempFlags);
		if (Status != ERROR_SUCCESS)
		{
			goto cleanup;
		}

		if ((dwTempFlags & NCRYPT_PERSIST_FLAG) == 0)
		{
			//we are done here.
			goto cleanup;
		}
	}

	//Remove the existing property
	Status = LookupExistingKeyProperty(pKey,
		pszProperty,
		&pExistingProperty);

	if (Status != NTE_NOT_FOUND)
	{
		RemoveEntryList(&pExistingProperty->ListEntry);
		HeapFree(GetProcessHeap(), 0, pExistingProperty);
	}

	//Create a new property and attach it to the key object.
	Status = CreateNewProperty(
		pszProperty,
		pbInput,
		cbInput,
		dwTempFlags,
		&pProperty);
	if (Status != ERROR_SUCCESS)
	{
		goto cleanup;
	}
	InsertTailList(&pKey->PropertyList, &pProperty->ListEntry);

	//Write the new properties to AKV if the key is already finished
	if (pProperty->fPersisted && pKey->fFinished)
	{
		// TODO: implement persistence in AKV to modify a property once it is already finished

	}

	Status = ERROR_SUCCESS;

cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :     Completes a key storage key. The key cannot be used
*                   until this function has been called.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_BAD_FLAGS                   The dwFlags parameter contains a
*                                            value that is not valid.
*/
SECURITY_STATUS
WINAPI
KSPFinalizeKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("FinalizeKey", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;
	KSP_PROVIDER		*pProvider = NULL;
	KSP_KEY				*pKey = NULL;
	AKV_KEY				*currentKey = NULL;

	//
	// Validate input parameters.
	//

	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	pKey = KspValidateKeyHandle(hKey);

	if (pKey == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if (pKey->fFinished == TRUE)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if ((dwFlags & ~(NCRYPT_NO_KEY_VALIDATION |
		NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG |
		NCRYPT_SILENT_FLAG)) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}

	if (dwFlags & NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG)
	{
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}

	Status = CreateKeyInKeyStore(pKey, &currentKey);
	if (Status != ERROR_SUCCESS) {
		goto cleanup;
	}


	//Parse key.
	Status = ParseMemoryKey(pKey, currentKey);
	if (Status != ERROR_SUCCESS) {
		goto cleanup;
	}

	pKey->fFinished = TRUE;

	Status = ERROR_SUCCESS;

cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :     Deletes a CNG KSP key
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            NCRYPT_KEY_HANDLE hKey          Handle to a KSP key
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_BAD_FLAGS                   The dwFlags parameter contains a
*                                            value that is not valid.
*            NTE_INTERNAL_ERROR              Key file deletion failed.
*/
SECURITY_STATUS
WINAPI
KSPDeleteKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__inout NCRYPT_KEY_HANDLE hKey,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("DeleteKey", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status = ERROR_SUCCESS;
	KSP_PROVIDER		*pProvider;
	KSP_KEY				*pKey = NULL;
	
	// Validate input parameters.
	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	pKey = KspValidateKeyHandle(hKey);

	if (pKey == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if ((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}

	//Delete the key if it is already stored in AKV
	if (pKey->fFinished == TRUE);
	{
		Status = RemoveKeyFromStore(pKey);
	}

cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}


///******************************************************************************
//* DESCRIPTION :     Free a CNG KSP key object
//*
//* INPUTS :
//*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
//*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key
//* RETURN :
//*            ERROR_SUCCESS                   The function was successful.
//*            NTE_INVALID_HANDLE              The handle is not a valid KSP
//*/
SECURITY_STATUS
WINAPI
KSPFreeKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey)
{
	context context;
	Context_Initialization("FreeKey", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status;
	KSP_PROVIDER		*pProvider;
	KSP_KEY				*pKey = NULL;

	// Validate input parameters.
	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	pKey = KspValidateKeyHandle(hKey);

	if (pKey == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	//
	// Free key object.
	//
	Status = DeleteKeyObject(pKey);
cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :     free a CNG KSP memory buffer object
*
* INPUTS :
*            PVOID   pvInput                 The buffer to free.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*/
SECURITY_STATUS
WINAPI
KSPFreeBuffer(
	__deref PVOID   pvInput)
{
	context					context;
	Context_Initialization("FreeBuffer", &context);
	Write_DebugData(context, LOG_CONTEXT);
	KSP_MEMORY_BUFFER *pBuffer;
	KSP_ENUM_STATE			*pEnumState;
	SECURITY_STATUS			Status = ERROR_SUCCESS;

	//
	// Is this one of the enumeration buffers, that needs to be
	// freed?
	//

	if (&g_KspEnumStateList == NULL || pvInput == NULL) {
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	pBuffer = RemoveMemoryBuffer(&g_KspEnumStateList, pvInput);

	if (pBuffer) {
		pEnumState = (KSP_ENUM_STATE *)pBuffer->pvBuffer;
		if (pEnumState != NULL) {
			HeapFree(GetProcessHeap(), 0, pEnumState);
			pEnumState = NULL;
		}
		if (pBuffer != NULL) {
			HeapFree(GetProcessHeap(), 0, pBuffer);
			pBuffer = NULL;
		}
		goto cleanup;
	}
	//
	// Free the buffer from the heap.
	//
	HeapFree(GetProcessHeap(), 0, pvInput);

cleanup:
	Status = ERROR_SUCCESS;
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}


/******************************************************************************
* DESCRIPTION :  encrypts a block of data.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object.
*            PBYTE   pbInput                 Plain text data to be encrypted.
*            DWORD   cbInput                 Size of the plain text data.
*            VOID    *pPaddingInfo           Padding information if padding sheme
*                                            is used.
*            DWORD   cbOutput                Size of the output buffer.
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing encrypted
*                                            data.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPEncrypt(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    VOID *pPaddingInfo,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("Encrypt", &context);
	Write_DebugData(context, LOG_CONTEXT);
	KSP_KEY						*pKey = NULL;

	BCRYPT_OAEP_PADDING_INFO*	oaepPaddingInfo = NULL;
	unsigned char				algorithm[MAX_JWA_ALGORITHM_LEN] = "";
	char*						base64Encoded = NULL;
	char						keyName[MAX_ID_SIZE] = { 0 };
	size_t						encrypt_len = 0;
	size_t						outputLen = 0;
	struct operation_response*	encryptResponse = NULL;

	SECURITY_STATUS				Status = NTE_INTERNAL_ERROR;
	NTSTATUS					ntStatus = STATUS_INTERNAL_ERROR;
	UNREFERENCED_PARAMETER(hProvider);

	// Validate input parameters.
	pKey = KspValidateKeyHandle(hKey);

	if (pKey == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}
	if (!pKey->fFinished)
	{
		Status = NTE_BAD_KEY_STATE;
		goto cleanup;
	}

	if (pbInput == NULL || cbInput == 0 ||
		pcbResult == NULL)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if ((dwFlags & ~(NCRYPT_NO_PADDING_FLAG |
		NCRYPT_PAD_PKCS1_FLAG |
		NCRYPT_PAD_OAEP_FLAG |
		NCRYPT_SILENT_FLAG)) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}

	//
	// Verify that this key is allowed to decrypt.
	//

	if ((pKey->dwKeyUsagePolicy & NCRYPT_ALLOW_DECRYPT_FLAG) == 0)
	{
		Status = (DWORD)NTE_PERM;
		goto cleanup;
	}


	if (dwFlags & NCRYPT_PAD_OAEP_FLAG) {
		oaepPaddingInfo = (BCRYPT_OAEP_PADDING_INFO*)pPaddingInfo;
		if ((wcscmp(oaepPaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA1RSA)) == 0) || (wcscmp(oaepPaddingInfo->pszAlgId, KSP_SHA1) == 0))
		{
			strcpy((char*)algorithm, "RSA-OAEP");
			Write_Free_Text("RSA-OAEP donde debe", LOG_CONTEXT);
		}
		else if ((wcscmp(oaepPaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA256RSA)) == 0) || (wcscmp(oaepPaddingInfo->pszAlgId, KSP_SHA256) == 0))
		{
			strcpy((char*)algorithm, "RSA-OAEP-256");
			Write_Free_Text("RS256 donde debe", LOG_CONTEXT);
		}
		else {
			Status = NTE_BAD_ALGID;
			goto cleanup;
		}
	}
	else {
		strcpy((char*)algorithm, "RSA1_5");
		Write_Free_Text("RSA1_5 donde debe", LOG_CONTEXT);
	}

	base64Encoded = base64encode((unsigned char*)pbInput, cbInput);
	if (base64Encoded == NULL) {
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}

	wcstombs(keyName, pKey->pszKeyName, MAX_ID_SIZE);
	struct operation_data* plainData = Store_OperationData(TOKEN, keyName, HOST, (char*)algorithm, base64Encoded);
	free(base64Encoded);
	if (plainData == NULL) {
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}
	int result = Encript_Data(plainData, &encryptResponse);
	Free_OperationData(plainData);
	switch (result)
	{
	case HTTP_OK:
		Status = ERROR_SUCCESS;
		break;
	case ALLOCATE_ERROR:
		Status = NTE_NO_MEMORY;
		goto cleanup;
	case BAD_REQUEST:
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	case UNAUTHORIZED:
	case FORBIDDEN:
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	default:
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	}
	outputLen = 4 * (strlen(encryptResponse->value) / 3); //base64 ratio of output to input bytes = 4:3
	unsigned char* encrypt = malloc(outputLen);
	if (encrypt == NULL) {
		Status = NTE_NO_MEMORY;
		Free_OperationResponse(encryptResponse);
		goto cleanup;
	}
	result = base64url_decode((char*)encrypt, outputLen, encryptResponse->value, strlen(encryptResponse->value), &encrypt_len);
	Free_OperationResponse(encryptResponse);
	if (result != 0 || encrypt_len > outputLen) {
		free(encrypt);
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	}
	if (pbOutput != NULL) {
		if (encrypt_len > cbOutput)
		{
			*pcbResult = (DWORD)encrypt_len;
			free(encrypt);
			Status = NTE_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		else
		{
			memcpy(pbOutput, encrypt, encrypt_len);
		}
	}
	*pcbResult = (DWORD)encrypt_len;
	free(encrypt);

	Status = ERROR_SUCCESS;


cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Decrypts a block of data.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object.
*            PBYTE   pbInput                 Encrypted data blob.
*            DWORD   cbInput                 Size of the encrypted data blob.
*            VOID    *pPaddingInfo           Padding information if padding sheme
*                                            is used.
*            DWORD   cbOutput                Size of the output buffer.
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing decrypted
*                                            data.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/

SECURITY_STATUS
WINAPI
KSPDecrypt(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    VOID *pPaddingInfo,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("Decrypt", &context);
	Write_DebugData(context, LOG_CONTEXT);
	KSP_KEY *pKey;
	DWORD BlockLength = 0;
	BCRYPT_OAEP_PADDING_INFO	*oaepPaddingInfo = NULL;
	unsigned char				algorithm[MAX_JWA_ALGORITHM_LEN] = "";
	char*						base64Encoded = NULL;
	char						keyName[MAX_ID_SIZE] = { 0 };
	size_t						decrypt_len = 0;
	size_t						outputLen = 0;
	struct operation_response	*decryptResponse = NULL;
	SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
	NTSTATUS    ntStatus = ERROR_SUCCESS;
	UNREFERENCED_PARAMETER(hProvider);

	// Validate input parameters.
	pKey = KspValidateKeyHandle(hKey);

	if (pKey == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if (pbInput == NULL || cbInput == 0 ||
		pcbResult == NULL)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if ((dwFlags & ~(NCRYPT_NO_PADDING_FLAG |
		NCRYPT_PAD_PKCS1_FLAG |
		NCRYPT_PAD_OAEP_FLAG |
		NCRYPT_SILENT_FLAG)) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}


	//
	// Verify that this key is allowed to decrypt.
	//

	if ((pKey->dwKeyUsagePolicy & NCRYPT_ALLOW_DECRYPT_FLAG) == 0)
	{
		Status = (DWORD)NTE_PERM;
		goto cleanup;
	}

	BlockLength = (pKey->dwKeyBitLength + 7) / 8;

	if (cbInput != BlockLength)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if (dwFlags & NCRYPT_PAD_OAEP_FLAG) {
		oaepPaddingInfo = (BCRYPT_OAEP_PADDING_INFO*)pPaddingInfo;
		if ((wcscmp(oaepPaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA1RSA)) == 0) || (wcscmp(oaepPaddingInfo->pszAlgId, KSP_SHA1) == 0))
		{
			strcpy((char *)algorithm, "RSA-OAEP");
			Write_Free_Text("RSA-OAEP donde debe", LOG_CONTEXT);
		}
		else if ((wcscmp(oaepPaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA256RSA)) == 0) || (wcscmp(oaepPaddingInfo->pszAlgId, KSP_SHA256) == 0)) 
		{
			strcpy((char *)algorithm, "RSA-OAEP-256");
			Write_Free_Text("RS256 donde debe", LOG_CONTEXT);
		}
		else  {
			Status = NTE_BAD_ALGID;
			goto cleanup;
		}
	}
	else {
		strcpy((char *)algorithm, "RSA1_5");
		Write_Free_Text("RSA1_5 donde debe", LOG_CONTEXT);
	}

	base64Encoded = base64encode((unsigned char *)pbInput, cbInput);
	if (base64Encoded == NULL) {
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}

	wcstombs(keyName, pKey->pszKeyName, MAX_ID_SIZE);
	struct operation_data *encryptData = Store_OperationData(TOKEN, keyName, HOST, (char*)algorithm, base64Encoded);
	free(base64Encoded);
	if (encryptData == NULL) {
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}
	int result = Decript_Data(encryptData, &decryptResponse);
	Free_OperationData(encryptData);
	switch (result)
	{
	case HTTP_OK:
		Status = ERROR_SUCCESS;
		break;
	case ALLOCATE_ERROR:
		Status = NTE_NO_MEMORY;
		goto cleanup;
	case BAD_REQUEST:
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	case UNAUTHORIZED:
	case FORBIDDEN:
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	default:
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	}
	outputLen = 4 * (strlen(decryptResponse->value) / 3); //base64 ratio of output to input bytes = 4:3
	unsigned char* decrypt = malloc(outputLen);
	if (decrypt == NULL) {
		Status = NTE_NO_MEMORY;
		Free_OperationResponse(decryptResponse);
		goto cleanup;
	}
	result = base64url_decode((char *)decrypt, outputLen, decryptResponse->value, strlen(decryptResponse->value), &decrypt_len);
	Free_OperationResponse(decryptResponse);
	if (result != 0 || decrypt_len > outputLen) {
		free(decrypt);
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	}
	if (pbOutput != NULL) {
		if (decrypt_len > cbOutput)
		{
			*pcbResult = (DWORD)decrypt_len;
			free(decrypt);
			Status = NTE_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		else
		{
			memcpy(pbOutput, decrypt, decrypt_len);
		}
	}
	*pcbResult = (DWORD)decrypt_len;
	free(decrypt);

	Status = ERROR_SUCCESS;

cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Determines if a key storage provider supports a
*                specific cryptographic algorithm.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            LPCWSTR pszAlgId                Name of the cryptographic
*                                            Algorithm in question
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The algorithm is supported.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               This algorithm is not supported.
*/
SECURITY_STATUS
WINAPI
KSPIsAlgSupported(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    LPCWSTR pszAlgId,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("IsAlgSupported", &context);
	Write_DebugData(context, LOG_CONTEXT);
	KSP_PROVIDER		*pProvider = NULL;
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;

	// Validate input parameters.
	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if (pszAlgId == NULL)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if ((dwFlags & ~NCRYPT_SILENT_FLAG) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}

	// For now this KSP only supports the RSA algorithm.
	if (wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) != 0)
	{
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}

	Status = ERROR_SUCCESS;
cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Obtains the names of the algorithms that are supported by
*                the key storage provider.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object.
*            DWORD   dwAlgOperations         The crypto operations that are to
*                                            be enumerated.
*            DWORD   dwFlags                 Flags
*
* OUTPUTS:
*            DWORD * pdwAlgCount             Number of supported algorithms.
*            NCryptAlgorithmName **ppAlgList List of supported algorithms.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The crypto operations are not supported.
*/
SECURITY_STATUS
WINAPI
KSPEnumAlgorithms(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    DWORD   dwAlgOperations,
	__out   DWORD * pdwAlgCount,
	__deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("EnumAlgorithms", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;
	KSP_PROVIDER		*pProvider = NULL;
	NCryptAlgorithmName *pCurrentAlg = NULL;
	PBYTE				pbCurrent = NULL;
	PBYTE				pbOutput = NULL;
	DWORD				cbOutput = 0;

	// Validate input parameters.
	pProvider = KspValidateProvHandle(hProvider);

	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if (pdwAlgCount == NULL || ppAlgList == NULL)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if ((dwFlags & ~NCRYPT_SILENT_FLAG) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}


	if (dwAlgOperations == 0 ||
		((dwAlgOperations & NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION) != 0) ||
		((dwAlgOperations & NCRYPT_SIGNATURE_OPERATION)) != 0)
	{
		cbOutput += sizeof(NCryptAlgorithmName) +
			sizeof(BCRYPT_RSA_ALGORITHM);
	}
	else
	{
		//For now KSP only supports RSA.
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}

	//Allocate the output buffer.
	pbOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbOutput);
	if (pbOutput == NULL)
	{
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}

	pCurrentAlg = (NCryptAlgorithmName *)pbOutput;
	pbCurrent = pbOutput + sizeof(NCryptAlgorithmName);

	pCurrentAlg->dwFlags = 0;
	pCurrentAlg->dwClass = NCRYPT_SIGNATURE_INTERFACE;
	pCurrentAlg->dwAlgOperations = NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |
		NCRYPT_SIGNATURE_OPERATION;

	pCurrentAlg->pszName = (LPWSTR)pbCurrent;
	CopyMemory(pbCurrent,
		BCRYPT_RSA_ALGORITHM,
		sizeof(BCRYPT_RSA_ALGORITHM));
	pbCurrent += sizeof(BCRYPT_RSA_ALGORITHM);

	*pdwAlgCount = 1;
	*ppAlgList = (NCryptAlgorithmName *)pbOutput;

	Status = ERROR_SUCCESS;

cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Obtains the names of the keys that are stored by the provider.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            LPCWSTR pszScope                Unused
*            NCryptKeyName **ppKeyName       Name of the retrieved key
*            PVOID * ppEnumState             Enumeration state information
*            DWORD   dwFlags                 Flags
*
* OUTPUTS:
*            PVOID * ppEnumState             Enumeration state information that
*                                            is used in subsequent calls to
*                                            this function.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               NCRYPT_MACHINE_KEY_FLAG is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
KSPEnumKeys(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in_opt LPCWSTR pszScope,
	__deref_out NCryptKeyName **ppKeyName,
	__inout PVOID * ppEnumState,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("EnumKeys", &context);
	Write_DebugData(context, LOG_CONTEXT);
	KSP_PROVIDER			*pProvider = NULL;
	NCryptKeyName			*pKeyName = NULL;
	KSP_MEMORY_BUFFER *pBuffer = NULL;
	PVOID					pEnumState = NULL;
	SECURITY_STATUS			Status = NTE_INTERNAL_ERROR;
	NTSTATUS				ntstatus = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(pszScope);
	// Validate input parameters.
	pProvider = KspValidateProvHandle(hProvider);
	if (pProvider == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if (ppKeyName == NULL || ppEnumState == NULL)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if ((dwFlags & ~(NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG)) != 0)
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}

	pEnumState = *ppEnumState;
	if (pEnumState == NULL)
	{
		ntstatus = Get_Key_List(
			&pEnumState,
			&pKeyName);
		Status = NormalizeNteStatus(ntstatus);
		if (Status != ERROR_SUCCESS) {
			goto cleanup;
		}

		// Allocate structure to hold the returned pEnumState buffer.
		pBuffer = (KSP_MEMORY_BUFFER*)HeapAlloc(
			GetProcessHeap(),
			0,
			sizeof(KSP_MEMORY_BUFFER));
		if (pBuffer == NULL)
		{
			Status = NTE_NO_MEMORY;
			goto cleanup;
		}
		ZeroMemory(pBuffer, sizeof(KSP_MEMORY_BUFFER));

		// Add the returned pEnumState buffer to a global list, so that
		// the KSP will know the correct way to free the buffer.
		pBuffer->pvBuffer = pEnumState;
		//@@Critical section code would need to be added here for multi-threaded support.@@
		InsertTailList(
			&g_KspEnumStateList,
			&pBuffer->List);
		pBuffer = NULL;
	}
	else
	{
		// Make sure that the passed in pEnumState buffer is one
		// that we recognize.
		if (LookupMemoryBuffer(
			&g_KspEnumStateList,
			pEnumState) == NULL)
		{
			Status = NTE_INVALID_PARAMETER;
			goto cleanup;
		}

		ntstatus = Find_Next_Key(
			pEnumState,
			&pKeyName);
		Status = NormalizeNteStatus(ntstatus);
		if (Status != ERROR_SUCCESS)
		{
			goto cleanup;
		}
	}


	// Build output data.
	*ppKeyName = pKeyName;
	pKeyName = NULL;
	*ppEnumState = pEnumState;
	pEnumState = NULL;
	Status = ERROR_SUCCESS;
cleanup:
	if (pKeyName)
	{
		HeapFree(GetProcessHeap(), 0, pKeyName);
	}

	if (pBuffer)
	{
		HeapFree(GetProcessHeap(), 0, pBuffer);
	}
	if (Status != NTE_NO_MORE_ITEMS) {
		if (pEnumState)
		{
			HeapFree(GetProcessHeap(), 0, pEnumState);
		}
	}
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Imports a key into the KSP from a memory BLOB.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider     A handle to a KSP provider
*                                             object.
*            NCRYPT_KEY_HANDLE hImportKey     Unused
*            LPCWSTR pszBlobType              Type of the key blob.
*            NCryptBufferDesc *pParameterList Additional parameter information.
*            PBYTE   pbData                   Key blob.
*            DWORD   cbData                   Size of the key blob.
*            DWORD   dwFlags                  Flags
*
* OUTPUTS:
*            NCRYPT_KEY_HANDLE *phKey        KSP key object imported
*                                            from the key blob.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The type of the key blob is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_INTERNAL_ERROR              Decoding failed.
*/
SECURITY_STATUS
WINAPI
KSPImportKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in_opt NCRYPT_KEY_HANDLE hImportKey,
	__in    LPCWSTR pszBlobType,
	__in_opt NCryptBufferDesc *pParameterList,
	__out   NCRYPT_KEY_HANDLE *phKey,
	__in_bcount(cbData) PBYTE pbData,
	__in    DWORD   cbData,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("ImportKey", &context);
	Write_DebugData(context, LOG_CONTEXT);
	
	SECURITY_STATUS         Status = NTE_NOT_SUPPORTED;
	
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(hImportKey);
	UNREFERENCED_PARAMETER(pszBlobType);
	UNREFERENCED_PARAMETER(pParameterList);
	UNREFERENCED_PARAMETER(phKey);
	UNREFERENCED_PARAMETER(pbData);
	UNREFERENCED_PARAMETER(cbData);
	UNREFERENCED_PARAMETER(dwFlags);

cleanup:

	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Exports a key storage key into a memory BLOB.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider     A handle to a KSP provider
*                                             object.
*            NCRYPT_KEY_HANDLE hKey           A handle to the KSP key
*                                             object to export.
*            NCRYPT_KEY_HANDLE hExportKey     Unused
*            LPCWSTR pszBlobType              Type of the key blob.
*            NCryptBufferDesc *pParameterList Additional parameter information.
*            DWORD   cbOutput                 Size of the key blob.
*            DWORD   dwFlags                  Flags
*
* OUTPUTS:
*            PBYTE pbOutput                  Key blob.
*            DWORD * pcbResult               Required size of the key blob.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The type of the key blob is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_INTERNAL_ERROR              Encoding failed.
*/
SECURITY_STATUS
WINAPI
KSPExportKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_opt NCRYPT_KEY_HANDLE hExportKey,
	__in    LPCWSTR pszBlobType,
	__in_opt NCryptBufferDesc *pParameterList,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("ExportKey", &context);
	Write_DebugData(context, LOG_CONTEXT);
	KSP_PROVIDER		*pProvider = NULL;
	KSP_KEY             *pKey = NULL;
	BOOL                fPkcs7Blob = FALSE;
	BOOL                fPkcs8Blob = FALSE;
	BOOL                fPublicKeyBlob = FALSE;
	BOOL                fPrivateKeyBlob = FALSE;
	SECURITY_STATUS     Status = NTE_INTERNAL_ERROR;

	UNREFERENCED_PARAMETER(hExportKey);

	// Validate input parameters.
	pProvider = KspValidateProvHandle(hProvider);
	if (pProvider == NULL) {
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}
	pKey = KspValidateKeyHandle(hKey);
	if (pKey == NULL) {
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}
	if (pcbResult == NULL) {
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}
	if ((dwFlags & ~(NCRYPT_SILENT_FLAG | NCRYPT_EXPORT_LEGACY_FLAG)) != 0) {
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}
	if (dwFlags & NCRYPT_EXPORT_LEGACY_FLAG) {
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}

	//
	// Export key.
	//
	if (wcscmp(pszBlobType, BCRYPT_PUBLIC_KEY_BLOB) == 0) {
		fPublicKeyBlob = TRUE;
	}
	else if (wcscmp(pszBlobType, BCRYPT_PRIVATE_KEY_BLOB) == 0) {
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}
	else if (wcscmp(pszBlobType, BCRYPT_RSAPUBLIC_BLOB) == 0) {
		fPublicKeyBlob = TRUE;
	}
	else if (wcscmp(pszBlobType, BCRYPT_RSAPRIVATE_BLOB) == 0 ||
		wcscmp(pszBlobType, BCRYPT_RSAFULLPRIVATE_BLOB) == 0) {
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}
	else if (wcscmp(pszBlobType, NCRYPT_PKCS7_ENVELOPE_BLOB) == 0) {
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}
	else if (wcscmp(pszBlobType, NCRYPT_PKCS8_PRIVATE_KEY_BLOB) == 0) {
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}
	else {
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}

	//Export the public key blob.
	if (fPublicKeyBlob) {
		if (pbOutput != NULL) {
			if (cbOutput > pKey->cbPubKeyInfo)
			{
				*pcbResult = (DWORD)pKey->cbPubKeyInfo;
				Status = NTE_BUFFER_TOO_SMALL;
				goto cleanup;
			}
			else
			{
				memcpy(pbOutput, pKey->pbPubKeyInfo, pKey->cbPubKeyInfo);
			}
		}
		*pcbResult = (DWORD)pKey->cbPubKeyInfo;
		Status = ERROR_SUCCESS;
	}
	else {
		Status = NTE_NOT_SUPPORTED;
	}

cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  creates a signature of a hash value.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object
*            VOID    *pPaddingInfo           Padding information is padding sheme
*                                            is used
*            PBYTE  pbHashValue              Hash to sign.
*            DWORD  cbHashValue              Size of the hash.
*            DWORD  cbSignature              Size of the signature
*            DWORD  dwFlags                  Flags
* OUTPUTS:
*            PBYTE  pbSignature              Output buffer containing signature.
*                                            If pbOutput is NULL, required buffer
*                                            size will return in *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPSignHash(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_opt    VOID  *pPaddingInfo,
	__in_bcount(cbHashValue) PBYTE pbHashValue,
	__in    DWORD   cbHashValue,
	__out_bcount_part_opt(cbSignaturee, *pcbResult) PBYTE pbSignature,
	__in    DWORD   cbSignaturee,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("SignHash", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS				Status = NTE_INTERNAL_ERROR;
	KSP_KEY						*pKey = NULL;
	BCRYPT_PKCS1_PADDING_INFO	*pkcs1PaddingInfo = NULL;
	struct operation_response	*signResponse = NULL;
	char*						base64Encoded = NULL;
	char						keyName[MAX_ID_SIZE] = { 0 };
	size_t						sign_len = 0;
	size_t						outputLen = 0;
	unsigned char				algorithm[MAX_JWA_ALGORITHM_LEN] = "";
	UNREFERENCED_PARAMETER(hProvider);

	//
	// Validate input parameters.
	//
	pKey = KspValidateKeyHandle(hKey);
	if (pKey == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if (pcbResult == NULL)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if (dwFlags & ~(BCRYPT_PAD_PKCS1 | BCRYPT_PAD_PSS | NCRYPT_SILENT_FLAG))
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}

	if (pKey->fFinished == FALSE)
	{
		Status = NTE_BAD_KEY_STATE;
		goto cleanup;
	}

	if (pbHashValue == NULL || cbHashValue == 0)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}
	//
	// Verify that this key is allowed to perform sign operations.
	//

	if ((pKey->dwKeyUsagePolicy & NCRYPT_ALLOW_SIGNING_FLAG) == 0)
	{
		Status = (DWORD)NTE_PERM;
		goto cleanup;
	}

	if (dwFlags & BCRYPT_PAD_PKCS1) {
		pkcs1PaddingInfo = (BCRYPT_PKCS1_PADDING_INFO*)pPaddingInfo;
		FILE *f;

		if ((wcscmp(pkcs1PaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA256RSA)) == 0) || (wcscmp(pkcs1PaddingInfo->pszAlgId, KSP_SHA256) == 0)) {
			strcpy((char *)algorithm, "RS256");
		}
		else if ((wcscmp(pkcs1PaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA384RSA)) == 0) || (wcscmp(pkcs1PaddingInfo->pszAlgId, KSP_SHA384) == 0)) {
			strcpy((char *)algorithm, "RS384");
		}
		else if ((wcscmp(pkcs1PaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA512RSA)) == 0) || (wcscmp(pkcs1PaddingInfo->pszAlgId, KSP_SHA512) == 0)) {
			strcpy((char *)algorithm, "RS512");
		}
		else {
			Status = NTE_BAD_ALGID;
			goto cleanup;
		}
	}

	base64Encoded = base64encode((unsigned char *)pbHashValue, cbHashValue);
	if (base64Encoded == NULL) {
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}

	wcstombs(keyName, pKey->pszKeyName, MAX_ID_SIZE);
	struct operation_data *signData = Store_OperationData(TOKEN, keyName, HOST, (char *)algorithm, base64Encoded);
	free(base64Encoded);
	if (signData == NULL) {
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}
	int result = Sign(signData, &signResponse);
	Free_OperationData(signData);
	switch (result)
	{
	case HTTP_OK:
		Status = ERROR_SUCCESS;
		break;
	case ALLOCATE_ERROR:
		Status = NTE_NO_MEMORY;
		goto cleanup;
	case BAD_REQUEST:
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	case UNAUTHORIZED:
	case FORBIDDEN:
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	default:
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	}
	outputLen = 4 * (strlen(signResponse->value) / 3); //base64 ratio of output to input bytes = 4:3 // TODO: review, from base64 to bytes the ratio is the inverse
	unsigned char* sign = malloc(outputLen);
	if (sign == NULL) {
		Status = NTE_NO_MEMORY;
		Free_OperationResponse(signResponse);
		goto cleanup;
	}
	result = base64url_decode((char *)sign, outputLen, signResponse->value, strlen(signResponse->value), &sign_len);
	Free_OperationResponse(signResponse);
	if (result != 0 || sign_len > outputLen) {
		free(sign);
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	}
	if (pbSignature != NULL) {
		if (sign_len > cbSignaturee)
		{
			*pcbResult = (DWORD)sign_len;
			free(sign);
			Status = NTE_BUFFER_TOO_SMALL;
			goto cleanup;
		}
		else
		{
			memcpy(pbSignature, sign, sign_len);
		}
	}
	*pcbResult = (DWORD)sign_len;
	free(sign);

	Status = ERROR_SUCCESS;

cleanup:
	Error_Writter(&context, Status);
	Write_DebugData(context, LOG_CONTEXT);
	return Status;
}

/******************************************************************************
* DESCRIPTION :  Verifies that the specified signature matches the specified hash
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object
*            VOID    *pPaddingInfo           Padding information is padding sheme
*                                            is used.
*            PBYTE  pbHashValue              Hash data
*            DWORD  cbHashValue              Size of the hash
*            PBYTE  pbSignature              Signature data
*            DWORD  cbSignaturee             Size of the signature
*            DWORD  dwFlags                  Flags
*
* RETURN :
*            ERROR_SUCCESS                   The signature is a valid signature.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
KSPVerifySignature(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_opt    VOID *pPaddingInfo,
	__in_bcount(cbHashValue) PBYTE pbHashValue,
	__in    DWORD   cbHashValue,
	__in_bcount(cbSignaturee) PBYTE pbSignature,
	__in    DWORD   cbSignaturee,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("VerifySignature", &context);
	Write_DebugData(context, LOG_CONTEXT);
	SECURITY_STATUS				Status = NTE_INTERNAL_ERROR;
	KSP_KEY						*pKey = NULL;
	BCRYPT_PKCS1_PADDING_INFO	*pkcs1PaddingInfo = NULL;
	struct operation_response	*signResponse = NULL;
	char*						base64Encoded = NULL;
	char						keyName[500] = { 0 };
	size_t						sign_len = 0;
	size_t						outputLen = 0;
	unsigned char				algorithm[MAX_JWA_ALGORITHM_LEN] = "";
	UNREFERENCED_PARAMETER(hProvider);

	// Validate input parameters.
	pKey = KspValidateKeyHandle(hKey);
	if (pKey == NULL)
	{
		Status = NTE_INVALID_HANDLE;
		goto cleanup;
	}

	if (pKey->fFinished == FALSE)
	{
		Status = NTE_BAD_KEY_STATE;
		goto cleanup;
	}

	if (pbHashValue == NULL || cbHashValue == 0)
	{
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}

	if (dwFlags & ~(BCRYPT_PAD_PKCS1 | BCRYPT_PAD_PSS | NCRYPT_SILENT_FLAG))
	{
		Status = NTE_BAD_FLAGS;
		goto cleanup;
	}

	if (dwFlags & BCRYPT_PAD_PKCS1) {
		pkcs1PaddingInfo = (BCRYPT_PKCS1_PADDING_INFO*)pPaddingInfo;
		if ((wcscmp(pkcs1PaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA256RSA)) == 0) || (wcscmp(pkcs1PaddingInfo->pszAlgId, KSP_SHA256) == 0)) {
			strcpy((char *)algorithm, "RS256");
		}
		else if ((wcscmp(pkcs1PaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA384RSA)) == 0) || (wcscmp(pkcs1PaddingInfo->pszAlgId, KSP_SHA384) == 0)) {
			strcpy((char *)algorithm, "RS384");
		}
		else if ((wcscmp(pkcs1PaddingInfo->pszAlgId, TEXT(szOID_RSA_SHA512RSA)) == 0) || (wcscmp(pkcs1PaddingInfo->pszAlgId, KSP_SHA512) == 0)) {
			strcpy((char *)algorithm, "RS512");
		}
		else {
			Status = NTE_BAD_ALGID;
			goto cleanup;
		}
	}

	char* shaBase64Encoded = NULL;
	shaBase64Encoded = base64encode((unsigned char*)pbHashValue, cbHashValue);
	if (shaBase64Encoded == NULL) {
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}
	char* signBase64Encoded = NULL;
	signBase64Encoded = base64encode(pbSignature, cbSignaturee);
	if (signBase64Encoded == NULL) {
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}
	wcstombs(keyName, pKey->pszKeyName, 500);
	struct verify_data *verifyData = Store_VerifyData(keyName, TOKEN, HOST, (char *)algorithm, shaBase64Encoded, signBase64Encoded);
	free(shaBase64Encoded);
	free(signBase64Encoded);
	if (verifyData == NULL) {
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}
	int result = Verify(verifyData);
	Free_VerifyData(verifyData);
	switch (result)
	{
	case TRUE:
		Status = ERROR_SUCCESS;
		goto cleanup;
	case FALSE:
		Status = NTE_BAD_SIGNATURE;
		goto cleanup;
	case ALLOCATE_ERROR:
		Status = NTE_NO_MEMORY;
		goto cleanup;
	case BAD_REQUEST:
		Status = NTE_INVALID_PARAMETER;
		goto cleanup;
	case UNAUTHORIZED:
	case FORBIDDEN:
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	default:
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	}

cleanup:

	return Status;
}

SECURITY_STATUS
WINAPI
KSPPromptUser(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in_opt NCRYPT_KEY_HANDLE hKey,
	__in    LPCWSTR  pszOperation,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("PromptUser", &context);
	Write_DebugData(context, LOG_CONTEXT);
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pszOperation);
	UNREFERENCED_PARAMETER(dwFlags);
	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI
KSPNotifyChangeKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__inout HANDLE *phEvent,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("NotifyChangeKey", &context);
	Write_DebugData(context, LOG_CONTEXT);
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(phEvent);
	UNREFERENCED_PARAMETER(dwFlags);
	return NTE_NOT_SUPPORTED;
}


SECURITY_STATUS
WINAPI
KSPSecretAgreement(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hPrivKey,
	__in    NCRYPT_KEY_HANDLE hPubKey,
	__out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
	__in    DWORD   dwFlags)
{
	context context;
	Context_Initialization("SecretAgreement", &context);
	Write_DebugData(context, LOG_CONTEXT);
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(hPrivKey);
	UNREFERENCED_PARAMETER(hPubKey);
	UNREFERENCED_PARAMETER(phAgreedSecret);
	UNREFERENCED_PARAMETER(dwFlags);
	return NTE_NOT_SUPPORTED;
}


SECURITY_STATUS
WINAPI
KSPDeriveKey(
	__in        NCRYPT_PROV_HANDLE   hProvider,
	__in_opt    NCRYPT_SECRET_HANDLE hSharedSecret,
	__in        LPCWSTR              pwszKDF,
	__in_opt    NCryptBufferDesc     *pParameterList,
	__out_bcount_part_opt(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
	__in        DWORD                cbDerivedKey,
	__out       DWORD                *pcbResult,
	__in        ULONG                dwFlags)
{
	context context;
	Context_Initialization("DeriveKey", &context);
	Write_DebugData(context, LOG_CONTEXT);
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(hSharedSecret);
	UNREFERENCED_PARAMETER(pwszKDF);
	UNREFERENCED_PARAMETER(pParameterList);
	UNREFERENCED_PARAMETER(pbDerivedKey);
	UNREFERENCED_PARAMETER(cbDerivedKey);
	UNREFERENCED_PARAMETER(pcbResult);
	UNREFERENCED_PARAMETER(dwFlags);
	return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI
KSPFreeSecret(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_SECRET_HANDLE hSharedSecret)
{
	context context;
	Context_Initialization("FreeSecret", &context);
	Write_DebugData(context, LOG_CONTEXT);
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(hSharedSecret);
	return NTE_NOT_SUPPORTED;
}
