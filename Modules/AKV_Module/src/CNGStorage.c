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

#ifdef CNG_KSP
#include "interface.h"

LIST_ENTRY KEY_LIST = { 0 };

ERROR_CODE ClientRest_ErrorConverter(int clientRestError)
{
	switch (clientRestError)
	{
	case ALLOCATE_ERROR:
		return MD_HOST_MEMORY;
	case UNAUTHORIZED:
		return MD_INVALID_TOKEN;
	case FORBIDDEN:
		return MD_FUNCTION_FAILED;
	case NOT_FOUND:
		return MD_NOT_FOUND;
	case BAD_REQUEST:
		return MD_INVALID_PARAMETER;
	default:
		if (clientRestError < 0) return MD_NOT_READY;
		else return MD_FUNCTION_FAILED;
	}
}

void Remove_all_key_list(void)
{
	PLIST_ENTRY pList = { 0 };
	LIST_ENTRY* pKList = &KEY_LIST;
	KSP_MEMORY_BUFFER *pBuffer = NULL;
	if (*(DWORD*)pKList == NULL) return;
	pList = pKList->Flink;
	if ((pList->Flink == pList) || (NULL == KEY_LIST.Flink)) return;
	while (pList != pList->Flink)
	{
		pBuffer = CONTAINING_RECORD(pList, KSP_MEMORY_BUFFER, List.Flink);
		if ((AKV_KEY *)pBuffer->pvBuffer != NULL) {
			Free_KeyCreationResponse(((AKV_KEY *)pBuffer->pvBuffer)->key_data);
		}
		HeapFree(GetProcessHeap(), 0, pBuffer->pvBuffer);
		pBuffer->pvBuffer = NULL;
		RemoveEntryList(&pBuffer->List);
		HeapFree(GetProcessHeap(), 0, pBuffer);
		pList = pList->Flink;
	}
	RemoveHeadList(&KEY_LIST);
	ZeroMemory(&KEY_LIST, sizeof(LIST_ENTRY));
}

ERROR_CODE Get_Key_List(
	__out		PVOID		  *ppEnumState,
	__deref_out NCryptKeyName **ppKeyName)
{
	NCryptKeyName				*ppOutKeyName = NULL;
	KSP_MEMORY_BUFFER		*pBuffer = NULL;
	ERROR_CODE					status = MD_NO_ERROR;
	struct basic_http_data		*petitionData = NULL;
	struct list_key				*keyList = NULL, *pCurrentKey = NULL;
	struct id_http_data			*getParam;
	struct key_data_response	*returnedKey = NULL;
	AKV_KEY						*pCurrentKeyData = NULL, *firstKey = NULL;
	BOOL						first = TRUE;

	if (NULL == KEY_LIST.Flink) {
		InitializeListHead(&KEY_LIST);
	}
	if (KEY_LIST.Flink == KEY_LIST.Flink->Flink) {
		petitionData = Store_BasicHttpData(TOKEN, HOST);
		if (petitionData == NULL) return MD_HOST_MEMORY;
		ERROR_CODE result = Get_ListKeys(petitionData, &keyList);
		Free_BasicHttpData(petitionData);
		if (result != HTTP_OK) {
			status = ClientRest_ErrorConverter(result);
			goto cleanup;
		}
		if (keyList == NULL) {
			status = MD_UNDEFINED_ERROR;
			goto cleanup;
		}
		pCurrentKey = keyList;
		while (NULL != pCurrentKey) {
			returnedKey = NULL;
			getParam = Store_IdHttpData(TOKEN, HOST, pCurrentKey->id);
			if (getParam == NULL) {
				status = MD_HOST_MEMORY;
				goto cleanup;
			}
			result = Get_Key(getParam, &returnedKey);
			Free_IdHttpData(getParam);
			if (result != HTTP_OK) {
				status = ClientRest_ErrorConverter(result);
				goto cleanup;
			}
			pCurrentKeyData = (AKV_KEY*)HeapAlloc(GetProcessHeap(), 0, sizeof(AKV_KEY));
			if (NULL == pCurrentKeyData) {
				status = MD_HOST_MEMORY;
				goto cleanup;
			}
			pCurrentKeyData->handler = pCurrentKey->keyHandler;
			pCurrentKeyData->key_data = returnedKey;
			returnedKey = NULL;
			if (first) {
				firstKey = pCurrentKeyData;
				first = FALSE;
			}
			pBuffer = (KSP_MEMORY_BUFFER*)HeapAlloc(GetProcessHeap(), 0, sizeof(KSP_MEMORY_BUFFER));
			if (pBuffer == NULL) {
				status = MD_HOST_MEMORY;
				goto cleanup;
			}
			ZeroMemory(pBuffer, sizeof(KSP_MEMORY_BUFFER));
			pBuffer->pvBuffer = pCurrentKeyData;
			pCurrentKeyData = NULL;
			//@@Critical section code would need to be added here for multi-threaded support.@@
			InsertTailList(&KEY_LIST, &pBuffer->List);
			pBuffer = NULL;
			pCurrentKey = pCurrentKey->next;
		}
		Free_ListKey(keyList);
		keyList = NULL;
	}
	else {
		KSP_MEMORY_BUFFER *pBuffer = NULL;
		LIST_ENTRY* pkey = &KEY_LIST;
		pBuffer = CONTAINING_RECORD(pkey->Flink, KSP_MEMORY_BUFFER, List.Flink);
		firstKey = (AKV_KEY*)pBuffer->pvBuffer;
	}
	status = ReadKeyNameFromMemory(firstKey->key_data, &ppOutKeyName);
	if (MD_NO_ERROR != status) goto cleanup;
	KSP_ENUM_STATE * pEnumState = (KSP_ENUM_STATE*)HeapAlloc(GetProcessHeap(), 0, sizeof(KSP_ENUM_STATE));
	if (pEnumState == NULL) {
		status = MD_HOST_MEMORY;
		goto cleanup;
	}
	pEnumState->dwIndex = firstKey->handler;
	LIST_ENTRY* pKList = &KEY_LIST;
	pEnumState->hFind = pKList->Flink;

	*ppEnumState = pEnumState;
	*ppKeyName = ppOutKeyName;

	return status;

cleanup:
	if (returnedKey) {
		Free_KeyCreationResponse(returnedKey);
	}
	if (keyList) {
		Free_ListKey(keyList);
	}
	if (pCurrentKeyData) {
		HeapFree(GetProcessHeap(), 0, pCurrentKeyData);
	}
	Remove_all_key_list();
	return status;
}

/******************************************************************************
* DESCRIPTION : Read the name of the key from the memory buffer.
*
* INPUTS:
*           key_data_response  returnedKey  key structure in memory.
*
* OUTPUS:
*           NCryptKeyName **ppKeyName    Name of the key.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  Open file operation failed.
*/
ERROR_CODE
ReadKeyNameFromMemory(
	__in struct key_data_response *returnedKey,
	__deref_out NCryptKeyName **ppKeyName)
{
	wchar_t				staticKeyName[MAX_LABEL_SIZE] = { 0 };
	wchar_t				staticAlgName[MAX_LABEL_SIZE] = { 0 };
	SECURITY_STATUS		Status = MD_UNDEFINED_ERROR;
	PBYTE				pbCurrent = NULL;
	NCryptKeyName       *pOutput = NULL;
	DWORD				cbOutput = 0;
	DWORD				cbKeyName = 0;
	DWORD				cbAlgName = 0;


	Status = Ncrypt_Algorithm_Parser(returnedKey->keytype, &staticAlgName);
	if (Status != STATUS_SUCCESS) {
		return Status;
	}

	swprintf(staticKeyName, MAX_LABEL_SIZE, L"%hs", returnedKey->id);
	cbKeyName = (DWORD)wcslen(staticKeyName) * sizeof(WCHAR);
	cbAlgName = (DWORD)wcslen(staticAlgName) * sizeof(WCHAR);
	cbOutput = sizeof(NCryptKeyName) + cbKeyName + sizeof(WCHAR) + cbAlgName + sizeof(WCHAR);
	pOutput = (NCryptKeyName *)HeapAlloc(GetProcessHeap(), 0, cbOutput);
	if (pOutput == NULL)
	{
		Status = MD_HOST_MEMORY;
		return Status;
	}
	pbCurrent = (PBYTE)(pOutput + 1);
	pOutput->dwFlags = 0;
	//Sample KSP does not support legacy keys.
	pOutput->dwLegacyKeySpec = 0;
	pOutput->pszName = (LPWSTR)pbCurrent;
	CopyMemory(pbCurrent, staticKeyName, cbKeyName);
	pbCurrent += cbKeyName;
	*(LPWSTR)pbCurrent = L'\0';
	pbCurrent += sizeof(WCHAR);
	//Name of the algorithm.
	pOutput->pszAlgid = (LPWSTR)pbCurrent;
	CopyMemory(pbCurrent, staticAlgName, cbAlgName);
	pbCurrent += cbAlgName;
	*(LPWSTR)pbCurrent = L'\0';
	pbCurrent += sizeof(WCHAR);
	*ppKeyName = pOutput;
	Status = MD_NO_ERROR;
	return Status;
}

ERROR_CODE Find_Next_Key(
	__inout PVOID pEnumState,
	__deref_out NCryptKeyName **ppKeyName)
{
	NCryptKeyName				*pKeyName = NULL;
	KSP_ENUM_STATE				*pState = NULL;
	AKV_KEY						*currentKey = NULL;
	NCryptKeyName				*ppOutKeyName = NULL;
	LIST_ENTRY					*pkey;
	KSP_MEMORY_BUFFER		*pBuffer = NULL;
	SECURITY_STATUS				Status = MD_UNDEFINED_ERROR;
	//Find next.
	pState = (KSP_ENUM_STATE *)pEnumState;
	pkey = ((LIST_ENTRY *)pState->hFind);

	if (pkey == NULL) {
		return MD_NO_MORE_ITEMS;
	}
	if (pkey == pkey->Flink) {
		return MD_NO_MORE_ITEMS;
	}
	if (pkey->Flink == &KEY_LIST) {
		return MD_NO_MORE_ITEMS;
	}

	pBuffer = CONTAINING_RECORD(pkey->Flink, KSP_MEMORY_BUFFER, List.Flink);
	if (NULL == pBuffer->pvBuffer) {
		pState->hFind = pkey->Flink;
		return MD_NO_MORE_ITEMS;
	}
	currentKey = (AKV_KEY *)(pBuffer->pvBuffer);
	if (currentKey->handler <= pState->dwIndex || currentKey->handler != pState->dwIndex + 1) {
		pState->hFind = pkey->Flink;
		return MD_NO_MORE_ITEMS;
	}
	Status = ReadKeyNameFromMemory(currentKey->key_data, &ppOutKeyName);
	if (MD_NO_ERROR != Status) return Status;
	pState->dwIndex = currentKey->handler;
	pState->hFind = pkey->Flink;
	*ppKeyName = ppOutKeyName;
	return MD_NO_ERROR;
}

AKV_KEY *Find_Current_Key(KSP_KEY * pKey)
{
	PLIST_ENTRY pList = { 0 };
	LIST_ENTRY *pKList = &KEY_LIST;
	KSP_MEMORY_BUFFER *pBuffer = NULL;
	AKV_KEY *currentKey = NULL;
	BOOL found = FALSE;
	wchar_t  ws[MAX_LABEL_SIZE];
	pList = pKList->Flink;
	if (pList == NULL) return NULL;
	if ((pList->Flink == pList) || (NULL == KEY_LIST.Flink)) return NULL;
	while (pList != pKList)
	{
		pBuffer = CONTAINING_RECORD(pList, KSP_MEMORY_BUFFER, List.Flink);
		currentKey = (AKV_KEY *)(pBuffer->pvBuffer);
		swprintf(ws, MAX_LABEL_SIZE, L"%hs", currentKey->key_data->id);
		if (wcscmp(ws, pKey->pszKeyName) == 0)
		{
			found++;
			break;
		}
		pList = pList->Flink;
	}
	if (found) return currentKey;
	else return NULL;
}

AKV_KEY *Find_Key_By_Name(LPWSTR keyName)
{
	PLIST_ENTRY pList = { 0 };
	LIST_ENTRY *pKList = &KEY_LIST;
	KSP_MEMORY_BUFFER *pBuffer = NULL;
	AKV_KEY *currentKey = NULL;
	BOOL found = FALSE;
	wchar_t  ws[MAX_LABEL_SIZE];
	pList = pKList->Flink;
	if (pList == NULL) return NULL;
	if ((pList->Flink == pList) || (NULL == KEY_LIST.Flink)) return NULL;
	while (pList != pKList)
	{
		pBuffer = CONTAINING_RECORD(pList, KSP_MEMORY_BUFFER, List.Flink);
		currentKey = (AKV_KEY *)(pBuffer->pvBuffer);
		swprintf(ws, MAX_LABEL_SIZE, L"%hs", currentKey->key_data->id);
		//Write_Free_Text(currentKey->key_data->id); //BORRAR
		if (wcscmp(ws, keyName) == 0)
		{
			found++;
			break;
		}
		pList = pList->Flink;
	}
	if (found) return currentKey;
	else return NULL;
}

/******************************************************************************
* DESCRIPTION : Parse the key file blob to get the private and public key and
*               properties.
* INPUTS:
*           KSP_KEY *pKey         A handle to the key object
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*/
ERROR_CODE
ParseMemoryKey(
	__inout KSP_KEY *pKey,
	__in	AKV_KEY *currentKey)
{
	DWORD				keyAlgorithm = 0;
	KSP_PROPERTY* pProperty = NULL;
	SECURITY_STATUS		Status = NTE_INTERNAL_ERROR;
	DWORD				keyUsage = 0;
	char				b64dModule[2048] = { 0 };
	char				b64dExponent[512] = { 0 };
	DWORD				modulusBit = 0, res;
	char				publicExponent[10];
	size_t				modLen = 0;
	size_t				expLen = 0;
	DWORD				cbPubKey;
	DWORD				cbPublicExp;
	DWORD				cbModulus;
	BCRYPT_RSAKEY_BLOB	*pOutput = NULL;
	PBYTE				pbCurrent = NULL;
	keyAlgorithm = Key_Algorithm_Parser(currentKey);
	if (keyAlgorithm == NTE_BAD_KEY || keyAlgorithm == MD_UNDEFINED_ERROR) {
		Status = (NTSTATUS)keyAlgorithm;
		goto cleanup;
	}
	pKey->dwAlgID = keyAlgorithm;
	//Set the key usage policy if it is set.
	int allOperations = 0;
	Status = Key_Ops_Parser(currentKey, &keyUsage, &allOperations);
	if (Status != ERROR_SUCCESS) {
		goto cleanup;
	}
	pKey->dwKeyUsagePolicy = keyUsage;
	/*pProperty = (SAMPLEKSP_PROPERTY*)HeapAlloc(
		GetProcessHeap(),
		0,
		sizeof(SAMPLEKSP_PROPERTY));
	if (pProperty == NULL)
	{
		return NTE_NO_MEMORY;
	}
	InitializeListHead(&pKey->PropertyList);
	ZeroMemory(pProperty->szName, NCRYPT_MAX_PROPERTY_NAME + 1);
	CopyMemory(pProperty->szName, NCRYPT_KEY_USAGE_PROPERTY, sizeof(NCRYPT_KEY_USAGE_PROPERTY));
	pProperty->cbPropertyData = keyUsage;
	pProperty->fBuildin = FALSE;
	pProperty->fPersisted = FALSE;
	InsertTailList(&pKey->PropertyList, &pProperty->ListEntry);*/

	//Set the export policy if it is set.
	pKey->dwExportPolicy = (DWORD)0;
	/*pProperty = (SAMPLEKSP_PROPERTY*)HeapAlloc(
		GetProcessHeap(),
		0,
		sizeof(SAMPLEKSP_PROPERTY));
	if (pProperty == NULL)
	{
		return NTE_NO_MEMORY;
	}
	ZeroMemory(pProperty->szName, NCRYPT_MAX_PROPERTY_NAME + 1);
	CopyMemory(pProperty->szName, NCRYPT_EXPORT_POLICY_PROPERTY, sizeof(NCRYPT_EXPORT_POLICY_PROPERTY));
	pProperty->cbPropertyData = 0;
	pProperty->fBuildin = FALSE;
	pProperty->fPersisted = FALSE;
	InsertTailList(&pKey->PropertyList, &pProperty->ListEntry);*/
	//Set public key size.
	res = base64url_decode(b64dModule, 2048, currentKey->key_data->n, strlen(currentKey->key_data->n), &modLen);
	if (res == 0) {
		modulusBit = modLen * 8;
	}
	else {
		Status = NTE_INTERNAL_ERROR;
		return Status;
	}
	res = base64url_decode(b64dExponent, 512, currentKey->key_data->e, strlen(currentKey->key_data->e), &expLen);
	if (res != 0) {
		Status = NTE_INTERNAL_ERROR;
		return Status;
	}
	
	/*cbPublicExp = (DWORD)strlen(base64urldecoded);*/
	cbPublicExp = expLen;
	cbModulus = (DWORD)modLen;
	cbPubKey = sizeof(BCRYPT_RSAKEY_BLOB) + cbPublicExp + cbModulus;
	pOutput = (BCRYPT_RSAKEY_BLOB *)HeapAlloc(GetProcessHeap(), 0, cbPubKey);
	if (pOutput == NULL)
	{
		Status = NTE_NO_MEMORY;
		return Status;
	}
	ZeroMemory(pOutput, cbPubKey);
	pbCurrent = (PBYTE)(pOutput + 1);
	pOutput->Magic = BCRYPT_RSAPUBLIC_MAGIC;
	pOutput->BitLength = modulusBit;
	pOutput->cbPublicExp = cbPublicExp;
	CopyMemory(pbCurrent, b64dExponent, cbPublicExp);
	pbCurrent += cbPublicExp;
	pOutput->cbModulus = cbModulus;
	CopyMemory(pbCurrent, b64dModule, cbModulus);
	pKey->pszKeyBlobType = BCRYPT_RSAFULLPRIVATE_BLOB;
	pKey->cbPubKeyInfo = cbPubKey;
	pKey->pbPubKeyInfo = (PVOID)pOutput;
	pKey->dwKeyBitLength = modulusBit;





	
	
	






	/*pProperty = (SAMPLEKSP_PROPERTY*)HeapAlloc(
		GetProcessHeap(),
		0,
		sizeof(SAMPLEKSP_PROPERTY));
	if (pProperty == NULL)
	{
		return NTE_NO_MEMORY;
	}
	ZeroMemory(pProperty->szName, NCRYPT_MAX_PROPERTY_NAME + 1);
	CopyMemory(pProperty->szName, NCRYPT_LENGTH_PROPERTY, sizeof(NCRYPT_LENGTH_PROPERTY));
	pProperty->cbPropertyData = modulusBit;
	pProperty->fBuildin = TRUE;
	pProperty->fPersisted = TRUE;
	InsertTailList(&pKey->PropertyList, &pProperty->ListEntry);*/

	////Set the export policy if it is set.
	//Status = LookupExistingKeyProperty(
	//	pKey,
	//	NCRYPT_EXPORT_POLICY_PROPERTY,
	//	&pProperty);
	//if ((Status == ERROR_SUCCESS) && pProperty->fBuildin)
	//{
	//	if (pProperty->cbPropertyData != sizeof(DWORD))
	//	{
	//		Status = NTE_BAD_KEY;
	//		goto cleanup;
	//	}
	//	CopyMemory(&pKey->dwExportPolicy, pProperty + 1, sizeof(DWORD));
	//}
	pKey->managed = currentKey->key_data->managed;
	Status = ERROR_SUCCESS;
cleanup:
	return Status;
}

ERROR_CODE FindKeyInKeyStore(
	__in	LPCWSTR pszKeyName,
	__out	AKV_KEY **ppCurrentKey)
{
	KSP_MEMORY_BUFFER		*pBuffer = NULL;
	ERROR_CODE					status = MD_NO_ERROR;
	struct id_http_data			*getParam;
	struct key_data_response	*returnedKey = NULL;
	AKV_KEY						*pCurrentKeyData = NULL;
	int							result;
	LIST_ENTRY					*pKList = &KEY_LIST;
	PLIST_ENTRY					pList = { 0 };
	AKV_KEY						*lastKey;
	DWORD						cbKeyName = 0;
	char						keyName[MAX_PATH] = { 0 };
	if (NULL == KEY_LIST.Flink) {
		InitializeListHead(&KEY_LIST);
	}
	if (pszKeyName != NULL)
	{
		cbKeyName = (DWORD)(wcslen(pszKeyName) + 1) * sizeof(WCHAR);
		if (cbKeyName > MAX_PATH) {
			status = NTE_INVALID_PARAMETER;
			goto cleanup;
		}
		if (wcstombs(keyName, pszKeyName, cbKeyName - 1) <= 0) {
			status = NTE_INVALID_PARAMETER;
			goto cleanup;
		}
		keyName[cbKeyName] = '\0';
		for (int i = 0; i < strlen(keyName); i++) { // charater '.' dont allowed. Workarround certificate importing
			if (keyName[i] == '.') {
				keyName[i] = '\0';
				break;
			}
		}
	}
	getParam = Store_IdHttpData(TOKEN, HOST, keyName);
	if (getParam == NULL) {
		status = MD_HOST_MEMORY;
		goto cleanup;
	}
	result = Get_Key(getParam, &returnedKey);
	Free_IdHttpData(getParam);
	if (result != HTTP_OK) {
		status = ClientRest_ErrorConverter(result);
		goto cleanup;
	}
	pCurrentKeyData = (AKV_KEY*)HeapAlloc(GetProcessHeap(), 0, sizeof(AKV_KEY));
	if (NULL == pCurrentKeyData) {
		status = MD_HOST_MEMORY;
		goto cleanup;
	}
	if (KEY_LIST.Flink == KEY_LIST.Flink->Flink) {
		pCurrentKeyData->handler = 1;
	}
	else {
		pList = pKList->Blink;
		pBuffer = CONTAINING_RECORD(pList, KSP_MEMORY_BUFFER, List.Flink);
		lastKey = (AKV_KEY *)(pBuffer->pvBuffer);
		pCurrentKeyData->handler = lastKey->handler + 1;
	}
	pCurrentKeyData->key_data = returnedKey;
	returnedKey = NULL;
	pBuffer = (KSP_MEMORY_BUFFER*)HeapAlloc(GetProcessHeap(), 0, sizeof(KSP_MEMORY_BUFFER));
	if (pBuffer == NULL) {
		status = MD_HOST_MEMORY;
		goto cleanup;
	}
	ZeroMemory(pBuffer, sizeof(KSP_MEMORY_BUFFER));
	pBuffer->pvBuffer = pCurrentKeyData;
	//@@Critical section code would need to be added here for multi-threaded support.@@
	InsertTailList(&KEY_LIST, &pBuffer->List);
	pBuffer = NULL;
	*ppCurrentKey = pCurrentKeyData;
	return status;

cleanup:
	if (returnedKey) {
		Free_KeyCreationResponse(returnedKey);
	}
	if (pCurrentKeyData) {
		HeapFree(GetProcessHeap(), 0, pCurrentKeyData);
	}
	return status;
}


ERROR_CODE CreateKeyInKeyStore(
	__in	KSP_KEY *pCreationKey,
	__out	AKV_KEY **ppCreatedKey)
{
	KSP_MEMORY_BUFFER		*pBuffer = NULL;
	ERROR_CODE					status = STATUS_SUCCESS;
	struct key_data				*getParam;
	struct key_data_response	*returnedKey = NULL;
	AKV_KEY						*pCurrentKeyData = NULL;
	int							result;
	LIST_ENTRY					*pKList = &KEY_LIST;
	PLIST_ENTRY					pList = { 0 };
	AKV_KEY						*lastKey;
	DWORD						cbKeyName = 0;
	char						keyName[MAX_PATH] = { 0 };
	char						staticAlgName[MAX_ALGORITHM_TYPE_LENGHT] = { 0 };
	char						keySize[MAX_KEY_SIZE];
	char						*key_ops[MAX_OPS] = { 0 };

	if (NULL == KEY_LIST.Flink) {
		InitializeListHead(&KEY_LIST);
	}
	if (pCreationKey == NULL) {
		status = NTE_INTERNAL_ERROR;
		goto cleanup;
	}
	status = Key_Reverse_Algorithm_Parser(&staticAlgName, pCreationKey->dwAlgID);
	if (status != STATUS_SUCCESS) {
		goto cleanup;
	}
	if (pCreationKey->dwAlgID == KSP_RSA_ALGID) {
		if (pCreationKey->dwKeyBitLength < KSP_RSA_MIN_LENGTH || pCreationKey->dwKeyBitLength > KSP_RSA_MAX_LENGTH) {
			status = NTE_BAD_KEY;
			goto cleanup;
		}
	}
	sprintf(keySize, "%d", pCreationKey->dwKeyBitLength);
	if (pCreationKey->pszKeyName == NULL) {
		status = NTE_BAD_KEY;
		goto cleanup;
	}
	cbKeyName = (DWORD)(wcslen(pCreationKey->pszKeyName) + 1) * sizeof(WCHAR);
	if (cbKeyName > MAX_PATH) {
		status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}
	if (wcstombs(keyName, pCreationKey->pszKeyName, cbKeyName - 1) <= 0) {
		status = NTE_INVALID_PARAMETER;
		goto cleanup;
	}
	keyName[cbKeyName] = '\0';
	for (int i = 0; i < strlen(keyName); i++) { // charater '.' dont allowed. Workarround certificate importing
		if (keyName[i] == '.') {
			keyName[i] = '\0';
			break;
		}
	}

	status = Key_Reverse_Ops_Parser(&key_ops, pCreationKey->dwKeyUsagePolicy);
	if (status != ERROR_SUCCESS) {
		goto cleanup;
	}

	getParam = Store_KeyData(HOST, keyName, staticAlgName, keySize, key_ops, TOKEN, NULL, NULL, NULL);
	if (getParam == NULL) {
		status = MD_HOST_MEMORY;
		goto cleanup;
	}
	result = Create_key(getParam, &returnedKey);
	Free_KeyData(getParam);
	if (result != HTTP_OK) {
		status = ClientRest_ErrorConverter(result);
		goto cleanup;
	}
	pCurrentKeyData = (AKV_KEY*)HeapAlloc(GetProcessHeap(), 0, sizeof(AKV_KEY));
	if (NULL == pCurrentKeyData) {
		status = MD_HOST_MEMORY;
		goto cleanup;
	}
	if (KEY_LIST.Flink == KEY_LIST.Flink->Flink) {
		pCurrentKeyData->handler = 1;
	}
	else {
		pList = pKList->Blink;
		wchar_t  ws[MAX_LABEL_SIZE];
		pBuffer = CONTAINING_RECORD(pList, KSP_MEMORY_BUFFER, List.Flink);
		lastKey = (AKV_KEY *)(pBuffer->pvBuffer);
		pCurrentKeyData->handler = lastKey->handler + 1;
	}
	pCurrentKeyData->key_data = returnedKey;
	returnedKey = NULL;
	pBuffer = (KSP_MEMORY_BUFFER*)HeapAlloc(GetProcessHeap(), 0, sizeof(KSP_MEMORY_BUFFER));
	if (pBuffer == NULL) {
		status = MD_HOST_MEMORY;
		goto cleanup;
	}
	ZeroMemory(pBuffer, sizeof(KSP_MEMORY_BUFFER));
	pBuffer->pvBuffer = pCurrentKeyData;
	//@@Critical section code would need to be added here for multi-threaded support.@@
	InsertTailList(&KEY_LIST, &pBuffer->List);
	pBuffer = NULL;
	*ppCreatedKey = pCurrentKeyData;
	return status;

cleanup:
	if (returnedKey) {
		Free_KeyCreationResponse(returnedKey);
	}
	if (pCurrentKeyData) {
		HeapFree(GetProcessHeap(), 0, pCurrentKeyData);
	}
	return status;
}


DWORD Key_Algorithm_Parser(AKV_KEY *key) {
	if (key == NULL) return (DWORD)MD_UNDEFINED_ERROR;
	if (strcmp(key->key_data->keytype, "RSA") == 0) return KSP_RSA_ALGID;
	else if (strcmp(key->key_data->keytype, "RSA_HSM") == 0) return KSP_RSA_ALGID;
	else return (DWORD)NTE_BAD_KEY;
}

DWORD Ncrypt_Algorithm_Parser(char *keyType, wchar_t *ncryptAlgorithm) {
	if ((keyType == NULL) || (ncryptAlgorithm == NULL)) {
		return (DWORD)MD_UNDEFINED_ERROR;
	}
	if ((strcmp(keyType, "RSA") == 0) || (strcmp(keyType, "RSA_HSM") == 0)) {
		wcsncpy(ncryptAlgorithm, NCRYPT_RSA_ALGORITHM, wcslen(NCRYPT_RSA_ALGORITHM));
	}
	else return (DWORD)NTE_BAD_KEY;
	return MD_NO_ERROR;
}

DWORD Key_Reverse_Algorithm_Parser(char *keyType, DWORD kspAlgorithm) {
	if (keyType == NULL) {
		return (DWORD)MD_UNDEFINED_ERROR;
	}
	if (kspAlgorithm == KSP_RSA_ALGID) {
		if (!HSM_PROCESSED) {
			strncpy(keyType, "RSA", strlen("RSA"));
		}
		else {
			strncpy(keyType, "RSA_HSM", strlen("RSA_HSM"));
		}
	}
	else return (DWORD)NTE_BAD_KEY;
	return (DWORD)MD_NO_ERROR;
}

DWORD Key_Ops_Parser(AKV_KEY *currentKey, DWORD *keyUsage, int *allOperations) {
	if (currentKey == NULL) {
		return NTE_INTERNAL_ERROR;
	}
	for (int i = 0; i < MAX_OPS; i++) {
		if (currentKey->key_data->key_ops[i] == NULL) {
			break;
		}
		if (!strcmp(currentKey->key_data->key_ops[i], encrypt_op)) {
			*keyUsage = *keyUsage | NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
			(*allOperations)++;
		}
		if (!strcmp(currentKey->key_data->key_ops[i], decrypt_op)) {
			*keyUsage = *keyUsage | NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
			(*allOperations)++;
		}
		else if (!strcmp(currentKey->key_data->key_ops[i], sign_op)) {
			*keyUsage = *keyUsage | NCRYPT_ALLOW_SIGNING_FLAG;
			(*allOperations)++;
		}
		if (*allOperations >= ALLOPERATIONS) {
			*keyUsage = NCRYPT_ALLOW_ALL_USAGES;
			break;
		}
	}
	return ERROR_SUCCESS;
}

DWORD Key_Reverse_Ops_Parser(char **keyOps, DWORD keyUsage) {
	DWORD status = ERROR_SUCCESS;
	int index = 0;
	if ((keyUsage & NCRYPT_ALLOW_ALL_USAGES) == NCRYPT_ALLOW_ALL_USAGES || (keyUsage & NCRYPT_ALLOW_KEY_AGREEMENT_FLAG) == NCRYPT_ALLOW_KEY_AGREEMENT_FLAG || (keyUsage & NCRYPT_ALLOW_DECRYPT_FLAG) == NCRYPT_ALLOW_DECRYPT_FLAG) {
		keyOps[index] = _strdup(encrypt_op);
		if (keyOps[index] == NULL) {
			status = NTE_NO_MEMORY;
			goto cleanup;
		}
		index++;
		keyOps[index] = _strdup(decrypt_op);
		if (keyOps[index] == NULL) {
			status = NTE_NO_MEMORY;
			goto cleanup;
		}
		index++;
	}
	if ((keyUsage & NCRYPT_ALLOW_ALL_USAGES) == NCRYPT_ALLOW_ALL_USAGES || (keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) == NCRYPT_ALLOW_SIGNING_FLAG) {
		keyOps[index] = _strdup(sign_op);
		if (keyOps[index] == NULL) {
			status = NTE_NO_MEMORY;
			goto cleanup;
		}
		index++;
		keyOps[index] = _strdup(verify_op);
		if (keyOps[index] == NULL) {
			status = NTE_NO_MEMORY;
			goto cleanup;
		}
		index++;
	}
	if ((keyUsage & NCRYPT_ALLOW_ALL_USAGES) == NCRYPT_ALLOW_ALL_USAGES){
		keyOps[index] = _strdup(wrapkey_op);
		if (keyOps[index] == NULL) {
			status = NTE_NO_MEMORY;
			goto cleanup;
		}
		index++;
		keyOps[index] = _strdup(unwrapKey_op);
		if (keyOps[index] == NULL) {
			status = NTE_NO_MEMORY;
			goto cleanup;
		}
		index++;
	}
	return status;
cleanup:
	for (int i = 0; i < index; i++) {
		if (keyOps[i] != NULL) {
			free(keyOps[i]);
		}
	}
	return status;
}
#endif