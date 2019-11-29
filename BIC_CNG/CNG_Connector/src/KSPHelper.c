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
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <intsafe.h>
#include <strsafe.h>
#include "KSP.h"

///////////////////////////////////////////////////////////////////////////////
//
// Forward declarations of local routines
//
///////////////////////////////////////////////////////////////////////////////

BCRYPT_RSAKEY_BLOB*
KspValidateRSACNGPrivateKey(
	__in_bcount(cbKeyBlob)  PBYTE pbKeyBlob,
	__in  DWORD cbKeyBlob);

///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION :     Convert NTSTATUS error code to SECURITY_STATUS error code
*
* INPUTS :
*            NTSTATUS NtStatus          Error code of NTSTATUS format
* RETURN :
*            SECURITY_STATUS            Converted error code
*/
SECURITY_STATUS
NormalizeNteStatus(
	__in NTSTATUS NtStatus)
{
	SECURITY_STATUS SecStatus;
	switch (NtStatus)
	{
	case STATUS_SUCCESS:
		SecStatus = ERROR_SUCCESS;
		break;

	case STATUS_NO_MEMORY:
	case STATUS_INSUFFICIENT_RESOURCES:
		SecStatus = NTE_NO_MEMORY;
		break;

	case STATUS_INVALID_PARAMETER:
		SecStatus = NTE_INVALID_PARAMETER;
		break;

	case STATUS_INVALID_HANDLE:
		SecStatus = NTE_INVALID_HANDLE;
		break;

	case STATUS_BUFFER_TOO_SMALL:
		SecStatus = NTE_BUFFER_TOO_SMALL;
		break;

	case STATUS_NOT_SUPPORTED:
		SecStatus = NTE_NOT_SUPPORTED;
		break;

	case STATUS_INTERNAL_ERROR:
	case ERROR_INTERNAL_ERROR:
		SecStatus = NTE_INTERNAL_ERROR;
		break;

	case STATUS_INVALID_SIGNATURE:
		SecStatus = NTE_BAD_SIGNATURE;
		break;

	case STATUS_LOGON_FAILURE:
		SecStatus = NTE_INCORRECT_PASSWORD;
		break;
	case STATUS_DECRYPTION_FAILED:
		SecStatus = NTE_DECRYPTION_FAILURE;
		break;
	case STATUS_DEVICE_REMOVED:
		SecStatus = NTE_DEVICE_NOT_FOUND;
		break;
	case STATUS_DEVICE_UNREACHABLE:
		SecStatus = NTE_DEVICE_NOT_READY;
		break;
	case STATUS_INVALID_TOKEN:
		SecStatus = NTE_PERM;
		break;
	case STATUS_NO_MORE_ENTRIES:
		SecStatus = NTE_NO_MORE_ITEMS;
		break;
	default:
		SecStatus = NTE_INTERNAL_ERROR;
		break;
	}

	return SecStatus;
}

///////////////////////////////////////////////////////////////////////////////
/*****************************************************************************
* DESCRIPTION :    Validate KSP provider handle
*
* INPUTS :
*           NCRYPT_PROV_HANDLE hProvider                A NCRYPT_PROV_HANDLE handle
*
* RETURN :
*           A pointer to a KSP_PROVIDER struct    The function was successful.
*           NULL                                        The handle is invalid.
*/
KSP_PROVIDER *
KspValidateProvHandle(
	__in    NCRYPT_PROV_HANDLE hProvider)
{
	KSP_PROVIDER *pProvider = NULL;

	if (hProvider == 0)
	{
		return NULL;
	}

	pProvider = (KSP_PROVIDER *)hProvider;

	if (pProvider->cbLength < sizeof(KSP_PROVIDER) ||
		pProvider->dwMagic != KSP_PROVIDER_MAGIC)
	{
		return NULL;
	}

	return pProvider;
}

/*****************************************************************************
* DESCRIPTION :    Validate KSP key handle
*
* INPUTS :
*           NCRYPT_KEY_HANDLE hKey                 An NCRYPT_KEY_HANDLE handle
*
* RETURN :
*           A pointer to a KSP_KEY struct    The function was successful.
*           NULL                                   The handle is invalid.
*/
KSP_KEY *
KspValidateKeyHandle(
	__in    NCRYPT_KEY_HANDLE hKey)
{
	KSP_KEY *pKey = NULL;

	if (hKey == 0)
	{
		return NULL;
	}

	pKey = (KSP_KEY *)hKey;

	if (pKey->cbLength < sizeof(KSP_KEY) ||
		pKey->dwMagic != KSP_KEY_MAGIC)
	{
		return NULL;
	}

	return pKey;
}

/*****************************************************************************
* DESCRIPTION :    Validate a CNG Key Blob
*
* INPUTS :
*          PBYTE pbKeyBlob               A CNG key Blob
*
* RETURN :
*          A pointer to a BCRYPT_RSAKEY_BLOB struct    The function was successful.
*          NULL                                        The handle is not a valid
*                                                      CNG RSA private key blob.
*/
BCRYPT_RSAKEY_BLOB*
KspValidateRSACNGPrivateKey(
	__in_bcount(cbKeyBlob)
	PBYTE pbKeyBlob,
	__in  DWORD cbKeyBlob)
{
	DWORD    cbCount = 0;
	BCRYPT_RSAKEY_BLOB* rsaCNGKeyBlob = NULL;

	if (pbKeyBlob == 0)
	{
		return NULL;
	}

	if (cbKeyBlob < sizeof(BCRYPT_RSAKEY_BLOB))
	{
		return NULL;
	}

	rsaCNGKeyBlob = (BCRYPT_RSAKEY_BLOB*)pbKeyBlob;

	if ((rsaCNGKeyBlob->Magic != BCRYPT_RSAPRIVATE_MAGIC &&
		rsaCNGKeyBlob->Magic != BCRYPT_RSAFULLPRIVATE_MAGIC) ||
		rsaCNGKeyBlob->BitLength < KSP_RSA_MIN_LENGTH ||
		rsaCNGKeyBlob->BitLength > KSP_RSA_MAX_LENGTH ||
		rsaCNGKeyBlob->BitLength % KSP_RSA_INCREMENT != 0)
	{
		return NULL;
	}

	if (ULongAdd(rsaCNGKeyBlob->cbModulus, rsaCNGKeyBlob->cbPrime1, &cbCount) != S_OK ||
		ULongAdd(cbCount, rsaCNGKeyBlob->cbPrime2, &cbCount) != S_OK ||
		ULongAdd(cbCount, rsaCNGKeyBlob->cbPublicExp, &cbCount) != S_OK)
	{
		return NULL;
	}

	if (rsaCNGKeyBlob->Magic == BCRYPT_RSAFULLPRIVATE_MAGIC)
	{
		if (ULongAdd(cbCount, rsaCNGKeyBlob->cbPrime1 * 2, &cbCount) != S_OK ||
			ULongAdd(cbCount, rsaCNGKeyBlob->cbPrime2, &cbCount) != S_OK ||
			ULongAdd(cbCount, rsaCNGKeyBlob->cbModulus, &cbCount) != S_OK)
		{
			return NULL;
		}
	}
	if (cbKeyBlob < cbCount)
	{
		return NULL;
	}

	return rsaCNGKeyBlob;

}

/******************************************************************************
*
* DESCRIPTION : Protect the plain text private key and attach it to the key
*               object.
*
* INPUTS :
*               LPCWSTR pszBlobType    Type of the key blob
*               PBYTE  pbInput         CNG RSA private key blob
*               DWORD  cbInput         Length of the key blob
*               KSP_KEY* pKey          KSP key handle
* OUTPUTS :
*               KSP_KEY* pKey          KSP key handle with private key
*                                      attached.
* RETURN :
*               ERROR_SUCCESS          The function was successful.
*               NTE_BAD_DATA           The key blob is not valid.
*               NTE_NO_MEMORY          A memory allocation failure occurred.
*               HRESULT                Error information returned by CryptProtectData
*/
SECURITY_STATUS
ProtectAndSetPrivateKey(
	__in LPCWSTR pszBlobType,
	__in_bcount(cbKeyBlob)
	PBYTE  pbKeyBlob,
	__in DWORD  cbKeyBlob,
	__inout KSP_KEY* pKey)
{
	DATA_BLOB DataIn = { 0 };
	DATA_BLOB DataOut = { 0 };
	BCRYPT_RSAKEY_BLOB* rsaKeyBlob = NULL;
	SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

	//Validate the blob.
	rsaKeyBlob = KspValidateRSACNGPrivateKey(pbKeyBlob, cbKeyBlob);
	if (rsaKeyBlob == NULL)
	{
		Status = NTE_BAD_KEY;
		goto cleanup;
	}

	//Set the key length.
	pKey->dwKeyBitLength = rsaKeyBlob->BitLength;
	//Set the key type.
	/*if (wcscmp(pszBlobType, BCRYPT_PRIVATE_KEY_BLOB) == 0)
	{
		pKey->pszKeyBlobType = BCRYPT_RSAPRIVATE_BLOB;

	}
	else
	{
		pKey->pszKeyBlobType = (LPWSTR)pszBlobType;
	}*/

	//Encrypt the private key blob
	DataIn.pbData = pbKeyBlob;
	DataIn.cbData = cbKeyBlob;
	if (!CryptProtectData(
		&DataIn,
		L"Private Key",
		NULL,
		NULL,
		NULL,
		CRYPTPROTECT_UI_FORBIDDEN,
		&DataOut
	))
	{
		Status = NTE_INTERNAL_ERROR;
		goto cleanup;
	}

	//// Attach the blob to the key object. It will be processed further
	//// once the key is finalized.
	//if (pKey->pbPrivateKey)
	//{   //If there is already a private key attached to the key object,
	//	//clean the old key.
	//	SecureZeroMemory(pKey->pbPrivateKey, pKey->cbPrivateKey);
	//	HeapFree(GetProcessHeap(), 0, pKey->pbPrivateKey);
	//}

	//pKey->pbPrivateKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, DataOut.cbData);

	//if (pKey->pbPrivateKey == NULL)
	//{
	//	Status = NTE_NO_MEMORY;
	//	goto cleanup;
	//}

	//CopyMemory(pKey->pbPrivateKey, DataOut.pbData, DataOut.cbData);
	//pKey->cbPrivateKey = DataOut.cbData;
	Status = ERROR_SUCCESS;
cleanup:
	if (DataOut.pbData)
	{
		LocalFree(DataOut.pbData);
	}
	return Status;
}


///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION : Helper function that removes the memory buffer from the
*               KSP's list of allocated memory buffers, and returns
*               the buffer so it can be freed. (This function does not free
*               the buffer's memory from the heap.)
* INPUTS :
*               LIST_ENTRY *pBufferList  The list head.
				PVOID pvBuffer           The buffer to remove from the list.
* RETURN :
*               KSP_MEMORY_BUFFER  The memory buffer found.
*               NULL                     There is no such buffer in the list.
*/
KSP_MEMORY_BUFFER *
RemoveMemoryBuffer(
	__in LIST_ENTRY *pBufferList,
	__in PVOID pvBuffer)
{
	PLIST_ENTRY pList = { 0 };
	KSP_MEMORY_BUFFER *pBuffer = NULL;
	BOOL fFound = FALSE;

	pList = pBufferList->Flink;

	while (pList != pBufferList)
	{
		pBuffer = CONTAINING_RECORD(pList, KSP_MEMORY_BUFFER, List.Flink);
		pList = pList->Flink;

		if (pBuffer->pvBuffer == pvBuffer)
		{
			RemoveEntryList(&pBuffer->List);
			fFound = TRUE;
			break;
		}
	}

	if (fFound)
	{
		return pBuffer;
	}
	else
	{
		return NULL;
	}
}

/******************************************************************************
*
* DESCRIPTION : Lookup the buffer in the allocated KSP memory buffer
*               list.
*
* INPUTS :
*               LIST_ENTRY *pBufferList  The list head.
				PVOID pvBuffer           The buffer to look for.
* RETURN :
*               KSP_MEMORY_BUFFER  The memory buffer found.
*               NULL                     There is no such buffer in the list.
*/
KSP_MEMORY_BUFFER *
LookupMemoryBuffer(
	__in LIST_ENTRY *pBufferList,
	__in PVOID pvBuffer)
{
	PLIST_ENTRY pList = { 0 };
	KSP_MEMORY_BUFFER *pBuffer = NULL;
	BOOL fFound = FALSE;


	pList = pBufferList->Flink;

	while (pList != pBufferList)
	{
		pBuffer = CONTAINING_RECORD(pList, KSP_MEMORY_BUFFER, List.Flink);
		pList = pList->Flink;

		if (pBuffer->pvBuffer == pvBuffer)
		{
			fFound = TRUE;
			break;
		}
	}


	if (fFound)
	{
		return pBuffer;
	}
	else
	{
		return NULL;
	}

}

///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION : Creates a new KSP key object.
*
* INPUTS :
*               LPCWSTR                Name of the key (keyfile)
* OUTPUTS :
*               KSP_KEY* pKey    New KSP key object
* RETURN :
*               ERROR_SUCCESS          The function was successful.
*               NTE_BAD_DATA           The key blob is not valid.
*               NTE_NO_MEMORY          A memory allocation failure occurred.
*               HRESULT                Error information returned by CryptProtectData.
*/
SECURITY_STATUS
WINAPI
CreateNewKeyObject(
	__in_opt LPCWSTR pszKeyName,
	__deref_out KSP_KEY **ppKey)
{
	KSP_KEY *pKey = NULL;
	DWORD   cbKeyName = 0;
	SECURITY_STATUS   Status = NTE_INTERNAL_ERROR;

	//Initialize the key object.
	pKey = (KSP_KEY *)HeapAlloc(GetProcessHeap(), 0, sizeof(KSP_KEY));
	if (pKey == NULL)
	{
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}
	SecureZeroMemory(pKey, sizeof(KSP_KEY));
	pKey->cbLength = sizeof(KSP_KEY);
	pKey->dwMagic = KSP_KEY_MAGIC;
	pKey->dwAlgID = KSP_RSA_ALGID;
	pKey->dwKeyBitLength = 0;
	pKey->fFinished = FALSE;

	//Copy the keyname into the key struct.
	if (pszKeyName != NULL)
	{
		cbKeyName = (DWORD)(wcslen(pszKeyName) + 1) * sizeof(WCHAR);
		if (cbKeyName > MAX_PATH)
		{
			Status = NTE_INVALID_PARAMETER;
			goto cleanup;
		}
		//cbKeyName = cbKeyName * sizeof(WCHAR);  //TODO: the count bytes is multiplied two times by sizeof(WCHAR)
		pKey->pszKeyName = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, cbKeyName);
		if (pKey->pszKeyName == NULL)
		{
			Status = NTE_NO_MEMORY;
			goto cleanup;
		}
		CopyMemory(pKey->pszKeyName, pszKeyName, cbKeyName);
	}
	else
	{
		pKey->pszKeyName = NULL;
	}


	//Initialize the property list.
	InitializeListHead(&pKey->PropertyList);

	//Security descriptor creation
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD szPSD= 0;
	Status = CreateSecurityDescriptor(pKey, 0, &pSD, &szPSD);

	pKey->cbSecurityDescr = szPSD;
	pKey->pbSecurityDescr = pSD;
	
	
	*ppKey = pKey;
	pKey = NULL;
	Status = ERROR_SUCCESS;

cleanup:
	if (pKey != NULL)
	{
		DeleteKeyObject(pKey);
	}
	return Status;
}


/******************************************************************************
*
* DESCRIPTION : Deletes the passed key object from memory.
*
* INPUTS :
*               KSP_KEY *pKey    The key object to delete.
* RETURN :
*               ERROR_SUCCESS          The function was successful.
*/
SECURITY_STATUS
WINAPI
DeleteKeyObject(
	__inout KSP_KEY *pKey)
{
	PLIST_ENTRY pList = { 0 };
	KSP_PROPERTY *pProperty = NULL;
	SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
	if (pKey == NULL) return Status;
	//Delete the key name.
	if (pKey->pszKeyName) {
		HeapFree(GetProcessHeap(), 0, pKey->pszKeyName);
		pKey->pszKeyName = NULL;
	}
	//Delete security descriptor.

	if (pKey->pbSecurityDescr) {
		LocalFree(pKey->cbSecurityDescr);
		pKey->pbSecurityDescr = NULL;
	}
	//Delete the property list.
	pList = pKey->PropertyList.Flink;
	while (pList != &pKey->PropertyList)
	{
		pProperty = CONTAINING_RECORD(
			pList,
			KSP_PROPERTY,
			ListEntry.Flink);
		pList = pList->Flink;
		RemoveEntryList(&pProperty->ListEntry);
		HeapFree(GetProcessHeap(), 0, pProperty);
	}

	if (pKey->pbPubKeyInfo) {
		HeapFree(GetProcessHeap(), 0, pKey->pbPubKeyInfo); //TODO: ?? Add pKey->pbPubKeyInfo = NULL;
	}

	HeapFree(GetProcessHeap(), 0, pKey);
	pKey = NULL;
	
	Status = ERROR_SUCCESS;
	////Delete public key handle.
	//if (pKey->hPublicKey)
	//{
	//	ntStatus = BCryptDestroyKey(pKey->hPublicKey);
	//	if (!NT_SUCCESS(ntStatus))
	//	{
	//		Status = NormalizeNteStatus(ntStatus);
	//	}
	//	pKey->hPublicKey = NULL;
	//}
	////Delete private key handle.
	//if (pKey->hPrivateKey)
	//{
	//	ntStatus = BCryptDestroyKey(pKey->hPrivateKey);
	//	if (!NT_SUCCESS(ntStatus))
	//	{
	//		Status = NormalizeNteStatus(ntStatus);
	//	}
	//	pKey->hPrivateKey = NULL;
	//}
	////Delete private key blob.
	//if (pKey->pbPrivateKey)
	//{
	//	SecureZeroMemory(pKey->pbPrivateKey, pKey->cbPrivateKey);
	//	HeapFree(GetProcessHeap(), 0, pKey->pbPrivateKey);
	//	pKey->pbPrivateKey = NULL;
	//}

	

	return Status;
}

///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION : Create a new property object
*
* INPUTS :
*           LPCWSTR pszProperty     Name of the property
*           PBYTE   pbProperty      Value of the property
*           DWORD   cbProperty      Length of the property
*           DWORD   dwFlags         Persisted property or not
* OUTPUTS:
*           KSP_PROPERTY    **ppProperty   The new property object
* RETURN :
*           ERROR_SUCCESS          The function was successful.
*           NTE_NO_MEMORY          A memory allocation failure occurred.
*           NTE_INVALID_PARAMETER  Invalid parameter
*/
SECURITY_STATUS
CreateNewProperty(
	__in_opt                LPCWSTR pszProperty,
	__in_bcount(cbProperty) PBYTE   pbProperty,
	__in                    DWORD   cbProperty,
	__in                    DWORD   dwFlags,
	__deref_out             KSP_PROPERTY    **ppProperty)
{
	KSP_PROPERTY *pProperty = NULL;
	SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

	pProperty = (KSP_PROPERTY *)HeapAlloc(
		GetProcessHeap(),
		0,
		sizeof(KSP_PROPERTY) + cbProperty);
	if (pProperty == NULL)
	{
		return NTE_NO_MEMORY;
	}

	//Copy the property name.
	Status = StringCchCopyW(pProperty->szName,
		sizeof(pProperty->szName) / sizeof(WCHAR),
		pszProperty);
	if (Status != ERROR_SUCCESS)
	{
		HeapFree(GetProcessHeap(), 0, pProperty);
		return NTE_INVALID_PARAMETER;
	}

	pProperty->cbPropertyData = cbProperty;

	if (dwFlags & NCRYPT_PERSIST_ONLY_FLAG)
	{
		pProperty->fBuildin = FALSE;
	}
	else
	{
		pProperty->fBuildin = TRUE;
	}

	if (dwFlags & (NCRYPT_PERSIST_FLAG | NCRYPT_PERSIST_ONLY_FLAG))
	{
		//Persisted property.
		pProperty->fPersisted = TRUE;
	}
	else
	{   //Non-persisted property.
		pProperty->fPersisted = FALSE;
	}
	//Copy the property value.
	CopyMemory((PBYTE)(pProperty + 1), pbProperty, cbProperty);

	*ppProperty = pProperty;

	return ERROR_SUCCESS;
}

/******************************************************************************
*
* DESCRIPTION : Look for property object in the property list of the key.
*
* INPUTS :
*            KSP_KEY *pKey    Key object
*            LPCWSTR pszProperty,   Name of the property
* OUTPUTS:
*           KSP_PROPERTY    **ppProperty   The property object found
* RETURN :
*           ERROR_SUCCESS          The function was successful.
*           NTE_NOT_FOUND          No such property exists.
*/
SECURITY_STATUS
LookupExistingKeyProperty(
	__in    KSP_KEY *pKey,
	__in    LPCWSTR pszProperty,
	__out   KSP_PROPERTY **ppProperty)
{
	PLIST_ENTRY pList;
	KSP_PROPERTY *pProperty;

	pList = pKey->PropertyList.Flink;

	while (pList != &pKey->PropertyList)
	{
		pProperty = CONTAINING_RECORD(pList, KSP_PROPERTY, ListEntry.Flink);
		pList = pList->Flink;

		if (wcscmp(pszProperty, pProperty->szName) == 0)
		{
			*ppProperty = pProperty;
			return ERROR_SUCCESS;
		}
	}

	return NTE_NOT_FOUND;
}


/******************************************************************************
*
* DESCRIPTION : Set a nonpersistent property on the key object.
*
* INPUTS :
*           KSP_KEY *pKey    Key object
*           LPCWSTR pszProperty    Name of the property
*           PBYTE    pbInput       Value of the property
*           DWORD    cbInput       Length of the property value buffer
*           DWORD*   dwFlags       Flags
* OUTPUTS:
*           DWORD*   dwFlags       Whether the property should also be persisted
* RETURN :
*           ERROR_SUCCESS          The function was successful.
*           NTE_BAD_DATA           The property value is invalid.
*           NTE_BAD_KEY_STATE      The key is already written to the file system.
*           NTE_NOT_SUPPORTED      The operation is not supported.
*           NTE_NO_MEMORY          A memory allocation failure occurred.
*/
SECURITY_STATUS
SetBuildinKeyProperty(
	__inout    KSP_KEY           *pKey,
	__in    LPCWSTR pszProperty,
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__inout    DWORD*   dwFlags)
{
	SECURITY_STATUS         Status = NTE_INTERNAL_ERROR;
	NTSTATUS                NtStatus = STATUS_INTERNAL_ERROR;
	DWORD                   dwPolicy = 0;
	LPCWSTR                 pszTmpProperty = pszProperty;
	DWORD                   dwTempFlags = *dwFlags;

	if (wcscmp(pszTmpProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
	{
		if (cbInput != sizeof(DWORD))
		{
			Status = NTE_BAD_DATA;
			goto cleanup;
		}
		if (pKey->fFinished == TRUE)
		{
			// This property can only be set before the key is written
			// to the file system.
			Status = NTE_BAD_KEY_STATE;
			goto cleanup;
		}

		dwPolicy = *(DWORD *)pbInput;

		if ((dwPolicy & ~(NCRYPT_ALLOW_EXPORT_FLAG |
			NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG |
			NCRYPT_ALLOW_ARCHIVING_FLAG |
			NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG)) != 0)
		{
			// Only support the listed set of policy flags.
			Status = NTE_NOT_SUPPORTED;
			goto cleanup;
		}

		pKey->dwExportPolicy = dwPolicy;

		// Allow this copy of the key to be exported if one of the
		// archive flags is set.
		if ((dwPolicy & NCRYPT_ALLOW_ARCHIVING_FLAG) != 0)
		{
			pKey->dwExportPolicy |= NCRYPT_ALLOW_EXPORT_FLAG;
		}
		if ((dwPolicy & NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG) != 0)
		{
			pKey->dwExportPolicy |= NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
		}

		// Clear the archive flags so that they don't get stored to disk.
		dwPolicy &= ~(NCRYPT_ALLOW_ARCHIVING_FLAG | NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG);
		//This property should be persistent and needs to be written back to the
		//file system.
		dwTempFlags |= NCRYPT_PERSIST_FLAG;

	}
	else if (wcscmp(pszTmpProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
	{
		if (cbInput != sizeof(DWORD))
		{
			Status = NTE_BAD_DATA;
			goto cleanup;
		}

		if (pKey->fFinished == TRUE)
		{
			// This property can only be set before the key is finalized.
			Status = NTE_BAD_KEY_STATE;
			goto cleanup;
		}

		pKey->dwKeyUsagePolicy = *(DWORD *)pbInput;

		//This property should be persistent and needs to be written back to the
		//file system.
		dwTempFlags |= NCRYPT_PERSIST_FLAG;
	}
	else if (wcscmp(pszTmpProperty, NCRYPT_LENGTH_PROPERTY) == 0)
	{
		if (cbInput != sizeof(DWORD))
		{
			Status = NTE_BAD_DATA;
			goto cleanup;
		}
		if (pKey->fFinished == TRUE)
		{
			// This property can only be set before the key is finalized.
			Status = NTE_BAD_KEY_STATE;
			goto cleanup;
		}

		pKey->dwKeyBitLength = *(DWORD *)pbInput;
		// Make sure that the specified length is one that we support.
		if (pKey->dwKeyBitLength < KSP_RSA_MIN_LENGTH ||
			pKey->dwKeyBitLength > KSP_RSA_MAX_LENGTH ||
			pKey->dwKeyBitLength % KSP_RSA_INCREMENT)
		{
			Status = NTE_NOT_SUPPORTED;
			goto cleanup;
		}

		// Key length is not persisted, and clear the persisted
		// flag if it's set.
		dwTempFlags &= ~NCRYPT_PERSIST_FLAG;

		//Update the property of the private key.
	/*	NtStatus = BCryptSetProperty(
			pKey->hPrivateKey,
			BCRYPT_KEY_LENGTH,
			pbInput,
			cbInput,
			0);
		if (!NT_SUCCESS(NtStatus))
		{
			Status = NormalizeNteStatus(NtStatus);
			goto cleanup;
		}*/

	}
	else if (wcscmp(pszTmpProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
	{
		if ((cbInput == 0) ||
			(!IsValidSecurityDescriptor(pbInput)) ||
			(GetSecurityDescriptorLength(pbInput) > cbInput))
		{
			Status = NTE_BAD_DATA;
			goto cleanup;
		}

		pKey->dwSecurityFlags = dwTempFlags;

		if (pKey->pbSecurityDescr)
		{
			HeapFree(GetProcessHeap(), 0, pKey->pbSecurityDescr);
		}

		pKey->pbSecurityDescr = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbInput);
		if (pKey->pbSecurityDescr == NULL)
		{
			Status = NTE_NO_MEMORY;
			goto cleanup;
		}

		pKey->cbSecurityDescr = cbInput;
		CopyMemory(pKey->pbSecurityDescr, pbInput, cbInput);

		// Security descriptor does not need to be saved into key file
		dwTempFlags &= ~NCRYPT_PERSIST_FLAG;

		// The key has been finalized, so write the file again so that
		// the new security descriptor is set it on the file.
		if (pKey->fFinished)
		{
			Status = WriteKeyToStore(pKey);
			if (Status != ERROR_SUCCESS)
			{
				goto cleanup;
			}
		}

	}
	else if (wcscmp(pszTmpProperty, BCRYPT_PRIVATE_KEY_BLOB) == 0)
	{
		BCRYPT_RSAKEY_BLOB*  keyBlob = (BCRYPT_RSAKEY_BLOB*)pbInput;
		LPWSTR           pszBlobType = NULL;

		if (pKey->fFinished == TRUE)
		{
			// This key has already been finalized.
			Status = NTE_BAD_KEY_STATE;
			goto cleanup;
		}

		if (keyBlob->Magic == BCRYPT_RSAPRIVATE_MAGIC)
		{
			pszBlobType = BCRYPT_RSAPRIVATE_BLOB;
		}
		else if (keyBlob->Magic == BCRYPT_RSAFULLPRIVATE_MAGIC)
		{
			pszBlobType = BCRYPT_RSAFULLPRIVATE_BLOB;
		}
		else
		{
			Status = NTE_BAD_DATA;
			goto cleanup;
		}

		// Private key is not a persisted property.
		// The key will be stored when NCryptFinalizeKey is called.
		dwTempFlags &= ~NCRYPT_PERSIST_FLAG;

		// Set the private key blob, key length and key type.
		Status = ProtectAndSetPrivateKey(
			(LPCWSTR)pszBlobType,
			pbInput,
			cbInput,
			pKey);
		if (Status != ERROR_SUCCESS)
		{
			goto cleanup;
		}
	}
	else if (wcscmp(pszTmpProperty, NCRYPT_WINDOW_HANDLE_PROPERTY) == 0 ||
		wcscmp(pszTmpProperty, NCRYPT_UI_POLICY_PROPERTY) == 0 ||
		wcscmp(pszTmpProperty, NCRYPT_USE_CONTEXT_PROPERTY) == 0)
	{
		// Although implementation is not demonstrated by this KSP,
		// these properties are required to support certificate enrollment
		// scenarios.  Production KSPs that need to support certificate
		// enrollment must add handling for these properties.
		Status = ERROR_SUCCESS;
		goto cleanup;
	}
	else
	{
		Status = NTE_NOT_SUPPORTED;
		goto cleanup;
	}

	Status = ERROR_SUCCESS;
cleanup:
	*dwFlags = dwTempFlags;
	return Status;
}


///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION : Transform the KSP algorithm identifier into BCRYPT nomenclature.
*
* INPUT:
*           DWORD   dwAlgID  The KSP algorithm identifier
*
* OUTPUTS:
*          LPWSTR*  BCRYPT algorithm name
*
* RETURN :
*           ERROR_SUCCESS           The function was successful.
*           NTE_INVALID_PARAMETER   The key name parameter is invalid.
*/

SECURITY_STATUS
BcryptAlgorithmTranscriptor(
	__in DWORD dwAlgID,
	__out LPWSTR* pszKeyName)
{
	SECURITY_STATUS SecStatus = ERROR_SUCCESS;
	switch (dwAlgID)
	{
	case KSP_RSA_ALGID:
		*pszKeyName = BCRYPT_RSA_ALGORITHM;
		break;
	default:
		SecStatus = SecStatus = NTE_INTERNAL_ERROR;
	}
	return SecStatus;
}


void Error_Writter(struct context * context, SECURITY_STATUS cngError) {
	switch (cngError) {
	case ERROR_SUCCESS:
		strcpy(context->error, "ERROR_SUCCESS");
		return;
	case NTE_NO_MEMORY:
		strcpy(context->error, "NTE_NO_MEMORY");
		break;
	case NTE_INVALID_PARAMETER:
		strcpy(context->error, "NTE_INVALID_PARAMETER");
		break;
	case NTE_INVALID_HANDLE:
		strcpy(context->error, "NTE_INVALID_HANDLE");
		break;
	case NTE_BUFFER_TOO_SMALL:
		strcpy(context->error, "NTE_BUFFER_TOO_SMALL");
		break;
	case NTE_NOT_SUPPORTED:
		strcpy(context->error, "NTE_NOT_SUPPORTED");
		break;
	case NTE_INTERNAL_ERROR:
		strcpy(context->error, "NTE_INTERNAL_ERROR");
		break;
	case NTE_BAD_SIGNATURE:
		strcpy(context->error, "NTE_BAD_SIGNATURE");
		break;
	case NTE_INCORRECT_PASSWORD:
		strcpy(context->error, "NTE_INCORRECT_PASSWORD");
		break;
	case NTE_DECRYPTION_FAILURE:
		strcpy(context->error, "NTE_DECRYPTION_FAILURE");
		break;
	case NTE_DEVICE_NOT_FOUND:
		strcpy(context->error, "NTE_DEVICE_NOT_FOUND");
		break;
	case NTE_DEVICE_NOT_READY:
		strcpy(context->error, "NTE_DEVICE_NOT_READY");
		break;
	case NTE_PERM:
		strcpy(context->error, "NTE_PERM");
		break;
	case NTE_NO_MORE_ITEMS:
		strcpy(context->error, "NTE_NO_MORE_ITEMS");
		break;
	case NTE_EXISTS:
		strcpy(context->error, "NTE_EXISTS");
		break;
	case NTE_BAD_FLAGS:
		strcpy(context->error, "NTE_BAD_FLAGS");
		break;
	case NTE_BAD_KEY_STATE:
		strcpy(context->error, "NTE_BAD_KEY_STATE");
		break;
	case NTE_BAD_ALGID:
		strcpy(context->error, "NTE_BAD_ALGID");
		break;
	default:
		strcpy(context->error, "NTE_INTERNAL_ERROR");
		break;
	}
}
