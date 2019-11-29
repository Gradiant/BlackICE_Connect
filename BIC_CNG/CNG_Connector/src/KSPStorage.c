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
#include <Userenv.h>
#include <intsafe.h>
#include <strsafe.h>
#include <Aclapi.h>
#include <UserEnv.h>
#include "KSP.h"
#include <tchar.h>
#include "sddl.h"
#include <stdio.h>
#include <accctrl.h>
#include <assert.h>

/******************************************************************************
* DESCRIPTION : Remove the key file from the key storage.
*
* INPUTS:
*           KSP_KEY pKey         A handle to the key object.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  Deletion failed.
*/
SECURITY_STATUS
RemoveKeyFromStore(
	__in KSP_KEY *pKey)
{
	LPWSTR pszFilePath = NULL;
	DWORD dwReturn = 0;
	SECURITY_STATUS Status;
	
	Status = NTE_NOT_SUPPORTED;

	return Status;
}

/******************************************************************************
* DESCRIPTION : Write the key into key storage.
*
* INPUTS:
*           KSP_KEY *pKey         A handle to the key object.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  File operation failed.
*/
SECURITY_STATUS
WriteKeyToStore(
	__inout KSP_KEY *pKey
)
{
	SECURITY_STATUS Status;
	PBYTE pbPrivateKeyBlob = NULL;
	DWORD cbPrivateKeyBlob = 0;
	PBYTE pbKeyFile = NULL;
	DWORD cbKeyFile = 0;

	PSECURITY_DESCRIPTOR securityDescriptor = NULL;
	DWORD securityFlags = 0;
	Status = ERROR_SUCCESS; 

	return Status;
}

/******************************************************************************
* DESCRIPTION : Create new security descriptor on the key.
* INPUTS:
*           KSP_KEY *pKey         A handle to the key object.
*           DWORD   dwSecurityFlags     Flags
*
* OUTPUS:
*    PSECURITY_ATTRIBUTES *ppSecurityDescr  Security attributes on the key
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_INVALID_HANDLE  The key handle is invalid.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*/
SECURITY_STATUS
CreateSecurityDescriptor(__in    KSP_KEY *pKey,
	__in    DWORD   dwSecurityFlags,
	__out	PSECURITY_DESCRIPTOR *pSD,
	__out	DWORD *szPSD) {
	SECURITY_STATUS			 Status = NTE_INTERNAL_ERROR;
	PSECURITY_DESCRIPTOR     pSecurityDescriptor = NULL;
	PSID                     SystemSID = NULL;
	PSID                     EveryoneSID = NULL;
	PACL                     Dacl = NULL;
	UCHAR                    DaclBuffer[1024] = { 0 };
	SID_IDENTIFIER_AUTHORITY SIDAuthNt = SECURITY_NT_AUTHORITY;
	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
	DWORD                    Bytes = 0;
	DWORD					 Size = 0;
	PSECURITY_DESCRIPTOR	 SecurityDescriptorResult = NULL;

	//
	// Create a default security descriptor with system as the owner, system
	// as a the primary group, and a DACL that grants everyone full control
	//
	  // Initialize a security descriptor.  
	pSecurityDescriptor = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR,
		SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (NULL == pSecurityDescriptor) {
		Status = NTE_NO_MEMORY;
		goto Cleanup;
	}
	// Initialize the security descriptor
	if (!InitializeSecurityDescriptor(
		pSecurityDescriptor,
		SECURITY_DESCRIPTOR_REVISION)) {
		Status = NTE_INTERNAL_ERROR;
		goto Cleanup;
	}

	// Create the sytem SID for the security descriptor owner/group
	if (!AllocateAndInitializeSid(
		&SIDAuthNt,
		1,
		SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0,
		&SystemSID)) {
		Status = NTE_NO_MEMORY;
		goto Cleanup;
	}

	// Create the everyone SID
	if (!AllocateAndInitializeSid(
		&SIDAuthWorld,
		1,
		SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0,
		&EveryoneSID)) {
		Status = NTE_NO_MEMORY;
		goto Cleanup;
	}

	// Set the owner of the security descriptor to System.
	if (!SetSecurityDescriptorOwner(pSecurityDescriptor, SystemSID, TRUE)) {
		Status = NTE_INTERNAL_ERROR;
		goto Cleanup;
	}

	// Set the primary group to System.
	if (!SetSecurityDescriptorGroup(pSecurityDescriptor, SystemSID, TRUE)) {
		Status = NTE_INTERNAL_ERROR;
		goto Cleanup;
	}

	// Initialize the DACL
	Dacl = (PACL)DaclBuffer;
	if (!InitializeAcl(Dacl, ARRAYSIZE(DaclBuffer), ACL_REVISION)) {
		Status = NTE_INTERNAL_ERROR;
		goto Cleanup;
	}

	// Add an ACE to the DACL to grant everyone full control
	if (!AddAccessAllowedAce(Dacl, ACL_REVISION, KEY_ALL_ACCESS, EveryoneSID)) {
		Status = NTE_INTERNAL_ERROR;
		goto Cleanup;
	}

	// Now add the dACL to the security descriptor.
	if (!SetSecurityDescriptorDacl(pSecurityDescriptor, TRUE, Dacl, FALSE)) {
		Status = NTE_INTERNAL_ERROR;
		goto Cleanup;
	}

	
	//// Convert to a self relative security descriptor
	if (!MakeSelfRelativeSD(pSecurityDescriptor, NULL, &Size))
	{
		// First call to MakeSelfRelativeSD should return 
		// ERROR_INSUFFICIENT_BUFFER and set Size to the necessary buffer
		// length
		assert(GetLastError() == ERROR_INSUFFICIENT_BUFFER);

		SecurityDescriptorResult = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, Size);
		if (NULL == SecurityDescriptorResult)
		{
			Status = NTE_NO_MEMORY;
			goto Cleanup;
		}

		if (!MakeSelfRelativeSD(
			pSecurityDescriptor,
			SecurityDescriptorResult,
			&Size))
		{
			LocalFree(SecurityDescriptorResult);
			SecurityDescriptorResult = NULL;
			Status = NTE_INTERNAL_ERROR;
			goto Cleanup;
		}

		// We have successfully created a self-relative security descriptor 
		// with the Central Access Policy and resource attributes

	}
	else
	{
		SecurityDescriptorResult = NULL;
		Status = NTE_INTERNAL_ERROR;
		goto Cleanup;
	}
	*szPSD = Size;
	*pSD = SecurityDescriptorResult;
	Status = ERROR_SUCCESS;
Cleanup:
	if (EveryoneSID) {
		FreeSid(EveryoneSID);
	}
	if (SystemSID) {
		FreeSid(SystemSID);
	}
	if (pSecurityDescriptor) {
		LocalFree(pSecurityDescriptor);
	}
	return Status;
}