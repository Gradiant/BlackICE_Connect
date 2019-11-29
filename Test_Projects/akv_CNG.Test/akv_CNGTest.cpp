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

#include "CppUnitTest.h"

extern "C" {
#include "KSPConfig.h"
}

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace akv_CNGTest
{
	TEST_CLASS(UnitTest1) {
public:
	TEST_METHOD(Enumerate_Provider_Provider_Registered_Test) {
		NTSTATUS		ntStatus = STATUS_SUCCESS;
		unsigned long	numProv = 0;

		ntStatus = EnumerateProviders(&numProv, GRADIANT_KSP_PROVIDER_NAME);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enumeration error");
		Assert::IsTrue(numProv > 0, L"Windows CNG registre providers are 0");
	}
	TEST_METHOD(Open_Provider) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider;
		DWORD				dwFlags = 0;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
	}
	TEST_METHOD(Open_Bad_Provider) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider;
		DWORD				dwFlags = 0;

		ntStatus = NCryptOpenStorageProvider(&phProvider, L"Not Existing Provider", dwFlags);
		Assert::AreEqual(STATUS_NOT_FOUND, ntStatus, L"Bad provider error");
	}
	TEST_METHOD(Free_Open_Provider) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider;
		DWORD				dwFlags = 0;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
	}
	TEST_METHOD(Free_Not_Open_Provider) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider = 0;

		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(NTE_INVALID_HANDLE, ntStatus, L"Free not open provider error");
	}
	TEST_METHOD(Free_Bad_Handler_Provider) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	*phProvider;

		phProvider = (NCRYPT_PROV_HANDLE*)HeapAlloc(GetProcessHeap(), 0, 50);
		Assert::AreNotEqual((NCRYPT_PROV_HANDLE *)NULL, phProvider, L"No memory");
		ntStatus = NCryptFreeObject((NCRYPT_PROV_HANDLE)phProvider);
		HeapFree(GetProcessHeap(), 0, phProvider);
		Assert::AreEqual(NTE_INVALID_HANDLE, ntStatus, L"Free not open provider error");
	}
	TEST_METHOD(Enum_First_Key) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider = 0;
		DWORD				dwFlags = 0;
		NCryptKeyName		*ppKeyName = NULL;
		void				*ppEnumState = NULL;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
	}
	TEST_METHOD(Enum_All_Keys) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider = 0;
		DWORD				dwFlags = 0;
		NCryptKeyName		*ppKeyName = NULL;
		void				*ppEnumState = NULL;
		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		while (ntStatus != NTE_NO_MORE_ITEMS) {
			
			ntStatus = NCryptEnumKeys(
				phProvider,
				NULL,
				&ppKeyName,
				&ppEnumState,
				dwFlags
			);
		}
		Assert::AreEqual(NTE_NO_MORE_ITEMS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
	}
	TEST_METHOD(Free_Enum_Keys_Name) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider = 0;
		DWORD				dwFlags = 0;
		NCryptKeyName		*ppKeyName = NULL;
		void				*ppEnumState = NULL;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptFreeBuffer(
			ppKeyName
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
	}
	TEST_METHOD(Free_Enum_Keys_Buffer) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider = 0;
		DWORD				dwFlags = 0;
		NCryptKeyName		*ppKeyName = NULL;
		void				*ppEnumState = NULL;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptFreeBuffer(
			ppEnumState
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
	}
	TEST_METHOD(Free_Enum_Buffer_All_Keys) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider = 0;
		DWORD				dwFlags = 0;
		NCryptKeyName		*ppKeyName = NULL;
		PVOID				ppEnumState = NULL;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		while (ntStatus != NTE_NO_MORE_ITEMS) {
			ntStatus = NCryptEnumKeys(
				phProvider,
				NULL,
				&ppKeyName,
				&ppEnumState,
				dwFlags
			);
		}
		Assert::AreEqual(NTE_NO_MORE_ITEMS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptFreeBuffer(
			ppEnumState
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
	}
	TEST_METHOD(Free_Bad_Enum_Keys_Buffer) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider = 0;
		DWORD				dwFlags = 0;
		NCryptKeyName		*ppKeyName = NULL;
		void				*ppEnumState = NULL;

		ppEnumState = (void*)HeapAlloc(GetProcessHeap(), 0, 50);
		Assert::AreNotEqual((void *)NULL, ppEnumState, L"No memory");
		ntStatus = NCryptFreeBuffer(ppEnumState);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
	}
	TEST_METHOD(Free_Null_Enum_Keys_Buffer) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider = 0;
		DWORD				dwFlags = 0;
		NCryptKeyName		*ppKeyName = NULL;
		void				*ppEnumState = NULL;

		ntStatus = NCryptFreeBuffer(ppEnumState);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
	}
	TEST_METHOD(Sign_Hash) {
		NTSTATUS					ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE			phProvider = 0;
		DWORD						dwFlags = 0;
		NCryptKeyName				*ppKeyName = NULL;
		void						*ppEnumState = NULL;
		char						sha256[] = "9437086A7EEF592F3F2373AFD9158A7D2F0EF64AF5E2E64F7B58AE8A1A113F92", *pos = sha256;
		NCRYPT_KEY_HANDLE			phKey = NULL;
		PBYTE						pbSignature;
		DWORD						dwSigLen = 0;
		DWORD						pcbResult;
		BCRYPT_PKCS1_PADDING_INFO	paddingInfo;
		unsigned char		sha256Bytes[32];
		for (size_t count = 0; count < sizeof sha256Bytes / sizeof *sha256Bytes; count++) {
			sscanf(pos, "%2hhx", &sha256Bytes[count]);
			pos += 2;
		}


		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptOpenKey(
			phProvider,
			&phKey,
			ppKeyName->pszName,
			0,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		//-------------------------------------------------------------------
		// Determine the size of the signature and allocate memory.
		paddingInfo.pszAlgId = TEXT(szOID_RSA_SHA256RSA);
		ntStatus = NCryptSignHash(
			phKey,
			&paddingInfo,
			sha256Bytes,
			32,
			NULL,
			0,
			&pcbResult,
			BCRYPT_PAD_PKCS1
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Sign hash error");
		//-------------------------------------------------------------------
		// Allocate memory for the signature buffer.

		pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pcbResult);
		Assert::AreNotEqual((PBYTE)NULL, pbSignature, L"No memory");
		//-------------------------------------------------------------------
		// Sign the hash object.
		dwSigLen = pcbResult;
		ntStatus = NCryptSignHash(
			phKey,
			&paddingInfo,
			sha256Bytes,
			32,
			pbSignature,
			dwSigLen,
			&pcbResult,
			BCRYPT_PAD_PKCS1
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Sign hash error");
		HeapFree(GetProcessHeap(), 0, pbSignature);
		//-------------------------------------------------------------------
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
		ntStatus = NCryptFreeBuffer(ppEnumState);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
	}
	TEST_METHOD(Sign_Bad_Hash) {
		NTSTATUS					ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE			phProvider = 0;
		DWORD						dwFlags = 0;
		NCryptKeyName				*ppKeyName = NULL;
		void						*ppEnumState = NULL;
		char						sha256[] = "437086A7EEF592F3F2373AFD9158A7D2F0EF64AF5E2E64F7B58AE8A1A113F92", *pos = sha256;
		NCRYPT_KEY_HANDLE			phKey = NULL;
		PBYTE						pbSignature;
		DWORD						dwSigLen = 0;
		DWORD						pcbResult;
		BCRYPT_PKCS1_PADDING_INFO	paddingInfo;
		unsigned char		sha256Bytes[31];
		for (size_t count = 0; count < sizeof sha256Bytes / sizeof *sha256Bytes; count++) {
			sscanf(pos, "%2hhx", &sha256Bytes[count]);
			pos += 2;
		}


		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptOpenKey(
			phProvider,
			&phKey,
			ppKeyName->pszName,
			0,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		//-------------------------------------------------------------------
		// Determine the size of the signature and allocate memory.
		paddingInfo.pszAlgId = TEXT(szOID_RSA_SHA256RSA);
		ntStatus = NCryptSignHash(
			phKey,
			&paddingInfo,
			sha256Bytes,
			31,
			NULL,
			0,
			&pcbResult,
			BCRYPT_PAD_PKCS1
		);
		Assert::AreEqual(NTE_INVALID_PARAMETER, ntStatus, L"Sign hash error");
		//-------------------------------------------------------------------
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
		ntStatus = NCryptFreeBuffer(ppEnumState);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
	}
	TEST_METHOD(Sign_Not_Supported_Hash) {
		NTSTATUS					ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE			phProvider = 0;
		DWORD						dwFlags = 0;
		NCryptKeyName				*ppKeyName = NULL;
		void						*ppEnumState = NULL;
		char						sha256[] = "9437086A7EEF592F3F2373AFD9158A7D2F0EF64AF5E2E64F7B58AE8A1A113F92", *pos = sha256;
		NCRYPT_KEY_HANDLE			phKey = NULL;
		PBYTE						pbSignature;
		DWORD						dwSigLen = 0;
		DWORD						pcbResult;
		BCRYPT_PKCS1_PADDING_INFO	paddingInfo;
		unsigned char		sha256Bytes[32];
		for (size_t count = 0; count < sizeof sha256Bytes / sizeof *sha256Bytes; count++) {
			sscanf(pos, "%2hhx", &sha256Bytes[count]);
			pos += 2;
		}


		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptOpenKey(
			phProvider,
			&phKey,
			ppKeyName->pszName,
			0,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Oepn key error");
		//-------------------------------------------------------------------
		// Determine the size of the signature and allocate memory.
		paddingInfo.pszAlgId = TEXT(szOID_RSA_SHA1RSA);
		ntStatus = NCryptSignHash(
			phKey,
			&paddingInfo,
			sha256Bytes,
			32,
			NULL,
			0,
			&pcbResult,
			BCRYPT_PAD_PKCS1
		);
		Assert::AreEqual(NTE_BAD_ALGID, ntStatus, L"Sign hash error");
		//-------------------------------------------------------------------
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
		ntStatus = NCryptFreeBuffer(ppEnumState);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
	}
	TEST_METHOD(Verify_Hash) {
		NTSTATUS					ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE			phProvider = 0;
		DWORD						dwFlags = 0;
		NCryptKeyName				*ppKeyName = NULL;
		void						*ppEnumState = NULL;
		char						sha256[] = "9437086A7EEF592F3F2373AFD9158A7D2F0EF64AF5E2E64F7B58AE8A1A113F92", *pos = sha256;
		NCRYPT_KEY_HANDLE			phKey = NULL;
		PBYTE						pbSignature;
		DWORD						dwSigLen = 0;
		DWORD						pcbResult;
		BCRYPT_PKCS1_PADDING_INFO	paddingInfo;
		unsigned char		sha256Bytes[32];
		for (size_t count = 0; count < sizeof sha256Bytes / sizeof *sha256Bytes; count++) {
			sscanf(pos, "%2hhx", &sha256Bytes[count]);
			pos += 2;
		}


		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptOpenKey(
			phProvider,
			&phKey,
			ppKeyName->pszName,
			0,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		//-------------------------------------------------------------------
		// Determine the size of the signature and allocate memory.
		paddingInfo.pszAlgId = TEXT(szOID_RSA_SHA256RSA);
		ntStatus = NCryptSignHash(
			phKey,
			&paddingInfo,
			sha256Bytes,
			32,
			NULL,
			0,
			&pcbResult,
			BCRYPT_PAD_PKCS1
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Sign hash error");
		//-------------------------------------------------------------------
		// Allocate memory for the signature buffer.

		pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pcbResult);
		Assert::AreNotEqual((PBYTE)NULL, pbSignature, L"No memory");
		//-------------------------------------------------------------------
		// Sign the hash object.
		dwSigLen = pcbResult;
		ntStatus = NCryptSignHash(
			phKey,
			&paddingInfo,
			sha256Bytes,
			32,
			pbSignature,
			dwSigLen,
			&pcbResult,
			BCRYPT_PAD_PKCS1
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Sign hash error");
		//-------------------------------------------------------------------
		ntStatus = NCryptVerifySignature(
			phKey,
			&paddingInfo,
			sha256Bytes,
			32,
			pbSignature,
			dwSigLen,
			BCRYPT_PAD_PKCS1
		);
		HeapFree(GetProcessHeap(), 0, pbSignature);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Verify signature error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
		ntStatus = NCryptFreeBuffer(ppEnumState);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
	}
	TEST_METHOD(Export_PubKey) {
		NTSTATUS					ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE			phProvider = 0;
		DWORD						dwFlags = 0;
		NCryptKeyName				*ppKeyName = NULL;
		void						*ppEnumState = NULL;
		NCRYPT_KEY_HANDLE			phKey = NULL;
		DWORD						pcbResult;
		PBYTE						pbOutput;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptOpenKey(
			phProvider,
			&phKey,
			ppKeyName->pszName,
			0,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		//-------------------------------------------------------------------
		// Determine the size of the signature and allocate memory.
		ntStatus = NCryptExportKey(
			phKey,
			NULL,
			BCRYPT_RSAPUBLIC_BLOB,
			NULL,
			NULL,
			0,
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Sign hash error");
		//-------------------------------------------------------------------
		// Allocate memory for the signature buffer.

		pbOutput = (PBYTE)HeapAlloc(GetProcessHeap(), 0, pcbResult);
		Assert::AreNotEqual((PBYTE)NULL, pbOutput, L"No memory");
		//-------------------------------------------------------------------
		// Sign the hash object.
		ntStatus = NCryptExportKey(
			phKey,
			NULL,
			BCRYPT_RSAPUBLIC_BLOB,
			NULL,
			pbOutput,
			pcbResult,
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Sign hash error");
		HeapFree(GetProcessHeap(), 0, pbOutput);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Verify signature error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
		ntStatus = NCryptFreeBuffer(ppEnumState);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
	}
	TEST_METHOD(Free_Open_Key) {
		NTSTATUS					ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE			phProvider = NULL;
		DWORD						dwFlags = 0;
		NCryptKeyName				*ppKeyName = NULL;
		void						*ppEnumState = NULL;
		NCRYPT_KEY_HANDLE			phKey = NULL;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptOpenKey(
			phProvider,
			&phKey,
			ppKeyName->pszName,
			0,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		ntStatus = NCryptFreeObject(phKey);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free key error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
		ntStatus = NCryptFreeBuffer(ppEnumState);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
	}
	TEST_METHOD(Get_Key_Lenghts) {
		NTSTATUS					ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE			phProvider = NULL;
		DWORD						dwFlags = 0;
		NCryptKeyName				*ppKeyName = NULL;
		void						*ppEnumState = NULL;
		NCRYPT_KEY_HANDLE			phKey = NULL;
		DWORD						pcbResult;
		PBYTE						pbOutput = NULL;
		DWORD						cbOutput = 0;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		ntStatus = NCryptEnumKeys(
			phProvider,
			NULL,
			&ppKeyName,
			&ppEnumState,
			dwFlags
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptOpenKey(
			phProvider,
			&phKey,
			ppKeyName->pszName,
			0,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		ntStatus = NCryptGetProperty(
			phKey,
			NCRYPT_LENGTHS_PROPERTY,
			pbOutput,
			cbOutput,
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		pbOutput = new byte[pcbResult];
		cbOutput = pcbResult;
		ntStatus = NCryptGetProperty(
			phKey,
			NCRYPT_LENGTHS_PROPERTY,
			pbOutput,
			cbOutput,
			&pcbResult,
			0
		);
		
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		delete pbOutput;
		ntStatus = NCryptFreeObject(phKey);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free key error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
		ntStatus = NCryptFreeBuffer(ppEnumState);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum Keys error");
	}
	TEST_METHOD(Create_Persisted_Key) {
		NTSTATUS					ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE			phProvider = 0;
		DWORD						dwFlags = 0;
		NCryptKeyName				*ppKeyName = NULL;
		PBYTE						pbOutput = NULL;
		DWORD						cbOutput = 0;
		NCRYPT_KEY_HANDLE			phKey = NULL;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		/*	ntStatus = NCryptOpenKey(
				phProvider,
				&phKey,
				L"cnglengths",
				0,
				0
			);
			Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		*/

		DWORD version = 0;
		DWORD pcbResult = 0;
		DWORD *pVersion = &version;
		ntStatus = NCryptGetProperty(
			phProvider,
			NCRYPT_VERSION_PROPERTY,
			(PBYTE)version,
			sizeof(version),
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		ntStatus = NCryptGetProperty(
			phProvider,
			NCRYPT_IMPL_TYPE_PROPERTY,
			(PBYTE)version,
			sizeof(version),
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		ntStatus = NCryptGetProperty(
			phProvider,
			NCRYPT_MAX_NAME_LENGTH_PROPERTY,
			(PBYTE)version,
			sizeof(version),
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		DWORD pdwAlgCount = 0;
		NCryptAlgorithmName *ppAlgList = NULL;
		ntStatus = NCryptEnumAlgorithms(
			phProvider,
			NCRYPT_SIGNATURE_OPERATION,
			&pdwAlgCount,
			&ppAlgList,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum algorithm error");
		ntStatus = NCryptCreatePersistedKey(
			phProvider,
			&phKey,
			BCRYPT_RSA_ALGORITHM,
			NULL,
			0,
			0
		);
		ntStatus = NCryptCreatePersistedKey(
			phProvider,
			&phKey,
			BCRYPT_RSA_ALGORITHM,
			L"sampleTestKey",
			0,
			//0
			NCRYPT_OVERWRITE_KEY_FLAG
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		ntStatus = NCryptGetProperty(
			phKey,
			NCRYPT_LENGTHS_PROPERTY,
			pbOutput,
			cbOutput,
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		pbOutput = new byte[pcbResult];
		cbOutput = pcbResult;
		ntStatus = NCryptGetProperty(
			phKey,
			NCRYPT_LENGTHS_PROPERTY,
			pbOutput,
			cbOutput,
			&pcbResult,
			0
		);
		
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		delete pbOutput;
		ntStatus = NCryptFinalizeKey(
			phKey,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Finalize key error");
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
	}
	TEST_METHOD(Enum_and_free_All_Keys) {
		NTSTATUS			ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE	phProvider = 0;
		DWORD				dwFlags = 0;
		NCryptKeyName		*ppKeyName = NULL;
		void				*ppEnumState = NULL;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");

		while (ntStatus != NTE_NO_MORE_ITEMS) {
			ntStatus = NCryptEnumKeys(
				phProvider,
				NULL,
				&ppKeyName,
				&ppEnumState,
				dwFlags
			);
			if (ntStatus != NTE_NO_MORE_ITEMS) {
				ntStatus = NCryptFreeBuffer(
					ppKeyName
				);
			}
		}
		Assert::AreEqual(NTE_NO_MORE_ITEMS, ntStatus, L"Enum Keys error");
		ntStatus = NCryptFreeBuffer(
			ppEnumState
		);
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
	}
	TEST_METHOD(Create_Persisted_Key_not_exists) {
		NTSTATUS					ntStatus = STATUS_SUCCESS;
		NCRYPT_PROV_HANDLE			phProvider = 0;
		DWORD						dwFlags = 0;
		NCryptKeyName				*ppKeyName = NULL;
		PBYTE						pbOutput = NULL;
		DWORD						cbOutput = 0;
		NCRYPT_KEY_HANDLE			phKey = NULL;

		ntStatus = NCryptOpenStorageProvider(&phProvider, GRADIANT_KSP_PROVIDER_NAME, dwFlags);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open provider error");
		/*	ntStatus = NCryptOpenKey(
				phProvider,
				&phKey,
				L"cnglengths",
				0,
				0
			);
			Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		*/

		DWORD version = 0;
		DWORD pcbResult = 0;
		DWORD *pVersion = &version;
		ntStatus = NCryptGetProperty(
			phProvider,
			NCRYPT_VERSION_PROPERTY,
			(PBYTE)version,
			sizeof(version),
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		ntStatus = NCryptGetProperty(
			phProvider,
			NCRYPT_IMPL_TYPE_PROPERTY,
			(PBYTE)version,
			sizeof(version),
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		ntStatus = NCryptGetProperty(
			phProvider,
			NCRYPT_MAX_NAME_LENGTH_PROPERTY,
			(PBYTE)version,
			sizeof(version),
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		DWORD pdwAlgCount = 0;
		NCryptAlgorithmName *ppAlgList = NULL;
		ntStatus = NCryptEnumAlgorithms(
			phProvider,
			NCRYPT_SIGNATURE_OPERATION,
			&pdwAlgCount,
			&ppAlgList,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Enum algorithm error");
		ntStatus = NCryptCreatePersistedKey(
			phProvider,
			&phKey,
			BCRYPT_RSA_ALGORITHM,
			NULL,
			0,
			0
		);
		ntStatus = NCryptCreatePersistedKey(
			phProvider,
			&phKey,
			BCRYPT_RSA_ALGORITHM,
			L"cngTestKey",
			0,
			0
		);
		//TODO: Check ntStatus after callint NCryptCreatePersistedKey
		ntStatus = NCryptFinalizeKey(
			phKey,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Open key error");
		ntStatus = NCryptGetProperty(
			phKey,
			NCRYPT_LENGTHS_PROPERTY,
			pbOutput,
			cbOutput,
			&pcbResult,
			0
		);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		pbOutput = new byte[pcbResult];
		cbOutput = pcbResult;
		ntStatus = NCryptGetProperty(
			phKey,
			NCRYPT_LENGTHS_PROPERTY,
			pbOutput,
			cbOutput,
			&pcbResult,
			0
		);
		NCRYPT_SUPPORTED_LENGTHS casa = *(NCRYPT_SUPPORTED_LENGTHS*)pbOutput;
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Get key property error");
		delete pbOutput;
		/*	ntStatus = NCryptFinalizeKey(
				phKey,
				0
			);
*/
		ntStatus = NCryptFreeObject(phProvider);
		Assert::AreEqual(STATUS_SUCCESS, ntStatus, L"Free provider error");
	}

	};
}