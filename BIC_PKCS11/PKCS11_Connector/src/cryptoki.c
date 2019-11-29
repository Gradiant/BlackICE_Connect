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

#include <cryptoki.h>
#include <src/cJSON.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/obj_mac.h>
#include <cryptokiTypes.h>
#ifdef _WIN32
#include <tchar.h>
#endif
#include "Helpers/common.h"
#include "Helpers/common.h"

#define BUFSIZE MAX_PATH
CK_BBOOL initialized = CK_FALSE;
struct sessions *session = NULL_PTR;
struct objects *cacheTokenObjects = NULL_PTR;

// TODO: Implement concurrency using semophores for mutual exclusion

CK_FUNCTION_LIST pkcs11_functions =
{
	{ 2, 20 },
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	int resultado = ConfigureApplication();
	InitializeLogs(LOG_CONTEXT);
	lastCallTimer.certificateListeTimer = 0;
	lastCallTimer.keyListTimer = 0;
	lastCallTimer.secretListTimer = 0;
	context context;
	Context_Initialization("C_Initialize", &context);
	Write_DebugData(context, LOG_CONTEXT);
	TOKEN = NULL_PTR;
	if (resultado < 0) {
		if (resultado == BAD_CONF_FILE) {
			strcpy(context.error, "CKR_ARGUMENTS_BAD");
			Write_DebugData(context, LOG_CONTEXT);
			return CKR_ARGUMENTS_BAD;
		}
		else if (resultado == HOST_MEMORY) {
			strcpy(context.error, "CKR_HOST_MEMORY");
			Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
		else {
			strcpy(context.error, "CKR_GENERAL_ERROR");
			Write_DebugData(context, LOG_CONTEXT);
			return (CKR_GENERAL_ERROR);
		}
	}
	if (initialized == CK_TRUE) {
		strcpy(context.error, "CKR_CRYPTOKI_ALREADY_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_ALREADY_INITIALIZED; //non fatal error
	}
	NOT_USED(pInitArgs);
	initialized = CK_TRUE;
	strcpy(context.error, "CKR_OK");
	Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	context context;
	Context_Initialization("C_Finalize", &context);
	Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (pReserved != NULL_PTR) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	NOT_USED(pReserved);
	initialized = CK_FALSE;
	//session_opened = CK_FALSE; //Revisar
	if (TOKEN != NULL) {
		free(TOKEN);
		TOKEN = NULL;
	}
	Free_Sessions(&session);
	Free_All_TokenObject(&cacheTokenObjects);
	strcpy(context.error, "CKR_OK");
	Write_DebugData(context, LOG_CONTEXT);
	ClearGlobalData();
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	context context;
	Context_Initialization("C_GetInfo", &context);
	Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (NULL == pInfo) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	pInfo->cryptokiVersion.major = 0x02;
	pInfo->cryptokiVersion.minor = 0x20;
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, MANUFACTURER_ID, strlen(MANUFACTURER_ID));
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, LIBRARY_DESCRIPTION, strlen(LIBRARY_DESCRIPTION));
	pInfo->libraryVersion.major = 0x01;
	pInfo->libraryVersion.minor = 0x00;
	strcpy(context.error, "CKR_OK");
	Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	context context;
	Context_Initialization("C_GetFunctionList", &context);
	Write_DebugData(context, LOG_CONTEXT);
	if (NULL == ppFunctionList) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	*ppFunctionList = &pkcs11_functions;
	strcpy(context.error, "CKR_OK");
	Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	context context;
	Context_Initialization("C_GetSlotList", &context);
	Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	NOT_USED(tokenPresent);
	if (pulCount == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (pSlotList == NULL)
	{
		*pulCount = 1;
	}
	else
	{
		if (*pulCount == 0) {
			strcpy(context.error, "CKR_BUFFER_TOO_SMALL");
			Write_DebugData(context, LOG_CONTEXT);
			return CKR_BUFFER_TOO_SMALL;
		}
		pSlotList[0] = SLOT_ID;
		*pulCount = 1;
	}
	strcpy(context.error, "CKR_OK");
	Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	context context;
	Context_Initialization("C_GetSlotInfo", &context);
	Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	NOT_USED(slotID);
	//if (SLOT_ID != slotID) return CKR_SLOT_ID_INVALID; //Pensar si esto es necesario
	if (NULL == pInfo) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, SLOT_DESCRIPTION, strlen(SLOT_DESCRIPTION));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, SLOT_MANUFACTURER_ID, strlen(SLOT_MANUFACTURER_ID));
	pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;
	strcpy(context.error, "CKR_OK");
	Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	context context;
	Context_Initialization("C_GetTokenInfo", &context);
	Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(slotID);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	//if (SLOT_ID != slotID) return CKR_SLOT_ID_INVALID;
	if (NULL == pInfo) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	memset(pInfo->label, ' ', sizeof(pInfo->label));
	memcpy(pInfo->label, TOKEN_INFO_LABEL, strlen(TOKEN_INFO_LABEL));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, TOKEN_INFO_MANUFACTURER_ID, strlen(TOKEN_INFO_MANUFACTURER_ID));
	memset(pInfo->model, ' ', sizeof(pInfo->model));
	memcpy(pInfo->model, TOKEN_INFO_MODEL, strlen(TOKEN_INFO_MODEL));
	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	memcpy(pInfo->serialNumber, TOKEN_INFO_SERIAL_NUMBER, strlen(TOKEN_INFO_SERIAL_NUMBER));
	// P�gina 42 del manual Table 11, Token Information Flags
	pInfo->flags = (CK_FLAGS)0 | CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED;
	if (CIPHER) pInfo->flags = pInfo->flags | CKF_USER_PIN_INITIALIZED;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = sessionCount(session, CKS_ALL_SESSIONS);
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = sessionCount(session, (CKS_RW_SO_FUNCTIONS | CKS_RW_PUBLIC_SESSION | CKS_RW_USER_FUNCTIONS));
	pInfo->ulMaxPinLen = TOKEN_INFO_MAX_PIN_LEN;
	pInfo->ulMinPinLen = TOKEN_INFO_MIN_PIN_LEN;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;
	char buff[20];
	time_t now = time(NULL);
	strftime(buff, 20, "%Y%m%d%H%M%S00", localtime(&now));
	strncpy((char *)pInfo->utcTime, buff, 16);
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	context context;
	Context_Initialization("C_GetMechanismList", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(slotID);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (pulCount == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (pMechanismList == NULL)
	{
		*pulCount = 7;
	}
	else
	{
		if (*pulCount < 7) {
			strcpy(context.error, "CKR_BUFFER_TOO_SMALL");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_BUFFER_TOO_SMALL;
		}
		pMechanismList[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
		pMechanismList[1] = CKM_RSA_PKCS;
		pMechanismList[2] = CKM_RSA_PKCS_OAEP;
		pMechanismList[3] = CKM_SHA256_RSA_PKCS;
		pMechanismList[4] = CKM_SHA384_RSA_PKCS;
		pMechanismList[5] = CKM_SHA512_RSA_PKCS;
		pMechanismList[6] = CKM_VENDOR_DEFINED;
		*pulCount = 7;
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	context context;
	Context_Initialization("C_GetMechanismInfo", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(slotID);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (pInfo == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	switch (type)
	{
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 2048;
		pInfo->flags = CKF_GENERATE_KEY_PAIR | CKF_HW;
		break;
	case CKM_RSA_PKCS:
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 2048;
		pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_HW;
		break;
	case CKM_SHA256_RSA_PKCS:
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 2048;
		pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_HW;
		break;
	case CKM_SHA384_RSA_PKCS:
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 2048;
		pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_HW;
		break;
	case CKM_SHA512_RSA_PKCS:
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 2048;
		pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_HW;
		break;
	case CKM_RSA_PKCS_OAEP:
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 2048;
		pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_HW;
		break;
	case CKM_VENDOR_DEFINED:
		pInfo->flags = CKF_WRAP | CKF_UNWRAP | CKF_HW;
		break;
	default:
		strcpy(context.error, "CKR_MECHANISM_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_MECHANISM_INVALID;
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	context context;
	Context_Initialization("C_InitToken", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(slotID);
	NOT_USED(pPin);
	NOT_USED(ulPinLen);
	NOT_USED(pLabel);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	context context;
	Context_Initialization("C_InitPIN", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (pPin == NULL) return CKR_ARGUMENTS_BAD;
	if ((ulPinLen < TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > TOKEN_INFO_MAX_PIN_LEN))	return CKR_PIN_LEN_RANGE;
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (currentSession->sessionState != CKS_RW_SO_FUNCTIONS) return CKR_USER_NOT_LOGGED_IN;
	if (CIPHER) return CKR_GENERAL_ERROR;
	CK_ULONG result = EncryptAllConfigurationData(pPin, ulPinLen);
	if (result != CKR_OK) {
		Error_Writter(&context, result);
		 Write_DebugData(context, LOG_CONTEXT);
		return result;
	}
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	context context;
	Context_Initialization("C_SetPIN", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (pOldPin == NULL || pNewPin == NULL) return CKR_ARGUMENTS_BAD;
	if ((ulOldLen < TOKEN_INFO_MIN_PIN_LEN) || (ulOldLen > TOKEN_INFO_MAX_PIN_LEN) || (ulNewLen < TOKEN_INFO_MIN_PIN_LEN) || (ulNewLen > TOKEN_INFO_MAX_PIN_LEN))	return CKR_PIN_LEN_RANGE;
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (currentSession->sessionState < CKS_RW_PUBLIC_SESSION) return CKR_SESSION_READ_ONLY;
	if (!CIPHER) return CKR_GENERAL_ERROR;
	CK_CHAR *old_TenantID = NULL_PTR, *old_Host = NULL_PTR, *old_Password = NULL_PTR;
	CK_ULONG result = BackUp_Old_Credentials(&old_TenantID, &old_Host, &old_Password);
	if (result != CKR_OK) {
		Error_Writter(&context, result);
		 Write_DebugData(context, LOG_CONTEXT);
		return result;
	}
	ClearGlobalData();
	result = ConfigureApplication();
	if (result < 0) {
		Free_SecretData();
		TENANTID = (char *)old_TenantID;
		HOST = (char *)old_Host;
		PASSWORD = (char *)old_Password;
		if (result == HOST_MEMORY) {
			strcpy(context.error, "CKR_HOST_MEMORY");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
		else {
			strcpy(context.error, "CKR_GENERAL_ERROR");
			 Write_DebugData(context, LOG_CONTEXT);
			return (CKR_GENERAL_ERROR);
		}
	}
	result = DecryptAllConfigurationData(pOldPin, ulOldLen) != CKR_OK;
	if (result != CKR_OK) {
		Free_SecretData();
		TENANTID = (char *)old_TenantID;
		HOST = (char *)old_Host;
		PASSWORD = (char *)old_Password;
		Error_Writter(&context, result);
		 Write_DebugData(context, LOG_CONTEXT);
		return result;
	}
	result = EncryptAllConfigurationData(pNewPin, ulNewLen);
	if (result != CKR_OK) {
		Free_SecretData();
		TENANTID = (char *)old_TenantID;
		HOST = (char *)old_Host;
		PASSWORD = (char *)old_Password;
		Error_Writter(&context, result);
		 Write_DebugData(context, LOG_CONTEXT);
		return result;
	}
	Free_Old_Credentials(old_TenantID, old_Host, old_Password);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	context context;
	Context_Initialization("C_OpenSession", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (SLOT_ID != slotID) {
		strcpy(context.error, "CKR_SLOT_ID_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SLOT_ID_INVALID;
	}
	if (!(flags & CKF_SERIAL_SESSION)) {
		strcpy(context.error, "CKR_SESSION_PARALLEL_NOT_SUPPORTED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED; //Por ahora no soporta operaciones en paralelo
	}
	// TODO Callback with pApplication and Notify, max num of sessions
	NOT_USED(pApplication);
	NOT_USED(Notify);
	if (phSession == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	CK_ULONG returnValue = CKR_OK;
	returnValue = New_Session(phSession, flags, &session);
	if (returnValue != CKR_OK) {
		Error_Writter(&context, returnValue);
		 Write_DebugData(context, LOG_CONTEXT);
		return returnValue;
	}
	CK_ULONG userType;
	returnValue = Check_User_Type(session, &userType);
	if (returnValue != CKR_OK) {
		Error_Writter(&context, returnValue);
		 Write_DebugData(context, LOG_CONTEXT);
		return returnValue;
	}
	if (userType != CKU_PUBLIC) {
		returnValue = Change_Session_State(session, TRUE, userType);
		if (returnValue != CKR_OK) {
			Error_Writter(&context, returnValue);
			 Write_DebugData(context, LOG_CONTEXT);
			return returnValue;
		}
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	context context;
	Context_Initialization("C_CloseSession", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	Delete_Session(currentSession->sessionHandler, &session);
	if (sessionCount(session, CKS_ALL_SESSIONS) == 0) {
		ClearGlobalData();
		if (ConfigureApplication() < 0) {
			strcpy(context.error, "CKR_GENERAL_ERROR");
			 Write_DebugData(context, LOG_CONTEXT);
			return (CKR_GENERAL_ERROR);
		}
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	context context;
	Context_Initialization("C_CloseAllSessions", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (slotID == NULL_PTR) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (SLOT_ID != slotID) {
		strcpy(context.error, "CKR_SLOT_ID_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SLOT_ID_INVALID;
	}
	Free_Sessions(&session);
	ClearGlobalData();
	if (ConfigureApplication() < 0) {
		strcpy(context.error, "CKR_GENERAL_ERROR");
		 Write_DebugData(context, LOG_CONTEXT);
		return (CKR_GENERAL_ERROR);
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	context context;
	Context_Initialization("C_GetSessionInfo", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	pInfo->slotID = 1;
	pInfo->state = currentSession->sessionState;
	pInfo->ulDeviceError = 0;
	pInfo->flags = (CK_FLAGS)0 | (CK_ULONG)4; // This flag is provided for backward compatibility, and should always be set to true
	if (currentSession->sessionState > CKS_RO_USER_FUNCTIONS) {
		pInfo->flags = pInfo->flags | (CK_ULONG)2;
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	context context;
	Context_Initialization("C_GetOperationState", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pOperationState);
	NOT_USED(pulOperationStateLen);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	context context;
	Context_Initialization("C_SetOperationState", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pOperationState);
	NOT_USED(ulOperationStateLen);
	NOT_USED(hEncryptionKey);
	NOT_USED(hAuthenticationKey);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{// No SO login required. Backward compatibility
	context context;
	Context_Initialization("C_Login", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	CK_ULONG result;
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if ((userType != CKU_SO) && (userType != CKU_USER) && (userType != CKU_CONTEXT_SPECIFIC)) {
		strcpy(context.error, "CKR_USER_TYPE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_TYPE_INVALID;
	}
	if (userType == CKU_USER && CIPHER == FALSE) {
		strcpy(context.error, "CKR_USER_PIN_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_PIN_NOT_INITIALIZED;
	}
	if (pPin == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	switch (currentSession->sessionState)
	{
	case CKS_RO_PUBLIC_SESSION:
		if (userType == CKU_CONTEXT_SPECIFIC || userType == CKU_USER) {
			result = DecryptAllConfigurationData(pPin, ulPinLen);
			if (result != CKR_OK) {
				Error_Writter(&context, result);
				 Write_DebugData(context, LOG_CONTEXT);
				return result;
			}
			result = GetAccesToken((CK_CHAR **)&TOKEN);
			if (result != CKR_OK) {
				Error_Writter(&context, result);
				 Write_DebugData(context, LOG_CONTEXT);
				return result;
			}
			currentSession->sessionState = CKS_RO_USER_FUNCTIONS;
		}
		else {
			strcpy(context.error, "CKR_SESSION_READ_ONLY_EXISTS");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_SESSION_READ_ONLY_EXISTS;
		}
		break;
	case CKS_RO_USER_FUNCTIONS:
		if (userType == CKU_CONTEXT_SPECIFIC || userType == CKU_USER) {
			result = DecryptAllConfigurationData(pPin, ulPinLen);
			if (result != CKR_OK) {
				Error_Writter(&context, result);
				 Write_DebugData(context, LOG_CONTEXT);
				return result;
			}
			result = GetAccesToken((CK_CHAR **)&TOKEN);
			if (result != CKR_OK) {
				Error_Writter(&context, result);
				 Write_DebugData(context, LOG_CONTEXT);
				return result;
			}
		}
		else {
			strcpy(context.error, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		break;
	case CKS_RW_PUBLIC_SESSION:
		if (userType == CKU_CONTEXT_SPECIFIC || userType == CKU_USER) {
			result = DecryptAllConfigurationData(pPin, ulPinLen);
			if (result != CKR_OK) {
				Error_Writter(&context, result);
				 Write_DebugData(context, LOG_CONTEXT);
				return result;
			}
			result = GetAccesToken((CK_CHAR **)&TOKEN);
			if (result != CKR_OK) {
				Error_Writter(&context, result);
				 Write_DebugData(context, LOG_CONTEXT);
				return result;
			}
			currentSession->sessionState = CKS_RW_USER_FUNCTIONS;
		}
		else {
			currentSession->sessionState = CKS_RW_SO_FUNCTIONS;
		}
		break;
	case CKS_RW_USER_FUNCTIONS:
		if (userType == CKU_CONTEXT_SPECIFIC || userType == CKU_USER) {
			result = DecryptAllConfigurationData(pPin, ulPinLen) != CKR_OK;
			if (result != CKR_OK) {
				Error_Writter(&context, result);
				 Write_DebugData(context, LOG_CONTEXT);
				return result;
			}
			result = GetAccesToken((CK_CHAR **)&TOKEN);
			if (result != CKR_OK) {
				Error_Writter(&context, result);
				 Write_DebugData(context, LOG_CONTEXT);
				return result;
			}
		}
		else {
			strcpy(context.error, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		break;
	case CKS_RW_SO_FUNCTIONS:
		if (userType == CKU_CONTEXT_SPECIFIC || userType == CKU_USER) {
			strcpy(context.error, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		else {
			strcpy(context.error, "CKR_USER_ALREADY_LOGGED_IN");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_USER_ALREADY_LOGGED_IN;
		}
		break;
	}
	result = Change_Session_State(session, TRUE, userType);
	if (result != CKR_OK) {
		Error_Writter(&context, result);
		 Write_DebugData(context, LOG_CONTEXT);
		return result;
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	context context;
	Context_Initialization("C_Logout", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (TOKEN != NULL) {
		free(TOKEN);
		TOKEN = NULL;
	}
	Free_All_TokenObject(&cacheTokenObjects);
	switch (currentSession->sessionState)
	{
	case CKS_RO_PUBLIC_SESSION:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	case CKS_RO_USER_FUNCTIONS:
		currentSession->sessionState = CKS_RO_PUBLIC_SESSION;
		break;
	case CKS_RW_USER_FUNCTIONS:
		currentSession->sessionState = CKS_RW_PUBLIC_SESSION;
		break;
	case CKS_RW_PUBLIC_SESSION:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	case CKS_RW_SO_FUNCTIONS:
		currentSession->sessionState = CKS_RW_PUBLIC_SESSION;
		break;
	}
	CK_ULONG error = Change_Session_State(session, FALSE, 0);
	if (error != CKR_OK) {
		Error_Writter(&context, error);
		 Write_DebugData(context, LOG_CONTEXT);
		return error;
	}
	ClearGlobalData();
	int result = ConfigureApplication();
	if (result < 0) {
		if (result == HOST_MEMORY) {
			strcpy(context.error, "CKR_HOST_MEMORY");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
		else {
			strcpy(context.error, "CKR_GENERAL_ERROR");
			 Write_DebugData(context, LOG_CONTEXT);
			return (CKR_GENERAL_ERROR);
		}
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	context context;
	Context_Initialization("C_CreateObject", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	CK_ULONG error = CKR_OK;
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (currentSession->operationState != OPERATION_FREE) {
		strcpy(context.error, "CKR_OPERATION_ACTIVE");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_ACTIVE; // Investigar si es necesario
	}
	switch (currentSession->sessionState) {
	case CKS_RO_PUBLIC_SESSION:
	case CKS_RO_USER_FUNCTIONS:
		strcpy(context.error, "CKR_SESSION_READ_ONLY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_READ_ONLY;
	case CKS_RW_PUBLIC_SESSION:
	case CKS_RW_SO_FUNCTIONS:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	case CKS_RW_USER_FUNCTIONS:
		break;
	}
	BOOL existCKA_CLASS = FALSE;
	CK_ULONG objectType;
	int count = 0;
	for (CK_ULONG i = 0; i < ulCount; i++) {
		if (pTemplate[i].type == CKA_CLASS) {
			existCKA_CLASS = TRUE;
			objectType = *(CK_ULONG*)pTemplate[i].pValue;
			count++;
		}
		PKCS11_Attribute_Transriptor(pTemplate[i], &context);
	}
	if (!existCKA_CLASS) {
		strcpy(context.error, "CKR_TEMPLATE_INCOMPLETE");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_TEMPLATE_INCOMPLETE;
	}
	if (count > 1) {
		strcpy(context.error, "CKR_TEMPLATE_INCONSISTENT");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_TEMPLATE_INCONSISTENT;
	}
	struct objects *newObject = NULL_PTR;
	error = ObjectCreator(&newObject, pTemplate, ulCount, objectType, (CK_CHAR *)TOKEN, &cacheTokenObjects);
	if (error != CKR_OK) {
		Error_Writter(&context, error);
		 Write_DebugData(context, LOG_CONTEXT);
		return error;
	}
	*phObject = newObject->objectHandler;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	context context;
	Context_Initialization("C_CopyObject", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(hObject);
	NOT_USED(pTemplate);
	NOT_USED(ulCount);
	NOT_USED(phNewObject);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_ULONG error;
	struct delete_key * keyData;
	struct id_http_data * deleteId;
	struct delete_update_cert_response *deleteCertResponse;
	int result;
	context context;
	Context_Initialization("C_DestroyObject", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (currentSession->operationState != OPERATION_FREE) {
		strcpy(context.error, "CKR_OPERATION_ACTIVE");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_ACTIVE; // Investigar si es necesario
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, hObject);
	if (currentObject == NULL) {
		strcpy(context.error, "CKR_OBJECT_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OBJECT_HANDLE_INVALID;
	}
	switch (currentSession->sessionState) {
	case CKS_RO_PUBLIC_SESSION:
	case CKS_RO_USER_FUNCTIONS:
		strcpy(context.error, "CKR_SESSION_READ_ONLY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_READ_ONLY;
	case CKS_RW_PUBLIC_SESSION:
	case CKS_RW_SO_FUNCTIONS:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	case CKS_RW_USER_FUNCTIONS:
		break;
	default:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	}
	switch (currentObject->type) {
	case CKO_CERTIFICATE:
		deleteId = Store_IdHttpData(TOKEN, HOST, (char *)currentObject->id);
		if (deleteId == NULL) return CKR_HOST_MEMORY;
		result = Delete_Certificate(deleteId, &deleteCertResponse);
		Free_IdHttpData(deleteId);
		if (result != HTTP_OK && result != CKR_OK) {
			if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
			else if (result < HTTP_OK) error = CKR_TOKEN_NOT_PRESENT;
			else if (result == UNAUTHORIZED) error = CKR_PIN_EXPIRED;
			else if (result == FORBIDDEN) error = CKR_GENERAL_ERROR;
			else if (result == NOT_FOUND) error = CKR_TOKEN_NOT_PRESENT;
			else if (result == BAD_REQUEST) error = CKR_TEMPLATE_INCONSISTENT;
			else error = CKR_FUNCTION_FAILED;
			Error_Writter(&context, error);
			 Write_DebugData(context, LOG_CONTEXT);
			return error;
		}
		Free_DeleteUpdateCertResponse(deleteCertResponse);
		break;
	case CKO_PRIVATE_KEY:
	case CKO_PUBLIC_KEY:
		keyData = Store_DeleteKey(HOST, (char *)currentObject->id, TOKEN);
		if (keyData == NULL) return CKR_HOST_MEMORY;
		result = Delete_key(keyData);
		Free_DeleteKey(keyData);
		if (result != HTTP_OK && result != CKR_OK) {
			if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
			else if (result < HTTP_OK) error = CKR_TOKEN_NOT_PRESENT;
			else if (result == UNAUTHORIZED) error = CKR_PIN_EXPIRED;
			else if (result == FORBIDDEN) error = CKR_TOKEN_WRITE_PROTECTED;
			else if (result == NOT_FOUND) error = CKR_TOKEN_NOT_PRESENT;
			else if (result == BAD_REQUEST) error = CKR_TEMPLATE_INCONSISTENT;
			else error = CKR_FUNCTION_FAILED;
			Error_Writter(&context, error);
			 Write_DebugData(context, LOG_CONTEXT);
			return error;
		}
		break;
	case CKO_SECRET_KEY:
		break;
	case CKO_DATA:
		deleteId = Store_IdHttpData(TOKEN, HOST, (char *)currentObject->id);
		if (deleteId == NULL) return CKR_HOST_MEMORY;
		result = Delete_Secret(deleteId);
		Free_IdHttpData(deleteId);
		if (result != HTTP_OK && result != CKR_OK) {
			if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
			else if (result < HTTP_OK) error = CKR_TOKEN_NOT_PRESENT;
			else if (result == UNAUTHORIZED) error = CKR_PIN_EXPIRED;
			else if (result == FORBIDDEN) error = CKR_TOKEN_WRITE_PROTECTED;
			else if (result == NOT_FOUND) error = CKR_TOKEN_NOT_PRESENT;
			else if (result == BAD_REQUEST) error = CKR_TEMPLATE_INCONSISTENT;
			else error = CKR_FUNCTION_FAILED;
			Error_Writter(&context, error);
			 Write_DebugData(context, LOG_CONTEXT);
			return error;
		}
		break;
	default:
		break;
	}
	Free_CacheObject_By_Id(&cacheTokenObjects, (char *)currentObject->id, currentObject->type);
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	context context;
	Context_Initialization("C_GetObjectSize", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(hObject);
	NOT_USED(pulSize);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	context context;
	Context_Initialization("C_GetAttributeValue", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	// ToDo estudiar operation_state
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (ulCount == 0 || pTemplate == NULL_PTR) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, hObject);
	/*Write_debugData("\nhandler:", NULL, 0, &hObject, 1);*/
	if (currentObject == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	CK_ULONG result;
	for (CK_ULONG i = 0; i < ulCount; i++) {
		result = getAttributeInspector(&pTemplate[i], currentObject, (CK_CHAR_PTR)TOKEN, &context);
		if (result != CKR_OK) {
			Error_Writter(&context, result);
			 Write_DebugData(context, LOG_CONTEXT);
			pTemplate[i].ulValueLen = (CK_ULONG)(-1); // GCC: lvalue required as left operand of assignment
			return result;
		}
		context.dataIn[0] = '\0';
		context.dataOut[0] = '\0';
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	context context;
	Context_Initialization("C_SetAttributeValue", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	// ToDo estudiar operation_state
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (ulCount == 0 || pTemplate == NULL_PTR) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, hObject);
	/*Write_debugData("\nhandler:", NULL, 0, &hObject, 1);*/
	if (currentObject == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	switch (currentSession->sessionState) {
	case CKS_RO_PUBLIC_SESSION:
	case CKS_RO_USER_FUNCTIONS:
		strcpy(context.error, "CKR_SESSION_READ_ONLY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_READ_ONLY;
	case CKS_RW_PUBLIC_SESSION:
	case CKS_RW_SO_FUNCTIONS:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	case CKS_RW_USER_FUNCTIONS:
		break;
	}
	CK_ULONG result = objectUpdate(&pTemplate, ulCount, currentObject, &cacheTokenObjects, (CK_CHAR_PTR)TOKEN, &context);
	if (result != CKR_OK) { //cuidado
		Error_Writter(&context, result);
		 Write_DebugData(context, LOG_CONTEXT);
		return result;
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	context context;
	Context_Initialization("C_FindObjectsInit", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (currentSession->operationState != OPERATION_FREE) {
		strcpy(context.error, "CKR_OPERATION_ACTIVE");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_ACTIVE;
	}
	if (currentSession->findObjects.foundObjects != NULL_PTR) Free_FoundObjects(currentSession);
	if (currentSession->sessionState != CKS_RW_USER_FUNCTIONS && currentSession->sessionState != CKS_RO_USER_FUNCTIONS) {
		currentSession->operationState = OPERATION_FIND;
		sprintf(context.dataOut, "%d objects found", currentSession->findObjects.numFound);
		 Write_DebugData(context, LOG_CONTEXT);
		strcpy(context.error, "CKR_OK");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OK;
	}
	////******* DEBUG *********////
	for (CK_ULONG i = 0; i < ulCount; i++) {
		PKCS11_Attribute_Transriptor(pTemplate[i], &context);
	}
	////***********************////
	CK_ULONG error, objectType;
	if (pTemplate == NULL || ulCount == 0) {
		error = Object_Searcher(currentSession, pTemplate, ulCount, CKO_ALL_OBJECTS, (CK_CHAR_PTR)TOKEN, &cacheTokenObjects);
		if (error != CKR_OK) {
			Error_Writter(&context, error);
			 Write_DebugData(context, LOG_CONTEXT);
			return error;
		}
		if (currentSession->findObjects.foundObjects != NULL_PTR) currentSession->findObjects.currentObjectHandler = currentSession->findObjects.foundObjects->object->objectHandler;
		currentSession->operationState = OPERATION_FIND;
		sprintf(context.dataOut, "%d objects found", currentSession->findObjects.numFound);
		 Write_DebugData(context, LOG_CONTEXT);
		strcpy(context.error, "CKR_OK");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OK;
	}
	BOOL existCKA_CLASS = FALSE;
	for (CK_ULONG i = 0; i < ulCount; i++) {
		if (pTemplate[i].pValue == NULL || pTemplate[i].ulValueLen <= 0) {
			strcpy(context.error, "CKR_ATTRIBUTE_VALUE_INVALID");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		if (pTemplate[i].type == CKA_CLASS)
		{
			existCKA_CLASS = TRUE;
			if (pTemplate[i].ulValueLen != sizeof(CK_ULONG)) {
				strcpy(context.error, "CKR_ATTRIBUTE_VALUE_INVALID");
				 Write_DebugData(context, LOG_CONTEXT);
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			objectType = *(CK_ULONG*)pTemplate[i].pValue;
			switch ((int)objectType)
			{
			case CKO_DATA:
				error = Object_Searcher(currentSession, pTemplate, ulCount, CKO_DATA, (CK_CHAR_PTR)TOKEN, &cacheTokenObjects);
				if (error != CKR_OK) {
					lastCallTimer.secretListTimer = 0;
					Error_Writter(&context, error);
					 Write_DebugData(context, LOG_CONTEXT);
					return error;
				}
				break;
			case CKO_SECRET_KEY: // Not soported in Azure Key Vault
				currentSession->operationState = OPERATION_FIND;
				sprintf(context.dataOut, "%d objects found", currentSession->findObjects.numFound);
				 Write_DebugData(context, LOG_CONTEXT);
				strcpy(context.error, "CKR_OK");
				 Write_DebugData(context, LOG_CONTEXT);
				return CKR_OK;
			case CKO_CERTIFICATE:
				error = Object_Searcher(currentSession, pTemplate, ulCount, CKO_CERTIFICATE, (CK_CHAR_PTR)TOKEN, &cacheTokenObjects);
				if (error != CKR_OK) {
					lastCallTimer.certificateListeTimer = 0;
					Error_Writter(&context, error);
					 Write_DebugData(context, LOG_CONTEXT);
					return error;
				}
				break;
			case CKO_PUBLIC_KEY:
				error = Object_Searcher(currentSession, pTemplate, ulCount, CKO_PUBLIC_KEY, (CK_CHAR_PTR)TOKEN, &cacheTokenObjects);
				if (error != CKR_OK) {
					lastCallTimer.keyListTimer = 0;
					Error_Writter(&context, error);
					 Write_DebugData(context, LOG_CONTEXT);
					return error;
				}
				break;
			case CKO_PRIVATE_KEY:
				error = Object_Searcher(currentSession, pTemplate, ulCount, CKO_PRIVATE_KEY, (CK_CHAR_PTR)TOKEN, &cacheTokenObjects);
				if (error != CKR_OK) {
					lastCallTimer.keyListTimer = 0;
					Error_Writter(&context, error);
					 Write_DebugData(context, LOG_CONTEXT);
					return error;
				}
				break;
			default:
				currentSession->operationState = OPERATION_FIND;
				sprintf(context.dataOut, "%d objects found", currentSession->findObjects.numFound);
				 Write_DebugData(context, LOG_CONTEXT);
				strcpy(context.error, "CKR_OK");
				 Write_DebugData(context, LOG_CONTEXT);
				return CKR_OK;
			}
		}
		if (existCKA_CLASS) break;
	}
	if (!existCKA_CLASS) {
		error = Object_Searcher(currentSession, pTemplate, ulCount, CKO_ALL_OBJECTS, (CK_CHAR_PTR)TOKEN, &cacheTokenObjects);
		if (error != CKR_OK) {
			Error_Writter(&context, error);
			 Write_DebugData(context, LOG_CONTEXT);
			return error;
		}
	}
	if (currentSession->findObjects.foundObjects != NULL_PTR) currentSession->findObjects.currentObjectHandler = currentSession->findObjects.foundObjects->object->objectHandler;
	currentSession->operationState = OPERATION_FIND;
	sprintf(context.dataOut, "%d objects found", currentSession->findObjects.numFound);
	 Write_DebugData(context, LOG_CONTEXT);
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	context context;
	Context_Initialization("C_FindObjects", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	//if (currentSession->sessionState != CKS_RW_USER_FUNCTIONS && currentSession->sessionState != CKS_RO_USER_FUNCTIONS) {
	//	strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED-1");
	//	 Write_DebugData(context, LOG_CONTEXT);
	//	return CKR_OPERATION_NOT_INITIALIZED;
	//}
	if (currentSession->operationState != OPERATION_FIND) {
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	if ((phObject == NULL) || ulMaxObjectCount == 0 || pulObjectCount == NULL_PTR) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (currentSession->findObjects.numFound == 0) {
		phObject = NULL_PTR;
		*pulObjectCount = 0;
		strcpy(context.error, "CKR_OK");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OK;
	}
	*pulObjectCount = 0;
	CK_ULONG i = 0;
	CK_ULONG *handlers;
	struct found_objects_list *currentObject;
	currentObject = Find_FoundObject(currentSession, currentSession->findObjects.currentObjectHandler);
	if (currentSession->findObjects.numLeft <= ulMaxObjectCount) {
		handlers = calloc(currentSession->findObjects.numLeft, sizeof(CK_OBJECT_HANDLE));
		if (handlers == NULL) {
			strcpy(context.error, "CKR_HOST_MEMORY");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
		for (i = 0; i < currentSession->findObjects.numLeft; i++) {
			if (currentObject == NULL_PTR) break;
			handlers[i] = currentObject->object->objectHandler;
			currentObject = currentObject->next;
			if (currentObject != NULL_PTR) {
				currentSession->findObjects.currentObjectHandler = currentObject->object->objectHandler;
			}
			*pulObjectCount = i + 1;
		}
		memcpy(phObject, handlers, currentSession->findObjects.numLeft * sizeof(CK_OBJECT_HANDLE));
		free(handlers);
		currentSession->findObjects.numLeft = 0;
	}
	else {
		handlers = calloc(ulMaxObjectCount, sizeof(CK_OBJECT_HANDLE));
		if (handlers == NULL) {
			strcpy(context.error, "CKR_HOST_MEMORY");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
		for (i = 0; i < ulMaxObjectCount; i++) {
			if (currentObject == NULL) break;// return CKR_GENERAL_ERROR;
			handlers[i] = currentObject->object->objectHandler;
			currentObject = currentObject->next;
			if (currentObject != NULL_PTR) {
				currentSession->findObjects.currentObjectHandler = currentObject->object->objectHandler;
			}
			currentSession->findObjects.numLeft--;
			*pulObjectCount = i + 1;
		}
		memcpy(phObject, handlers, ulMaxObjectCount * sizeof(CK_OBJECT_HANDLE));
		free(handlers);
	}
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	context context;
	Context_Initialization("C_FindObjectsFinal", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (currentSession->operationState != OPERATION_FIND) {
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	Free_FoundObjects(session);
	currentSession->operationState = OPERATION_FREE;
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	context context;
	Context_Initialization("C_EncryptInit", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (pMechanism == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (currentSession->operationState != OPERATION_FREE) {
		strcpy(context.error, "CKR_OPERATION_ACTIVE");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_ACTIVE;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, hKey);
	if (currentObject == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (currentObject->type != CKO_PUBLIC_KEY) {
		strcpy(context.error, "CKR_KEY_TYPE_INCONSISTENT");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_TYPE_INCONSISTENT;
	}
	if (currentObject->keyObject->commonPublicKeyAtt.canEncrypt != CK_TRUE) {
		strcpy(context.error, "CKR_KEY_FUNCTION_NOT_PERMITTED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	CK_ULONG type = (CK_MECHANISM_TYPE)pMechanism->mechanism;
	switch (type)
	{
	case  CKM_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_RSA_PKCS");
		break;
	case CKM_RSA_PKCS_OAEP:
		strcpy(currentSession->operationAlgorithm, "CKM_RSA_PKCS_OAEP");
		break;
	default:
		strcpy(context.error, "CKR_MECHANISM_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_MECHANISM_INVALID;
	}
	currentSession->findObjects.currentObjectHandler = hKey;
	currentSession->operationState = OPERATION_ENCRYPT;
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	context context;
	Context_Initialization("C_Encrypt", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	CK_ULONG error = CKR_OK;
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if ((currentSession->operationState != OPERATION_ENCRYPT) || (currentSession->findObjects.currentObjectHandler <= 0)) {
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, currentSession->findObjects.currentObjectHandler);
	if (currentObject == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	if (currentObject->type != CKO_PUBLIC_KEY) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_KEY_TYPE_INCONSISTENT");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_TYPE_INCONSISTENT;
	}
	if (currentObject->keyObject->commonPublicKeyAtt.canEncrypt != CK_TRUE) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_KEY_FUNCTION_NOT_PERMITTED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	if ((pData == NULL) || (ulDataLen <= 0)) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	struct operation_response *encryptResponse = NULL_PTR;
	unsigned char algorithm[MAX_ALGORITHM_TYPE_LENGHT] = "";
	if (!strcmp(currentSession->operationAlgorithm, "CKM_RSA_PKCS")) {
		strcpy((char*)algorithm, "RSA1_5");
	}
	else if (!strcmp(currentSession->operationAlgorithm, "CKM_RSA_PKCS_OAEP")) {
		strcpy((char*)algorithm, "RSA-OAEP");
	}
	else {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	char* base64Encoded = NULL;
	base64Encoded = base64encode(pData, ulDataLen);
	if (base64Encoded == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	struct operation_data *plaintTextData = Store_OperationData(TOKEN, (char*)currentObject->keyObject->commonKeyAtt.id, HOST, (char*)algorithm, base64Encoded);
	if (plaintTextData == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	free(base64Encoded);
	int result = Encript_Data(plaintTextData, &encryptResponse);
	Free_OperationData(plaintTextData);
	if (result != HTTP_OK) {
		if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
		else if (result < HTTP_OK) error = CKR_DEVICE_REMOVED;
		else if (result == UNAUTHORIZED) error = CKR_USER_NOT_LOGGED_IN;
		else if (result == FORBIDDEN) error = CKR_GENERAL_ERROR;
		else if (result == NOT_FOUND) error = CKR_DEVICE_REMOVED;
		else if (result == BAD_REQUEST) error = CKR_DATA_INVALID;
		else error = CKR_FUNCTION_FAILED;
		currentSession->operationState = OPERATION_FREE;
		Error_Writter(&context, error);
		 Write_DebugData(context, LOG_CONTEXT);
		return error;
	}
	size_t encrypt_len = 0;
	size_t outputLen = 4 * (strlen(encryptResponse->value) / 3); //base64 ratio of output to input bytes = 4:3
	unsigned char *encrypt = malloc(outputLen);
	if (encrypt == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	result = base64url_decode((char *)encrypt, outputLen, encryptResponse->value, strlen(encryptResponse->value), &encrypt_len);
	Free_OperationResponse(encryptResponse);
	if (result != 0) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_FUNCTION_FAILED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_FUNCTION_FAILED;
	}
	if (pEncryptedData != NULL && pulEncryptedDataLen > 0) {
		if ((CK_ULONG)encrypt_len > *pulEncryptedDataLen)
		{
			currentSession->operationState = OPERATION_FREE;
			free(encrypt);
			strcpy(context.error, "CKR_BUFFER_TOO_SMALL");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pEncryptedData, encrypt, encrypt_len);
			currentSession->operationState = OPERATION_FREE;
		}
	}
	*pulEncryptedDataLen = (CK_ULONG)encrypt_len;
	free(encrypt);
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	context context;
	Context_Initialization("C_EncryptUpdate", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pPart);
	NOT_USED(ulPartLen);
	NOT_USED(pEncryptedPart);
	NOT_USED(pulEncryptedPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	context context;
	Context_Initialization("C_EncryptFinal", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pLastEncryptedPart);
	NOT_USED(pulLastEncryptedPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	context context;
	Context_Initialization("C_DecryptInit", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (pMechanism == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (currentSession->sessionState != CKS_RW_USER_FUNCTIONS && currentSession->sessionState != CKS_RO_USER_FUNCTIONS) {
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	}
	if (currentSession->operationState != OPERATION_FREE) {
		strcpy(context.error, "CKR_OPERATION_ACTIVE");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_ACTIVE;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, hKey);
	if (currentObject == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (currentObject->type != CKO_PRIVATE_KEY) {
		strcpy(context.error, "CKR_KEY_TYPE_INCONSISTENT");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_TYPE_INCONSISTENT;
	}
	if (currentObject->keyObject->commonPrivateKeyAtt.canDecrypt != CK_TRUE) {
		strcpy(context.error, "CKR_KEY_FUNCTION_NOT_PERMITTED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	CK_ULONG type = (CK_MECHANISM_TYPE)pMechanism->mechanism;
	switch (type)
	{
	case  CKM_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_RSA_PKCS");
		break;
	case CKM_RSA_PKCS_OAEP:
		strcpy(currentSession->operationAlgorithm, "CKM_RSA_PKCS_OAEP");
		break;
	default:
		strcpy(context.error, "CKR_MECHANISM_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_MECHANISM_INVALID;
	}
	currentSession->findObjects.currentObjectHandler = hKey;
	currentSession->operationState = OPERATION_DECRYPT;
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	context context;
	Context_Initialization("C_Decrypt", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	CK_ULONG error = CKR_OK;
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if ((currentSession->operationState != OPERATION_DECRYPT) || (currentSession->findObjects.currentObjectHandler <= 0)) {
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, currentSession->findObjects.currentObjectHandler);
	if (currentObject == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	if ((pEncryptedData == NULL) || (ulEncryptedDataLen <= 0)) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	struct operation_response *decryptResponse = NULL_PTR;
	unsigned char algorithm[MAX_ALGORITHM_TYPE_LENGHT] = "";
	if (!strcmp(currentSession->operationAlgorithm, "CKM_RSA_PKCS")) {
		strcpy((char *)algorithm, "RSA1_5");
	}
	else if (!strcmp(currentSession->operationAlgorithm, "CKM_RSA_PKCS_OAEP")) {
		strcpy((char *)algorithm, "RSA-OAEP");
	}
	else {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	char* base64Encoded = NULL;
	base64Encoded = base64encode(pEncryptedData, ulEncryptedDataLen);
	if (base64Encoded == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	struct operation_data *encryptData = Store_OperationData(TOKEN, (char *)currentObject->keyObject->commonKeyAtt.id, HOST, (char *)algorithm, base64Encoded);
	if (encryptData == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	free(base64Encoded);
	int result = Decript_Data(encryptData, &decryptResponse);
	Free_OperationData(encryptData);
	if (result != HTTP_OK) {
		if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
		else if (result < HTTP_OK) error = CKR_DEVICE_REMOVED;
		else if (result == UNAUTHORIZED) error = CKR_USER_NOT_LOGGED_IN;
		else if (result == FORBIDDEN) error = CKR_GENERAL_ERROR;
		else if (result == NOT_FOUND) error = CKR_DEVICE_REMOVED;
		else if (result == BAD_REQUEST) error = CKR_DATA_INVALID;
		else error = CKR_FUNCTION_FAILED;
		currentSession->operationState = OPERATION_FREE;
		Error_Writter(&context, error);
		 Write_DebugData(context, LOG_CONTEXT);
		return error;
	}
	size_t decrypt_len = 0;
	size_t outputLen = 4 * (strlen(decryptResponse->value) / 3); //base64 ratio of output to input bytes = 4:3
	unsigned char *decrypt = malloc(outputLen);
	if (decrypt == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	result = base64url_decode((char *)decrypt, outputLen, decryptResponse->value, strlen(decryptResponse->value), &decrypt_len);
	Free_OperationResponse(decryptResponse);
	if (result != 0) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_FUNCTION_FAILED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_FUNCTION_FAILED;
	}
	if (pData != NULL) {
		if ((CK_ULONG)decrypt_len > *pulDataLen)
		{
			currentSession->operationState = OPERATION_FREE;
			free(decrypt);
			strcpy(context.error, "CKR_BUFFER_TOO_SMALL");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pData, decrypt, decrypt_len);
			currentSession->operationState = OPERATION_FREE;
		}
	}
	*pulDataLen = (CK_ULONG)decrypt_len;
	free(decrypt);
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	context context;
	Context_Initialization("C_DecryptUpdate", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pEncryptedPart);
	NOT_USED(ulEncryptedPartLen);
	NOT_USED(pPart);
	NOT_USED(pulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	context context;
	Context_Initialization("C_DecryptFinal", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pLastPart);
	NOT_USED(pulLastPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	context context;
	Context_Initialization("C_DigestInit", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pMechanism);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	context context;
	Context_Initialization("C_Digest", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pData);
	NOT_USED(ulDataLen);
	NOT_USED(pDigest);
	NOT_USED(pulDigestLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	context context;
	Context_Initialization("C_DigestUpdate", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pPart);
	NOT_USED(ulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	context context;
	Context_Initialization("C_DigestKey", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(hKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	context context;
	Context_Initialization("C_DigestFinal", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pDigest);
	NOT_USED(pulDigestLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	context context;
	Context_Initialization("C_SignInit", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (currentSession->operationState != OPERATION_FREE) {
		strcpy(context.error, "CKR_OPERATION_ACTIVE");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_ACTIVE;
	}
	if (pMechanism == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (currentSession->sessionState != CKS_RW_USER_FUNCTIONS && currentSession->sessionState != CKS_RO_USER_FUNCTIONS) {
		return CKR_USER_NOT_LOGGED_IN;
		strcpy(context.error, "CKS_RO_USER_FUNCTIONS");
		 Write_DebugData(context, LOG_CONTEXT);
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, hKey);
	if (currentObject == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (currentObject->type != CKO_PRIVATE_KEY) {
		strcpy(context.error, "CKR_KEY_TYPE_INCONSISTENT");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_TYPE_INCONSISTENT;
	}
	if (currentObject->keyObject->commonPrivateKeyAtt.canSign != CK_TRUE) {
		strcpy(context.error, "CKR_KEY_FUNCTION_NOT_PERMITTED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	CK_ULONG type = (CK_MECHANISM_TYPE)pMechanism->mechanism;
	switch (type)
	{
	case  CKM_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_RSA_PKCS");
		break;
	case CKM_SHA256_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_SHA256_RSA_PKCS");
		break;
	case CKM_SHA384_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_SHA384_RSA_PKCS");
		break;
	case CKM_SHA512_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_SHA512_RSA_PKCS");
		break;
	default:
		strcpy(context.error, "CKR_MECHANISM_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_MECHANISM_INVALID;
	}
	currentSession->findObjects.currentObjectHandler = hKey;
	currentSession->operationState = OPERATION_SIGN;
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	context context;
	Context_Initialization("C_Sign", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	CK_ULONG error = CKR_OK;
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if ((currentSession->operationState != OPERATION_SIGN) || (currentSession->findObjects.currentObjectHandler <= 0)) {
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, currentSession->findObjects.currentObjectHandler);
	if (currentObject == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	if (currentObject->type != CKO_PRIVATE_KEY) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_KEY_TYPE_INCONSISTENT");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_TYPE_INCONSISTENT;
	}
	if (currentObject->keyObject->commonPrivateKeyAtt.canSign != CK_TRUE) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_KEY_FUNCTION_NOT_PERMITTED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	if ((pData == NULL) || (ulDataLen <= 0) || (pulSignatureLen == NULL)) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (ulDataLen < 49) { // minimum value acepted sha256
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return(CKR_ARGUMENTS_BAD);
	}
	struct operation_response *signResponse = NULL_PTR;
	int sha_len;
	int hashtype;
	unsigned char * sha = DecodeASN1Hash(pData, ulDataLen, &hashtype, &sha_len);
	if (sha == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return(CKR_ARGUMENTS_BAD);
	}
	unsigned char algorithm[MAX_JWA_ALGORITHM_LEN] = "";
	switch (hashtype) {
	case SHA_256:
		strcpy((char *)algorithm, "RS256");
		break;
	case SHA_384:
		strcpy((char *)algorithm, "RS384");
		break;
	case SHA_512:
		strcpy((char *)algorithm, "RS512");
		break;
	default:
		free(sha);
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	char* base64Encoded = NULL;
	base64Encoded = base64encode((unsigned char *)sha, sha_len);
	if (base64Encoded == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	free(sha);
	struct operation_data *signData = Store_OperationData(TOKEN, (char *)currentObject->keyObject->commonKeyAtt.id, HOST, (char *)algorithm, base64Encoded);
	if (signData == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	free(base64Encoded);
	int result = Sign(signData, &signResponse);
	Free_OperationData(signData);
	if (result != HTTP_OK) {
		if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
		else if (result < HTTP_OK) error = CKR_DEVICE_REMOVED;
		else if (result == UNAUTHORIZED) error = CKR_USER_NOT_LOGGED_IN;
		else if (result == FORBIDDEN) error = CKR_GENERAL_ERROR;
		else if (result == NOT_FOUND) error = CKR_DEVICE_REMOVED;
		else if (result == BAD_REQUEST) error = CKR_DATA_INVALID;
		else error = CKR_FUNCTION_FAILED;
		currentSession->operationState = OPERATION_FREE;
		Error_Writter(&context, error);
		 Write_DebugData(context, LOG_CONTEXT);
		return error;
	}
	size_t sign_len = 0;
	size_t outputLen = 4 * (strlen(signResponse->value) / 3); //base64 ratio of output to input bytes = 4:3
	unsigned char* sign = malloc(outputLen);
	if (sign == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	result = base64url_decode((char *)sign, outputLen, signResponse->value, strlen(signResponse->value), &sign_len);
	Free_OperationResponse(signResponse);
	if (result != 0 || sign_len > outputLen) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_FUNCTION_FAILED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_FUNCTION_FAILED;
	}
	if (pSignature != NULL) {
		if (sign_len > *pulSignatureLen)
		{
			currentSession->operationState = OPERATION_FREE;
			*pulSignatureLen = (CK_ULONG)sign_len;
			free(sign);
			strcpy(context.error, "CKR_BUFFER_TOO_SMALL");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pSignature, sign, sign_len);
			currentSession->operationState = OPERATION_FREE;
		}
	}
	*pulSignatureLen = (CK_ULONG)sign_len;
	free(sign);
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	context context;
	Context_Initialization("C_SignUpdate", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pPart);
	NOT_USED(ulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	context context;
	Context_Initialization("C_SignFinal", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pSignature);
	NOT_USED(pulSignatureLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	context context;
	Context_Initialization("C_SignRecoverInit", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pMechanism);
	NOT_USED(hKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	context context;
	Context_Initialization("C_SignRecover", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pData);
	NOT_USED(ulDataLen);
	NOT_USED(pSignature);
	NOT_USED(pulSignatureLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	context context;
	Context_Initialization("C_VerifyInit", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (pMechanism == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (currentSession->operationState != OPERATION_FREE) {
		strcpy(context.error, "CKR_OPERATION_ACTIVE");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_ACTIVE;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, hKey);
	if (currentObject == NULL) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (currentObject->type != CKO_PUBLIC_KEY) {
		strcpy(context.error, "CKR_KEY_TYPE_INCONSISTENT");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_TYPE_INCONSISTENT;
	}
	if (currentObject->keyObject->commonPublicKeyAtt.canVerify != CK_TRUE) {
		strcpy(context.error, "CKR_KEY_FUNCTION_NOT_PERMITTED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	CK_ULONG type = (CK_MECHANISM_TYPE)pMechanism->mechanism;
	switch (type)
	{
	case  CKM_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_RSA_PKCS");
		break;
	case CKM_SHA256_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_SHA256_RSA_PKCS");
		break;
	case CKM_SHA384_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_SHA384_RSA_PKCS");
		break;
	case CKM_SHA512_RSA_PKCS:
		strcpy(currentSession->operationAlgorithm, "CKM_SHA512_RSA_PKCS");
		break;
	default:
		strcpy(context.error, "CKR_MECHANISM_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_MECHANISM_INVALID;
	}
	currentSession->findObjects.currentObjectHandler = hKey;
	currentSession->operationState = OPERATION_VERIFY;
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;

}

CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	context context;
	Context_Initialization("C_Verify", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if ((currentSession->operationState != OPERATION_VERIFY) || (currentSession->findObjects.currentObjectHandler <= 0)) {
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, currentSession->findObjects.currentObjectHandler);
	if (currentObject == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_OPERATION_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	if (currentObject->type != CKO_PUBLIC_KEY) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_KEY_TYPE_INCONSISTENT");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_TYPE_INCONSISTENT;
	}
	if (currentObject->keyObject->commonPublicKeyAtt.canVerify != CK_TRUE) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_KEY_FUNCTION_NOT_PERMITTED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	if ((pData == NULL) || (ulDataLen <= 0)) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	if (ulDataLen < 49) { // minimum value acepted sha256
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return(CKR_ARGUMENTS_BAD);
	}
	int sha_len;
	int hashtype;
	unsigned char * sha = DecodeASN1Hash(pData, ulDataLen, &hashtype, &sha_len);
	if (sha == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return(CKR_ARGUMENTS_BAD);
	}
	unsigned char algorithm[MAX_JWA_ALGORITHM_LEN] = "";
	switch (hashtype) {
	case SHA_256:
		strcpy((char *)algorithm, "RS256");
		break;
	case SHA_384:
		strcpy((char *)algorithm, "RS384");
		break;
	case SHA_512:
		strcpy((char *)algorithm, "RS512");
		break;
	default:
		free(sha);
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	char* shaBase64Encoded = NULL;
	shaBase64Encoded = base64encode((unsigned char*)sha, sha_len);
	if (shaBase64Encoded == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	free(sha);
	char* signBase64Encoded = NULL;
	signBase64Encoded = base64encode(pSignature, ulSignatureLen);
	if (signBase64Encoded == NULL) {
		currentSession->operationState = OPERATION_FREE;
		free(shaBase64Encoded);
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	struct verify_data *verifyData = Store_VerifyData((char *)currentObject->keyObject->commonKeyAtt.id, TOKEN, HOST, (char *)algorithm, shaBase64Encoded, signBase64Encoded);
	free(shaBase64Encoded);
	free(signBase64Encoded);
	if (verifyData == NULL) {
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	int result = Verify(verifyData);
	Free_VerifyData(verifyData);
	switch (result)
	{
	case TRUE:
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_OK");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OK;
	case FALSE:
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_SIGNATURE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SIGNATURE_INVALID;
	case ALLOCATE_ERROR:
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	case BAD_REQUEST:
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	case UNAUTHORIZED:
	case FORBIDDEN:
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_FUNCTION_FAILED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_FUNCTION_FAILED;
	default:
		currentSession->operationState = OPERATION_FREE;
		strcpy(context.error, "CKR_GENERAL_ERROR");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_GENERAL_ERROR;
	}
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	context context;
	Context_Initialization("C_VerifyUpdate", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pPart);
	NOT_USED(ulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	context context;
	Context_Initialization("C_VerifyFinal", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pSignature);
	NOT_USED(ulSignatureLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	context context;
	Context_Initialization("C_VerifyRecoverInit", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pMechanism);
	NOT_USED(hKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	context context;
	Context_Initialization("C_VerifyRecover", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pSignature);
	NOT_USED(ulSignatureLen);
	NOT_USED(pData);
	NOT_USED(pulDataLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	context context;
	Context_Initialization("C_DigestEncryptUpdate", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pPart);
	NOT_USED(ulPartLen);
	NOT_USED(pEncryptedPart);
	NOT_USED(pulEncryptedPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	context context;
	Context_Initialization("C_DecryptDigestUpdate", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pEncryptedPart);
	NOT_USED(ulEncryptedPartLen);
	NOT_USED(pPart);
	NOT_USED(pulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	context context;
	Context_Initialization("C_SignEncryptUpdate", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pPart);
	NOT_USED(ulPartLen);
	NOT_USED(pEncryptedPart);
	NOT_USED(pulEncryptedPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	context context;
	Context_Initialization("C_DecryptVerifyUpdate", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pEncryptedPart);
	NOT_USED(ulEncryptedPartLen);
	NOT_USED(pPart);
	NOT_USED(pulPartLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	context context;
	Context_Initialization("C_GenerateKey", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pMechanism);
	NOT_USED(pTemplate);
	NOT_USED(ulCount);
	NOT_USED(phKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	context context;
	Context_Initialization("C_GenerateKeyPair", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	CK_ULONG error;
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (currentSession->operationState != OPERATION_FREE) {
		strcpy(context.error, "CKR_OPERATION_ACTIVE");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_OPERATION_ACTIVE; // Investigar si es necesario
	}
	switch (currentSession->sessionState) {
	case CKS_RO_PUBLIC_SESSION:
	case CKS_RO_USER_FUNCTIONS:
		strcpy(context.error, "CKR_SESSION_READ_ONLY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_READ_ONLY;
	case CKS_RW_PUBLIC_SESSION:
	case CKS_RW_SO_FUNCTIONS:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	case CKS_RW_USER_FUNCTIONS:
		break;
	}
    //if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN) {
    if ((pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN) && (pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN)) {
		strcpy(context.error, "CKR_MECHANISM_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_MECHANISM_INVALID;
	}
	////******* DEBUG *********////
    Write_Free_Text("Writing public atributes", LOG_CONTEXT);
	/*Write_debugData("															PublicTemplate\n", NULL, 0, NULL, 0);*/
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
		PKCS11_Attribute_Transriptor(pPublicKeyTemplate[i], &context);
	}
    Write_Free_Text("Writing private atributes", LOG_CONTEXT);
	/*Write_debugData("															PrivateTemplate\n", NULL, 0, NULL, 0);*/
	for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
		PKCS11_Attribute_Transriptor(pPrivateKeyTemplate[i], &context);
	}
	CK_ULONG result;
	struct key_data *keyData = calloc(1, sizeof(struct key_data));
	if (keyData == NULL) {
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	struct key_attributes *keyAttributes = calloc(1, sizeof(struct key_attributes));
	if (keyAttributes == NULL) {
		Free_KeyData(keyData);
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	keyData->attributes = keyAttributes;
	if ((pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) || (pMechanism->mechanism == CKM_RSA_PKCS)) {
		if (HSM_PROCESSED == FALSE) {
			keyData->keytype = _strdup("RSA");
		}
		else {
			keyData->keytype = _strdup("RSA-HSM");
		}
		if (keyData->keytype == NULL) {
			Free_KeyData(keyData);
			strcpy(context.error, "CKR_HOST_MEMORY");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
	}
    if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
        if (HSM_PROCESSED == FALSE) {
            keyData->keytype = _strdup("EC");
        } else {
            keyData->keytype = _strdup("EC-HSM");
        }
        if (keyData->keytype == NULL) {
            Free_KeyData(keyData);
            strcpy(context.error, "CKR_HOST_MEMORY");
            Write_DebugData(context, LOG_CONTEXT);
            return CKR_HOST_MEMORY;
        }
    }
	for (CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
		result = Template2JWK(pPublicKeyTemplate[i], keyData, CKO_PUBLIC_KEY, pMechanism->mechanism);
		if (result != CKR_OK) {
			Free_KeyData(keyData);
			Error_Writter(&context, result);
			 Write_DebugData(context, LOG_CONTEXT);
			return result;
		}
	}
	for (CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
		result = Template2JWK(pPrivateKeyTemplate[i], keyData, CKO_PRIVATE_KEY, pMechanism->mechanism);
		if (result != CKR_OK) {
			Free_KeyData(keyData);
			Error_Writter(&context, result);
			 Write_DebugData(context, LOG_CONTEXT);
			return result;
		}
	}
	if (keyAttributes != NULL) { //For Azure key Vault key attributes default value
		if (keyAttributes->created == 0 && keyAttributes->enabled == 0 && keyAttributes->exp == 0 && keyAttributes->nbf == 0 && keyAttributes->updated == 0) {
			Free_KeyAttributes(keyAttributes);
			keyAttributes = NULL;
			keyData->attributes = NULL;
		}
	}
	result = KeyMaterial_Checker(keyData);
	if (result != CKR_OK) {
		Free_KeyData(keyData);
		Error_Writter(&context, result);
		 Write_DebugData(context, LOG_CONTEXT);
		return result;
	}
	keyData->host = _strdup(HOST);
	if (keyData->host == NULL) {
		Free_KeyData(keyData);
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	keyData->token = _strdup(TOKEN);
	if (keyData->token == NULL) {
		Free_KeyData(keyData);
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	struct key_data_response *keyResponse = NULL_PTR;
	int res = Create_key(keyData, &keyResponse);
	Free_KeyData(keyData);
	if (res != HTTP_OK && res != CKR_OK) {
		if (res == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
		else if (res < HTTP_OK) error = CKR_TOKEN_NOT_PRESENT;
		else if (res == UNAUTHORIZED) error = CKR_PIN_INCORRECT;
		else if (res == FORBIDDEN) error = CKR_GENERAL_ERROR;
		else if (res == NOT_FOUND) error = CKR_TOKEN_NOT_PRESENT;
		else if (res == BAD_REQUEST) error = CKR_TEMPLATE_INCONSISTENT;
		else error = CKR_FUNCTION_FAILED;
		Error_Writter(&context, error);
		 Write_DebugData(context, LOG_CONTEXT);
		return error;
	}
	struct keyObject *pkcs11_PublicKey = AzurePKCS11KeyTranslator(keyResponse, CKO_PUBLIC_KEY, (CK_CHAR_PTR)TOKEN, cacheTokenObjects);
	if (pkcs11_PublicKey == NULL) {
		Free_KeyCreationResponse(keyResponse);
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	struct keyObject *pkcs11_PrivateKey = AzurePKCS11KeyTranslator(keyResponse, CKO_PRIVATE_KEY, (CK_CHAR_PTR)TOKEN, cacheTokenObjects);
	if (pkcs11_PrivateKey == NULL) {
		free(pkcs11_PrivateKey);
		Free_KeyCreationResponse(keyResponse);
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	struct objects *pkcs11_Private_Key_object = New_TokenObject(&cacheTokenObjects, (CK_CHAR_PTR)keyResponse->id, CKO_PRIVATE_KEY);
	if (pkcs11_Private_Key_object == NULL) {
		Free_KeyCreationResponse(keyResponse);
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	else  pkcs11_Private_Key_object->keyObject = pkcs11_PrivateKey;
	struct objects *pkcs11_Public_Key_object = New_TokenObject(&cacheTokenObjects, (CK_CHAR_PTR)keyResponse->id, CKO_PUBLIC_KEY);
    if (pkcs11_Public_Key_object == NULL) {
        Free_Object(pkcs11_Private_Key_object);
		Free_KeyCreationResponse(keyResponse);
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	else  pkcs11_Public_Key_object->keyObject = pkcs11_PublicKey;
	Free_KeyCreationResponse(keyResponse);
	*phPrivateKey = pkcs11_Private_Key_object->objectHandler;
	*phPublicKey = pkcs11_Public_Key_object->objectHandler;
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	context context;
	Context_Initialization("C_WrapKey", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hWrappingKey);
	CK_ULONG error = CKR_OK;
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	struct objects *currentObject = Find_Object(cacheTokenObjects, hKey);
	if (currentObject == NULL) {
		strcpy(context.error, "CKR_KEY_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_HANDLE_INVALID;
	}
	if ((currentObject->type != CKO_PUBLIC_KEY) && (currentObject->type != CKO_PRIVATE_KEY) && (currentObject->type != CKO_SECRET_KEY)) {
		strcpy(context.error, "CKR_KEY_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_KEY_HANDLE_INVALID;
	}
	switch (currentSession->sessionState) {
	case CKS_RW_PUBLIC_SESSION:
	case CKS_RO_PUBLIC_SESSION:
	case CKS_RW_SO_FUNCTIONS:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	case CKS_RO_USER_FUNCTIONS:
	case CKS_RW_USER_FUNCTIONS:
		break;
	default:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	}
	if (pMechanism->mechanism != CKM_VENDOR_DEFINED) {
		strcpy(context.error, "CKR_MECHANISM_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_MECHANISM_INVALID;
	}
	struct simple_operation_response * backOperationResponse = NULL;
	struct id_http_data *requestData = Store_IdHttpData(TOKEN, HOST, (char *)currentObject->keyObject->commonKeyAtt.id);
	if (requestData == NULL) {
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	int result = Backup_Key(requestData, &backOperationResponse);
	Free_IdHttpData(requestData);
	if (result != HTTP_OK) {
		if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
		else if (result < HTTP_OK) error = CKR_DEVICE_REMOVED;
		else if (result == UNAUTHORIZED) error = CKR_USER_NOT_LOGGED_IN;
		else if (result == FORBIDDEN) error = CKR_GENERAL_ERROR;
		else if (result == NOT_FOUND) error = CKR_DEVICE_REMOVED;
		else if (result == BAD_REQUEST) error = CKR_DATA_INVALID;
		else error = CKR_FUNCTION_FAILED;
		currentSession->operationState = OPERATION_FREE;
		Error_Writter(&context, error);
		 Write_DebugData(context, LOG_CONTEXT);
		return error;
	}
	if (pWrappedKey != NULL && *pulWrappedKeyLen > 0) {
		if ((CK_ULONG)(strlen(backOperationResponse->value) > *pulWrappedKeyLen))
		{
			Free_SimpleOperationResponse(backOperationResponse);
			strcpy(context.error, "CKR_BUFFER_TOO_SMALL");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pWrappedKey, backOperationResponse->value, strlen(backOperationResponse->value));
		}
	}
	*pulWrappedKeyLen = (CK_ULONG)strlen(backOperationResponse->value);
	Free_SimpleOperationResponse(backOperationResponse);
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	context context;
	Context_Initialization("C_UnwrapKey", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(ulAttributeCount);
	NOT_USED(pTemplate);
	NOT_USED(hUnwrappingKey);
	CK_ULONG error = CKR_OK;
	if (initialized == CK_FALSE) {
		strcpy(context.error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (session == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_CLOSED");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_CLOSED;
	}
	struct sessions *currentSession = Find_Current_Session(session, hSession);
	if (currentSession == NULL_PTR) {
		strcpy(context.error, "CKR_SESSION_HANDLE_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_SESSION_HANDLE_INVALID;
	}
	if (Session_Timeout(currentSession->openTime)) {
		C_CloseSession(currentSession->sessionHandler);
		return CKR_SESSION_CLOSED;
	}
	if (pWrappedKey == NULL_PTR || ulWrappedKeyLen <= 0) {
		strcpy(context.error, "CKR_ARGUMENTS_BAD");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_ARGUMENTS_BAD;
	}
	switch (currentSession->sessionState) {
	case CKS_RW_PUBLIC_SESSION:
	case CKS_RO_PUBLIC_SESSION:
	case CKS_RW_SO_FUNCTIONS:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	case CKS_RO_USER_FUNCTIONS:
	case CKS_RW_USER_FUNCTIONS:
		break;
	default:
		strcpy(context.error, "CKR_USER_NOT_LOGGED_IN");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_USER_NOT_LOGGED_IN;
	}
	if (pMechanism->mechanism != CKM_VENDOR_DEFINED) {
		strcpy(context.error, "CKR_MECHANISM_INVALID");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_MECHANISM_INVALID;
	}
	char * wrappedKey = calloc(1, ulWrappedKeyLen + 1);
	if (wrappedKey == NULL) {
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	memcpy(wrappedKey, pWrappedKey, ulWrappedKeyLen);
	wrappedKey[ulWrappedKeyLen] = '\0';
	struct key_data_response *keyResponse = NULL_PTR;
	struct value_http_data *requestData = Store_ValueHttpData(TOKEN, HOST, NULL);
	if (requestData == NULL) {
		free(wrappedKey);
		strcpy(context.error, "CKR_HOST_MEMORY");
		 Write_DebugData(context, LOG_CONTEXT);
		return CKR_HOST_MEMORY;
	}
	requestData->value = wrappedKey;
	int result = Restore_Key(requestData, &keyResponse);
	Free_ValueHttpData(requestData);
	if (result != HTTP_OK) {
		if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
		else if (result < HTTP_OK) error = CKR_DEVICE_REMOVED;
		else if (result == UNAUTHORIZED) error = CKR_USER_NOT_LOGGED_IN;
		else if (result == FORBIDDEN) error = CKR_GENERAL_ERROR;
		else if (result == NOT_FOUND) error = CKR_DEVICE_REMOVED;
		else if (result == BAD_REQUEST) error = CKR_DATA_INVALID;
		else error = CKR_FUNCTION_FAILED;
		currentSession->operationState = OPERATION_FREE;
		Error_Writter(&context, error);
		 Write_DebugData(context, LOG_CONTEXT);
		return error;
	}
	if ((strcmp(keyResponse->keytype, "RSA") == 0) || (strcmp(keyResponse->keytype, "RSA-HSM") == 0)) {
		struct keyObject *pkcs11_PublicKey = AzurePKCS11KeyTranslator(keyResponse, CKO_PUBLIC_KEY, (CK_CHAR_PTR)TOKEN, cacheTokenObjects);
		if (pkcs11_PublicKey == NULL) {
			Free_KeyCreationResponse(keyResponse);
			strcpy(context.error, "CKR_HOST_MEMORY");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
		struct keyObject *pkcs11_PrivateKey = AzurePKCS11KeyTranslator(keyResponse, CKO_PRIVATE_KEY, (CK_CHAR_PTR)TOKEN, cacheTokenObjects);
		if (pkcs11_PrivateKey == NULL) {
			free(pkcs11_PrivateKey);
			Free_KeyCreationResponse(keyResponse);
			strcpy(context.error, "CKR_HOST_MEMORY");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
		struct objects *pkcs11_Private_Key_object = New_TokenObject(&cacheTokenObjects, (CK_CHAR_PTR)keyResponse->id, CKO_PRIVATE_KEY);
		if (pkcs11_Private_Key_object == NULL) {
			Free_KeyCreationResponse(keyResponse);
			strcpy(context.error, "CKR_HOST_MEMORY");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
		else  pkcs11_Private_Key_object->keyObject = pkcs11_PrivateKey;
		struct objects *pkcs11_Public_Key_object = New_TokenObject(&cacheTokenObjects, (CK_CHAR_PTR)keyResponse->id, CKO_PUBLIC_KEY);
		if (pkcs11_Private_Key_object == NULL) {
			Free_Object(pkcs11_Private_Key_object);
			Free_KeyCreationResponse(keyResponse);
			strcpy(context.error, "CKR_HOST_MEMORY");
			 Write_DebugData(context, LOG_CONTEXT);
			return CKR_HOST_MEMORY;
		}
		else  pkcs11_Public_Key_object->keyObject = pkcs11_PublicKey;
		*phKey = pkcs11_Private_Key_object->objectHandler;
	}
	Free_KeyCreationResponse(keyResponse);
	strcpy(context.error, "CKR_OK");
	 Write_DebugData(context, LOG_CONTEXT);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	context context;
	Context_Initialization("C_DeriveKey", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pMechanism);
	NOT_USED(hBaseKey);
	NOT_USED(pTemplate);
	NOT_USED(ulAttributeCount);
	NOT_USED(phKey);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	context context;
	Context_Initialization("C_SeedRandom", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(pSeed);
	NOT_USED(ulSeedLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	context context;
	Context_Initialization("C_GenerateRandom", &context);
	strcpy(context.error, "CKR_FUNCTION_NOT_SUPPORTED");
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	NOT_USED(RandomData);
	NOT_USED(ulRandomLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	context context;
	Context_Initialization("C_GetFunctionStatus", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	context context;
	Context_Initialization("C_CancelFunction", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(hSession);
	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	context context;
	Context_Initialization("C_WaitForSlotEvent", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(flags);
	NOT_USED(pSlot);
	NOT_USED(pReserved);
	return CKR_NO_EVENT;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetUnmanagedStructSizeList)(CK_ULONG_PTR pSizeList, CK_ULONG_PTR pulCount)
{
	context context;
	Context_Initialization("C_GetUnmanagedStructSizeList", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(pSizeList);
	NOT_USED(pulCount);
	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_EjectToken)(CK_SLOT_ID slotID)
{
	context context;
	Context_Initialization("C_EjectToken", &context);
	 Write_DebugData(context, LOG_CONTEXT);
	NOT_USED(slotID);
	return CKR_OK;
}
