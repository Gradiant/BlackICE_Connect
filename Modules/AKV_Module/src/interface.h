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

#ifndef INTERFACE_H
#define INTERFACE_H 
#include "clientRest.h"
#define KEK_KEY_LEN  (32)
#define ITERATION  (20000) 
#define ALLOPERATIONS (3)

typedef unsigned char U_CHAR;
typedef unsigned char * U_CHAR_PTR;
typedef unsigned long int U_LONG;

#ifdef PKCS11
#ifndef CK_PTR
#define CK_PTR *
#endif
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "../../PKCS11_Connector/src/cryptoki.h"
#define MD_PIN_INVALID				CKR_PIN_INCORRECT
#define MD_HOST_MEMORY				CKR_HOST_MEMORY
#define MD_UNDEFINED_ERROR			CKR_GENERAL_ERROR
#define MD_PIN_NOT_INITIALIZED		CKR_USER_PIN_NOT_INITIALIZED
#define MD_TOKEN_NOT_PRESENT		CKR_TOKEN_NOT_PRESENT
#define MD_FUNCTION_FAILED			CKR_FUNCTION_FAILED
#define MD_NO_ERROR					CKR_OK
#define MD_NOT_FOUND				CKR_DEVICE_REMOVED
#define MD_NOT_READY				CKR_TOKEN_NOT_PRESENT
#define MD_INVALID_PARAMETER		CKR_ARGUMENTS_BAD
#define MD_INVALID_TOKEN			CKR_PIN_EXPIRED

typedef CK_ULONG					ERROR_CODE;
#endif
#ifdef CNG_KSP
#include "../../CNG_Connector/src/KSP.h"
#define MD_PIN_INVALID			STATUS_LOGON_FAILURE
#define MD_HOST_MEMORY			STATUS_INSUFFICIENT_RESOURCES
#define MD_UNDEFINED_ERROR		STATUS_INTERNAL_ERROR
#define	MD_PIN_NOT_INITIALIZED	STATUS_DECRYPTION_FAILED
#define MD_NO_ERROR				STATUS_SUCCESS
#define MD_TOKEN_NOT_PRESENT	STATUS_NO_SUCH_DEVICE
#define MD_FUNCTION_FAILED		STATUS_INTERNAL_ERROR
#define MD_NOT_FOUND			STATUS_DEVICE_REMOVED
#define MD_NOT_READY			STATUS_DEVICE_UNREACHABLE
#define MD_INVALID_PARAMETER	STATUS_INVALID_PARAMETER
#define MD_INVALID_TOKEN		STATUS_INVALID_TOKEN
#define MD_NO_MORE_ITEMS		STATUS_NO_MORE_ENTRIES

typedef LONG					ERROR_CODE;

typedef struct _AKV_KEY {
	LONG					 handler;
	struct key_data_response *key_data;
} AKV_KEY;

#endif

#ifdef CNG_INSTALLER
#define MD_PIN_INVALID			-1
#define MD_HOST_MEMORY			-1
#define MD_UNDEFINED_ERROR		-1
#define	MD_PIN_NOT_INITIALIZED	-1
#define MD_NO_ERROR				0
#define MD_TOKEN_NOT_PRESENT	-1
#define MD_FUNCTION_FAILED		-1
#define MD_NOT_FOUND			-1
#define MD_NOT_READY			-1
#define MD_INVALID_PARAMETER	-1
#define MD_INVALID_TOKEN		-1
#define MD_NO_MORE_ITEMS		-1

typedef long					ERROR_CODE;
#endif

struct basic_http_data;
struct list_key;
struct id_http_data;
struct key_data_response;

/***************************************************************************************//**
 *                                     Keys Helper
*******************************************************************************************/
/**
* @param pPin User PIN to derive the Encryption key.
* @param ulPinLen User PIN length.
* @param configurationKey Resulting encryption key to encrypt the Azure Key Vault credentials.
* @param salt salt.
* @param saltSize Salt length.
* @return Result of the operation for error handling.
* @brief DeriveKey Function to derive a encryption key to encrypt Azure Key Vault credentials
*/
ERROR_CODE DeriveKey(U_CHAR_PTR pPin, U_LONG ulPinLen, U_CHAR **configurationKey, const unsigned char *salt, U_LONG saltSize);
/**
* @param iv User Resulting IV to generate the encryption key.
* @param id First piece of the IV
* @param suffix Second piece of the IV
* @return Result of the operation for error handling.
* @brief DeriveKey Function to generate a pseudorandom IV
*/
ERROR_CODE IVCalculator(const unsigned char *iv, U_CHAR_PTR id, U_CHAR_PTR suffix);
/**
* @param parameter Parameter to encrypt.
* @param cipherData Resulting encrypted parameter
* @param iv Initialization vector
* @param configurationKey Encryption key
* @return Result of the operation for error handling.
* @brief EncryptParameter Function to encrypt one parameter
*/
ERROR_CODE EncryptParameter(U_CHAR *parameter, U_CHAR **cipherData, const unsigned char *iv, U_CHAR *configurationKey);
/**
* @param ciphertext Parameter to decrypt.
* @param ciphertext_len Encrypted parameter length.
* @param configurationKey Encryption key.
* @param iv Initialization vector
* @param plainData Resulting deciphered data
* @return Result of the operation for error handling.
* @brief DecryptParameter Function to decrypt one parameter
*/
ERROR_CODE DecryptParameter(unsigned char *ciphertext, int ciphertext_len, U_CHAR *configurationKey, unsigned char *iv, U_CHAR **plainData);
/**
* @param parameter Configuration parameter to encrypt.
* @param parameterName Configuration parameter name.
* @param configurationKey Encryption key.
* @return Result of the operation for error handling.
* @brief EncryptConfigurationData Function to encrypt a configuration parameter
*/
ERROR_CODE EncryptConfigurationData(U_CHAR_PTR *parameter, U_CHAR_PTR parameterName, U_CHAR_PTR configurationKey);
/**
* @param pPin User PIN to derive the Encryption key.
* @param ulPinLen User PIN length.
* @return Result of the operation for error handling.
* @brief EncryptAllConfigurationData Function to encrypt all the configuration data.
*/
ERROR_CODE EncryptAllConfigurationData(U_CHAR_PTR pPin, U_LONG ulPinLen);
/**
* @param parameter Configuration parameter to decrypt.
* @param parameterName Configuration parameter name.
* @param configurationKey Encryption key.
* @return Result of the operation for error handling.
* @brief DecryptConfigurationData Function to decrypt a configuration parameter
*/
ERROR_CODE DecryptConfigurationData(U_CHAR_PTR *parameter, U_CHAR_PTR parameterName, U_CHAR_PTR configurationKey);
/**
* @param pPin User PIN to derive the Encryption key.
* @param ulPinLen User PIN length.
* @return Result of the operation for error handling.
* @brief DecryptAllConfigurationData Function to decrypt all the configuration data.
*/
ERROR_CODE DecryptAllConfigurationData(U_CHAR_PTR pPin, U_LONG ulPinLen);
/**
* @param azureToken Azure Token to connect with the Key Vault API.
* @return Result of the operation for error handling.
* @brief GetAzureToken Function to request a new token from Azure Key Vault.
*/
ERROR_CODE GetAccesToken(U_CHAR **azureToken);

ERROR_CODE ClientRest_ErrorConverter(int clientRestError);

#ifdef CNG_KSP

ERROR_CODE Get_Key_List(__out PVOID *ppEnumState, __deref_out NCryptKeyName **ppKeyName);

void Remove_all_key_list(void);

ERROR_CODE Find_Next_Key(__inout PVOID pEnumState,	__deref_out NCryptKeyName **ppKeyName);

AKV_KEY *Find_Current_Key(__inout KSP_KEY *pKey);

AKV_KEY *Find_Key_By_Name(LPWSTR keyName);

ERROR_CODE ReadKeyNameFromMemory(__in struct key_data_response *returnedKey, __deref_out NCryptKeyName **ppKeyName);

ERROR_CODE ParseMemoryKey(__inout KSP_KEY *pKey, __in AKV_KEY *currentKey);

ERROR_CODE FindKeyInKeyStore(__in LPCWSTR pszKeyName, __out AKV_KEY **ppCurrentKey);

ERROR_CODE CreateKeyInKeyStore(__in	KSP_KEY *pCreationKey, __out AKV_KEY **ppCreatedKey);
#endif

#endif /* INTERFACE_H */