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
 * this work is derived from the RSA Security Inc. PKCS #11
 * Cryptographic Token Interface (Cryptoki)"
 *******************************************************************************/

#ifndef ___CRYPTOKI_H_INC___
#define ___CRYPTOKI_H_INC___

#ifdef _WIN32
	#pragma pack(push, cryptoki, 1)
	//#define CRYPTOKI_EXPORTS
	/* Specifies that the function is a DLL entry point. */
	#define CK_IMPORT_SPEC __declspec(dllimport)
#else
	#define CK_IMPORT_SPEC
#endif

/* Define CRYPTOKI_EXPORTS during the build of cryptoki libraries. Do
* not define it in applications.
*/
#ifdef CRYPTOKI_EXPORTS
/* Specified that the function is an exported DLL entry point. */
	#ifdef _WIN32
		#define CK_EXPORT_SPEC __declspec(dllexport)
	#else
		#define CK_EXPORT_SPEC
	#endif
#else
	#define CK_EXPORT_SPEC CK_IMPORT_SPEC
#endif

/* Ensures the calling convention for Win32 builds */
#ifdef _WIN32
	#define CK_CALL_SPEC __cdecl
#else
	#define CK_CALL_SPEC
#endif

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION(returnType, name) returnType CK_EXPORT_SPEC CK_CALL_SPEC name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (CK_CALL_SPEC CK_PTR name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include <pkcs11.h>
#ifdef _WIN32
	#pragma pack(pop, cryptoki)
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <src/clientRest.h>
#include <src/librb64u.h>
#include <openssl/asn1.h>
#include <src/Debug.h>


struct sessions;
struct objects;




#define MANUFACTURER_ID "Gradiant"
#define LIBRARY_DESCRIPTION "Wrapper pkcs11 Azure Key Vault"
#define SLOT_ID 1
#define SLOT_DESCRIPTION "Virtual slot"
#define SLOT_MANUFACTURER_ID "Gradiant"
#define TOKEN_INFO_LABEL "BlackICEConnect"
#define TOKEN_INFO_MANUFACTURER_ID "www.gradiant.org"
#define TOKEN_INFO_MODEL "API 1.0"
#define TOKEN_INFO_SERIAL_NUMBER "SN00000001"
#define TOKEN_INFO_MAX_PIN_LEN 256
#define TOKEN_INFO_MIN_PIN_LEN 4
#define NOT_USED(P) (void)(P)
// The operating state must be changed when multithreading is implemented
#define OPERATION_FREE   (100)
#define OPERATION_SIGN   (101)
#define OPERATION_VERIFY (102)
#define OPERATION_FIND   (103)
#define OPERATION_ENCRYPT (104)
#define OPERATION_DECRYPT (105)
#define CKS_ALL_SESSIONS (99)
#define CKO_ALL_OBJECTS (99)
//#define  _DEBUG




/***************************************************************************************//**
*                                     Prototypes
*******************************************************************************************/
/***************************************************************************************//**
*                                     Session helper
*******************************************************************************************/
/**
* @param phSession Session handler.
* @param flags Kind of session.
* @param session Pointer to the sessions list. @see sessions
* @return Result of the operation for error handling.
* @brief New_Session Insert a new session in the list of active sessions
*/
CK_ULONG New_Session(CK_SESSION_HANDLE_PTR phSession, CK_FLAGS flags, struct sessions ** session);
/**
* @param session Pointer to the sessions list. @see sessions
* @param hSession Session handler to look for.
* @return Pointer to the current session @see sessions.
* @brief Find_Current_Session Search for a specific session in the list of active sessions
*/
struct sessions *Find_Current_Session(struct sessions *session, CK_ULONG hSession);
/**
* @param session Pointer to the sessions list. @see sessions
* @return Void.
* @brief Free_Sessions Free all sessions.
*/
void Free_Sessions(struct sessions **session);
/**
* @param session Pointer to the sessions list. @see sessions
* @param sessionType Type of session.
* @return Result of the operation for error handling.
* @brief sessionCount Cuenta el n�mero de sesiones de un tipo concreto.
*/
CK_ULONG sessionCount(struct sessions * session, CK_ULONG sessionType);
/**
* @param sessionHandler Handler of the session to release.
* @param session Pointer to the session list. @see sessions
* @return Void.
* @brief Delete_Session Delete a specific session.
*/
void Delete_Session(CK_ULONG sessionHandler, struct sessions ** session);
/**
* @param session Pointer to the session list. @see sessions
* @return BOOL True if the user is logged false any way.
* @brief Is_User_Logged Checks if the user is logged.
*/
BOOL Is_User_Logged(struct sessions *session);
/**
* @param session Pointer to the session list. @see sessions
* @param userLogged True if the user is logged false any way.
* @param userType User type. Nomal user or SO.
* @return Result of the operation for error handling.
* @brief Change_Session_State Change all session states if the user log in or log out.
*/
CK_ULONG Change_Session_State(struct sessions * session, BOOL userLogged, CK_ULONG userType);
/**
* @param session Pointer to the session list. @see sessions
* @param userType User type. Nomal user or SO.
* @return Result of the operation for error handling.
* @brief Check_User_Type check all sessions to check what type of user is logged in.
*/
CK_ULONG Check_User_Type(struct sessions * session, CK_ULONG *userType);
/***************************************************************************************//**
*                                     Find Object Helper
*******************************************************************************************/
/**
* @param object Pointer to the object. @see objects
* @return Void.
* @brief Free_Object Safte free of the objects.
*/
void Free_Object(struct objects * object);
/**
* @param session Pointer to the current sessions. @see sessions
* @return Void.
* @brief Free_SessionObjects Free all the objects stored in a session.
*/
void Free_SessionObjects(struct sessions *session);
/**
* @param session Pointer to the current sessions. @see sessions
* @param id Object identifier.
* @param type Object type.
* @return Pointer to the new object. @see objects
* @brief New_Object Create a new object with an identifier and a type.
*/
struct objects *New_SessionObject(struct sessions * session, CK_CHAR_PTR id, CK_ULONG type);
/**
* @param object Pointer to the current object. @see object
* @param session Pointer to the current sessions. @see sessions
* @return Void.
* @brief Free_Object Free the current object for the current session.
*/
void Free_SessionObject(struct objects * object, struct sessions * session);
/**
* @param session Pointer to the current sessions. @see sessions
* @param objectHandler Object handler.
* @return Pointer to the found object. @see objects
* @brief Find_Object Search for a specific object in the current session.
*/
struct objects *Find_Object(struct objects *session, CK_ULONG objectHandler);
/**
* @param session Pointer to the current sessions. @see sessions
* @return Void.
* @brief Free_FoundObjects Free all the objects founded.
*/
void Free_FoundObjects(struct sessions *session);
/**
* @param session Pointer to the current sessions. @see sessions
* @param id Object id.
* @param type Type of the object.
* @param object Object pointer @see objects.
* @return Returns true if the object exist and false in other case.
* @brief Exist_Object S Returns true if the object exist and false in other case.
*/
BOOL Exist_SessionObject(struct sessions *session, char *id, CK_ULONG type, struct objects ** object);
/**
* @param session Pointer to the current sessions. @see sessions
* @param object Pointer to the current object. @see objects
* @return Result of the operation for error handling.
* @brief New_FoundObject Create a new object found.
*/
CK_ULONG New_FoundObject(struct sessions * session, struct objects * object);
/**
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @param session Pointer to the current sessions. @see sessions
* @param objectHandler Object handler.
* @return Pointer to the found object. @see found_objects_list
* @brief Find_FoundObject Search for a specific object in the current session.
*/
struct found_objects_list *Find_FoundObject(struct sessions *session, CK_ULONG objectHandler);
/**
* @param session Pointer to the current sessions. @see sessions
* @param cacheTokenObjects Pointer to the cache of token objects. @see objects
* @param type Type of the object.
* @return void
* @brief Collect_FoundObjects_From_Cache Collect all found objects from the cache.
*/
void Collect_FoundObjects_From_Cache(struct sessions *session, struct objects * cacheTokenObjects, CK_ULONG type);
/***************************************************************************************//**
*                                     Token Objects Helper
*******************************************************************************************/
/**
* @param cacheTokenObjects Pointer to the cache of token objects. @see objects
* @param id Object id.
* @param type Type of the object.
* @return Pointer to the new Token object. @see objects
* @brief New_TokenObject Create a new cache token object.
*/
struct objects * New_TokenObject(struct objects ** cacheTokenObjects, CK_CHAR_PTR id, CK_ULONG type);
/**
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @return Pointer to the new Token object. @see objects
* @brief Free_TokenObject Free the current cache token object.
*/
void Free_TokenObject(struct objects ** cacheTokenObjects, struct objects * object);
/**
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @param objectHandler Object handler.
* @return Pointer to the found object. @see objects
* @brief Find_FoundObject Search for a specific object in the cahe.
*/
struct objects *Find_TokenObject(struct objects * cacheTokenObjects, CK_ULONG objectHandler);
/**
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @param id Object id.
* @param type Type of the object.
* @param object Object pointer @see objects.
* @return Returns true if the object exist and false in other case.
* @brief Exist_Object S Returns true if the object exist and false in other case.
*/
BOOL Exist_TokenObject(struct objects * cacheTokenObjects, char *id, CK_ULONG type, struct objects ** object);
/**
* @param session Pointer to the cache. @see objects
* @return Void.
* @brief Free_All_TokenObject Free all the objects stored in a the cache.
*/
void Free_All_TokenObject(struct objects ** cacheTokenObjects);
/**
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @param id Object id.
* @param type Type of the object.
* @return Void
* @brief Free_CacheObject_By_Id If the object is a certificate type, it deletes all the keys and and the certificate, if the object is a key type (private or public), tries to eliminate the keys .
*/
void Free_CacheObject_By_Id(struct objects ** cacheTokenObjects, char *id, CK_ULONG type);
/***************************************************************************************//**
*                                     Primitive Helper
*******************************************************************************************/
/**
* @param session Pointer to the current sessions. @see sessions
* @param pTemplate Template with the required attributes @see CK_ATTRIBUTE
* @param ulcount Number of attributes in the template
* @param type Object Type.
* @param token. Grant access to the Azure Key Vault Rest API.
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @return Result of the operation for error handling.
* @brief Object_Searcher Find all objects that match the template. If the template is null it looks for all objects.
*/
CK_ULONG Object_Searcher(struct sessions * session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulcount, CK_ULONG type, CK_CHAR_PTR token, struct objects ** cacheTokenObjects);
/**
* @param object Pointer to the current object. @see object
* @param attribute Attribute to compare in the object @see CK_ATTRIBUTE
* @param match Match flag
* @param token. Grant access to the Azure Key Vault Rest API.
* @return  Result of the operation for error handling.
* @brief Compare_Attributes Function to compare an attribute with those of the referenced object
*/
CK_ULONG Compare_Attributes(struct objects *object, CK_ATTRIBUTE attribute, int *match, CK_CHAR_PTR token);
/**
* @param object Pointer to the current object. @see objects
* @param attribute Attribute to compare in the object @see CK_ATTRIBUTE
* @param match Match flag
* @param token. Grant access to the Azure Key Vault Rest API.
* @return  Result of the operation for error handling.
* @brief Compare_CommonAttributes Subfunction to compare an attribute with the object common attributes of the referenced object @see Compare_Attributes
*/
CK_ULONG Compare_CommonAttributes(struct objects * object, CK_ATTRIBUTE attribute, int * match, CK_CHAR_PTR token);
/**
* @param object Pointer to the current object. @see objects
* @param attribute Attribute to compare in the object @see CK_ATTRIBUTE
* @param match Match flag
* @param token. Grant access to the Azure Key Vault Rest API.
* @return  Result of the operation for error handling.
* @brief Compare_CommonKeyAttributes Subfunction to compare an attribute with the object common key attributes of the referenced key object @see Compare_Attributes
*/
CK_ULONG Compare_CommonKeyAttributes(struct objects * object, CK_ATTRIBUTE attribute, int * match, CK_CHAR_PTR token);
/**
* @param session Pointer to the current session @see session
* @param type Kind of object
* @param token. Grant access to the Azure Key Vault Rest API.
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @return  Result of the operation for error handling.
* @brief Object_Collector Store a list of all objects in a class.
*/
CK_ULONG Object_Collector(struct sessions * session, CK_ULONG type, CK_CHAR_PTR token, struct objects ** cacheTokenObect);
/**
* @param pTemplate Template with the required attributes @see CK_ATTRIBUTE
* @param currentObject Pointer to the current object @see objects
* @param token. Grant access to the Azure Key Vault Rest API.
* @param context Context for the log @see context
* @return  Result of the operation for error handling.
* @brief getAttributeInspector It separates the objects into types and calls the corresponding function responsible for returning the required information in the template. @see switch_common_attributes @see switch_certificate_attributes @see switch_public_private_key_attributes @see switch_secret_attributes
*/
CK_ULONG getAttributeInspector(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, CK_CHAR_PTR token, struct context *context);
/**
* @param pTemplate Template with the required attributes @see CK_ATTRIBUTE
* @param currentObject Pointer to the current object @see objects
* @param context Context for the log
* @return  Result of the operation for error handling.
* @brief switch_common_attributes Place the required attribute values in the template.
*/
CK_ULONG switch_common_attributes(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, struct context *context);
/**
* @param pTemplate Template with the required attributes @see CK_ATTRIBUTE
* @param currentObject Pointer to the current object @see objects
* @param token. Grant access to the Azure Key Vault Rest API.
* @param context Context for the log @see context
* @return  Result of the operation for error handling.
* @brief switch_certificate_attributes Place the required attribute values in the template.
*/
CK_ULONG switch_certificate_attributes(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, CK_CHAR_PTR token, struct context *context);
/**
* @param pTemplate Template with the required attributes. @see CK_ATTRIBUTE
* @param currentObject Pointer to the current object. @see objects
* @param token. Grant access to the Azure Key Vault Rest API.
* @param context Context for the log @see context
* @return  Result of the operation for error handling.
* @brief switch_public_private_key_attributes Place the required attribute values in the template.
*/
CK_ULONG switch_public_private_key_attributes(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, CK_CHAR_PTR token, struct context * context);
/**
* @param pTemplate Template with the required attributes. @see CK_ATTRIBUTE
* @param currentObject Pointer to the current object. @see objects
* @param context Context for the log @see context
* @return  Result of the operation for error handling.
* @brief switch_secret_attributes Place the required attribute values in the template.
*/
CK_ULONG switch_secret_attributes(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, struct context * context);
/**
* @param pTemplate Template with the required attributes @see CK_ATTRIBUTE
* @param ulcount Number of attributes in the template
* @param currentObject Pointer to the current object @see objects
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @param token. Grant access to the Azure Key Vault Rest API.
* @param context Context for the log @see context
* @return  Result of the operation for error handling.
* @brief objectUpdate It separates the objects into types and update the attributes that it can be updated
*/
CK_ULONG objectUpdate(CK_ATTRIBUTE_PTR *pTemplate, CK_ULONG ulCount, struct objects *currentObject, struct objects ** cacheTokenObect, CK_CHAR_PTR token, struct context *context);
/**
* @param key_ops Array of operations that can be done with the key. / Could be NULL for default behavior
* @param currentObject Pointer to the current object. @see objects
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @return  Result of the operation for error handling.
* @brief fillKeyOps Fill the key ops with the data in private and public keys
*/
CK_ULONG fillKeyOps(char *key_ops[], struct objects *currentObject, struct objects ** cacheTokenObect);
/**
* @param pTemplate Template with the required attributes @see CK_ATTRIBUTE
* @param updateKey Pointer to the new key data.
* @param currentObject Pointer to the current object.
* @param consolidate Flag to indicate if the information was accepted by Azure and can be consolidated.
* @return Result of the operation for error handling.
* @brief UpdateKey Update key data to store in Azure, only consolidate the new information if Azure accepts the change
*/
CK_ULONG UpdateKey(CK_ATTRIBUTE pTemplate, struct update_key *updateKey, struct objects *currentObject, BOOL consolidate);
/**
* @param pTemplate Template with the required attributes @see CK_ATTRIBUTE
* @param updateSecret Pointer to the new secret data.
* @param currentObject Pointer to the current object.
* @param consolidate Flag to indicate if the information was accepted by Azure and can be consolidated.
* @return Result of the operation for error handling.
* @brief UpdateSecret Update secret data to store in Azure, only consolidate the new information if Azure accepts the change
*/
CK_ULONG UpdateSecret(CK_ATTRIBUTE pTemplate, struct secret_creation_data *updateSecret, struct objects *currentObject, BOOL consolidate);
/**
* @param newObject Pointer to the new object. @see objects
* @param pTemplate Template with the required attributes @see CK_ATTRIBUTE
* @param ulCount Number of attributes in the template
* @param type Object Type.
* @param token. Grant access to the Azure Key Vault Rest API.
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @return Result of the operation for error handling.
* @brief ObjectCreator Create a new object in Azure with the template information.
*/
CK_ULONG ObjectCreator(struct objects **newObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG type, CK_CHAR_PTR token, struct objects ** cacheTokenObect);
/**
* @param value Base64 certificate.
* @param size Size of the DER encoded certificate.
* @return DER encoded certificate.
* @brief CertifiacteDERencode Encodes the  in DER format the certificate from Azure in base64 format.
*/
CK_CHAR_PTR *CertifiacteDERencode(CK_CHAR_PTR value, CK_ULONG * size);
/**
* @param certValue Certificate in base64.
* @param type Certificate fields to extract (CKA_ISSUER, CKA_SUBJECT, CKA_SERIAL_NUMBER).
* @param size Size of the extracted fields.
* @return Extracted fields in DER format.
* @brief ExtractCertData Extract from the certificate different fields in DER format.
*/
CK_CHAR_PTR * ExtractCertData(CK_CHAR_PTR * certValue, CK_ULONG type, CK_ULONG * size);
/**
* @param date Unixtime format date @see time_t
* @return CK_DATE format date @see CK_DATE
* @brief Unixtime2CK_DATE Convert unix format to CK DATE
*/
CK_DATE Unixtime2CK_DATE(time_t date);
/**
* @param certData Certified with Azure format. @see delete_update_cert_response
* @return Certified with PKCS#11 format. @see certificateObject
* @brief AzurePKCS11CertificateTranslator Translates the certificate in Azure format to pkcs11 format.
*/
struct certificateObject * AzurePKCS11CertificateTranslator(struct delete_update_cert_response *certData);
/**
* @param keyData Key with Azure format. @see key_data_response
* @param Type of key (CKO_PRIVATE_KEY, CKO_PUBLIC_KEY).
* @param token. Grant access to the Azure Key Vault Rest API.
* @param cacheTokenObjects Pointer to the chache of token objects. @see objects
* @return Key with PKCS#11 format. @see keyObject
* @brief AzurePKCS11KeyTranslator Translates the key in Azure format to pkcs11 formatr
*/
struct keyObject * AzurePKCS11KeyTranslator(struct key_data_response *keyData, CK_ULONG type, CK_CHAR_PTR token, struct objects ** cacheTokenObjects);
/**
* @param secretData Secret Data with Azure format. @see secret_item_data
* @return dataObject with PKCS#11 format. @see dataObject
* @brief AzurePKCS11DataObjectTranslator Translates the secret data in Azure format to pkcs11 formatr
*/
struct dataObject * AzurePKCS11DataObjectTranslator(struct secret_item_data *secretData);
/**
* @param hashed Hashed data.
* @param plain Data to hash.
* @param plen Lenght of the data.
* @return Length of the hash.
* @brief HashSHA256 Compute the sha256 hash of the data.
*/
int HashSHA256(unsigned char *hashed, const unsigned char *plain, size_t plen);
/**
* @param pTemplate Points to the template for the public or private key
* @param key_data Key material for the Azure Key Vault request
* @param type Key type (public or private)
* @param mechanism Key geneartion mechanism.
* @return Error code.
* @brief Template2JWK Parse pkcs11 key to Azure Key Vault key
*/
CK_ULONG Template2JWK(CK_ATTRIBUTE pTemplate, struct key_data *keyData, CK_ULONG type, CK_MECHANISM_TYPE mechanism);
/**
* @param pTemplate Points to the template for the CKO_DATA
* @param secretCreationData Secret metadata for the Azure Key Vault request
* @return Error code.
* @brief Template2JWS Parse pkcs11 data to Azure Key Vault secret
*/
CK_ULONG Template2JWS(CK_ATTRIBUTE_PTR pTemplate, struct secret_creation_data **secretCreationData);
/**
* @param key_data key material for the Azure Key Vault request
* @return Error code.
* @brief KeyMaterial_Checker Verify that all key material is complete to make the request.
*/
CK_ULONG KeyMaterial_Checker(struct key_data *keyData);
/**
* @param secretData Secret metadata for the Azure Key Vault request
* @return Error code.
* @brief SecretMetadata_Checker Verify that all secret metadata is complete to make the request.
*/
CK_ULONG SecretMetadata_Checker(struct secret_creation_data *secretData);
/**
* @param pTemplate Points to the template for the certificate
* @param certData Certificate material for the Azure Key Vault request
* @return Error code.
* @brief Template2JWCert Parse pkcs11 certificate to Azure Key Vault certificate
*/
CK_ULONG Template2JWCert(CK_ATTRIBUTE pTemplate, struct import_cert_data *certData);
/**
* @param create_cert Certificate material for the Azure Key Vault request
* @return Error code.
* @brief KeyMaterial_Checker Verify that all certificate material is complete to make the request.
*/
CK_ULONG CertificateMaterial_Checker(struct import_cert_data * certData);
/**
* @param date Date in PKCS#11 format.
* @return Date in linux format.
* @brief Ck_Date2unixtime Transforms the dates from pkcs#11 format to linux format.
*/
time_t Ck_Date2unixtime(CK_DATE date);
/**
* @param pData pointer to the ASN1 encoded data with the hash and the hash type.
* @param ulDataLen size of the data pointed by pData.
* @param ASN1HashType hash type.
* @param hashLen hash lenght.
* @return hash data.
* @brief DecodeASN1Hash Decode the asn1 data and extract the hash and hash type
*/
unsigned char * DecodeASN1Hash(CK_BYTE_PTR pData, CK_ULONG ulDataLen, int * ASN1HashType, int *hashLen);
///**
//* @param azureToken Azure Token to connect with the Key Vault API.
//* @return Result of the operation for error handling.
//* @brief GetAzureToken Function to request a new token from Azure Key Vault. 
//*/
//CK_ULONG GetAzureToken(CK_CHAR **azureToken);
/**
* @param old_TenantID Backup of the TenantID.
* @param old_Host Backup of the Host.
* @param old_Password Backup of the Password.
* @return Result of the operation for error handling.
* @brief BackUp_Old_Credentials Backup the Azure Key Vault credentials.
*/
CK_ULONG BackUp_Old_Credentials(CK_CHAR **old_TenantID, CK_CHAR **old_Host, CK_CHAR **old_Password);
/**
* @param old_TenantID Backup of the TenantID.
* @param old_Host Backup of the Host.
* @param old_Password Backup of the Password.
* @return Result of the operation for error handling.
* @brief BackUp_Old_Credentials Free the old Azure Key Vault credentials.
*/
void Free_Old_Credentials(CK_CHAR *old_TenantID, CK_CHAR *old_Host, CK_CHAR *old_Password);
///***************************************************************************************//**
//*                                     Keys Helper
//*******************************************************************************************/
///**
//* @param pPin User PIN to derive the Encryption key.
//* @param ulPinLen User PIN length.
//* @param configurationKey Resulting encryption key to encrypt the Azure Key Vault credentials. 
//* @param salt salt.
//* @param saltSize Salt length.
//* @return Result of the operation for error handling.
//* @brief DeriveKey Function to derive a encryption key to encrypt Azure Key Vault credentials
//*/
//CK_ULONG DeriveKey(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_CHAR **configurationKey, const unsigned char *salt, CK_ULONG saltSize);
///**
//* @param iv User Resulting IV to generate the encryption key.
//* @param id First piece of the IV
//* @param suffix Second piece of the IV
//* @return Result of the operation for error handling.
//* @brief DeriveKey Function to generate a pseudorandom IV
//*/
//CK_ULONG IVCalculator(const unsigned char *iv, CK_CHAR_PTR id, CK_CHAR_PTR suffix);
///**
//* @param parameter Parameter to encrypt.
//* @param cipherData Resulting encrypted parameter
//* @param iv Initialization vector
//* @param configurationKey Encryption key
//* @return Result of the operation for error handling.
//* @brief EncryptParameter Function to encrypt one parameter
//*/
//CK_ULONG EncryptParameter(CK_CHAR *parameter, CK_CHAR **cipherData, const unsigned char *iv, CK_CHAR *configurationKey);
///**
//* @param ciphertext Parameter to decrypt.
//* @param ciphertext_len Encrypted parameter length.
//* @param configurationKey Encryption key.
//* @param iv Initialization vector
//* @param plainData Resulting deciphered data
//* @return Result of the operation for error handling.
//* @brief DecryptParameter Function to decrypt one parameter
//*/
//CK_ULONG DecryptParameter(unsigned char *ciphertext, int ciphertext_len, CK_CHAR *configurationKey, unsigned char *iv, CK_CHAR **plainData);
///**
//* @param parameter Configuration parameter to encrypt.
//* @param parameterName Configuration parameter name.
//* @param configurationKey Encryption key.
//* @return Result of the operation for error handling.
//* @brief EncryptConfigurationData Function to encrypt a configuration parameter
//*/
//CK_ULONG EncryptConfigurationData(CK_CHAR_PTR *parameter, CK_CHAR_PTR parameterName, CK_CHAR_PTR configurationKey);
///**
//* @param pPin User PIN to derive the Encryption key.
//* @param ulPinLen User PIN length.
//* @return Result of the operation for error handling.
//* @brief EncryptAllConfigurationData Function to encrypt all the configuration data.
//*/
//CK_ULONG EncryptAllConfigurationData(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
///**
//* @param parameter Configuration parameter to decrypt.
//* @param parameterName Configuration parameter name.
//* @param configurationKey Encryption key.
//* @return Result of the operation for error handling.
//* @brief DecryptConfigurationData Function to decrypt a configuration parameter
//*/
//CK_ULONG DecryptConfigurationData(CK_CHAR_PTR *parameter, CK_CHAR_PTR parameterName, CK_CHAR_PTR configurationKey);
///**
//* @param pPin User PIN to derive the Encryption key.
//* @param ulPinLen User PIN length.
//* @return Result of the operation for error handling.
//* @brief DecryptAllConfigurationData Function to decrypt all the configuration data.
//*/
//CK_ULONG DecryptAllConfigurationData(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);


BOOL Session_Timeout(time_t session_opened);

#endif /* ___CRYPTOKI_H_INC___ */
