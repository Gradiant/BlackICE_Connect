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

#ifndef CLIENTRESTYPES_H_INCLUDED
#define CLIENTRESTYPES_H_INCLUDED

#define ALLOCATE_ERROR (-20)
#define PARSER_ERROR (-21)
#define CONF_FILE_NOT_FOUND (-22)
#define CLOSIGN_FILE_ERROR (-23)
#define BAD_CONF_FILE (-24)
#define HOST_MEMORY (-25)
#define SESSION_CLOSED (-26)
#define UNDEFINED_ERROR (-27)
#define OK (0)
#define FALSE_p (0)
#define TRUE_p (1)
#define GET_RQT (20)
#define DELETE_RQT (21)
#define MAX_OPS (6)
#define MAX_TOKEN_SIZE (1024)
//#define MAX_RECOVERYLEVEL (4)
//#define X509_KEY_USAGE_FLAGS (8)
//#define MAX_PERMITED_LENGTH (25)
//#define EMAIL_MAXIMUM_LENGTH (255)
#define MAX_SECRET_SIZE (25000 + 1)
#define MAX_CONTENT_TYPE (255 + 1)
#define MAX_ID_SIZE (60)
#define MAX_LABEL_SIZE (100)
#define MAX_ALGORITHM_TYPE_LENGHT (20)
#define MAXIMUM_PERMITED_PARAMETERS (8)
#define MAX_X5C_PARAMETERS (1)
#define MAX_KEY_SIZE (9 + 1)
// HTTP response codes 
#define HTTP_OK		  (200)
#define HTTP_ACCEPTED (202)
#define BAD_REQUEST   (400)
#define	UNAUTHORIZED  (401)
#define FORBIDDEN	  (403)
#define NOT_FOUND     (404)
#define METHOD_NOT_ALLOWED (405)

#define MAX_CONF_PARAMETER_SIZE (20)
#define CKU_PUBLIC (10)
#define TIMEOUT_INFINITE (-1)
#define TIMEOUT_DEFAULT (15)

#define MAX_JWA_ALGORITHM_LEN (10)

#define encrypt_op "encrypt"
#define decrypt_op "decrypt"
#define sign_op "sign"
#define verify_op "verify"
#define wrapkey_op "wrapKey"
#define unwrapKey_op "unwrapKey"

#define WINDOWS_AUTH "Windows"
#define SECURELOGIN_AUTH "SecureLogin"
#define AUTOLOGIN_AUTH "Autologin"

// This is the only thing needed here from common.h, that's why this is redeclared here instead of included.
typedef int BOOL;
char *APIVERSION;
char *AUTH_APIVERSION;
char *AUTH_URL;
char *RESOURCE;
char *CLIENTID;
char *TENANTID;
char *HOST;
char *PASSWORD;

#ifndef STRUCT_LOG_INFO
#define STRUCT_LOG_INFO
struct log_info {
	char *LOGS_PATH;
	int  DEBUG_LEVEL;
	long int MAX_LOG_BYTES;
	BOOL DELETE_PREV_LOG_FILE;
	BOOL LOG_MODE_SAVE_HISTORY;
} LOG_CONTEXT;
#endif /* STRUCT_LOG_INFO */

long int SESSION_TIMEOUT;
BOOL HSM_PROCESSED;
BOOL CIPHER;
char *TOKEN;
time_t TOKEN_CREATION;
char* AUTH_METHOD;

//GCC throws warning about those structs being declared inside parameter list of functions in this file (they are
//actually not included from ClientRest.h) and then it throws "error: conflicting types for <function_name>".
struct cert_policy;
struct issuer;
struct lifetime_actions;
struct x509_props;
struct cert_key_prop;

/***************************************************************************************//**
*                                     Prototypes
*******************************************************************************************/
/**
* @param token. Grant access to the Rest API.
* @param host.  Destination resource.
* @param id. Name of the key / Could be NULL for list keys but not for list key version.
* @returns. Pointer to the new struct id_http_data. @see id_http_data
* @brief Store_IdHttpData Function that creates the structure with the necessary data to make the following calls: Get_key,  Get_ListKeyVersion, Get_CertificateVersions, Get_GetCertificateOperation, Delete_Certificate, Delete_CertificateOperation, Get_CertPolicy, Get_Certificate.
*/
struct id_http_data *Store_IdHttpData(char *token, char *host, char *id);
/**
* @param delData Pointer to structure id_http_data. @see id_http_data
* @return Void.
* @brief Free_IdHttpData Function that frees all reserved memory in the structure id_http_data.
*/
void Free_IdHttpData(struct id_http_data *listKeyData);
/**
* @param token. Grant access to the Rest API.
* @param value. data to store.
* @param value. Name of the key / Could be NULL for list keys but not for list key version.
* @returns. Pointer to the new struct id_http_data. @see value_http_data
* @brief Store_ValueHttpData Function that creates the structure with the necessary data to make the following calls: Restore_Key.
*/
struct value_http_data *Store_ValueHttpData(char *token, char *host, char *value);
/**
* @param delData Pointer to structure value_http_data. @see value_http_data
* @return Void.
* @brief Free_ValueHttpData Function that frees all reserved memory in the structure value_http_data.
*/
void Free_ValueHttpData(struct value_http_data *delData);
/**
* @param url Complete rest request.
* @param parameters Post fields json style.
* @param token Grant access to the Rest API / Could be NULL if was invocated from  Get_AccesToken.
* @param sesion Flag that indicates if the request need authentication or not.
* @returns Pointer to the struct request_data. @see request_data
* @brief Function that creates structure with the required data fot Https_Request.
*/
struct request_data *Store_HttpsData(char *url, char *parameters, char *token, int sesion);
/**
* @param delData Pointer to structure request_data. @see request_data
* @return Void.
* @brief Free_HttpsData Function that frees all reserved memory in the structure request_data.
*/
void Free_HttpsData(struct request_data *delData);
/**
* @param token_type type of the token usually bearer (Azure only suports bearer).
* @param resource Resource to access.
* @param acces_token Grant access to the Rest API.
* @param expires_in How long does the token_acces.
* @param  ext_expires_in How long does the token_acces valid.
* @paraam expires_on When the token expires.
* @param  not_before
* @returns Pointer to the struct token_response. @see token_response
* @brief Store_AccesTokenResponse Function that creates structure with the acces_token information.
*/
struct token_response *Store_AccesTokenResponse(const char *token_type, const char *resource, const char *access_token, unsigned long int expires_in, unsigned long int ext_expires_in, unsigned long int expires_on, unsigned long int not_before);
/**
* @param delData Pointer to structure token_response. @see token_response
* @return Void.
* @brief Free_AccesTokenResponse Function that frees all reserved memory in the structure token_response.
*/
void Free_AccesTokenResponse(struct token_response *delData);
/**
* @param password Private password entered by the customer.
* @param authUrl Root of rest request.
* @param resource Resource to access.
* @param clientId This identifier will be assigned when Seq is set up as an application in the directory instance.
* @param tenantId This is the unique identifier of the Azure Active Directory instance
* @returns Pointer to the struct client_data @see client_data
* @brief Store_ClientData Function that creates the structure with the necessary data to get the token.
*/
struct client_data *Store_ClientData(char *password, char *authUrl, char *resource, char *clientId, char *tenantId);
/**
* @param delData Pointer to structure client_data. @see client_data
* @return Void.
* @brief Free_ClientData Function that frees all reserved memory in the structure client_data.
*/
void Free_ClientData(struct client_data *delData);
/**
* @param url Rest request
* @param token Grant access to the Rest API
* @returns Pointer to the struct basic_http_data @see basic_http_data
* @brief Store_BasicHttpData Function that creates the structure with the basic information to make the following calls: Get_ListKeys, Get_CertificateList.
*/
struct basic_http_data *Store_BasicHttpData(char *token, char *url);
/**
* @param delData Pointer to structure basic_http_data. @see basic_http_data
* @return Void.
* @brief Free_BasicHttpData Function that frees all reserved memory in the structure basic_http_data.
*/
void Free_BasicHttpData(struct basic_http_data *delData);
/**
* @param enabled Determines whether the object is enabled.
* @param nbf Not before date in UTC.
* @param exp Expiry date in UTC.
* @param created Creation time in UTC.
* @param updated Last updated time in UTC.
* @returns Pointer to the struct key_attributes. @see key_attributes
* @brief Store_KeyAttributes Function that creates structure with the required data for key attributes.
*/
struct key_attributes *Store_KeyAttributes(BOOL enabled, unsigned long int nbf, unsigned long int exp, unsigned long int created, unsigned long int updated);
/**
* @param delData Pointer to structure key_attributes. @see key_attributes
* @return Void.
* @brief Free_KeyAttributes Function that frees all reserved memory in the structure key_attributes.
*/
void Free_KeyAttributes(struct key_attributes *delData);
/**
* @param host  Destination resource.
* @param id The name for the new key.
* @param keytype The type of key to create. For valid key types, see JsonWebKeyType. Supported JsonWebKey key types (kty) for Elliptic Curve, RSA, HSM, Octet.
* @param keysize The key size in bytes. For example, 1024 or 2048.
* @param key_ops[] Array of operations that can be done with the key. / Could be NULL for default behavior
* @param token  Grant access to the Rest API.
* @param attributes The attributes of a key managed by the key vault service. / Could be NULL for default behavior. @see key_attributes
* @param tags Application specific metadata in the form of key-value pairs. / Could be NULL.
* @param crv Curve type for EC keys
* @returns Pointer to the struct key_data. @see key_data
* @brief Store_KeyData Function that creates structure with the required data to create a key. Create_key.
*/
struct key_data *Store_KeyData(char *host, char *id, char *keytype, char *keysize, char *key_ops[], const char *token, struct key_attributes *attributes, char *tags, char *crv);
/**
* @param delData Pointer to structure key_data. @see key_data
* @return Void.
* @brief Free_KeyData Function that frees all reserved memory in the structure key_data.
*/
void Free_KeyData(struct key_data *delData);
/**
* @param host  Destination resource.
* @param key_id The name for the new key.
* @param token  Grant access to the Rest API.
* @param key_ops[] Array of operations that can be done with the key. / Could be NULL for default behavior
* @param attributes The attributes of a key managed by the key vault service. / Could be NULL for default behavior. @see key_attributes
* @returns Pointer to the struct key_data. @see key_data
* @brief Store_UpdateKeyData Function that creates structure with the required data to create a key. Update_key.
*/
struct update_key *Store_UpdateKeyData(char *host, char *key_id, char *token, char *key_ops[], struct key_attributes *attributes);
/**
* @param delData Pointer to structure update_key. @see update_key
* @return Void.
* @brief Free_UpdateKeyData Function that frees all reserved memory in the structure update_key.
*/
void Free_UpdateKeyData(struct update_key *delData);
/**
* @param host  Destination resource.
* @param id The name for the new key.
* @param token  Grant access to the Rest API.
* @returns Pointer to the struct delete_key. @see delete_key
* @brief Store_DeleteKey Function that creates structure with the required data to delete a key. Delete_key.
*/
struct delete_key *Store_DeleteKey(char *host, char *id, const char *token);
/**
* @param delData Pointer to structure key_data. @see key_data
* @return Void.
* @brief Free_DeleteKey Function that frees all reserved memory in the structure delete_key.
*/
void Free_DeleteKey(struct delete_key *delData);
/**
* @param id The name for the new key.
* @param attributesn The attributes of a key managed by the key vault service. @see key_attributes
* @param tags Application specific metadata in the form of key-value pairs. / Could be NULL.
* @param managed True if the key's lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.
* @returns Pointer to the struct list_key. @see list_key
* @brief Store_ListKey Function that creates structure with the the response of the following functions: Get_ListKeys_version,Get_ListKeys.
**/
struct list_key *Store_ListKey(char * id, struct key_attributes *attributes, char *tags, BOOL managed);
/**
* @param delData Pointer to structure list_key. @see list_key
* @return Void.
* @brief Free_ListKey Function that frees all reserved memory in the structure list_key.
*/
void Free_ListKey(struct list_key *delData);
/**
* @param id The name for the new key whit the concrete version of the key.
* @param token  Grant access to the Rest API.
* @param host  Destination resource.
* @param signtype The signing/verification algorithm identifier. For more information on possible algorithm types, see JsonWebKeySignatureAlgorithm.
* @param hash The hash of the file to be signed
* @param value The value of the sign.
* @returns Pointer to the struct verify_data. @see verify_data
* @brief Store_VerifyData Function that creates structure with the required data to be verified. Verify call.
*/
struct verify_data *Store_VerifyData(char *id, char *token, char *host, char *signtype, char *hash, char *value);
/**
* @param delData Pointer to structure verify_data. @see verify_data
* @return Void.
* @brief Free_VerifyData Function that frees all reserved memory in the structure verify_data.
*/
void Free_VerifyData(struct verify_data *delData);
/**
* @param id The object identifier.
* @param sign The value returned by the operation.
* @return Pointer to the struct verify_data operation_response. @see operation_response
* @brief Store_OperationResponse Function that creates the structure with the result of the requested operation. Used in: Sign, Encript_Data, Decript_Data, parse_operation_response.
*/
struct operation_response *Store_OperationResponse(char *id, char *sign);
/**
* @param delData Pointer to structure operation_response. @see operation_response
* @return Void.
* @brief Free_OperationResponse Function that frees all reserved memory in the structure operation_response.
*/
void Free_OperationResponse(struct operation_response *delData);
/**
* @param value The value returned by the operation.
* @return Pointer to the struct simple_operation_response. @see simple_operation_response
* @brief Store_SimpleOperationResponse Function that creates the structure with the result of the requested operation. Used in: backup and restore a key.
*/
struct simple_operation_response *Store_SimpleOperationResponse(char *value);
/**
* @param delData Pointer to structure operation_response. @see operation_response
* @return Void.
* @brief Free_SimpleOperationResponse Function that frees all reserved memory in the structure simple_operation_response.
*/
void Free_SimpleOperationResponse(struct simple_operation_response *delData);
/**
* @param id. The name for the new key.
* @param keytype. Supported JsonWebKey key types (kty) for Elliptic Curve, RSA, HSM, Octet. Kty is usually set to RSA. Currently azure supports RSA or RSA_HSM.
* @param key_ops[] Identifies the operation(s) for which the key is intended to be used.
* @param n RSA modulus.
* @param e RSA public exponent.
* @param d RSA private exponent. / Could be NULL.
* @param dp RSA private key parameter. / Could be NULL.
* @param dq RSA private key parameter. / Could be NULL.
* @param qi RSA private key parameter. / Could be NULL.
* @param p RSA secret prime. / Could be NULL.
* @param q RSA secret prime, with p < q. / Could be NULL.
* @param k Symmetric key. / Could be NULL.
* @param key_hsm HSM Token, used with 'Bring Your Own Key'. / Could be NULL.
* @param attributes The key management attributes. @see key_attributes
* @param tags Application specific metadata in the form of key-value pairs. / Could be NULL.
* @param managed True if the key's lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.
* @returns Pointer to the struct key_data_response. @see key_data_response
* @brief Store_KeyDataResponse Function that creates the structure with the result of the following operations. Create_key, Get_Key, parse_create_key_response.
*/
struct key_data_response *Store_KeyDataResponse(char *id, char *keytype, char *key_ops[], char *n, char *e, char *d, char *dp, char *dq, char *qi, char *p, char *q, char *k, char *key_hsm, struct key_attributes *attributes, char *tags, BOOL managed, char *crv, char *x, char *y);
/**
* @param delData Pointer to structure key_data_response.
* @return Void.
* @brief Free_KeyCreationResponse Function that frees all reserved memory in the structure key_data_response.
*/
void Free_KeyCreationResponse(struct key_data_response *delData);
/**
* @param recoveryLevel[] Reflects the deletion recovery level currently in effect for certificates in the current vault. If it contains 'Purgeable', the certificate can be permanently deleted by a privileged user; otherwise, only the system can purge the certificate, at the end of the retention interval.
* @param enabled Determines whether the object is enabled.
* @param nbf Not before date in UTC.
* @param exp Expiry date in UTC.
* @param created Creation time in UTC.
* @param updated Last updated time in UTC.
* @returns Pointer to the struct cert_attributes. @see cert_attributes
* @brief Store_CertAttributes Function that creates structure with the required data to create certificate attributes.
*/
struct cert_attributes *Store_CertAttributes(char *recoveryLevel, BOOL enabled, unsigned long int nbf, unsigned long int exp, unsigned long int created, unsigned long int updated);
/**
* @param delData Pointer to structure cert_attributes. @see cert_attributes
* @return Void.
* @brief Free_CertAttributes Function that frees all reserved memory in the structure cert_attributes.
*/
void Free_CertAttributes(struct cert_attributes *delData);
/**
* @param token  Grant access to the Rest API.
* @param host  Destination resource.
* @param name The name of the certificate.
* @param base64Value Base64 encoded representation of the certificate object to import. This certificate needs to contain the private key.
* @param pwd If the private key in base64EncodedCertificate is encrypted, the password used for encryption.
* @param certPolicy The management policy for the certificate. @see cert_policy
* @param cerAttributes The attributes of the certificate (optional). @see cert_attributes
* @param tags Application specific metadata in the form of key-value pairs.
* @returns Pointer to the struct import_cert_data. @see import_cert_data
* @description Store_ImportCertData Function that creates structure with the required data to import certificates.
*/
struct import_cert_data *Store_ImportCertData(char * token, char *host, char *name, char * base64Value, char * pwd, struct cert_policy * certPolicy, struct cert_attributes * cerAttributes, char * tags);
/**
* @param delData Pointer to structure import_cert_data. @see import_cert_data
* @return Void.
* @brief Free_ImportCertData Function that frees all reserved memory in the structure import_cert_data.
*/
void Free_ImportCertData(struct import_cert_data *delData);
/**
* @param id The certificate id.
* @param keyProp Properties of the key backing a certificate. @see cert_key_prop
* @param x509Props Properties of the X509 component of a certificate. @see x509_props
* @param lifeTimeActions Actions that will be performed by Key Vault over the lifetime of a certificate. @see lifetime_actions
* @param cerAttributes The certificate attributes. @see cert_attributes
* @param issuer Parameters for the issuer of the X509 component of a certificate. @see issuer
* @returns Pointer to the struct cert_policy. @see cert_policy
* @brief Store_CertPolicy Function that creates structure with the required data to store cert policy.
*/
struct cert_policy *Store_CertPolicy(char *id, struct cert_key_prop *keyProp, struct x509_props *x509Props, struct lifetime_actions *lifeTimeActions, struct cert_attributes *cerAttributes, struct issuer *issuer);
/**
* @param delData Pointer to structure cert_policy. @see cert_policy
* @return Void.
* @brief Free_CertPolicy Function that frees all reserved memory in the structure cert_policy.
*/
void Free_CertPolicy(struct cert_policy *delData);
/**
* @param exportable Indicates if the private key can be exported.
* @param kty The key type.
* @param key_size The key size in bytes. For example; 1024 or 2048.
* @param reuse_key Indicates if the same key pair will be used on certificate renewal.
* @param contentType The media type (MIME type).
* @returns Pointer to the struct cert_key_prop. @see cert_key_prop
* @brief Store_CertKeyProp Function that creates structure with the required data  to store the key_props.
*/
struct cert_key_prop *Store_CertKeyProp(BOOL exportable, char *kty, int key_size, BOOL reuse_key, char *contentType);
/**
* @param delData Pointer to structure cert_key_prop. @see cert_key_prop
* @return Void.
* @brief Free_CertKeyProp Function that frees all reserved memory in the structure cert_key_prop.
*/
void Free_CertKeyProp(struct cert_key_prop *delData);
/**
* @param subject The subject name. Should be a valid X509 distinguished Name.
* @param ekus The enhanced key usage.
* @param emails Email addresses.
* @param dnsNames Domain names.
* @param upns User principal names.
* @param keyUsage List of key usages.
* @param validityMonths The duration that the ceritifcate is valid in months.
* @returns Pointer to the struct. @see x509_props
* @brief Store_X509Props Function that creates structure with the required data to set x509 Properties.
*/
struct x509_props *Store_X509Props(char *subject, char *ekus[], char *emails[], char *dnsNames[], char *upns[], char *keyUsage[], int  validityMonths);
/**
* @param delData Pointer to structure x509_props. @see x509_props
* @return Void.
* @brief Free_X509Props Function that frees all reserved memory in the structure x509_props.
*/
void Free_X509Props(struct x509_props *delData);
/**
* @param lifetimePercentage Percentage of lifetime at which to trigger. Value should be between 1 and 99.
* @param daysBeforeExpiry Days before expiry.
* @param actionType The type of the action.
* @returns Pointer to the struct lifetime_actions. @see lifetime_actions
* @brief Store_LifeTimeActions Function that creates structure with the required data to set the actions.
*/
struct lifetime_actions *Store_LifeTimeActions(int lifetimePercentage, int daysBeforeExpiry, char *actionType);
/**
* @param delData Pointer to structure lifetime_actions. @see lifetime_actions
* @return Void.
* @brief Free_LifeTimeActions Function that frees all reserved memory in the structure lifetime_actions.
*/
void Free_LifeTimeActions(struct lifetime_actions *delData);
/**
* @param name Name of the referenced issuer object or reserved names; for example, 'Self' or 'Unknown'.
* @param cty Type of certificate to be requested from the issuer provider.
* @returns Pointer to the struct issuer. @see issuer
* @brief Store_Issuer Function that creates structure with the required data to set the issuer.
*/
struct issuer *Store_Issuer(char *name, char *cty);
/**
* @param delData Pointer to structure issuer. @see issuer
* @return Void.
* @brief Free_Issuer Function that frees all reserved memory in the structure issuer.
*/
void Free_Issuer(struct issuer *delData);
/**
* @param certAttributes Certificate Attributes @see cert_attributes
* @param id Certificate identifier.
* @param tags Application specific metadata in the form of key-value pairs.
* @param x5t Thumbprint of the certificate.
* @returns Pointer to the struct cert_data. @see cert_data
* @brief Store_CertData Function that creates structure with the basic cert data.
*/
struct cert_data *Store_CertData(struct cert_attributes *certAttributes, char *id, char *tags, char *x5t);
/**
* @param delData Pointer to structure cert_data. @see cert_data
* @return Void.
* @brief Free_CertData Function that frees all reserved memory in the structure cert_data.
*/
void Free_CertData(struct cert_data * delData);
/**
* @param handler PKCS#11 identifier.
* @param certData Basic certificate data. @see cert_data
* @param next Pointer to the next certificate.
* @returns Pointer to the struct cert_list. @see cert_list
* @brief Store_CertList Function that creates structure whit certificate data. Result of the following calls: Get_CertificateList, Get_Certificate_Versions, parse_list_certificate_response.
*/
struct cert_list *Store_CertList(int handler, struct cert_data *certData, struct cert_list *next);
/**
* @param delData Pointer to structure cert_list. @see cert_list
* @return Void.
* @brief Free_CertList Function that frees all reserved memory in the structure cert_list.
*/
void Free_CertList(struct cert_list * delData);
/**
* @param id The certificate id.
* @param issuer Parameters for the issuer of the X509 component of a certificate. @see issuer
* @param csr The certificate signing request (CSR) that is being used in the certificate operation.
* @param cancellation_requested Indicates if cancellation was requested on the certificate operation.
* @param status Status of the certificate operation.
* @param target Location which contains the result of the certificate operation.
* @param request_id Identifier for the certificate operation.
* @returns Pointer to the struct cert_operation_response. @see cert_operation_response
* @brief Store_CertOperation Function that creates structure whit certificate operation response.
*/
struct cert_operation_response * Store_CertOperation(char *id, struct issuer *issuer, char *csr, BOOL cancellation_requested, char *status, char *target, char *request_id);
/**
* @param delData Pointer to structure cert_operation_response. @see cert_operation_response
* @return Void.
* @brief Free_CertOperation Function that frees all reserved memory in the structure cert_operation_response.
*/
void Free_CertOperation(struct cert_operation_response * delData);
/**
* @param token  Grant access to the Rest API.
* @param host  Destination resource.
* @param certPolicy The management policy for the certificate. @see cert_policy
* @param cerAttributes The attributes of the certificate (optional). @see cert_attributes
* @param tags Application specific metadata in the form of key-value pairs.
* @param name Description.
* @returns Pointer to the struct create_cert. @see create_cert
* @brief Store_CreateCertData Function that creates structure for create or update a certificate. Used on the following calls: Create_Certificate, Update_Certificate, Update_CertPolicy, CreateCertificate2Json.
*/
struct create_cert * Store_CreateCertData(const char *token, char *host, struct cert_policy *certPolicy, struct cert_attributes *cerAttributes, char *tags, char *name);
/**
* @param delData Pointer to structure create_cert. @see create_cert
* @return Void.
* @brief Free_CreateCertData Function that frees all reserved memory in the structure create_cert.
*/
void Free_CreateCertData(struct create_cert * delData);
/**
* @param id The certificate id.
* @param kid The key id.
* @param sid The secret id.
* @param x5t Thumbprint of the certificate.
* @param cer CER contents of x509 certificate.
* @param cerAttributes The certificate attributes. @see cert_attributes
* @param cerPolicy The management policy. @see cert_policy
* @param pendingId The id of the request.
* @returns Pointer to the struct delete_update_cert_response. @see delete_update_cert_response
* @brief Store_DeleteUpdateCertResponse Function that creates structure for delete or update certificate response.
*/
struct delete_update_cert_response *Store_DeleteUpdateCertResponse(char *id, char *kid, char *sid, char *x5t, char *cer, struct cert_attributes *cerAttributes, struct cert_policy *cerPolicy, char *pendingId);
/**
* @param delData Pointer to structure delete_update_cert_response. @see delete_update_cert_response
* @return Void.
* @brief Free_DeleteUpdateCertResponse Function that frees all reserved memory in the structure delete_update_cert_response.
*/
void Free_DeleteUpdateCertResponse(struct delete_update_cert_response * delData);
/**
* @param code The error code.
* @param message The error message.
* @param innererror The key vault server error.
* @returns Pointer to the struct error. @see error
* @brief Store_Error Function that creates structure for error manage.
*/
struct error *Store_Error(char* code, char *message, char *innererror);
/**
* @param delData Pointer to structure error. @see error
* @return Void.
* @brief Free_Error Function that frees all reserved memory in the structure error.
*/
void Free_Error(struct error *delData);
/**
* @param certOperationResponse Pointer to the cert_operation_response struct. @see cert_operation_response
* @param status_details The status details of the certificate operation.
* @param error Error encountered, if any, during the certificate operation. @see error
* @returns Pointer to the struct cert_operation_delete. @see cert_operation_delete
* @brief Store_CertOperationDelete Function that creates structure for the Delete Cetificate Response call.
*/
struct cert_operation_delete * Store_CertOperationDelete(struct cert_operation_response * certOperationResponse, char * status_details, struct error * error);
/**
* @param delData Pointer to structure cert_operation_delete. @see cert_operation_delete
* @return Void.
* @brief Free_CertOperationDelete Function that frees all reserved memory in the structure cert_operation_delete.
*/
void Free_CertOperationDelete(struct cert_operation_delete *delData);
/**
* @param token. Grant access to the Rest API.
* @param keyid Key identifier
* @param host  Destination resource.
* @param algorithm algorithm identifier
* @param value Value of the operation.
* @returns Pointer to the struct operation_data. @see operation_data
* @brief Store_OperationData Function that creates structure for an Operation Response call.
*/
struct operation_data * Store_OperationData(const char *token, char* keyid, char *host, char *algorithm, char *value);
/**
* @param delData Pointer to structure operation_data. @see operation_data
* @return Void.
* @brief Free_OperationData Function that frees all reserved memory in the structure operation_data.
*/
void Free_OperationData(struct operation_data *delData);
/**
* @param token  Grant access to the Rest API.
* @param host  Destination resource.
* @param name Certificate name.
* @param cerAttributes The attributes of the certificate (optional). @see cert_attributes.
* @param tags Application specific metadata in the form of key-value pairs. (Not used).
* @param x5c (X.509 Certificate Chain) Parameter.
* @returns Pointer to the struct merge_data. @see merge_data
* @brief Store_MergeData Function that creates structure for merges a certificate or a certificate chain with a key pair existing on the server.
*/
struct merge_data * Store_MergeData(char *token, char *host, char *certName, struct cert_attributes *cerAttributes, char *tags, char *x5c[]);
/**
* @param delData Pointer to structure merge_data. @see merge_data
* @return Void.
* @brief Free_OperationData Function that frees all reserved memory in the structure merge_data.
*/
void Free_MergeData(struct merge_data *delData);
/**
* @param id Secret identifier.
* @param contentType Type of the secret value such as a password.
* @param attributes The secret management attributes.
* @param tags Application specific metadata in the form of key-value pairs.
* @param managed True if the secret's lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.
* @param deletedDate The time when the secret was deleted, in UTC
* @param recoveryId The url of the recovery object, used to identify and recover the deleted secret.
* @param scheduledPurgeDate The time when the secret is scheduled to be purged, in UTC
* @brief Store_SecretItems Function that creates structure to store metadata about the secret items, see @secret_items
*/
struct secret_items *Store_SecretItems(char * id, char* contentType, struct cert_attributes *attributes, char *tags, BOOL managed, int deletedDate, char *recoveryId, int scheduledPurgeDate);
/**
* @param delData Pointer to structure secret_items. @see secret_items
* @return Void.
* @brief Free_SecretItems Function that frees all reserved memory in the structure secret_items.
*/
void Free_SecretItems(struct secret_items *delData);
/**
* @param id Secret identifier.
* @param kid If this is a secret backing a KV certificate, then this field specifies the corresponding key backing the KV certificate.
* @param value The secret value.
* @param contentType Type of the secret value such as a password.
* @param attributes The secret management attributes.
* @param tags Application specific metadata in the form of key-value pairs.
* @param managed True if the secret's lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.
* @param deletedDate The time when the secret was deleted, in UTC
* @param recoveryId The url of the recovery object, used to identify and recover the deleted secret.
* @param scheduledPurgeDate The time when the secret is scheduled to be purged, in UTC
* @brief Store_SecretItemsData Function that creates structure to store metadata about the secret items, see @secret_item_data
*/
struct secret_item_data *Store_SecretItemsData(char *id, char *kid, char *value, char *contentType, struct cert_attributes *attributes, char *tags, BOOL managed, int deletedDate, char *recoveryId, int scheduledPurgeDate);
/**
* @param delData Pointer to structure secret_item_data. @see secret_item_data
* @return Void.
* @brief Free_SecretItems Function that frees all reserved memory in the structure secret_item_data.
*/
void Free_SecretItemsData(struct secret_item_data *delData);
/**
* @param id Secret identifier.
* @param attributes The secret management attributes.
* @param contentType Type of the secret value such as a password.
* @param tags Application specific metadata in the form of key-value pairs.
* @brief Store_SecretUpdateResponse Function that creates structure to store metadata about the secret update response, see @secret_update_response
*/
struct secret_update_response *Store_SecretUpdateResponse(char *id, struct cert_attributes *attributes, char *contentType, char* tags);
/**
* @param delData Pointer to structure secret_update_response. @see secret_update_response
* @return Void.
* @brief Free_SecretUpdateResponse Function that frees all reserved memory in the structure secret_update_response.
*/
void Free_SecretUpdateResponse(struct secret_update_response *delData);
/**
* @param token  Grant access to the Rest API.
* @param host  Destination resource.
* @param id Secret identifier.
* @param attributes The secret management attributes.
* @param contentType Type of the secret value such as a password.
* @param tags Application specific metadata in the form of key-value pairs.
* @param value The secret value.
* @brief Store_SecretCreationData Function that creates structure to store metadata about the secret creation item, see @secret_creation_data
*/
struct secret_creation_data *Store_SecretCreationData(char *token, char *host, char *id, struct cert_attributes *attributes, char *contentType, char* tags, char *value);
/**
* @param delData Pointer to structure secret_creation_data. @see secret_creation_data
* @return Void.
* @brief Free_SecretItems Function that frees all reserved memory in the structure secret_creation_data.
*/
void Free_SecretCreationData(struct secret_creation_data *delData);
/**
* @return Void.
* @brief Free_SecretData Function that frees all secret data.
*/
void Free_SecretData(void);
/***************************************************************************************//**
*                                     Configuration file and function helper
*******************************************************************************************/
/**
* @returns Error identifier.
* @brief ConfigureApplication Initial Library Configuration Function.
*/
int ConfigureApplication(void);
/**
* @return Void.
* @brief clearGlobalData Clear all global data.
*/
void ClearGlobalData(void);
/**
* @return Error identifier.
* @brief EncryptConfFile Encrypt the configuration file.
*/
int EncryptConfFile(void);
/**
* @return Error identifier.
* @brief GetToken Get Azure Key Vault token.
*/
int GetToken(char **azureToken);
#endif // CLIENTRESTYPES_H_INCLUDED
