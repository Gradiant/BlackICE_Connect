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

#ifndef CLIENTREST_H_INCLUDED
#define CLIENTREST_H_INCLUDED

#include <curl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "clientRestTypes.h"

/**
* @param size Size of the data.
* @param data Data to store.
* @brief url_data Support structure for storing data and its length.
*/
struct url_data {
	size_t size;
	char *data;
};

/**
* @param url Full resource URL with request
* @param sesion Indicates if there is already an active session in which case the token will be passed
* @param parameters Parameters in JSON format for the request
* @param token. Grant access to the Rest API.
* @brief request_data Structure that stores the information needed to make the https call.
*/
struct request_data {
	char *url;
	int sesion;
	char *parameters;
	char * token;
};

/**
* @param token_type type of the token usually bearer (Azure only suports bearer).
* @param expires_in How long does the token_acces.
* @param  ext_expires_in How long does the token_acces valid.
* @paraam expires_on When the token expires.
* @param not_before
* @param resource Resource to access.
* @param access_token The requested access token. The app can use this token to authenticate to the secured resource, such as a web API.
* @brief token_response Structure to store token information response
*/
struct token_response {
	char *token_type;
	unsigned long int expires_in;
	unsigned long int ext_expires_in;
	unsigned long int expires_on;
	unsigned long int not_before;
	char *resource;
	char *access_token;
};

/**
* @param password Private password entered by the customer.
* @param AUTH_URL Root of rest request.
* @param RESOURCE Resource to access.
* @param CLIENTID This identifier will be assigned when Seq is set up as an application in the directory instance.
* @param CLIENTSECRET CLIENTSECRET Authentication key string.
* @param TENANTID This is the unique identifier of the Azure Active Directory instance
* @brief client_data Information needed for authentication and to receive the token.
*/
struct client_data {
	char *password;
	char *AUTH_URL;
	char *RESOURCE;
	char *CLIENTID;
	char *CLIENTSECRET;
	char *TENANTID;
};

/**
* @param token he requested access token. The app can use this token to authenticate to the secured resource, such as a web API.
* @param id. Name of the key / Could be NULL for list keys but not for list key version.
* @param host.  Destination resource.
* @brief id_http_data Structure with the necessary data to make the following calls: Get_key,  Get_ListKeyVersion, Get_CertificateVersions, Get_GetCertificateOperation, Delete_Certificate, Delete_CertificateOperation, Get_CertPolicy, Get_Certificate.
*/
struct id_http_data {
	char *token;
	char* id;
	char *host;
};
/**
* @param url Rest request.
* @param token Grant access to the Rest API.
* @brief basic_http_data structure with the basic information to make the following calls: Get_ListKeys, Get_CertificateList.
*/
struct basic_http_data {
	char *url;
	char *token;
};
/**
* @param token. Grant access to the Rest API.
* @param keyid Key identifier
* @param host  Destination resource.
* @param algorithm algorithm identifier
* @param value Value of the operation.
* @brief operation_data Structure for an Operation Response call.
*/
struct operation_data {
	char *token;
	char* keyid;
	char *host;
	char algorithm[MAX_ALGORITHM_TYPE_LENGHT];
	char *value;
};
/**
* @param keyid The object identifier.
* @param value The value returned by the operation.
* @brief operation_response Structure with the result of the requested operation. Used in: Sign, Encript_Data, Decript_Data, parse_operation_response.
*/
struct operation_response {
	char *keyid;
	char *value;
};

/**
* @param id The name for the new key whit the concrete version of the key.
* @param token  Grant access to the Rest API.
* @param host  Destination resource.
* @param signtype The signing/verification algorithm identifier. For more information on possible algorithm types, see JsonWebKeySignatureAlgorithm.
* @param hash The hash of the file to be signed
* @param value The value of the sign.
* @brief verify_data Structure with the required data to be verified. Verify call.
*/
struct verify_data {
	char *id;
	char *token;
	char *host;
	char *signtype;
	char *hash;
	char *value;
};

/**
* @param enabled Determines whether the object is enabled.
* @param nbf Not before date in UTC.
* @param exp Expiry date in UTC.
* @param created Creation time in UTC.
* @param updated Last updated time in UTC.
* @brief key_attributes Structure with the required data for key attributes.
*/
struct key_attributes {
	BOOL enabled;
	unsigned long int nbf;
	unsigned long int exp;
	unsigned long int created;
	unsigned long int updated;
};
/**
* @param host  Destination resource.
* @param id The name for the new key.
* @param keytype The type of key to create. For valid key types, see JsonWebKeyType. Supported JsonWebKey key types (kty) for Elliptic Curve, RSA, HSM, Octet.
* @param keysize The key size in bytes. For example, 1024 or 2048.
* @param key_ops Array of operations that can be done with the key. / Could be NULL for default behavior
* @param token  Grant access to the Rest API.
* @param attributes The attributes of a key managed by the key vault service. / Could be NULL for default behavior.
* @param tags Application specific metadata in the form of key-value pairs. / Could be NULL.
* @brief key_data Structure with the required data to create a key. Create_key.
*/
struct key_data {
	char *host;
	char *id;
	char *keytype;
	char *keysize;
	char *key_ops[MAX_OPS];
    char* crv;
	char *token;
	struct key_attributes *attributes;
	char *tags;
};
/**
* @param host  Destination resource.
* @param id The name for the new key.
* @param token  Grant access to the Rest API.
* @brief delete_key Structure with the required data to delete a key. Delete_key.
*/
struct delete_key {
	char *host;
	char *id;
	char *token;
};
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
* @param attributes The key management attributes.
* @param tags Application specific metadata in the form of key-value pairs. / Could be NULL.
* @param managed True if the key's lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.
* @brief key_data_response Structure with the result of the following operations. Create_key, Get_Key, parse_create_key_response.
*/
struct key_data_response {
	char id[MAX_ID_SIZE];
	char *keytype;
	char *key_ops[MAX_OPS];
	char *n;
	char *e;
	char *d;
	char *dp;
	char *dq;
	char *qi;
	char *p;
	char *q;
	char *k;
	char *key_hsm;
	struct key_attributes *attributes;
	char *tags;
	BOOL managed;
    char *crv;
    char *y;
    char *x;
};
/** 
* @param keyHandler PKCS#11 handler
* @param id The name for the new key.
* @param attributes The attributes of a key managed by the key vault service. @see key_attributes
* @param tags Application specific metadata in the form of key-value pairs. / Could be NULL.
* @param managed True if the key's lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.
* @param next Pointer to the next key.
* @brief list_key Structure with the the response of the following functions: Get_ListKeys_version,Get_ListKeys.
*/
struct list_key {
	int keyHandler;
	char id[MAX_ID_SIZE];
	struct key_attributes *attributes;
	char *tags;
	BOOL managed;
	struct list_key *next;
};
/**
* @param host  Destination resource.
* @param id The name for the new key.
* @param token  Grant access to the Rest API.
* @param key_ops[] Identifies the operation(s) for which the key is intended to be used.
* @param attributes The attributes of a key managed by the key vault service. @see key_attributes
* @brief update_key Structure with the required data to update a key. Update_key.
*/
struct update_key {
	char *host;
	char *key_id;
	char *token;
	char *key_ops[MAX_OPS];
	struct key_attributes *attributes;
};
/** 
* @param recoveryLevel[] Reflects the deletion recovery level currently in effect for certificates in the current vault. If it contains 'Purgeable', the certificate can be permanently deleted by a privileged user; otherwise, only the system can purge the certificate, at the end of the retention interval.
* @param enabled Determines whether the object is enabled.
* @param nbf Not before date in UTC.
* @param exp Expiry date in UTC.
* @param created Creation time in UTC.
* @param updated Last updated time in UTC.
* @brief cert_attributes Structure with the required data to create certificate attributes.
*/
struct cert_attributes {
	char *recoveryLevel;
	BOOL enabled;
	unsigned long int nbf;
	unsigned long int exp;
	unsigned long int created;
	unsigned long int updated;
};
/**
* @param certAttributes Certificate Attributes
* @param id Certificate identifier.
* @param tags Application specific metadata in the form of key-value pairs.
* @param x5t Thumbprint of the certificate.
* @brief cert_data Structure with the basic cert data.
*/
struct cert_data {
	struct cert_attributes *certAttributes;
	char *id;
	char *tags;
	char *x5t; //base64url Thumbprint of the certificate.
};
/**
* @param token  Grant access to the Rest API.
* @param host  Destination resource.
* @param name The name of the certificate.
* @param base64Value Base64 encoded representation of the certificate object to import. This certificate needs to contain the private key.
* @param pwd If the private key in base64EncodedCertificate is encrypted, the password used for encryption.
* @param certPolicy The management policy for the certificate.
* @param cerAttributes The attributes of the certificate (optional).
* @param tags Application specific metadata in the form of key-value pairs.
* @brief import_cert_data Structure with the required data to import certificates.
*/
struct import_cert_data {
	char *token;
	char *host;
	char *name;
	char *base64Value;
	char *pwd;
	struct cert_policy *certPolicy;
	struct cert_attributes *cerAttributes;
	char *tags;
};
/**
* @param id The certificate id.
* @param keyProp Properties of the key backing a certificate.
* @param x509Props Properties of the X509 component of a certificate.
* @param lifeTimeActions Actions that will be performed by Key Vault over the lifetime of a certificate.
* @param cerAttributes The certificate attributes.
* @param issuer Parameters for the issuer of the X509 component of a certificate.
* @brief cert_policy Structure with the required data to store cert policy
*/
struct cert_policy {
	char *id;
	struct cert_key_prop *keyProp;
	struct x509_props *x509Props;
	struct lifetime_actions *lifeTimeActions;
	struct cert_attributes *cerAttributes;
	struct issuer *issuer;
};
/**
* @param exportable Indicates if the private key can be exported.
* @param kty The key type.
* @param key_size The key size in bytes. For example; 1024 or 2048.
* @param reuse_key Indicates if the same key pair will be used on certificate renewal.
* @param contentType The media type (MIME type).
* @brief cert_key_prop Structure with the required data  to store the key_props.
*/
struct cert_key_prop {
	BOOL exportable;
	char *kty; 
	int key_size;
	BOOL reuse_key; 
	char *contentType;
};
/**
* @param subject The subject name. Should be a valid X509 distinguished Name.
* @param ekus The enhanced key usage.
* @param emails Email addresses.
* @param dnsNames Domain names.
* @param upns User principal names.
* @param keyUsage List of key usages.
* @param validityMonths The duration that the ceritifcate is valid in months.
* @brief x509_props Structure with the required data to set x509 Properties.
*/
struct x509_props {
	char *subject;
	char *ekus[MAXIMUM_PERMITED_PARAMETERS]; 
	char *emails[MAXIMUM_PERMITED_PARAMETERS];
	char *dnsNames[MAXIMUM_PERMITED_PARAMETERS];
	char *upns[MAXIMUM_PERMITED_PARAMETERS];
	char *keyUsage[MAXIMUM_PERMITED_PARAMETERS]; 
	int  validityMonths;
};
/**
* @param lifetimePercentage Percentage of lifetime at which to trigger. Value should be between 1 and 99.
* @param daysBeforeExpiry Days before expiry.
* @param actionType The type of the action. ActionType{ EmailContacts, AutoRenew }
* @brief lifetime_actions Structure with the required data to set the actions.
*/
struct lifetime_actions {
	// trigger: The condition that will execute the action.
	int lifetimePercentage; 
	int daysBeforeExpiry;
	// action: The action that will be executed.
	char *actionType; 
};
/**
* @param name Name of the referenced issuer object or reserved names; for example, 'Self' or 'Unknown'.
* @param cty Type of certificate to be requested from the issuer provider
* @brief issuer Structure with the required data to set the issuer.
*/
struct issuer {
	char *name; 
	char *cty; 
};
/**
* @param handler PKCS#11 identifier.
* @param certData Basic certificate data.
* @param next Pointer to the next certificate.
* @brief cert_list Structure whit certificate data. Result of the following calls: Get_CertificateList, Get_Certificate_Versions, parse_list_certificate_response.
*/
struct cert_list {
	int handler;
	struct cert_data *certData;
	struct cert_list *next;
};
/**
* @param id The certificate id.
* @param issuer Parameters for the issuer of the X509 component of a certificate.
* @param csr The certificate signing request (CSR) that is being used in the certificate operation.
* @param cancellation_requested Indicates if cancellation was requested on the certificate operation.
* @param status Status of the certificate operation.
* @param target Location which contains the result of the certificate operation.
* @param request_id Identifier for the certificate operation.
* @brief cert_operation_response Structure whit certificate operation response.
*/
struct cert_operation_response {
	char *id;
	struct issuer *issuer;
	char *csr;
	BOOL cancellation_requested;
	char *status;
	char *target;
	char *request_id;
};
/**
* @param token  Grant access to the Rest API.
* @param host  Destination resource.
* @param name Certificate name.
* @param certPolicy The management policy for the certificate.
* @param cerAttributes The attributes of the certificate (optional).
* @param tags Application specific metadata in the form of key-value pairs.
* @brief create_cert structure for create or update a certificate. Used on the following calls: Create_Certificate, Update_Certificate, Update_CertPolicy, CreateCertificate2Json. 
*/
struct create_cert {
	char *token;
	char *host;
	char *name;
	struct cert_policy *certPolicy;
	struct cert_attributes *cerAttributes;
	char *tags;
};
/**
* @param id The certificate id.
* @param kid The key id.
* @param sid The secret id.
* @param x5t Thumbprint of the certificate.
* @param cer CER contents of x509 certificate.
* @param cerAttributes The certificate attributes.
* @param cerPolicy The management policy.
* @param pendingId The id of the request.
* @brief delete_update_cert_response Structure for delete or update certificate response.
*/
struct delete_update_cert_response {
	char *id;
	char *kid;
	char *sid;
	char *x5t;
	char *cer;
	struct cert_attributes *cerAttributes;
	struct cert_policy *cerPolicy;
	char *pendingId;
};
/**
* @param code The error code.
* @param message The error message.
* @param innererror The key vault server error.
* @brief error Structure for error manage.
*/
struct error {
	char *code;
	char *message;
	char *innererror;
};
/**
* @param certOperationResponse Pointer to the cert_operation_response struct.
* @param status_details The status details of the certificate operation.
* @param error Error encountered, if any, during the certificate operation
* @brief cert_operation_delete Structure for the Delete Cetificate Response call.
*/
struct cert_operation_delete {
	struct cert_operation_response *certOperationResponse;
	struct error *error;
	char *status_details;
};
/**
* @param token  Grant access to the Rest API.
* @param host  Destination resource.
* @param name Certificate name.
* @param cerAttributes The attributes of the certificate (optional). @see cert_attributes.
* @param tags Application specific metadata in the form of key-value pairs. (Not used).
* @param x5c (X.509 Certificate Chain) Parameters.
* @brief merge_data Structure for merges a certificate or a certificate chain with a key pair existing on the server.
*/
struct merge_data {
	char *token;
	char *host;
	char *certName;
	struct cert_attributes *cerAttributes;
	char *tags;
	char *x5c[MAX_X5C_PARAMETERS];
};
/**
* @param value The value returned by the operation.
* @brief simple_operation_response Structure with the result of the requested operation. Used in: Backup and Restore Key.
*/
struct simple_operation_response {
	char *value;
};
/**
* @param token he requested access token. The app can use this token to authenticate to the secured resource, such as a web API.
* @param value. data to store.
* @param host.  Destination resource.
* @brief value_http_data Structure with the necessary data to make the following calls: Restore_Key.
*/
struct value_http_data {
	char *token;
	char *value;
	char *host;
};
/**
* @param attributes The secret management attributes.
* @param contentType Type of the secret value such as a password.
* @param deletedDate The time when the secret was deleted, in UTC
* @param id Secret identifier.
* @param managed True if the secret's lifetime is managed by key vault. If this is a key backing a certificate, then managed will be true.
* @param recoveryId The url of the recovery object, used to identify and recover the deleted secret.
* @param scheduledPurgeDate The time when the secret is scheduled to be purged, in UTC
* @param tags Application specific metadata in the form of key-value pairs.
* @brief secret_common_item Metadata about the secret items
*/
struct secret_common_item {
	struct cert_attributes *attributes;
	char contentType[MAX_CONTENT_TYPE];
	int deletedDate;
	char id[MAX_ID_SIZE];
	BOOL managed;
	char *recoveryId;
	int scheduledPurgeDate;
	char* tags;
};
/**
* @param secretCommonItem struct with secret data.
* @param next pointer to the next item.
* @brief secret_items List of secrets stored in Azure Key Vault
*/
struct secret_items {
	struct secret_common_item secretCommonItem;
	struct secret_items *next;
};
/**
* @param secretCommonItem struct with secret data.
* @param kid If this is a secret backing a KV certificate, then this field specifies the corresponding key backing the KV certificate.
* @param value The secret value.
* @brief secret_item_data Metadata about the secret items
*/
struct secret_item_data {
	struct secret_common_item secretCommonItem;
	char kid[MAX_ID_SIZE];
	char *value;
};
/**
* @param token he requested access token. The app can use this token to authenticate to the secured resource, such as a web API.
* @param host.  Destination resource.
* @param id Secret identifier.
* @param attributes The secret management attributes.
* @param contentType Type of the secret value such as a password.
* @param tags Application specific metadata in the form of key-value pairs.
* @param value The secret value.
* @brief secret_creation_data Metadata about the secret items to create a new secret object in Azure
*/
struct secret_creation_data {
	char *token;
	char *host;
	char id[MAX_ID_SIZE];
	struct cert_attributes *attributes;
	char contentType[MAX_CONTENT_TYPE];
	char* tags;
	char *value;
};
/**
* @param id Secret identifier.
* @param attributes The secret management attributes.
* @param contentType Type of the secret value such as a password.
* @param tags Application specific metadata in the form of key-value pairs.
* @brief secret_update_response Metadata about the secret items updated in Azure
*/
struct secret_update_response {
	char id[MAX_ID_SIZE];
	struct cert_attributes *attributes;
	char contentType[MAX_CONTENT_TYPE];
	char* tags;
};

/***************************************************************************************//**
*                                     Write Data
*******************************************************************************************/
size_t write_data(void *ptr, size_t size, size_t nmemb, struct url_data *data);

/***************************************************************************************//**
*                                     Prototypes
*******************************************************************************************/


/***************************************************************************************//**
*                                     HTTPS Request
*******************************************************************************************/
/**
* @param postdata Structure that stores the information needed to make the https call. @see request_data
* @param response Json response of the operation.
* @param operation Http operation type.
* @returns Result of the operation for error handling.
* @brief Performs requests through https to the Azure Rest API.
*/
int Https_Request(struct request_data *postData, char **response, char *operation);
/***************************************************************************************//**
*                                    Operations
*******************************************************************************************/
/**
* @param clientData Information needed for authentication and to receive the token. @see client_data
* @param postResponse Structure to store token information response. @see token_response
* @returns Result of the operation for error handling.
* @brief Get_AccesToken Function to get the authentication token.
*/
int Get_AccesToken(struct client_data *clientData, struct token_response **post_response);
/***************************************************************************************//**
*                                    Key Manage
*******************************************************************************************/
/**
* @param keyData Structure with the required data to create a key. @see key_data
* @param keyResponse Key data result of the key cration operation. @see key_data_response
* @returns Result of the operation for error handling.
* @brief Create_key Creates a new key, stores it, then returns key parameters and attributes to the client.
*/
int Create_key(struct key_data *keyData, struct key_data_response **keyResponse);
/**
* @param keyData Structure with the required data to create a key. @see key_data
* @param keyResponse Key data result of the key cration operation. @see key_data_response
* @returns Result of the operation for error handling.
* @brief Create_key Creates a new key, stores it, then returns key parameters and attributes to the client.
*/
int Update_key(struct update_key *updateKey, struct key_data_response **keyResponse);
/**
* @param keyData Data of the key to be deleted. @see delete_key
* @returns Result of the operation for error handling.
* @brief Delete_key This operation removes the cryptographic material associated with the key, which means the key is not usable for Sign/Verify, Wrap/Unwrap or Encrypt/Decrypt operations.
*/
int Delete_key(struct delete_key *keyData);
/**
* @param petitionData Structure with the information needed to find the keys. @see basic_http_data
* @param listKey List of structures with the searched keys @see list_key
* @returns Result of the operation for error handling.
* @brief Get_ListKeys The LIST operation is applicable to all key types, however only the base key identifier,attributes, and tags are provided in the response. Individual versions of a key are not listed in the response.
*/
int Get_ListKeys(struct  basic_http_data *petitionData, struct list_key **listKey);
/**
* @param keyData Key data to list its versions. @see id_http_data
* @param listKeyVersionResponse List of key versions @see list_key
* @returns Result of the operation for error handling.
* @brief Get_ListKeys_version The LIST VERSIONS operation is applicable for all versions having the same key name. The full key identifier, attributes, and tags are provided in the response.
*/
int Get_ListKeys_version(struct id_http_data *id, struct list_key **listKeyVersionResponse);
/**
* @param petitionData Struct with key identifier to request key data. @see id_http_data
* @param keyData Struct with the key data. @see key_data_response
* @returns Result of the operation for error handling.
* @brief Get_Key The GET operation is applicable to all key types; however only the public portion of a key stored in Azure Key Vault is returned. If the target key is symmetric, then no key material is released in the response.
*/
int Get_Key(struct id_http_data * petitionData, struct key_data_response **keyData);
/**
* @param backupKey Struct with key identifier to backup. @see id_http_data
* @param backOperationResponse Struct with the key data. @see simple_operation_response
* @returns Result of the operation for error handling.
* @brief Backup_Key Requests that a backup of the specified key be downloaded to the client. The Key Backup operation exports a key from Azure Key Vault in a protected form. 
*/
int Backup_Key(struct id_http_data * backupKey, struct simple_operation_response ** backOperationResponse);
/**
* @param restoreKey Struct with only connection data. @see basic_http_data
* @param restoreOperationResponse Struct with the key data. @see key_data_response
* @returns Result of the operation for error handling.
* @brief Restore_Key Restores a backed up key to a vault. Imports a previously backed up key into Azure Key Vault, restoring the key, its key identifier, attributes and access control policies. 
*/
int Restore_Key(struct value_http_data * restoreKey, struct key_data_response ** keyData);
/***************************************************************************************//**
*                                    Key Operations
*******************************************************************************************/
/**
* @param signData Structure with the necessary information for the signature and the hash of the data to sign @see operation_data
* @param signResponse Firma @see operation_response
* @returns Result of the operation for error handling.
* @brief Sign SIGN is applicable to asymmetric and symmetric keys stored in Azure Key Vault since this operation uses the private portion of the key.
*/
int Sign(struct operation_data *signData, struct operation_response **signResponse);
/**
* @param verifyData Structure with the necessary information for the verify a sign. @see verify_data
* @returns Result of the operation and error handling.
* @brief Verify VERIFY is applicable to symmetric keys stored in Azure Key Vault. VERIFY is not strictly necessary for asymmetric keys stored in Azure Key Vault since signature verification can be performed using the public portion of the key but this operation is supported as a convenience for callers that only have a key-reference and not the public portion of the key.
*/
int Verify(struct verify_data *verifyData);
/**
* @param opData Structure with the necessary information for the encryptation operation and the data to encrypt. @see operation_data
* @param opResponse Encrypted data. @see operation_response
* @returns Result of the operation for error handling.
* @brief Encript_Data The ENCRYPT operation encrypts an arbitrary sequence of bytes using an encryption key that is stored in Azure Key Vault. Note that the ENCRYPT operation only supports a single block of data, the size of which is dependent on the target key and the encryption algorithm to be used.
*/
int Encript_Data(struct operation_data * opData, struct operation_response **opResponse);
/**
* @param opData Structure with the necessary information for the decrypt operation and the data to decrypt. @see operation_data
* @param opResponse plain text data. @see operation_response
* @returns Result of the operation for error handling.
* @brief Decript_Data The DECRYPT operation decrypts a well-formed block of ciphertext using the target encryption key and specified algorithm. This operation is the reverse of the ENCRYPT operation; only a single block of data may be decrypted, the size of this block is dependent on the target key and the algorithm to be used.
*/
int Decript_Data(struct operation_data * opData, struct operation_response **opResponse);

/***************************************************************************************//**
*                                Certificate Manage
*******************************************************************************************/
/**
* @param urlTokenData Basic information needed for the request. @see basic_http_data
* @param certListResponse List of certificates @see cert_list
* @returns Result of the operation for error handling.
* @brief Get_CertificateList LIST current certificates.
*/
int Get_CertificateList(struct basic_http_data *getData, struct cert_list **certListResponse);
/**
* @param certId Struct with certificate identifier to request certificate versions. @see id_http_data
* @param certVersionListResponse List of certificates versions. @see cert_list
* @returns Result of the operation for error handling.
* @brief Get_CertificateVersions List all versions of a given certificate
*/
int Get_CertificateVersions(struct id_http_data *certId, struct cert_list **certVersionListResponse);
/**
* @param importData Certificate import data. @see import_cert_data
* @param importCertResponse Result of the importation operation. @see delete_update_cert_response
* @returns Result of the operation for error handling.
* @brief Import_Certificate Imports an existing valid certificate, containing a private key, into Azure Key Vault. The certificate to be imported can be in either PFX or PEM format. If the certificate is in PEM format the PEM file must contain the key as well as x509 certificates.
*/
int Import_Certificate(struct import_cert_data *importData, struct delete_update_cert_response **importCertResponse);
/**
* @param urlTokenData Bassic information to request de operation. @see id_http_data
* @param certOperationResponse Certificate operatcion state @see cert_operation_response
* @returns Result of the operation for error handling.
* @brief Get_GetCertificateOperation Gets the operation associated with a specified certificate. Authorization: requires the certificates/get permission.
*/
int Get_GetCertificateOperation(struct id_http_data *getData, struct cert_operation_response **certOperationResponse);
/**
* @param CreateCert Certificate data to be created. @see create_cert
* @param certOperationResponseState of the created operation. @see cert_operation_response
* @returns Result of the operation for error handling.
* @brief Create_Certificate Function to create a certificate.
*/
int Create_Certificate(struct create_cert *createCert, struct cert_operation_response **certOperationResponse);
/**
* @param deleteCert Basic data to eliminate a certificate. @see id_http_data
* @param deleteCertResponse Certificate data deleted. @see delete_update_cert_response
* @returns Result of the operation for error handling.
* @brief Delete_Certificate Deletes all versions of a certificate object along with its associated policy. Delete certificate cannot be used to remove individual versions of a certificate object.
*/
int Delete_Certificate(struct id_http_data *deleteCert, struct delete_update_cert_response **deleteCertResponse);
/**
* @param urlTokenData Basic data to delete an operation @see id_http_data
* @param certOperationDelete Status of the deletion operation @see cert_operation_delete
* @returns Result of the operation for error handling.
* @brief Delete_CertificateOperation Deletes the operation for a specified certificate. Authorization: requires the certificates/update permission.
*/
int Delete_CertificateOperation(struct id_http_data *urlTokenData, struct cert_operation_delete **certOperationDelete);
/**
* @param updateCert Data to update a certificate. @see create_cert
* @param updateCertResponse Updated data of a certificate. @see delete_update_cert_response
* @returns Result of the operation for error handling.
* @brief Update_Certificate The update operation changes non-read-only properties in the attributes or tags of current or specified version of a key vault certificate.
*/
int Update_Certificate(struct create_cert * updateCert, struct delete_update_cert_response ** updateCertResponse);
/**
* @param updatePolicy Structure with all the necessary data to update the policy of a certificate. @see create_cert
* @param certPolicy Empty structure to fill with the new policy. @see cert_policy
* @returns Result of the operation for error handling.
* @brief Update_CertPolicy Updates the policy for a certificate. PATCH will allow you to specify one or various properties in the request such that only this properties will be updated.
*/
int Update_CertPolicy(struct create_cert *updatePolicy, struct cert_policy **certPolicy);
/**
* @param getParameters Structure with all the necessary data to request cert policy. @see id_http_data
* @param certPolicy Cert policy data returned from Azure @see cert_policy
* @returns Result of the operation for error handling.
* @brief Get_CertPolicy. Gest the actual certificate policy from a certificate
*/
int Get_CertPolicy(struct id_http_data *getParameters, struct cert_policy **certPolicy);
/**
* @param getParameters Basic data to request information from a certificate  @see id_http_data
* @param getCertResponse Certificate data @see delete_update_cert_response
* @returns Result of the operation for error handling.
* @brief Get_Certificate Get the current or a particular verion of a key vault certificate.
*/
int Get_Certificate(struct id_http_data *getParameters, struct delete_update_cert_response **getCertResponse);
/**
* @param mergeData Certificate data to merge from a certificate  @see merge_data
* @param certOperationResponse Certificate data @see cert_operation_response
* @returns Result of the operation for error handling.
* @brief Merge_Certificate Merges a certificate or a certificate chain with a key pair existing on the server.
*/
int Merge_Certificate(struct merge_data * mergeData, struct cert_operation_response **certOperationResponse);
/***************************************************************************************//**
*                                Secret Manage
*******************************************************************************************/
/**
* @param petitionData Struct with basic connection data. @see basic_http_data
* @param secretList List of secrets stored in Azure Key Vault @see secret_items
* @returns Result of the operation for error handling.
* @brief Get_ListSecrets List secrets in a specified key vault.
*/
int Get_ListSecrets(struct basic_http_data *petitionData, struct secret_items **secretList);
/**
* @param petitionData Struct with basic connection data. @see id_http_data
* @param secretData Secret Data @see secret_item_data.
* @returns Result of the operation for error handling.
* @brief Get_SecretData Get the secret data.
*/
int Get_SecretData(struct id_http_data *petitionData, struct secret_item_data **secretData);
/**
* @param petitionData Data of the secret to be deleted. @see id_http_data
* @returns Result of the operation for error handling.
* @brief Delete_Secret Deletes a secret from a specified key vault. The DELETE operation applies to any secret stored in Azure Key Vault. DELETE cannot be applied to an individual version of a secret. This operation requires the secrets/delete permission.
*/
int Delete_Secret(struct id_http_data *petitionData);
/**
* @param petitionData Data of the secret to be deleted. @see id_http_data.
* @param secretData Secret Data @see secret_item_data.
* @returns Result of the operation for error handling.
* @brief Create_Secret Sets a secret in a specified key vault. The SET operation adds a secret to the Azure Key Vault. If the named secret already exists, Azure Key Vault creates a new version of that secret. This operation requires the secrets/set permission.
*/
int Create_Secret(struct secret_creation_data *petitionData, struct secret_item_data **secretData);
/**
* @param petitionData Data of the secret to be updated. @see secret_creation_data.
* @param secretData Secret Data @see secret_update_response.
* @returns Result of the operation for error handling.
* @brief Update_Secret Updates the attributes associated with a specified secret in a given key vault. The UPDATE operation changes specified attributes of an existing stored secret. Attributes that are not specified in the request are left unchanged. The value of a secret itself cannot be changed. This operation requires the secrets set permission.
*/
int Update_Secret(struct secret_creation_data *petitionData, struct secret_update_response **secretData);
/***************************************************************************************//**
 *                                    Json Parsers
*******************************************************************************************/
/**
* @param response Data to be parsed. 
* @param keyResponse Parse data. @see key_data_response
* @returns Result of the operation for error handling & Parse data.
* @brief parse_create_key_response
*/
int parse_create_key_response(char *response, struct key_data_response **keyResponse);
/**
* @param response Data to be parsed.
* @param listkeyResponse Parse data. @see list_key
* @param nextLink Next link to be parser
* @returns Result of the operation for error handling & Parse data.
* @brief parse_list_key_response
*/
int parse_list_key_response(char *response, struct list_key **listkeyResponse, char **nextLink);
/**
* @param response Data to be parsed.
* @param opResponse Parsed data. @see operation_response
* @returns Result of the operation for error handling & Parse data.
* @brief parse_operation_response
*/
int parse_operation_response(char *response, struct operation_response **opResponse);
/**
* @param response Data to be parsed.
* @param listCertResponse Parsed data. @see cert_list
* @param nextLink Next link to be parser
* @returns Result of the operation for error handling & Parse data.
* @brief parse_list_certificate_response
*/
int parse_list_certificate_response(char *response, struct cert_list **listCertResponse, char **nextLink);
/**
* @param response Data to be parsed.
* @param certOperationResponse Parse data. @see cert_operation_response
* @returns Result of the operation for error handling & Parse data.
* @brief parse_cert_operation_state
*/
int parse_cert_operation_state(char *response, struct cert_operation_response ** certOperationResponse);
/**
* @param response Data to be parsed.
* @param deleteCertResponse Parse data. @see delete_update_cert_response
* @returns Result of the operation for error handling & Parse data.
* @brief parse_delete_update_certificate_response
*/
int parse_delete_update_certificate_response(char *response, struct delete_update_cert_response **deleteCertResponse);
/**
* @param response Data to be parsed.
* @param certOperationDelete Parse data. @see cert_operation_delete
* @returns Result of the operation for error handling & Parse data.
* @brief parse_cert_operation_delete
*/
int parse_cert_operation_delete(char *response, struct cert_operation_delete **certOperationDelete);
/**
* @param response Data to be parsed.
* @param policy Parse data. @see cert_policy
* @returns Result of the operation for error handling & Parse data.
* @brief parse_policy
*/
int parse_policy(char *response, struct cert_policy **policy);
/**
* @param response Data to be parsed.
* @param tokenResponse Parse data. @see token_response
* @returns Result of the operation for error handling & Parse data.
* @brief parse_token_response
*/
int parse_token_response(char *response, struct token_response **tokenResponse);
/**
* @param response Data to be parsed.
* @param opResponse Parsed data. @see simple_operation_response
* @returns Result of the operation for error handling & Parse data.
* @brief parse_simple_operation_response
*/
int parse_simple_operation_response(char *response, struct simple_operation_response **opResponse);
/**
* @param response Data to be parsed.
* @param secretListResponse Parsed data. @see secret_items
* @param nextLink Next link to be parser
* @returns Result of the operation for error handling & Parse data.
* @brief Parse_secret_list_response
*/
int Parse_secret_list_response(char *response, struct secret_items **secretListResponse, char **nextLink);
/**
* @param response Data to be parsed.
* @param secretItemDatatResponse Parsed data. @see secret_item_data
* @returns Result of the operation for error handling & Parse data.
* @brief parse_secret_data_response
*/
int parse_secret_data_response(char *response, struct secret_item_data **secretItemDatatResponse);
/**
* @param response Data to be parsed.
* @param secretUpdateResponse Parsed data. @see secret_update_response
* @returns Result of the operation for error handling & Parse data.
* @brief parse_secret_data_update_response
*/
int parse_secret_data_update_response(char *response, struct secret_update_response **secretUpdateResponse);
/***************************************************************************************//**
*                                   Json Formaters
*******************************************************************************************/
/**
* @param CreateCert Date to be formatted. @see create_cert
* @returns Formatted data
* @brief CreateCertificate2Json
*/
char *CreateCertificate2Json(struct create_cert * CreateCert);
/**
* @param importData Date to be formatted. @see import_cert_data
* @returns Formatted data
* @brief CreateImport2Json
*/
char *CreateImport2Json(struct import_cert_data *importData);
/**
* @param opData Date to be formatted. @see operation_data
* @returns Formatted data
* @brief CreateOperation2Json
*/
char *CreateOperation2Json(struct operation_data *opData);
/**
* @param createKey Date to be formatted. @see key_data
* @returns Formatted data
* @brief CreateKey2Json
*/
char *CreateKey2Json(struct key_data *createKeyData);
/**
* @param updateKey Date to be formatted. @see update_key
* @returns Formatted data
* @brief UpdateKey2Json
*/
char *UpdateKey2Json(struct update_key *updateKey);
/**
* @param mergeData Date to be formatted. @see merge_data
* @returns Formatted data
* @brief CreateMergeCertificate2Json
*/
char *CreateMergeCertificate2Json(struct merge_data * mergeData);
/**
* @param createSecretData Date to be formatted. @see secret_creation_data
* @returns Formatted data
* @brief CreateSecret2Json
*/
char *CreateSecret2Json(struct secret_creation_data *createSecretData);
#endif // CLIENTREST_H_INCLUDED
