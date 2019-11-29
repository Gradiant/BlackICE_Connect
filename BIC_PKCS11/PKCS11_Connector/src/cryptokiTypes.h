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

#ifndef CRYPTOKITYPES_H_INCLUDED
#define CRYPTOKITYPES_H_INCLUDED
#include <cryptoki.h>
#define MAX_PKCS11_ALGORITHM_LEN (25)
#define CACHE_TIMER_SECS (15) 
#define SHA256_ASN1 "0609608648016503040201"
#define SHA384_ASN1 "0609608648016503040202"
#define SHA512_ASN1 "0609608648016503040203"
#define SHA_256 (256)
#define SHA_384 (384)
#define SHA_512 (512)
#define HASH_TYPE (22)
#define STRLEN(s) (sizeof(s)/sizeof(s[0]))
#define PERMITED_PUBLIC_EXPONENT ((CK_ULONG)0x10001)
#define KEK_KEY_LEN  (32)
#define ITERATION  (20000)

//*********************** PKCS#11 Object Attribute Structures*********************//
/**
* @param len Lenght of the data.
* @param data Data to store.
* @brief raw_data Struct to store raw data with its length. No \0 termination
*/
struct raw_data {
	CK_ULONG len;
	CK_CHAR_PTR data;
};

/**
* @param isToken CK_TRUE if object is a token object; CK_FALSE if object is a session object.
* @param isPrivate CK_TRUE if object is a private object; CK_FALSE if object is a public object.
* @param isModifiable CK_TRUE if object can be modified.
* @param label Description of the object.
* @brief CommonStorageObjectAttributes Struct to store the common attributes of pkcs#11 Objects.
*/
struct CommonStorageObjectAttributes {
	CK_BBOOL isToken;
	CK_BBOOL isPrivate;
	CK_BBOOL isModifiable;
	char label[MAX_LABEL_SIZE];
};

/**
* @param certificateType Type of a certificate.
* @param isTrusted The certificate can be trusted for the aplication that it was created.
* @param certificateCategory Categorization of the certificate: 0 = unspecified(default), 1 = token user, 2 authority, 3 = other entity.
* @param checkValue Cheksum.
* @param startDate Start date for the certificate.
* @param endDate End date for the certificate.
* @brief CommonCertificateObjectAttributes Struct to store the common certificate attributes of pkcs#11 Objects
*/
struct CommonCertificateObjectAttributes {
	CK_CERTIFICATE_TYPE certificateType;
	CK_BBOOL isTrusted;
	CK_ULONG certificateCategory;
	CK_BYTE_PTR checkValue;
	CK_DATE startDate;
	CK_DATE endDate;
};
/**
* @param subject DER-encoding of the certificate subject name. @see raw_data
* @param id Key identifier for public/private key pair.
* @param issuer DER-encoding of the certificate issuer name. @see raw_data
* @param serailNumber DER-encoding of the certificate serial number. @see raw_data
* @param value BER-encoding of the certificate. @see raw_data
* @param url If not empty this attribute gives the URL where the complete certificate can be obtained.
* @param hashOfSubjectPublicKey SHA-1 hash of the subject public key.
* @param hashOfIssuerPublicKey SHA-1 hash of the issuer public key.
* @param javaMidpSecurityDomain Java MIDP security domain:  0 = unspecified(default), 1 = manufacturer, 2 operator, 3 =third party.
* @brief x509CertificateObjectAttribute Struct to store the x509 certificate attributes of pkcs#11 Objects
*/
struct x509CertificateObjectAttribute {
	struct raw_data subject;
	CK_BYTE_PTR id;
	struct raw_data issuer;
	struct raw_data serailNumber;
	struct raw_data value;
	CK_CHAR_PTR url;
	CK_BYTE_PTR hashOfSubjectPublicKey;
	CK_BYTE_PTR hashOfIssuerPublicKey;
	CK_ULONG	javaMidpSecurityDomain;
};
/**
* @param keyType Type of key.
* @param id Key identifier for the key.
* @param startDate Start date for the key.
* @param endDate End date for the key.
* @param canDerive CK_TRUE if key supports key derivation.
* @param isLocal CK_TRUE only if key was either generated locally.
* @param mechanismType Identifier of the mechanism used to generate the key material.
* @param allowedMechanisms A list of mechanisms allowed to be used with this key. The number of mechanisms in the array is the ulValueLen component of the attribute divided by the size of CK_MECHANISM_TYPE.
* @brief CommonKeyAttributes Struct to store the common key attributes of pkcs#11 Objects
*/
struct CommonKeyAttributes {
	CK_KEY_TYPE keyType;
	CK_BYTE_PTR id;
	CK_DATE startDate;
	CK_DATE endDate;
	CK_BBOOL canDerive;
	CK_BBOOL isLocal;
	CK_MECHANISM_TYPE mechanismType;
	CK_MECHANISM_TYPE_PTR allowedMechanisms;
};
/**
* @param subject DER-encoding of the key subject name. @see raw_data
* @param canEncrypt CK_TRUE if key supports encryption.
* @param canVerify CK_TRUE if key supports verification where the signature is an appendix to the data.
* @param canVerrifyRecover CK_TRUE if key supports verification where the data is recovered from the signature.
* @param canWrap CK_TRUE if key supports wrapping.
* @param isTrusted The key can be trusted for the application that it was created. The wrapping key can be used to wrap keys with CKA_WRAP_WITH_TRUSTED set to CK_TRUE.
* @param wrapTemplate For wrapping keys. The attribute template to match against any keys wrapped using this wrapping key. Keys that do not match cannot be wrapped. The number of attributes in the array is the ulValueLen component of the attribute divided by the size of CK_ATTRIBUTE.
* @brief CommonPublicKeyAttributes Struct to store the public common key attributes of pkcs#11 Objects
*/
struct CommonPublicKeyAttributes {
	struct raw_data subject;
	CK_BBOOL canEncrypt;
	CK_BBOOL canVerify;
	CK_BBOOL canVerrifyRecover;
	CK_BBOOL canWrap;
	CK_BBOOL isTrusted;
	CK_ATTRIBUTE_PTR wrapTemplate;
};

/**
* @param subject DER-encoding of certificate subject name. @see raw_data
* @param isSensitive CK_TRUE if key is sensitive
* @param canDecrypt CK_TRUE if key supports decryption.
* @param canSign CK_TRUE if key supports signatures where the signature is an appendix to the data.
* @param canSignRecover CK_TRUE if key supports signatures where the data is recovered from the signature.
* @param canUnwrap CK_TRUE if key supports unwrapping.
* @param isExtractable CK_TRUE if key is extractable and can be wrapped.
* @param isAlwaysSensitive CK_TRUE if key has always had the CKA_SENSITIVE attribute set to CK_TRUE
* @param isNeverExtractable CK_TRUE if key has never had the CKA_EXTRACTABLE attribute set to CK_TRUE
* @param beWrapWithTrusted CK_TRUE if the key can only be wrapped with a wrapping key that has CKA_TRUSTED set to CK_TRUE. Default is CK_FALSE.
* @param unwrapTemplate. For wrapping keys. The attribute template to apply to any keys unwrapped using this wrapping key. Any user supplied template is applied after this template as if the object has already been created. The number of attributes in the array is the ulValueLen component of the attribute divided by the size of CK_ATTRIBUTE.
* @param isAlwaysAuthenticate If CK_TRUE, the user has to supply the PIN for each use (sign or decrypt) with the key. Default is CK_FALSE.
* @brief CommonPrivateKeyAttributes Struct to store the private common key attributes of pkcs#11 Objects
*/
struct CommonPrivateKeyAttributes {
	struct raw_data subject;
	CK_BBOOL isSensitive;
	CK_BBOOL canDecrypt;
	CK_BBOOL canSign;
	CK_BBOOL canSignRecover;
	CK_BBOOL canUnwrap;
	CK_BBOOL isExtractable;
	CK_BBOOL isAlwaysSensitive;
	CK_BBOOL isNeverExtractable;
	CK_BBOOL beWrapWithTrusted;
	CK_ATTRIBUTE_PTR unwrapTemplate;
	CK_BBOOL isAlwaysAuthenticate;
};
/**
* @param modulus Modulus n. @see raw_data
* @param modulusBits Length in bits of modulus n.
* @param publicExponent Public exponent e. @see raw_data
* @description RSAPublicKeyObjectAttributes Struct to store the RSA public key attributes of pkcs#11 Objects.
*/
struct RSAPublicKeyObjectAttributes {
	struct raw_data modulus;
	CK_ULONG modulusBits;
	struct raw_data publicExponent;
};
/**
* @param modulus Modulus n. @see raw_data
* @param publicExponent Public exponent e. @see raw_data
* @param privateExponent Private exponent d. @see raw_data
* @param prime1 Prime p. @see raw_data
* @param prime2 Prime q. @see raw_data
* @param exponent1 Private exponent d modulo p-1. @see raw_data
* @param exponent2 Private exponent d modulo q-1. @see raw_data
* @param coeficient CRT coefficient q-1 mod p. @see raw_data
* @brief RSAPrivateKeyObjectAttributes Struct to store the RSA private key attributes of pkcs#11 Objects.
*/
struct RSAPrivateKeyObjectAttributes {
	struct raw_data modulus;
	struct raw_data publicExponent;
	struct raw_data privateExponent;
	struct raw_data prime1;
	struct raw_data prime2;
	struct raw_data exponent1;
	struct raw_data exponent2;
	struct raw_data coeficient;
};

/**
 * @param x X component of an EC public key. @see raw_data
 * @param y Y component of an EC public key. @see raw_data
 * @brief The ECPublicKeyObjectAttributes Struct to store the EC public key attributes of pkcs#11 Objects.
 */
struct ECPublicKeyObjectAttributes {
    struct raw_data ecParams;
    struct raw_data ecPoint;
    struct raw_data x;
    struct raw_data y;
};

struct ECPrivateKeyObjectAttributes {
    struct raw_data ecParams;
    struct raw_data d;
};


//*********************** PKCS#11 Object Structures*********************//
/**
* @param commonAtt common attributes of the object. @see CommonStorageObjectAttributes
* @param commonKeyAtt common attributes of the key. @see CommonKeyAttributes
* @param commonPublicKeyAtt common public attributes of the key. @see CommonPublicKeyAttributes
* @param commonPrivateKeyAtt common public attributes of the key. @see CommonPrivateKeyAttributes
* @param RSApublicKeyObjectAtt RSA public part of the key. @see RSAPublicKeyObjectAttributes
* @param RSAPrivateKeyObjectAtt RSA private part of the key. @see RSAPrivateKeyObjectAttributes
* @description keyObject Struct to store the RSA private key object.
*/

struct keyObject {
	struct CommonStorageObjectAttributes commonAtt;
	struct CommonKeyAttributes commonKeyAtt;
	struct CommonPublicKeyAttributes commonPublicKeyAtt;
	struct CommonPrivateKeyAttributes commonPrivateKeyAtt;
	struct RSAPublicKeyObjectAttributes RSApublicKeyObjectAtt;
	struct RSAPrivateKeyObjectAttributes RSAPrivateKeyObjectAtt;
    struct ECPublicKeyObjectAttributes ECpublicKeyObjectAtt;
    struct ECPrivateKeyObjectAttributes ECprivateKeyObjectAtt;
};

/**
* @param commonAtt common attributes of the object. @see CommonStorageObjectAttributes
* @param commonCertificateAtt common attributes of the certificate. @see CommonCertificateObjectAttributes
* @param x509CertificateAtt x509 attributes of the certificate. @see x509CertificateObjectAttribute
* @brief certificateObject Struct to store the x509 certificates.
*/
struct certificateObject {
	struct CommonStorageObjectAttributes commonAtt;
	struct CommonCertificateObjectAttributes commonCertificateAtt;
	struct x509CertificateObjectAttribute x509CertificateAtt;
};
/**
* @param commonAtt common attributes of the object. @see CommonStorageObjectAttributes
* @param application Description of the application thath manages the object.
* @param objectId Object id.
* @param value Value of the object.
* @brief dataObject Struct to store the data objets.
*/
struct dataObject {
	struct CommonStorageObjectAttributes commonAtt;
	char *application;
	struct raw_data objectId;
	struct raw_data value;
};
/**
* @param objectHandler Handler to indetify the object.
* @param id Name of the object.
* @param type Type of object.
* @param certObject Certificate data, if the object is a certificate @see certificateObject
* @param keyObject  Key data, if the object is a key. @see keyObject
* @param dataObject  Secret data, if the object is a Data Object. @see dataObject
* @param next pointer to the next object. @see objects
* @brief objects Struct to store all pkcs information of an object.
*/
struct objects {
	CK_ULONG objectHandler;
	CK_CHAR_PTR id;
	CK_ULONG type;
	struct certificateObject *certObject;
	struct keyObject *keyObject;
	struct dataObject *dataObject;
	struct objects *next;
};

/**
* @param object Pointer to the object @see objects.
* @param next pointer to the next object. @see found_objects_list
* @brief objects Struct to store all pkcs information of an object.
*/
struct found_objects_list {
	struct objects *object;
	struct found_objects_list *next;
};


//*********************** PKCS#11 Session Structure*********************//
/**
* @param numFound Number of objects found in the session.
* @param numLeft Number of object left to be procesed by findobjects.
* @param foundObjects List of objects founded. @see objects
* @param currentObjectHandler Handler of the object being used.
* @brief find_objects Structure to store all objects found.
*/
struct find_objects {
	CK_ULONG numFound;
	CK_ULONG numLeft;
	struct objects *sessionObjects;
	struct found_objects_list *foundObjects;
	CK_ULONG currentObjectHandler;
};
/**
* @param sessionHandler Handler to indetify the session.
* @param findObjects Struct to store find objects information. @see find_objects
* @param sessionState State of the session.
* @param operationState State of the current operation.
* @param operationAlgorithm  Algorithm used in the current operation.
* @param openTime When the session was opened.
* @param next pointer to the next session @see sessions
* @brief sessions Struct to store all sessions.
*/
struct sessions {
	CK_ULONG sessionHandler;
	struct find_objects findObjects;
	CK_ULONG sessionState;
	CK_ULONG operationState;
	char operationAlgorithm[MAX_PKCS11_ALGORITHM_LEN];
	time_t openTime;
	struct sessions *next;
};

//*********************** Optimization *********************//
/**
* @param certificateListeTimer Certificate timer.
* @param keyListTimer Key timer.
* @param secretListTimer Secret timer.
* @brief last_call_timer Struct to store all calls timers.
*/
struct last_call_timer {
	time_t certificateListeTimer;
	time_t keyListTimer;
	time_t secretListTimer;
}lastCallTimer;


/***************************************************************************************//**
*                                     Prototypes
*******************************************************************************************/
/**
* @return Void
* @param delData Pointer to the object. @see keyObject
* @brief Free_keyObject Function to free al memory reserved for a key object.
*/
void Free_keyObject(struct keyObject * delData);
/**
* @return Void
* @param delData Pointer to the object. @see certificateObject
* @brief Free_CertificateObject Function to free al memory reserved for a certificate object.
*/
void Free_CertificateObject(struct certificateObject * delData);
/**
* @return Void
* @param delData Pointer to the object. @see dataObject
* @brief Free_DataObject Function to free al memory reserved for a data object.
*/
void Free_DataObject(struct dataObject * delData);
/**
* @return Void
* @param delData Pointer to the object. @see certificateObject
* @brief Initialize_CertObject Function to initialize object.
*/
void Initialize_CertObject(struct certificateObject * currentObject);
/**
* @return Void
* @param currentObject Pointer to the object. @see keyObject
* @brief Initialize_KeyObject Function to initialize object.
*/
void Initialize_KeyObject(struct keyObject * currentObject);
/**
* @param context Context of the function for debugin
* @param pkcs11Error PKCS#11 Error
* @brief Error_Writter Insert in context de correct pkcs#11 error.
*/
void Error_Writter(struct context * context, CK_ULONG pkcs11Error);
/**
* @param Template Template with data to transcrive
* @param context Context of the function for debugin
* @brief PKCS11_Attribute_Transriptor Transcribes pkcs11 data into printable data.
*/
void PKCS11_Attribute_Transriptor(CK_ATTRIBUTE Template, struct context * context);
/**
* @param ckBool Boolean data to parse
* @param ckBoolString String result
* @brief CK_BBOOL_To_String Transcribes pkcs11 boolean data into printable string.
*/
void CK_BBOOL_To_String(CK_BBOOL ckBool, char ckBoolString[]);
#endif //CRYPTOKITYPES_H_INCLUDED
