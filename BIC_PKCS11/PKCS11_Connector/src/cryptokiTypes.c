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

#include <cryptokiTypes.h>


void Free_keyObject(struct keyObject * delData) {
	if (delData != NULL) {
		if (delData->commonKeyAtt.id != NULL) free(delData->commonKeyAtt.id);
		if (delData->commonPrivateKeyAtt.subject.data != NULL) free(delData->commonPrivateKeyAtt.subject.data);
		if (delData->commonPublicKeyAtt.subject.data != NULL) free(delData->commonPublicKeyAtt.subject.data);
		if (delData->RSAPrivateKeyObjectAtt.coeficient.data != NULL) free(delData->RSAPrivateKeyObjectAtt.coeficient.data);
		if (delData->RSAPrivateKeyObjectAtt.exponent1.data != NULL) free(delData->RSAPrivateKeyObjectAtt.exponent1.data);
		if (delData->RSAPrivateKeyObjectAtt.exponent2.data != NULL) free(delData->RSAPrivateKeyObjectAtt.exponent2.data);
		if (delData->RSAPrivateKeyObjectAtt.modulus.data != NULL) free(delData->RSAPrivateKeyObjectAtt.modulus.data);
		if (delData->RSAPrivateKeyObjectAtt.prime1.data != NULL) free(delData->RSAPrivateKeyObjectAtt.prime1.data);
		if (delData->RSAPrivateKeyObjectAtt.prime2.data != NULL) free(delData->RSAPrivateKeyObjectAtt.prime2.data);
		if (delData->RSAPrivateKeyObjectAtt.privateExponent.data != NULL) free(delData->RSAPrivateKeyObjectAtt.privateExponent.data);
		if (delData->RSAPrivateKeyObjectAtt.publicExponent.data != NULL) free(delData->RSAPrivateKeyObjectAtt.publicExponent.data);
		if (delData->RSApublicKeyObjectAtt.modulus.data != NULL) free(delData->RSApublicKeyObjectAtt.modulus.data);
		if (delData->RSApublicKeyObjectAtt.publicExponent.data != NULL) free(delData->RSApublicKeyObjectAtt.publicExponent.data);
        if (delData->ECpublicKeyObjectAtt.ecParams.data != NULL) free(delData->ECpublicKeyObjectAtt.ecParams.data);
        if (delData->ECpublicKeyObjectAtt.ecPoint.data != NULL) free(delData->ECpublicKeyObjectAtt.ecPoint.data);
        if (delData->ECpublicKeyObjectAtt.x.data != NULL) free(delData->ECpublicKeyObjectAtt.x.data);
        if (delData->ECpublicKeyObjectAtt.y.data != NULL) free(delData->ECpublicKeyObjectAtt.y.data);
        if (delData->ECprivateKeyObjectAtt.ecParams.data != NULL) free(delData->ECprivateKeyObjectAtt.ecParams.data);
        if (delData->ECprivateKeyObjectAtt.d.data != NULL) free(delData->ECprivateKeyObjectAtt.d.data);
		free(delData);
	}
}



void Free_CertificateObject(struct certificateObject * delData) {
	if (delData != NULL) {
		if (delData->commonCertificateAtt.checkValue != NULL) free(delData->commonCertificateAtt.checkValue);
		if (delData->x509CertificateAtt.hashOfIssuerPublicKey != NULL) free(delData->x509CertificateAtt.hashOfIssuerPublicKey);
		if (delData->x509CertificateAtt.hashOfSubjectPublicKey != NULL) free(delData->x509CertificateAtt.hashOfSubjectPublicKey);
		if (delData->x509CertificateAtt.id != NULL) free(delData->x509CertificateAtt.id);
		if (delData->x509CertificateAtt.issuer.data != NULL) free(delData->x509CertificateAtt.issuer.data);
		if (delData->x509CertificateAtt.serailNumber.data != NULL) free(delData->x509CertificateAtt.serailNumber.data);
		if (delData->x509CertificateAtt.subject.data != NULL) free(delData->x509CertificateAtt.subject.data);
		if (delData->x509CertificateAtt.url) free(delData->x509CertificateAtt.url);
		if (delData->x509CertificateAtt.value.data) free(delData->x509CertificateAtt.value.data);
		free(delData);
	}
}


void Free_DataObject(struct dataObject * delData) {
	if (delData != NULL) {
		if (delData->application != NULL) free(delData->application);
		if (delData->objectId.data != NULL) free(delData->objectId.data);
		if (delData->value.data != NULL) free(delData->value.data);
		free(delData);
	}
}


void Initialize_CertObject(struct certificateObject * currentObject) {
	currentObject->commonCertificateAtt.checkValue = NULL;
	currentObject->x509CertificateAtt.hashOfIssuerPublicKey = NULL;
	currentObject->x509CertificateAtt.hashOfSubjectPublicKey = NULL;
	currentObject->x509CertificateAtt.id = NULL;
	currentObject->x509CertificateAtt.issuer.data = NULL;
	currentObject->x509CertificateAtt.issuer.len = 0;
	currentObject->x509CertificateAtt.serailNumber.data = NULL;
	currentObject->x509CertificateAtt.serailNumber.len = 0;
	currentObject->x509CertificateAtt.subject.data = NULL;
	currentObject->x509CertificateAtt.subject.len = 0;
	currentObject->x509CertificateAtt.url = NULL;
	currentObject->x509CertificateAtt.value.data = NULL;
	currentObject->x509CertificateAtt.value.len = 0;
}


void Initialize_KeyObject(struct keyObject * currentObject) {
	currentObject->commonKeyAtt.id = NULL;
	currentObject->commonPrivateKeyAtt.subject.data = NULL;
	currentObject->commonPrivateKeyAtt.subject.len = 0;
	currentObject->commonPublicKeyAtt.subject.data = NULL;
	currentObject->commonPublicKeyAtt.subject.len = 0;
	currentObject->RSAPrivateKeyObjectAtt.coeficient.data = NULL;
	currentObject->RSAPrivateKeyObjectAtt.coeficient.len = 0;
	currentObject->RSAPrivateKeyObjectAtt.exponent1.data = NULL;
	currentObject->RSAPrivateKeyObjectAtt.exponent1.len = 0;
	currentObject->RSAPrivateKeyObjectAtt.exponent2.data = NULL;
	currentObject->RSAPrivateKeyObjectAtt.exponent2.len = 0;
	currentObject->RSAPrivateKeyObjectAtt.modulus.data = NULL;
	currentObject->RSAPrivateKeyObjectAtt.modulus.len = 0;
	currentObject->RSAPrivateKeyObjectAtt.prime1.data = NULL;
	currentObject->RSAPrivateKeyObjectAtt.prime1.len = 0;
	currentObject->RSAPrivateKeyObjectAtt.prime2.data = NULL;
	currentObject->RSAPrivateKeyObjectAtt.prime2.len = 0;
	currentObject->RSAPrivateKeyObjectAtt.privateExponent.data = NULL;
	currentObject->RSAPrivateKeyObjectAtt.privateExponent.len = 0;
	currentObject->RSAPrivateKeyObjectAtt.publicExponent.data = NULL;
	currentObject->RSAPrivateKeyObjectAtt.publicExponent.len = 0;
	currentObject->RSApublicKeyObjectAtt.modulus.data = NULL;
	currentObject->RSApublicKeyObjectAtt.modulus.len = 0;
	currentObject->RSApublicKeyObjectAtt.publicExponent.data = NULL;
	currentObject->RSApublicKeyObjectAtt.publicExponent.len = 0;
    currentObject->ECpublicKeyObjectAtt.ecParams.data = NULL;
    currentObject->ECpublicKeyObjectAtt.ecParams.len = 0;
    currentObject->ECpublicKeyObjectAtt.ecPoint.data = NULL;
    currentObject->ECpublicKeyObjectAtt.ecPoint.len = 0;
    currentObject->ECpublicKeyObjectAtt.x.data = NULL;
    currentObject->ECpublicKeyObjectAtt.x.len = 0;
    currentObject->ECpublicKeyObjectAtt.y.data = NULL;
    currentObject->ECpublicKeyObjectAtt.y.len = 0;
    currentObject->ECprivateKeyObjectAtt.ecParams.data = NULL;
    currentObject->ECprivateKeyObjectAtt.ecParams.len = 0;
    currentObject->ECprivateKeyObjectAtt.d.data = NULL;
    currentObject->ECprivateKeyObjectAtt.d.len = 0;

}

void Error_Writter(struct context * context, CK_ULONG pkcs11Error) {
	switch (pkcs11Error) {
	case CKR_OK:
		strcpy(context->error, "CKR_OK");
		return;
	case CKR_CANCEL:
		strcpy(context->error, "CKR_CANCEL");
		return;
	case CKR_HOST_MEMORY:
		strcpy(context->error, "CKR_HOST_MEMORY");
		return;
	case CKR_SLOT_ID_INVALID:
		strcpy(context->error, "CKR_SLOT_ID_INVALID");
		return;
	case CKR_GENERAL_ERROR:
		strcpy(context->error, "CKR_GENERAL_ERROR");
		return;
	case CKR_FUNCTION_FAILED:
		strcpy(context->error, "CKR_FUNCTION_FAILED");
		return;
	case CKR_ARGUMENTS_BAD:
		strcpy(context->error, "CKR_ARGUMENTS_BAD");
		return;
	case CKR_NO_EVENT:
		strcpy(context->error, "CKR_NO_EVENT");
		return;
	case CKR_NEED_TO_CREATE_THREADS:
		strcpy(context->error, "CKR_NEED_TO_CREATE_THREADS");
		return;
	case CKR_CANT_LOCK:
		strcpy(context->error, "CKR_CANT_LOCK");
		return;
	case CKR_ATTRIBUTE_READ_ONLY:
		strcpy(context->error, "CKR_ATTRIBUTE_READ_ONLY");
		return;
	case CKR_ATTRIBUTE_SENSITIVE:
		strcpy(context->error, "CKR_ATTRIBUTE_SENSITIVE");
		return;
	case CKR_ATTRIBUTE_TYPE_INVALID:
		strcpy(context->error, "CKR_ATTRIBUTE_TYPE_INVALID");
		return;
	case CKR_ATTRIBUTE_VALUE_INVALID:
		strcpy(context->error, "CKR_ATTRIBUTE_VALUE_INVALID");
		return;
	case CKR_DATA_INVALID:
		strcpy(context->error, "CKR_DATA_INVALID");
		return;
	case CKR_DATA_LEN_RANGE:
		strcpy(context->error, "CKR_DATA_LEN_RANGE");
		return;
	case CKR_DEVICE_ERROR:
		strcpy(context->error, "CKR_DEVICE_ERROR");
		return;
	case CKR_DEVICE_MEMORY:
		strcpy(context->error, "CKR_DEVICE_MEMORY");
		return;
	case CKR_DEVICE_REMOVED:
		strcpy(context->error, "CKR_DEVICE_REMOVED");
		return;
	case CKR_ENCRYPTED_DATA_INVALID:
		strcpy(context->error, "CKR_ENCRYPTED_DATA_INVALID");
		return;
	case CKR_ENCRYPTED_DATA_LEN_RANGE:
		strcpy(context->error, "CKR_ENCRYPTED_DATA_LEN_RANGE");
		return;
	case CKR_FUNCTION_CANCELED:
		strcpy(context->error, "CKR_FUNCTION_CANCELED");
		return;
	case CKR_FUNCTION_NOT_PARALLEL:
		strcpy(context->error, "CKR_FUNCTION_NOT_PARALLEL");
		return;
	case CKR_FUNCTION_NOT_SUPPORTED:
		strcpy(context->error, "CKR_FUNCTION_NOT_SUPPORTED");
		return;
	case CKR_KEY_HANDLE_INVALID:
		strcpy(context->error, "CKR_KEY_HANDLE_INVALID");
		return;
	case CKR_KEY_SIZE_RANGE:
		strcpy(context->error, "CKR_KEY_SIZE_RANGE");
		return;
	case CKR_KEY_TYPE_INCONSISTENT:
		strcpy(context->error, "CKR_KEY_TYPE_INCONSISTENT");
		return;
	case CKR_KEY_NOT_NEEDED:
		strcpy(context->error, "CKR_KEY_NOT_NEEDED");
		return;
	case CKR_KEY_CHANGED:
		strcpy(context->error, "CKR_KEY_CHANGED");
		return;
	case CKR_KEY_NEEDED:
		strcpy(context->error, "CKR_KEY_NEEDED");
		return;
	case CKR_KEY_INDIGESTIBLE:
		strcpy(context->error, "CKR_KEY_INDIGESTIBLE");
		return;
	case CKR_KEY_FUNCTION_NOT_PERMITTED:
		strcpy(context->error, "CKR_KEY_FUNCTION_NOT_PERMITTED");
		return;
	case CKR_KEY_NOT_WRAPPABLE:
		strcpy(context->error, "CKR_KEY_NOT_WRAPPABLE");
		return;
	case CKR_KEY_UNEXTRACTABLE:
		strcpy(context->error, "CKR_KEY_UNEXTRACTABLE");
		return;
	case CKR_MECHANISM_INVALID:
		strcpy(context->error, "CKR_MECHANISM_INVALID");
		return;
	case CKR_MECHANISM_PARAM_INVALID:
		strcpy(context->error, "CKR_MECHANISM_PARAM_INVALID");
		return;
	case CKR_OBJECT_HANDLE_INVALID:
		strcpy(context->error, "CKR_OBJECT_HANDLE_INVALID");
		return;
	case CKR_OPERATION_ACTIVE:
		strcpy(context->error, "CKR_OPERATION_ACTIVE");
		return;
	case CKR_OPERATION_NOT_INITIALIZED:
		strcpy(context->error, "CKR_OPERATION_NOT_INITIALIZED");
		return;
	case CKR_PIN_INCORRECT:
		strcpy(context->error, "CKR_PIN_INCORRECT");
		return;
	case CKR_PIN_INVALID:
		strcpy(context->error, "CKR_PIN_INVALID");
		return;
	case CKR_PIN_LEN_RANGE:
		strcpy(context->error, "CKR_PIN_LEN_RANGE");
		return;
	case CKR_PIN_EXPIRED:
		strcpy(context->error, "CKR_PIN_EXPIRED");
		return;
	case CKR_PIN_LOCKED:
		strcpy(context->error, "CKR_PIN_LOCKED");
		return;
	case CKR_SESSION_CLOSED:
		strcpy(context->error, "CKR_SESSION_CLOSED");
		return;
	case CKR_SESSION_COUNT:
		strcpy(context->error, "CKR_SESSION_COUNT");
		return;
	case CKR_SESSION_HANDLE_INVALID:
		strcpy(context->error, "CKR_SESSION_HANDLE_INVALID");
		return;
	case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
		strcpy(context->error, "CKR_SESSION_PARALLEL_NOT_SUPPORTED");
		return;
	case CKR_SESSION_READ_ONLY:
		strcpy(context->error, "CKR_SESSION_READ_ONLY");
		return;
	case CKR_SESSION_EXISTS:
		strcpy(context->error, "CKR_SESSION_EXISTS");
		return;
	case CKR_SESSION_READ_ONLY_EXISTS:
		strcpy(context->error, "CKR_SESSION_READ_ONLY_EXISTS");
		return;
	case CKR_SESSION_READ_WRITE_SO_EXISTS:
		strcpy(context->error, "CKR_SESSION_READ_WRITE_SO_EXISTS");
		return;
	case CKR_SIGNATURE_INVALID:
		strcpy(context->error, "CKR_SIGNATURE_INVALID");
		return;
	case CKR_SIGNATURE_LEN_RANGE:
		strcpy(context->error, "CKR_SIGNATURE_LEN_RANGE");
		return;
	case CKR_TEMPLATE_INCOMPLETE:
		strcpy(context->error, "CKR_TEMPLATE_INCOMPLETE");
		return;
	case CKR_TEMPLATE_INCONSISTENT:
		strcpy(context->error, "CKR_TEMPLATE_INCONSISTENT");
		return;
	case CKR_TOKEN_NOT_PRESENT:
		strcpy(context->error, "CKR_TOKEN_NOT_PRESENT");
		return;
	case CKR_TOKEN_NOT_RECOGNIZED:
		strcpy(context->error, "CKR_TOKEN_NOT_RECOGNIZED");
		return;
	case CKR_TOKEN_WRITE_PROTECTED:
		strcpy(context->error, "CKR_TOKEN_WRITE_PROTECTED");
		return;
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
		strcpy(context->error, "CKR_UNWRAPPING_KEY_HANDLE_INVALID");
		return;
	case CKR_UNWRAPPING_KEY_SIZE_RANGE:
		strcpy(context->error, "CKR_UNWRAPPING_KEY_SIZE_RANGE");
		return;
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
		strcpy(context->error, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT");
		return;
	case CKR_USER_ALREADY_LOGGED_IN:
		strcpy(context->error, "CKR_USER_ALREADY_LOGGED_IN");
		return;
	case CKR_USER_NOT_LOGGED_IN:
		strcpy(context->error, "CKR_USER_NOT_LOGGED_IN");
		return;
	case CKR_USER_PIN_NOT_INITIALIZED:
		strcpy(context->error, "CKR_USER_PIN_NOT_INITIALIZED");
		return;
	case CKR_USER_TYPE_INVALID:
		strcpy(context->error, "CKR_USER_TYPE_INVALID");
		return;
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
		strcpy(context->error, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN");
		return;
	case CKR_USER_TOO_MANY_TYPES:
		strcpy(context->error, "CKR_USER_TOO_MANY_TYPES");
		return;
	case CKR_WRAPPED_KEY_INVALID:
		strcpy(context->error, "CKR_WRAPPED_KEY_INVALID");
		return;
	case CKR_WRAPPED_KEY_LEN_RANGE:
		strcpy(context->error, "CKR_WRAPPED_KEY_LEN_RANGE");
		return;
	case CKR_WRAPPING_KEY_HANDLE_INVALID:
		strcpy(context->error, "CKR_WRAPPING_KEY_HANDLE_INVALID");
		return;
	case CKR_WRAPPING_KEY_SIZE_RANGE:
		strcpy(context->error, "CKR_WRAPPING_KEY_SIZE_RANGE");
		return;
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
		strcpy(context->error, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT");
		return;
	case CKR_RANDOM_SEED_NOT_SUPPORTED:
		strcpy(context->error, "CKR_RANDOM_SEED_NOT_SUPPORTED");
		return;
	case CKR_RANDOM_NO_RNG:
		strcpy(context->error, "CKR_RANDOM_NO_RNG");
		return;
	case CKR_DOMAIN_PARAMS_INVALID:
		strcpy(context->error, "CKR_DOMAIN_PARAMS_INVALID");
		return;
	case CKR_BUFFER_TOO_SMALL:
		strcpy(context->error, "CKR_BUFFER_TOO_SMALL");
		return;
	case CKR_SAVED_STATE_INVALID:
		strcpy(context->error, "CKR_SAVED_STATE_INVALID");
		return;
	case CKR_INFORMATION_SENSITIVE:
		strcpy(context->error, "CKR_INFORMATION_SENSITIVE");
		return;
	case CKR_STATE_UNSAVEABLE:
		strcpy(context->error, "CKR_STATE_UNSAVEABLE");
		return;
	case CKR_CRYPTOKI_NOT_INITIALIZED:
		strcpy(context->error, "CKR_CRYPTOKI_NOT_INITIALIZED");
		return;
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:
		strcpy(context->error, "CKR_CRYPTOKI_ALREADY_INITIALIZED");
		return;
	case CKR_MUTEX_BAD:
		strcpy(context->error, "CKR_MUTEX_BAD");
		return;
	case CKR_MUTEX_NOT_LOCKED:
		strcpy(context->error, "CKR_MUTEX_NOT_LOCKED");
		return;
	case CKR_NEW_PIN_MODE:
		strcpy(context->error, "CKR_NEW_PIN_MODE");
		return;
	case CKR_NEXT_OTP:
		strcpy(context->error, "CKR_NEXT_OTP");
		return;
	case CKR_FUNCTION_REJECTED:
		strcpy(context->error, "CKR_FUNCTION_REJECTED");
		return;
	case CKR_VENDOR_DEFINED:
		strcpy(context->error, "CKR_VENDOR_DEFINED");
		return;
	default:
		strcpy(context->error, "UNKNOW_ERROR");
		return;
	}
}
void CK_BBOOL_To_String(CK_BBOOL ckBool, char ckBoolString[]) {
	if (ckBool == CK_TRUE) {
		strcpy(ckBoolString, "CK_TRUE");
	}
	else {
		strcpy(ckBoolString, "CK_FALSE");
	}
}

void PKCS11_Attribute_Transriptor(CK_ATTRIBUTE Template, struct context *context) {
	if (LOG_CONTEXT.DEBUG_LEVEL != TRACE) return;
	unsigned char *serialHex = NULL;
	int size;
	const unsigned char *p;
	char type[MAX_SMALL_DEBUG_BUFFER] = "";
	char staticValue[MAX_SMALL_DEBUG_BUFFER] = "";
	switch ((CK_ULONG)Template.type) {
		/* The following attribute types are defined: */
	case CKA_CLASS:
		strcpy(type, "CKA_CLASS");
		switch (*(CK_ULONG*)Template.pValue) {
		case CKO_CERTIFICATE:
			strcpy(staticValue, "CKO_CERTIFICATE");
			break;
		case CKO_DATA:
			strcpy(staticValue, "CKO_DATA");
			break;
		case CKO_PUBLIC_KEY:
			strcpy(staticValue, "CKO_PUBLIC_KEY");
			break;
		case CKO_PRIVATE_KEY:
			strcpy(staticValue, "CKO_PRIVATE_KEY");
			break;
		case CKO_SECRET_KEY:
			strcpy(staticValue, "CKO_SECRET_KEY");
			break;
		case CKO_HW_FEATURE:
			strcpy(staticValue, "CKO_HW_FEATURE");
			break;
		case CKO_DOMAIN_PARAMETERS:
			strcpy(staticValue, "CKO_DOMAIN_PARAMETERS");
			break;
		case CKO_MECHANISM:
			strcpy(staticValue, "CKO_MECHANISM");
			break;
		default:
			strcpy(staticValue, "Invalid CKO");
			break;
		}
		break;
	case CKA_TOKEN:
		strcpy(type, "CKA_TOKEN");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_PRIVATE:
		strcpy(type, "CKA_PRIVATE");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_LABEL:
		strcpy(type, "CKA_LABEL");
		if ((int)Template.ulValueLen < 29) {
			memcpy(staticValue, Template.pValue, (int)Template.ulValueLen);
			staticValue[(int)Template.ulValueLen] = '\0';
		}
		else {
			memcpy(staticValue, Template.pValue, 29);
			staticValue[29] = '\0';
		}
		break;
	case CKA_APPLICATION:
		strcpy(type, "CKA_APPLICATION");
		break;
	case CKA_VALUE:
		strcpy(type, "CKA_VALUE");
		break;
		/* CKA_OBJECT_ID is new for v2.10 */
	case CKA_OBJECT_ID:
		strcpy(type, "CKA_OBJECT_ID");
		break;
	case CKA_CERTIFICATE_TYPE:
		strcpy(type, "CKA_CERTIFICATE_TYPE");
		break;
	case CKA_ISSUER:
		strcpy(type, "CKA_ISSUER");
		size = (int)Template.ulValueLen;
		p = (const unsigned char*)Template.pValue;
		serialHex = malloc((size * 2) + 1);
		if (serialHex != NULL) {
			memset(serialHex, 0, size * 2);
			serialHex[size * 2] = '\0';
			for (int i = 0; i < size; i++) {
				sprintf(&serialHex[2 * i], "%02x", p[i]);
			}
			Write_Debug_Template(*context, type, staticValue, serialHex, LOG_CONTEXT);
			free(serialHex);
		}
		return;
	case CKA_SERIAL_NUMBER:
		strcpy(type, "CKA_SERIAL_NUMBER"); 
		size = (int)Template.ulValueLen;
		p = (const unsigned char*)Template.pValue;
		serialHex = malloc((size * 2) + 1);
		if (serialHex != NULL) {
			memset(serialHex, 0, size * 2);
			serialHex[size * 2] = '\0';
			for (int i = 0; i < size; i++) {
				sprintf(&serialHex[2 * i], "%02x", p[i]);
			}
			Write_Debug_Template(*context, type, staticValue, serialHex, LOG_CONTEXT);
			free(serialHex);
		}
		return;
	case CKA_AC_ISSUER:
		strcpy(type, "CKA_AC_ISSUER");
		size = (int)Template.ulValueLen;
		p = (const unsigned char*)Template.pValue;
		serialHex = malloc((size * 2) + 1);
		if (serialHex != NULL) {
			memset(serialHex, 0, size * 2);
			serialHex[size * 2] = '\0';
			for (int i = 0; i < size; i++) {
				sprintf(&serialHex[2 * i], "%02x", p[i]);
			}
			Write_Debug_Template(*context, type, staticValue, serialHex, LOG_CONTEXT);
			free(serialHex);
		}
		return;
	case CKA_OWNER:
		strcpy(type, "CKA_OWNER");
		size = (int)Template.ulValueLen;
		p = (const unsigned char*)Template.pValue;
		serialHex = malloc((size * 2) + 1);
		if (serialHex != NULL) {
			memset(serialHex, 0, size * 2);
			serialHex[size * 2] = '\0';
			for (int i = 0; i < size; i++) {
				sprintf(&serialHex[2 * i], "%02x", p[i]);
			}
			Write_Debug_Template(*context, type, staticValue, serialHex, LOG_CONTEXT);
			free(serialHex);
		}
		return;
	case CKA_ATTR_TYPES:
		strcpy(type, "CKA_ATTR_TYPES");
		size = (int)Template.ulValueLen;
		p = (const unsigned char*)Template.pValue;
		serialHex = malloc((size * 2) + 1);
		if (serialHex != NULL) {
			memset(serialHex, 0, size * 2);
			serialHex[size * 2] = '\0';
			for (int i = 0; i < size; i++) {
				sprintf(&serialHex[2 * i], "%02x", p[i]);
			}
			Write_Debug_Template(*context, type, staticValue, serialHex, LOG_CONTEXT);
			free(serialHex);
		}
		return;
		/* CKA_TRUSTED is new for v2.11 */
	case CKA_TRUSTED:
		strcpy(type, "CKA_TRUSTED");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
		/* CKA_CERTIFICATE_CATEGORY ...
		* CKA_CHECK_VALUE are new for v2.20 */
	case CKA_CERTIFICATE_CATEGORY:
		strcpy(type, "CKA_CERTIFICATE_CATEGORY");
		break;
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
		strcpy(type, "CKA_JAVA_MIDP_SECURITY_DOMAIN");
		break;
	case CKA_URL:
		strcpy(type, "CKA_URL");
		break;
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		strcpy(type, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY");
		break;
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		strcpy(type, "CKA_HASH_OF_ISSUER_PUBLIC_KEY");
		break;
	case CKA_CHECK_VALUE:
		strcpy(type, "CKA_CHECK_VALUE");
		break;
	case CKA_KEY_TYPE:
		strcpy(type, "CKA_KEY_TYPE");
		break;
	case CKA_SUBJECT:
		strcpy(type, "CKA_SUBJECT");
		size = (int)Template.ulValueLen;
		p = (const unsigned char*)Template.pValue;
		serialHex = malloc((size * 2) + 1);
		if (serialHex != NULL) {
			memset(serialHex, 0, size * 2);
			serialHex[size * 2] = '\0';
			for (int i = 0; i < size; i++) {
				sprintf(&serialHex[2 * i], "%02x", p[i]);
			}
			Write_Debug_Template(*context, type, staticValue, serialHex, LOG_CONTEXT);
			free(serialHex);
		}
		return;
	case CKA_ID:
		strcpy(type, "CKA_ID");
		if ((int)Template.ulValueLen < 29) {
			memcpy(staticValue, Template.pValue, (int)Template.ulValueLen);
			staticValue[(int)Template.ulValueLen] = '\0';
		}
		else {
			memcpy(staticValue, Template.pValue, 29);
			staticValue[29] = '\0';
		}
		break;
	case CKA_SENSITIVE:
		strcpy(type, "CKA_SENSITIVE");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_ENCRYPT:
		strcpy(type, "CKA_ENCRYPT");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_DECRYPT:
		strcpy(type, "CKA_DECRYPT");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_WRAP:
		strcpy(type, "CKA_WRAP");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_UNWRAP:
		strcpy(type, "CKA_UNWRAP");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_SIGN:
		strcpy(type, "CKA_SIGN");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_SIGN_RECOVER:
		strcpy(type, "CKA_SIGN_RECOVER");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_VERIFY:
		strcpy(type, "CKA_VERIFY");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_VERIFY_RECOVER:
		strcpy(type, "CKA_VERIFY_RECOVER");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_DERIVE:
		strcpy(type, "CKA_DERIVE");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_START_DATE:
		strcpy(type, "CKA_START_DATE");
		break;
	case CKA_END_DATE:
		strcpy(type, "CKA_END_DATE");
		break;
	case CKA_MODULUS:
		strcpy(type, "CKA_MODULUS");
		size = (int)Template.ulValueLen;
		p = (const unsigned char*)Template.pValue;
		serialHex = malloc((size * 2) + 1);
		if (serialHex != NULL) {
			memset(serialHex, 0, size * 2);
			serialHex[size * 2] = '\0';
			for (int i = 0; i < size; i++) {
				sprintf(&serialHex[2 * i], "%02x", p[i]);
			}
			Write_Debug_Template(*context, type, staticValue, serialHex, LOG_CONTEXT);
			free(serialHex);
		}
		return;
		break;
	case CKA_MODULUS_BITS:
		strcpy(type, "CKA_MODULUS_BITS");
		sprintf(staticValue, "%d", *(CK_ULONG*)Template.pValue);
		break;
	case CKA_PUBLIC_EXPONENT:
		strcpy(type, "CKA_PUBLIC_EXPONENT");
		size = (int)Template.ulValueLen;
		p = (const unsigned char*)Template.pValue;
		serialHex = malloc((size * 2) + 1);
		if (serialHex != NULL) {
			memset(serialHex, 0, size * 2);
			serialHex[size * 2] = '\0';
			for (int i = 0; i < size; i++) {
				sprintf(&serialHex[2 * i], "%02x", p[i]);
			}
			Write_Debug_Template(*context, type, staticValue, serialHex, LOG_CONTEXT);
			free(serialHex);
		}
		return;
		break;
	case CKA_PRIVATE_EXPONENT:
		strcpy(type, "CKA_PRIVATE_EXPONENT");
		break;
	case CKA_PRIME_1:
		strcpy(type, "CKA_PRIME_1");
		break;
	case CKA_PRIME_2:
		strcpy(type, "CKA_PRIME_2");
		break;
	case CKA_EXPONENT_1:
		strcpy(type, "CKA_EXPONENT_1");
		break;
	case CKA_EXPONENT_2:
		strcpy(type, "CKA_EXPONENT_2");
		break;
	case CKA_COEFFICIENT:
		strcpy(type, "CKA_COEFFICIENT");
		break;
	case CKA_PRIME:
		strcpy(type, "CKA_PRIME");
		break;
	case CKA_SUBPRIME:
		strcpy(type, "CKA_SUBPRIME");
		break;
	case CKA_BASE:
		strcpy(type, "CKA_BASE");
		break;
		/* CKA_PRIME_BITS and CKA_SUB_PRIME_BITS are new for v2.11 */
	case CKA_PRIME_BITS:
		strcpy(type, "CKA_PRIME_BITS");
		break;
	case CKA_SUBPRIME_BITS:
		strcpy(type, "CKA_SUBPRIME_BITS");
		break;
	case CKA_VALUE_BITS:
		strcpy(type, "CKA_VALUE_BITS");
		break;
	case CKA_VALUE_LEN:
		strcpy(type, "CKA_VALUE_LEN");
		break;
		/* CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
		* CKA_ALWAYS_SENSITIVE, CKA_MODIFIABLE, CKA_ECDSA_PARAMS,
		* and CKA_EC_POINT are new for v2.0 */
	case CKA_EXTRACTABLE:
		strcpy(type, "CKA_EXTRACTABLE");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_LOCAL:
		strcpy(type, "CKA_LOCAL");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_NEVER_EXTRACTABLE:
		strcpy(type, "CKA_NEVER_EXTRACTABLE");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_ALWAYS_SENSITIVE:
		strcpy(type, "CKA_ALWAYS_SENSITIVE");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
		/* CKA_KEY_GEN_MECHANISM is new for v2.11 */
	case CKA_KEY_GEN_MECHANISM:
		strcpy(type, "CKA_KEY_GEN_MECHANISM");
		break;
	case CKA_MODIFIABLE:
		strcpy(type, "CKA_MODIFIABLE");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
		/* CKA_ECDSA_PARAMS is deprecated in v2.11,
		* CKA_EC_PARAMS is preferred. */
	case CKA_ECDSA_PARAMS:
		strcpy(type, "CKA_ECDSA_PARAMS");
        size = (int)Template.ulValueLen;
        p = (const unsigned char*)Template.pValue;
        serialHex = malloc((size * 2) + 1);
        if (serialHex != NULL) {
            memset(serialHex, 0, size * 2);
            serialHex[size * 2] = '\0';
            for (int i = 0; i < size; i++) {
                sprintf(&serialHex[2 * i], "%02x", p[i]);
            }
            Write_Debug_Template(*context, type, staticValue, serialHex, LOG_CONTEXT);
            free(serialHex);
        }
        return;
		break;
    case CKA_EC_POINT:
		strcpy(type, "CKA_EC_POINT");
		break;
		/* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
		* are new for v2.10. Deprecated in v2.11 and onwards. */
	case CKA_SECONDARY_AUTH:
		strcpy(type, "CKA_SECONDARY_AUTH");
		break;
	case CKA_AUTH_PIN_FLAGS:
		strcpy(type, "CKA_AUTH_PIN_FLAGS");
		break;
		/* CKA_ALWAYS_AUTHENTICATE ...
		* CKA_UNWRAP_TEMPLATE are new for v2.20 */
	case CKA_ALWAYS_AUTHENTICATE:
		strcpy(type, "CKA_ALWAYS_AUTHENTICATE");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_WRAP_WITH_TRUSTED:
		strcpy(type, "CKA_WRAP_WITH_TRUSTED");
		CK_BBOOL_To_String(*(CK_BBOOL*)Template.pValue, staticValue);
		break;
	case CKA_WRAP_TEMPLATE:
		strcpy(type, "CKA_WRAP_TEMPLATE");
		break;
	case CKA_UNWRAP_TEMPLATE:
		strcpy(type, "CKA_UNWRAP_TEMPLATE");
		break;
		/* CKA_OTP... atttributes are new for PKCS #11 v2.20 amendment 3. */
	case CKA_OTP_FORMAT:
		strcpy(type, "CKA_OTP_FORMAT");
		break;
	case CKA_OTP_LENGTH:
		strcpy(type, "CKA_OTP_LENGTH");
		break;
	case CKA_OTP_TIME_INTERVAL:
		strcpy(type, "CKA_OTP_TIME_INTERVAL");
		break;
	case CKA_OTP_USER_FRIENDLY_MODE:
		strcpy(type, "CKA_OTP_USER_FRIENDLY_MODE");
		break;
	case CKA_OTP_CHALLENGE_REQUIREMENT:
		strcpy(type, "CKA_OTP_CHALLENGE_REQUIREMENT");
		break;
	case CKA_OTP_TIME_REQUIREMENT:
		strcpy(type, "CKA_OTP_TIME_REQUIREMENT");
		break;
	case CKA_OTP_COUNTER_REQUIREMENT:
		strcpy(type, "CKA_OTP_COUNTER_REQUIREMENT");
		break;
	case CKA_OTP_PIN_REQUIREMENT:
		strcpy(type, "CKA_OTP_PIN_REQUIREMENT");
		break;
	case CKA_OTP_COUNTER:
		strcpy(type, "CKA_OTP_COUNTER");
		break;
	case CKA_OTP_TIME:
		strcpy(type, "CKA_OTP_TIME");
		break;
	case CKA_OTP_USER_IDENTIFIER:
		strcpy(type, "CKA_OTP_USER_IDENTIFIER");
		break;
	case CKA_OTP_SERVICE_IDENTIFIER:
		strcpy(type, "CKA_OTP_SERVICE_IDENTIFIER");
		break;
	case CKA_OTP_SERVICE_LOGO:
		strcpy(type, "CKA_OTP_SERVICE_LOGO");
		break;
	case CKA_OTP_SERVICE_LOGO_TYPE:
		strcpy(type, "CKA_OTP_SERVICE_LOGO_TYPE");
		break;
		/* CKA_HW_FEATURE_TYPE, CKA_RESET_ON_INIT, and CKA_HAS_RESET
		* are new for v2.10 */
	case CKA_HW_FEATURE_TYPE:
		strcpy(type, "CKA_HW_FEATURE_TYPE");
		break;
	case CKA_RESET_ON_INIT:
		strcpy(type, "CKA_RESET_ON_INIT");
		break;
	case CKA_HAS_RESET:
		strcpy(type, "CKA_HAS_RESET");
		break;
		/* The following attributes are new for v2.20 */
	case CKA_PIXEL_X:
		strcpy(type, "CKA_PIXEL_X");
		break;
	case CKA_PIXEL_Y:
		strcpy(type, "CKA_PIXEL_Y");
		break;
	case CKA_RESOLUTION:
		strcpy(type, "CKA_RESOLUTION");
		break;
	case CKA_CHAR_ROWS:
		strcpy(type, "CKA_CHAR_ROWS");
		break;
	case CKA_CHAR_COLUMNS:
		strcpy(type, "CKA_CHAR_COLUMNS");
		break;
	case CKA_COLOR:
		strcpy(type, "CKA_COLOR");
		break;
	case CKA_BITS_PER_PIXEL:
		strcpy(type, "CKA_BITS_PER_PIXEL");
		break;
	case CKA_CHAR_SETS:
		strcpy(type, "CKA_CHAR_SETS");
		break;
	case CKA_ENCODING_METHODS:
		strcpy(type, "CKA_ENCODING_METHODS");
		break;
	case CKA_MIME_TYPES:
		strcpy(type, "CKA_MIME_TYPES");
		break;
	case CKA_MECHANISM_TYPE:
		strcpy(type, "CKA_MECHANISM_TYPE");
		break;
	case CKA_REQUIRED_CMS_ATTRIBUTES:
		strcpy(type, "CKA_REQUIRED_CMS_ATTRIBUTES");
		break;
	case CKA_DEFAULT_CMS_ATTRIBUTES:
		strcpy(type, "CKA_DEFAULT_CMS_ATTRIBUTES");
		break;
	case CKA_SUPPORTED_CMS_ATTRIBUTES:
		strcpy(type, "CKA_SUPPORTED_CMS_ATTRIBUTES");
		break;
	case CKA_ALLOWED_MECHANISMS:
		strcpy(type, "CKA_ALLOWED_MECHANISMS");
		break;
	case CKA_VENDOR_DEFINED:
		strcpy(type, "CKA_VENDOR_DEFINED");
		break;
	default:
		strcpy(type, "CKA_UNKNOWN");
		return;
	}
	Write_Debug_Template(*context, type, staticValue, NULL, LOG_CONTEXT);
	return;
}
