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

#include "interface.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <src/librb64u.h>

int HashSHA256(unsigned char *hashed, const unsigned char *plain, size_t plen) {
	EVP_MD_CTX *mdctx;
	int md_len = 0;
	if (!(mdctx = EVP_MD_CTX_create())) return 0;
	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
		if (mdctx) EVP_MD_CTX_destroy(mdctx);
		return 0;
	}
	if (1 != EVP_DigestUpdate(mdctx, plain, plen)) {
		if (mdctx) EVP_MD_CTX_destroy(mdctx);
		return 0;
	}
	if (1 != EVP_DigestFinal_ex(mdctx, hashed, &md_len)) {
		if (mdctx) EVP_MD_CTX_destroy(mdctx);
		return 0;
	}
	if (mdctx) EVP_MD_CTX_destroy(mdctx);
	return md_len;
}

ERROR_CODE DeriveKey(U_CHAR_PTR pPin, U_LONG ulPinLen, U_CHAR **configurationKey, const unsigned char *salt, U_LONG saltSize) {
	unsigned char *out = malloc(sizeof(unsigned char) * KEK_KEY_LEN);
	if (out == NULL) return MD_HOST_MEMORY;
	if (PKCS5_PBKDF2_HMAC(pPin, ulPinLen, salt, saltSize, ITERATION, EVP_sha256(), KEK_KEY_LEN, out) != 0)
	{
		*configurationKey = out;
		return MD_NO_ERROR;
	}
	else
	{
		*configurationKey = NULL;
		return MD_PIN_INVALID;
	}
}

ERROR_CODE IVCalculator(const unsigned char *iv, U_CHAR_PTR id, U_CHAR_PTR suffix) {
	if (id == NULL || suffix == NULL) return 0;
	size_t plainSize = strlen(id) + strlen(suffix);
	const unsigned char *plain = malloc(plainSize + 1);
	if (plain == NULL) return 0;
	strcpy(plain, id);
	strcat(plain, suffix);
	unsigned char hash256[SHA256_DIGEST_LENGTH] = "";
	int sha256Size = HashSHA256(&hash256, plain, plainSize);
	free(plain);
	if (sha256Size <= EVP_MAX_IV_LENGTH) return 0;
	memcpy(iv, hash256, EVP_MAX_IV_LENGTH);
	return 1;
}

ERROR_CODE EncryptParameter(U_CHAR *parameter, U_CHAR **cipherData, const unsigned char *iv, U_CHAR *configurationKey) {
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		*cipherData = NULL;
		return MD_NO_ERROR;
	}
	/* Initialise the encryption operation.
	* We are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, configurationKey, iv)) {
		*cipherData = NULL;
		return MD_NO_ERROR;
	}
	// The output buffer size needs to be bigger to accomodate incomplete blocks
	// See EVP_EncryptUpdate documentation for explanation:
	//https://www.openssl.org/docs/man1.0.2/crypto/EVP_EncryptUpdate.html
	int cipher_block_size = EVP_CIPHER_block_size(ctx->cipher);
	int outsize = strlen(parameter) + (cipher_block_size - 1);
	unsigned char *ciphertext = malloc(outsize);
	if (ciphertext == NULL) {
		*cipherData = NULL;
		return MD_NO_ERROR;
	}
	/* Provide the message to be encrypted, and obtain the encrypted output.
	* EVP_EncryptUpdate can be called multiple times if necessary
	*/
	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, parameter, strlen(parameter))) {
		*cipherData = NULL;
		return MD_NO_ERROR;
	}
	ciphertext_len = len;
	/* Finalise the encryption. Further ciphertext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		*cipherData = NULL;
		return MD_NO_ERROR;
	}
	ciphertext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	*cipherData = ciphertext;
	return ciphertext_len;
}

ERROR_CODE DecryptParameter(unsigned char *ciphertext, int ciphertext_len, U_CHAR *configurationKey, unsigned char *iv, U_CHAR **plainData)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new())) {
		*plainData = NULL;
		return 0;
	}
	/* Initialise the decryption operation.
	* We are using 256 bit AES (i.e. a 256 bit key). The
	* IV size for *most* modes is the same as the block size. For AES this
	* is 128 bits */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, configurationKey, iv)) {
		*plainData = NULL;
		return 0;
	}
	/* Provide the message to be decrypted, and obtain the plaintext output.
	* EVP_DecryptUpdate can be called multiple times if necessary
	*/
	unsigned char *plaintext = malloc(ciphertext_len + 1);
	if (ciphertext == NULL) {
		*plainData = NULL;
		return 0;
	}
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		free(plaintext);
		*plainData = NULL;
		return 0;
	}
	plaintext_len = len;
	/* Finalise the decryption. Further plaintext bytes may be written at
	* this stage.
	*/
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		free(plaintext);
		*plainData = NULL;
		return 0;
	}
	plaintext_len += len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	plaintext[plaintext_len] = '\0';
	*plainData = plaintext;
	return plaintext_len;
}

ERROR_CODE EncryptConfigurationData(U_CHAR_PTR *parameter, U_CHAR_PTR parameterName, U_CHAR_PTR configurationKey) {
	if (*parameter == NULL) return MD_UNDEFINED_ERROR;
	const unsigned char iv[EVP_MAX_IV_LENGTH] = "";
	if (!IVCalculator(&iv, (U_CHAR_PTR)CLIENTID, parameterName)) {
		return MD_UNDEFINED_ERROR;
	}
	U_CHAR *cipherData = NULL;
	U_LONG encryptDataSize = EncryptParameter(*parameter, &cipherData, iv, configurationKey);
	if (encryptDataSize <= 0) {
		return MD_UNDEFINED_ERROR;
	}
	char* base64Data = NULL;
	base64Data = base64encode(cipherData, encryptDataSize);
	if (base64Data == NULL) {
		free(cipherData);
		return MD_UNDEFINED_ERROR;
	}
	free(cipherData);
	free(*parameter);
	*parameter = base64Data;
	return MD_NO_ERROR;
}

ERROR_CODE EncryptAllConfigurationData(U_CHAR_PTR pPin, U_LONG ulPinLen) {
	if (CLIENTID != NULL) {
		U_CHAR_PTR  configurationKey = NULL;
		U_LONG result = DeriveKey(pPin, ulPinLen, &configurationKey, CLIENTID, strlen(CLIENTID));
		if (result != MD_NO_ERROR) return MD_UNDEFINED_ERROR;
		result = EncryptConfigurationData((U_CHAR_PTR)&TENANTID, (U_CHAR_PTR)&"TENANTID", configurationKey);
		if (result != MD_NO_ERROR) {
			free(configurationKey);
			return result;
		}
		result = EncryptConfigurationData((U_CHAR_PTR)&HOST, (U_CHAR_PTR)&"HOST", configurationKey);
		if (result != MD_NO_ERROR) {
			free(configurationKey);
			return result;
		}
		result = EncryptConfigurationData((U_CHAR_PTR)&PASSWORD, (U_CHAR_PTR)&"PASSWORD", configurationKey);
		if (result != MD_NO_ERROR) {
			free(configurationKey);
			return result;
		}
		free(configurationKey);
		result = EncryptConfFile();
		if (result != OK) {
			if (result == MD_HOST_MEMORY) {
				return MD_HOST_MEMORY;
			}
			else {
				return MD_UNDEFINED_ERROR;
			}
		}
		else return MD_NO_ERROR;
	}
	else return MD_UNDEFINED_ERROR;
}

ERROR_CODE DecryptConfigurationData(U_CHAR_PTR *parameter, U_CHAR_PTR parameterName, U_CHAR_PTR configurationKey) {
	if (*parameter == NULL) return MD_UNDEFINED_ERROR;
	const unsigned char iv[EVP_MAX_IV_LENGTH] = "";
	if (!IVCalculator(&iv, CLIENTID, parameterName)) {
		return MD_UNDEFINED_ERROR;
	}
	char* cipherData = NULL;
	size_t cipherDataLength;
	if (base64Decode(*parameter, &cipherData, &cipherDataLength))
		return MD_PIN_NOT_INITIALIZED;
	U_CHAR *plainData = NULL;
	U_LONG decryptDataSize = DecryptParameter(cipherData, cipherDataLength, configurationKey, iv, &plainData);
	if (decryptDataSize <= 0) {
		return MD_PIN_INVALID;
	}
	free(cipherData);
	if (*parameter != NULL) free(*parameter);
	*parameter = plainData;
	return MD_NO_ERROR;
}

ERROR_CODE DecryptAllConfigurationData(U_CHAR_PTR pPin, U_LONG ulPinLen) {
	U_CHAR_PTR  configurationKey = NULL;
	U_LONG result = DeriveKey(pPin, ulPinLen, &configurationKey, CLIENTID, strlen(CLIENTID));
	if (result != MD_NO_ERROR) return MD_UNDEFINED_ERROR;
	result = DecryptConfigurationData(&TENANTID, &"TENANTID", configurationKey);
	if (result != MD_NO_ERROR) {
		return result;
	}
	result = DecryptConfigurationData(&HOST, &"HOST", configurationKey);
	if (result != MD_NO_ERROR) {
		return result;
	}
	result = DecryptConfigurationData(&PASSWORD, (U_CHAR_PTR)&"PASSWORD", configurationKey);
	if (result != MD_NO_ERROR) {
		return result;
	}
	return result;
}

ERROR_CODE GetAccesToken(U_CHAR **azureToken) {
	struct token_response *tokenResponse = NULL;
	struct client_data *clientData = NULL;
	clientData = Store_ClientData(PASSWORD, AUTH_URL, RESOURCE, CLIENTID, TENANTID);
	int result = Get_AccesToken(clientData, &tokenResponse);
	Free_ClientData(clientData);
	if (result != HTTP_OK) {
		Free_AccesTokenResponse(tokenResponse);
		if (result < HTTP_OK) {
			return MD_TOKEN_NOT_PRESENT;
		}
		else {
			switch (result) {
			case ALLOCATE_ERROR:
				return MD_HOST_MEMORY;
			case UNAUTHORIZED:
				return MD_PIN_INVALID;
			case FORBIDDEN:
				return MD_UNDEFINED_ERROR;
			case NOT_FOUND:
				return MD_TOKEN_NOT_PRESENT;
			default:
				return MD_FUNCTION_FAILED;
			}
		}
	}
	else {
		U_CHAR_PTR token = (U_CHAR_PTR)_strdup(tokenResponse->access_token);
		Free_AccesTokenResponse(tokenResponse);
		if (token == NULL) return MD_HOST_MEMORY;
		*azureToken = token;
		return MD_NO_ERROR;
	}
}