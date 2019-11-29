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

#include "clientRest.h"
#include <src/cJSON.h>
#include <src/Debug.h>
#include <src/common.h>

size_t write_data(void *ptr, size_t size, size_t nmemb, struct url_data *data) {
	size_t index = data->size;
	size_t n = (size * nmemb);
	char* tmp;
	data->size += (size * nmemb);
	tmp = realloc(data->data, data->size + 1); /* +1 for '\0' */
	if (tmp) {
		data->data = tmp;
	}
	else {
		if (data->data) {
			free(data->data);
		}
		fprintf(stderr, "Failed to allocate memory.\n");
		return 0;
	}
	memcpy((data->data + index), ptr, n);
	data->data[data->size] = '\0';
	return size * nmemb;
}

int Https_Request(struct request_data *postData, char** response, char *operation) {
	struct url_data data;
	data.size = 0;
	data.data = malloc(4096); /* reasonable size initial buffer */
	if (NULL == data.data) {
		/*fprintf(stderr, "Failed to allocate memory.\n");*/
		return ALLOCATE_ERROR;
	}
	data.data[0] = '\0';
	long http_code = 0;
	CURL *curl;
	CURLcode res;
	size_t size;
	///* In windows, this will init the winsock stuff */
	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();
	char errbuf[CURL_ERROR_SIZE];
	if (curl) {
		/* First set the URL that is about to receive our POST. This URL can
		just as well be a https:// URL if that is what should receive the
		data. */
		struct curl_slist *chunk = NULL;
		/* Add a custom header */
		if (postData->sesion) {
			Write_Debug_Call(postData->url, LOG_CONTEXT);
			chunk = curl_slist_append(chunk, "Accept: application/json");
			chunk = curl_slist_append(chunk, "Content-Type: application/json");
			size = strlen("Authorization: Bearer ") + strlen(postData->token) + 1;
			char *auth = malloc(size);
			if (auth == NULL) {
				/* always cleanup */
				curl_easy_cleanup(curl);
				/* free the custom headers */
				curl_slist_free_all(chunk);
				curl_global_cleanup();
				return ALLOCATE_ERROR;
			}
			strcpy(auth, "Authorization: Bearer ");
			strcat(auth, postData->token);
			chunk = curl_slist_append(chunk, auth);
			free(auth);
			/* set our custom set of headers */
			res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
		}
		if (!strcmp(operation, "POST")) {
			curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
			/* Now specify the POST data */
			if (postData->parameters != NULL)
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData->parameters);
		}
		else if (!strcmp(operation, "PATCH")) {
			curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
			/* Now specify the POST data */
			if (postData->parameters != NULL)
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData->parameters);
		}
		else if (!strcmp(operation, "GET")) {
			curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
		}
		else if (!strcmp(operation, "DELETE")) {
			curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
		}
		else if (!strcmp(operation, "PUT")) {
			curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
			if (postData->parameters != NULL)
				curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData->parameters);
		}
		else {
			/* always cleanup */
			curl_easy_cleanup(curl);
			/* free the custom headers */
			curl_slist_free_all(chunk);
			curl_global_cleanup();
			free(data.data);
			return BAD_REQUEST;

		}
		//set curl verbose behavior
		//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		curl_easy_setopt(curl, CURLOPT_URL, postData->url);
		/* For HTTPS */
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		/* Set CURLOPT_ERRORBUFFER for error message and set errbuf=0*/
		errbuf[0] = 0;
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
		/*Define write function to write http response*/
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
		/*Define variable where response goes*/
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		// HTTP Status code
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
		/* Check for errors */
		if (res != CURLE_OK) {
			/* always cleanup */
			curl_easy_cleanup(curl);
			/* free the custom headers */
			curl_slist_free_all(chunk);
			curl_global_cleanup();
			free(data.data);
			return res;
		}
		/* free the custom headers */
		curl_slist_free_all(chunk);
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();
	if (data.data) {
		*response = data.data;
		return http_code;
	}
	else return -1;

}

int Get_AccesToken(struct client_data *clientData, struct token_response ** postResponse)
{
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(clientData->AUTH_URL) + strlen("/") + strlen(clientData->TENANTID) + strlen("/oauth2/token?api-version=") + strlen(AUTH_APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, clientData->AUTH_URL);
	strcat(url, "/");
	strcat(url, clientData->TENANTID);
	strcat(url, "/oauth2/token?api-version=");
	strcat(url, AUTH_APIVERSION);
	//seting parameters to post request
	size = sizeof(char)*(strlen("grant_type=client_credentials&resource=") + strlen("https://vault.azure.net&client_id=") + strlen(clientData->CLIENTID) + strlen("&client_secret=") + strlen(clientData->password) + 1);
	char *param = malloc(size);
	if (param == NULL) {
		free(url);
		return ALLOCATE_ERROR;
	}
	strcpy(param, "grant_type=client_credentials&resource=");
	strcat(param, "https://vault.azure.net&client_id=");
	strcat(param, clientData->CLIENTID);
	strcat(param, "&client_secret=");
	strcat(param, clientData->password);
	struct request_data *requestData;
	requestData = Store_HttpsData(url, param, NULL, FALSE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	char* response;
	int result = Https_Request(requestData, &response, "POST");
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_token_response(response, postResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response); // Only dynamic alloc if result > http_ok
		return result;
	}
}

int Get_ListKeys(struct basic_http_data *petitionData, struct list_key **listKey)
{
	BOOL validNextLink = TRUE;
	char *nextLink = NULL;
	char* response;
	struct request_data *requestData;;
	int result, res;
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(petitionData->url) + strlen("/keys?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, petitionData->url);
	strcat(url, "/keys?api-version=");
	strcat(url, APIVERSION);
	while (validNextLink) {
		requestData = Store_HttpsData(url, NULL, petitionData->token, TRUE_p);
		free(url);
		if (requestData == NULL) return ALLOCATE_ERROR;
		result = Https_Request(requestData, &response, "GET");
		if (result == UNAUTHORIZED) {	
			result = GetToken(&TOKEN);
			if (result == OK) {
				free(response);
				response = NULL;
				free(requestData->token);
				requestData->token = _strdup(TOKEN);
				result = Https_Request(requestData, &response, "GET");
			}
		}
		Free_HttpsData(requestData);
		if (result == HTTP_OK) {
			res = parse_list_key_response(response, listKey, &nextLink);
			free(response);
			if (res < 0) {
				if (nextLink != NULL) free(nextLink);
				return res;
			}
			else if (nextLink == NULL) return result;
			url = nextLink;
		}
		else {
			if (result > HTTP_OK) free(response);
			return result;
		}
	}
	return UNDEFINED_ERROR;
}

int Create_key(struct key_data *keyData, struct key_data_response **keyResponse)
{
	int result;
	size_t size;
	size = sizeof(char)*(strlen(keyData->host) + strlen("/keys/") + strlen(keyData->id) + strlen("/create?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, keyData->host);
	strcat(url, "/keys/");
	strcat(url, keyData->id);
	strcat(url, "/create?api-version=");
	strcat(url, APIVERSION);
	char *param;
	param = CreateKey2Json(keyData);
	if (param == NULL) 
	{
		free(url);
		return PARSER_ERROR;
	}
	char* response;
	struct request_data *postData;
	postData = Store_HttpsData(url, param, keyData->token, TRUE_p);
	free(url);
	free(param);
	if (postData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(postData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(postData->token);
			postData->token = _strdup(TOKEN);
			result = Https_Request(postData, &response, "POST");
		}
	}
	Free_HttpsData(postData);
	if (result == HTTP_OK) {
		int res = parse_create_key_response(response, keyResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Update_key(struct update_key * updateKey, struct key_data_response ** keyResponse)
{
	int result;
	size_t size;
	size = sizeof(char)*(strlen(updateKey->host) + strlen("/keys/") + strlen(updateKey->key_id) + strlen("?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, updateKey->host);
	strcat(url, "/keys/");
	strcat(url, updateKey->key_id);
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	char *param;
	param = UpdateKey2Json(updateKey);
	if (param == NULL)
	{
		free(url);
		return PARSER_ERROR;
	}
	char* response;
	struct request_data *postData;
	postData = Store_HttpsData(url, param, updateKey->token, TRUE_p);
	free(url);
	free(param);
	if (postData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(postData, &response, "PATCH");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(postData->token);
			postData->token = _strdup(TOKEN);
			result = Https_Request(postData, &response, "PATCH");
		}
	}
	Free_HttpsData(postData);
	if (result == HTTP_OK) {
		int res = parse_create_key_response(response, keyResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Delete_key(struct delete_key * keyData)
{
	size_t size;
	size = sizeof(char)*(strlen(keyData->host) + strlen("/keys/") + strlen(keyData->id) + strlen("?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, keyData->host);
	strcat(url, "/keys/");
	strcat(url, keyData->id);
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	char* response;
	struct request_data *requestData = Store_HttpsData(url, NULL, keyData->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	int result = Https_Request(requestData, &response, "DELETE");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			int result = Https_Request(requestData, &response, "DELETE");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		free(response);
		return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Get_ListKeys_version(struct id_http_data *keyData, struct list_key **listKeyVersionResponse) {
	BOOL validNextLink = TRUE;
	char *nextLink = NULL;
	char* response;
	struct request_data *requestData;;
	int result, res;
	size_t size;

	size = sizeof(char)*(strlen(keyData->host) + strlen("/keys/") + strlen(keyData->id) + strlen("/versions?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, keyData->host);
	strcat(url, "/keys/");
	strcat(url, keyData->id);
	strcat(url, "/versions?api-version=");
	strcat(url, APIVERSION);
	while (validNextLink) {
		requestData = Store_HttpsData(url, NULL, keyData->token, TRUE_p);
		free(url);
		if (requestData == NULL) return ALLOCATE_ERROR;
		result = Https_Request(requestData, &response, "GET");
		if (result == UNAUTHORIZED) {
			result = GetToken(&TOKEN);
			if (result == OK) {
				free(response);
				response = NULL;
				free(requestData->token);
				requestData->token = _strdup(TOKEN);
				result = Https_Request(requestData, &response, "GET");
			}
		}
		Free_HttpsData(requestData);
		if (result == HTTP_OK) {
			res = parse_list_key_response(response, listKeyVersionResponse, &nextLink);
			free(response);
			if (res < 0) {
				if (nextLink != NULL) free(nextLink);
				return res;
			}
			else if (nextLink == NULL) return result;
			url = nextLink;
		}
		else {
			if (result > HTTP_OK) free(response);
			return result;
		}

	}
	return UNDEFINED_ERROR;
}

int Get_Key(struct id_http_data *petitionData, struct key_data_response **keyData)
{
	int result;
	size_t size;
	char* exist;
	size = sizeof(char)*(strlen(petitionData->host) + strlen("/keys/") + strlen(petitionData->id) + strlen("?api-version=") + strlen(APIVERSION) + 2);//+2 one for \o one for posbile / if key version is not especificated
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, petitionData->host);
	strcat(url, "/keys/");
	strcat(url, petitionData->id);
	exist = strstr(petitionData->id, "/"); // only if no version
	if (exist == NULL)
		strcat(url, "/");
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	char* response;
	struct request_data *requestData = Store_HttpsData(url, NULL, petitionData->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(requestData, &response, "GET");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "GET");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_create_key_response(response, keyData);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Get_CertificateList(struct basic_http_data *urlTokenData, struct cert_list **certListResponse)
{
	BOOL validNextLink = TRUE;
	char *nextLink = NULL;
	char* response;
	struct request_data *requestData;;
	int result;
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(urlTokenData->url) + strlen("/certificates?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, urlTokenData->url);
	strcat(url, "/certificates?api-version=");
	strcat(url, APIVERSION);
	while (validNextLink) {
		requestData = Store_HttpsData(url, NULL, urlTokenData->token, TRUE_p);
		free(url);
		if (requestData == NULL) return ALLOCATE_ERROR;
		result = Https_Request(requestData, &response, "GET");
		if (result == UNAUTHORIZED) {
			result = GetToken(&TOKEN);
			if (result == OK) {
				free(response);
				response = NULL;
				free(requestData->token);
				requestData->token = _strdup(TOKEN);
				result = Https_Request(requestData, &response, "GET");
			}
		}
		Free_HttpsData(requestData);
		if (result == HTTP_OK) {
			int res = parse_list_certificate_response(response, certListResponse, &nextLink);
			free(response);
			if (res < 0) {
				if (nextLink != NULL) free(nextLink);
				return res;
			}
			else if (nextLink == NULL) return result;
			url = nextLink;
		}
		else {
			if (result > HTTP_OK) free(response);
			return result;
		}
	}
	return UNDEFINED_ERROR;
}

int Get_CertificateVersions(struct id_http_data *certId, struct cert_list **certVersionListResponse)
{
	BOOL validNextLink = TRUE;
	char *nextLink = NULL;
	char* response;
	struct request_data *requestData;;
	int result;
	size_t size;
	size = sizeof(char)*(strlen(certId->host) + strlen("/certificates/") + strlen(certId->id) + strlen("/versions?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, certId->host);
	strcat(url, "/certificates/");
	strcat(url, certId->id);
	strcat(url, "/versions?api-version=");
	strcat(url, APIVERSION);
	while (validNextLink) {
		requestData = Store_HttpsData(url, NULL, certId->token, TRUE_p);
		free(url);
		if (requestData == NULL) return ALLOCATE_ERROR;
		result = Https_Request(requestData, &response, "GET");
		if (result == UNAUTHORIZED) {
			result = GetToken(&TOKEN);
			if (result == OK) {
				free(response);
				response = NULL;
				free(requestData->token);
				requestData->token = _strdup(TOKEN);
				result = Https_Request(requestData, &response, "GET");
			}
		}
		Free_HttpsData(requestData);
		if (result == HTTP_OK) {
			int res = parse_list_certificate_response(response, certVersionListResponse, &nextLink);
			free(response);
			if (res < 0) {
				if (nextLink != NULL) free(nextLink);
				return res;
			}
			else if (nextLink == NULL) return result;
			url = nextLink;
		}
		else {
			if (result > HTTP_OK) free(response);
			return result;
		}
	}
	return UNDEFINED_ERROR;
}

int Import_Certificate(struct import_cert_data *importData, struct delete_update_cert_response **importCertResponse)
{
	int result;
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(importData->host) + strlen("/certificates/") + strlen(importData->name) + strlen("/import?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, importData->host);
	strcat(url, "/certificates/");
	strcat(url, importData->name);
	strcat(url, "/import?api-version=");
	strcat(url, APIVERSION);
	//strcat(url, "\0");
	char *param;
	param = CreateImport2Json(importData);
	if (param == NULL)
	{
		free(url);
		return PARSER_ERROR;
	}
	struct request_data *postData;
	postData = Store_HttpsData(url, param, importData->token, TRUE_p);
	free(url);
	free(param);
	if (postData == NULL) return ALLOCATE_ERROR;
	char* response;
	result = Https_Request(postData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(postData->token);
			postData->token = _strdup(TOKEN);
			result = Https_Request(postData, &response, "POST");
		}
	}
	Free_HttpsData(postData);
	if (result == HTTP_OK) {
		int res = parse_delete_update_certificate_response(response, importCertResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Get_GetCertificateOperation(struct id_http_data *urlTokenData, struct cert_operation_response **certOperationResponse)
{
	int result;
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(urlTokenData->host) + strlen("/certificates/") + strlen(urlTokenData->id) + strlen("/pending?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, urlTokenData->host);
	strcat(url, "/certificates/");
	strcat(url, urlTokenData->id);
	strcat(url, "/pending?api-version=");
	strcat(url, APIVERSION);
	struct request_data *requestData;
	requestData = Store_HttpsData(url, NULL, urlTokenData->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	char* response;
	result = Https_Request(requestData, &response, "GET");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "GET");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_cert_operation_state(response, certOperationResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Delete_CertificateOperation(struct id_http_data *urlTokenData, struct cert_operation_delete **certOperationDelete) {
	int result;
	size_t size;
	size = sizeof(char)*(strlen(urlTokenData->host) + strlen("/certificates/") + strlen(urlTokenData->id) + strlen("/pending?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, urlTokenData->host);
	strcat(url, "/certificates/");
	strcat(url, urlTokenData->id);
	strcat(url, "/pending?api-version=");
	strcat(url, APIVERSION);
	struct request_data *requestData;
	requestData = Store_HttpsData(url, NULL, urlTokenData->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	char* response;
	result = Https_Request(requestData, &response, "DELETE");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "DELETE");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_cert_operation_delete(response, certOperationDelete);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Update_Certificate(struct create_cert * updateCert, struct delete_update_cert_response ** updateCertResponse)
{
	char *exist;
	int result;
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(updateCert->host) + strlen("/certificates/") + strlen(updateCert->name) + strlen("?api-version=") + strlen(APIVERSION) + 2);//+2 one for \o one for posbile / if cert version is not especificated
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, updateCert->host);
	strcat(url, "/certificates/");
	strcat(url, updateCert->name);
	exist = strstr(updateCert->name, "/"); // only if no version
	if (exist == NULL)
		strcat(url, "/");
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	char *param;
	param = CreateCertificate2Json(updateCert);
	if (param == NULL)
	{
		free(url);
		return PARSER_ERROR;
	}
	struct request_data *requestData;
	requestData = Store_HttpsData(url, param, updateCert->token, TRUE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	char* response;
	result = Https_Request(requestData, &response, "PATCH");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "PATCH");
		}
	}
	Free_HttpsData(requestData);
	if ((result == HTTP_OK) || (result == HTTP_ACCEPTED)) {
		int res = parse_delete_update_certificate_response(response, updateCertResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Update_CertPolicy(struct create_cert * updatePolicy, struct cert_policy ** certPolicy)
{
	int result;
	size_t size;
	size = sizeof(char)*(strlen(updatePolicy->host) + strlen("/certificates/") + strlen(updatePolicy->name) + strlen("/policy?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, updatePolicy->host);
	strcat(url, "/certificates/");
	strcat(url, updatePolicy->name);
	strcat(url, "/policy?api-version=");
	strcat(url, APIVERSION);
	char *param;
	param = CreateCertificate2Json(updatePolicy);
	if (param == NULL)
	{
		free(url);
		return PARSER_ERROR;
	}
	struct request_data *requestData;
	requestData = Store_HttpsData(url, param, updatePolicy->token, TRUE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	char* response;
	result = Https_Request(requestData, &response, "PATCH");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "PATCH");
		}
	}
	Free_HttpsData(requestData);
	if ((result == HTTP_OK) || (result == HTTP_ACCEPTED)) {
		int res = parse_policy(response, certPolicy);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Get_CertPolicy(struct id_http_data * getParameters, struct cert_policy ** certPolicy)
{
	int result;
	size_t size;
	size = sizeof(char)*(strlen(getParameters->host) + strlen("/certificates/") + strlen(getParameters->id) + strlen("/policy?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, getParameters->host);
	strcat(url, "/certificates/");
	strcat(url, getParameters->id);
	strcat(url, "/policy?api-version=");
	strcat(url, APIVERSION);
	struct request_data *requestData;
	requestData = Store_HttpsData(url, NULL, getParameters->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	char* response;
	result = Https_Request(requestData, &response, "GET");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "GET");
		}
	}
	Free_HttpsData(requestData);
	if ((result == HTTP_OK) || (result == HTTP_ACCEPTED)) {
		int res = parse_policy(response, certPolicy);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Get_Certificate(struct id_http_data * getParameters, struct delete_update_cert_response ** getCertResponse)
{
	char *exist;
	int result;
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(getParameters->host) + strlen("/certificates/") + strlen(getParameters->id) + strlen("?api-version=") + strlen(APIVERSION) + 2);//+2 one for \o one for posbile / if cert version is not especificated
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, getParameters->host);
	strcat(url, "/certificates/");
	strcat(url, getParameters->id);
	exist = strstr(getParameters->id, "/"); // only if no version
	if (exist == NULL)
		strcat(url, "/");
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	struct request_data *requestData;
	requestData = Store_HttpsData(url, NULL, getParameters->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	char* response;
	result = Https_Request(requestData, &response, "GET");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "GET");
		}
	}
	Free_HttpsData(requestData);
	if ((result == HTTP_OK) || (result == HTTP_ACCEPTED)) {
		int res = parse_delete_update_certificate_response(response, getCertResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Create_Certificate(struct create_cert * CreateCert, struct cert_operation_response **certOperationResponse)
{
	int result;
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(CreateCert->host) + strlen("/certificates/") + strlen(CreateCert->name) + strlen("/create?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, CreateCert->host);
	strcat(url, "/certificates/");
	strcat(url, CreateCert->name);
	strcat(url, "/create?api-version=");
	strcat(url, APIVERSION);
	//strcat(url, "\0");
	char *param;
	param = CreateCertificate2Json(CreateCert);
	if (param == NULL)
	{
		free(url);
		return PARSER_ERROR;
	}
	struct request_data *requestData;
	requestData = Store_HttpsData(url, param, CreateCert->token, TRUE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	char* response;
	result = Https_Request(requestData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "POST");
		}
	}
	Free_HttpsData(requestData);
	if ((result == HTTP_OK) || (result == HTTP_ACCEPTED)) {
		int res = parse_cert_operation_state(response, certOperationResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Delete_Certificate(struct id_http_data * deleteCert, struct delete_update_cert_response **deleteCertResponse)
{
	size_t size;
	size = sizeof(char)*(strlen(deleteCert->host) + strlen("/certificates/") + strlen(deleteCert->id) + strlen("?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, deleteCert->host);
	strcat(url, "/certificates/");
	strcat(url, deleteCert->id);
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	//strcat(url, "\0");
	char* response;
	struct request_data *requestData = Store_HttpsData(url, NULL, deleteCert->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	int result = Https_Request(requestData, &response, "DELETE");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "DELETE");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_delete_update_certificate_response(response, deleteCertResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Sign(struct operation_data *signData, struct operation_response **signResponse) {
	int result;
	size_t size;
	size = sizeof(char)*(strlen(signData->host) + strlen("/keys/") + strlen(signData->keyid) + strlen("/sign?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, signData->host);
	strcat(url, "/keys/");
	strcat(url, signData->keyid);
	strcat(url, "/sign?api-version=");
	strcat(url, APIVERSION);
	char *param = CreateOperation2Json(signData);
	if (param == NULL) {
		free(url);
		return ALLOCATE_ERROR;
	}
	char* response;
	struct request_data *requestData = Store_HttpsData(url, param, signData->token, TRUE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(requestData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "POST");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_operation_response(response, signResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Verify(struct verify_data *verifyData) {
	int result;
	size_t size;
	size = sizeof(char)*(strlen(verifyData->host) + strlen("/keys/") + strlen(verifyData->id) + strlen("/verify?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, verifyData->host);
	strcat(url, "/keys/");
	strcat(url, verifyData->id);
	strcat(url, "/verify?api-version=");
	strcat(url, APIVERSION);
	//strcat(url, "\0");
	size = sizeof(char)*(strlen("{\"alg\":\"") + strlen(verifyData->signtype) + strlen("\",\"digest\":\"") + strlen(verifyData->hash) + strlen("\",\"value\":\"") + strlen(verifyData->value) + strlen("\"}") + 1);
	char *param = malloc(size);
	if (param == NULL) {
		free(url);
		return ALLOCATE_ERROR;
	}
	strcpy(param, "{\"alg\":\"");
	strcat(param, verifyData->signtype);
	strcat(param, "\",\"digest\":\"");
	strcat(param, verifyData->hash);
	strcat(param, "\",\"value\":\"");
	strcat(param, verifyData->value);
	strcat(param, "\"}");
	char* response;
	struct request_data *requestData = Store_HttpsData(url, param, verifyData->token, TRUE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(requestData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "POST");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		cJSON *root = cJSON_Parse(response);
		if (cJSON_GetObjectItem(root, "value") != NULL) result = cJSON_GetObjectItem(root, "value")->valueint;
		else result = FALSE;
		free(response);
		return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Encript_Data(struct operation_data * opData, struct operation_response ** opResponse)
{
	int result;
	size_t size;
	size = sizeof(char)*(strlen(opData->host) + strlen("/keys/") + strlen(opData->keyid) + strlen("/encrypt?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, opData->host);
	strcat(url, "/keys/");
	strcat(url, opData->keyid);
	strcat(url, "/encrypt?api-version=");
	strcat(url, APIVERSION);
	//strcat(url, "\0");
	char *param = CreateOperation2Json(opData);
	if (param == NULL) {
		free(url);
		return ALLOCATE_ERROR;
	}
	char* response;
	struct request_data *requestData = Store_HttpsData(url, param, opData->token, TRUE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(requestData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "POST");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_operation_response(response, opResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Decript_Data(struct operation_data * opData, struct operation_response ** opResponse)
{
	int result;
	size_t size;
	size = sizeof(char)*(strlen(opData->host) + strlen("/keys/") + strlen(opData->keyid) + strlen("/decrypt?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, opData->host);
	strcat(url, "/keys/");
	strcat(url, opData->keyid);
	strcat(url, "/decrypt?api-version=");
	strcat(url, APIVERSION);
	char *param = CreateOperation2Json(opData);
	if (param == NULL) {
		free(url);
		return ALLOCATE_ERROR;
	}
	char* response;
	struct request_data *requestData = Store_HttpsData(url, param, opData->token, TRUE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(requestData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "POST");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_operation_response(response, opResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Merge_Certificate(struct merge_data * mergeData, struct cert_operation_response **certOperationResponse)
{

	int result;
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(mergeData->host) + strlen("/certificates/") + strlen(mergeData->certName) + strlen("/pending/merge?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, mergeData->host);
	strcat(url, "/certificates/");
	strcat(url, mergeData->certName);
	strcat(url, "/pending/merge?api-version=");
	strcat(url, APIVERSION);
	//strcat(url, "\0");
	char *param;
	param = CreateMergeCertificate2Json(mergeData);
	if (param == NULL) return PARSER_ERROR;
	struct request_data *requestData;
	requestData = Store_HttpsData(url, param, mergeData->token, TRUE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	char* response;
	result = Https_Request(requestData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "POST");
		}
	}
	Free_HttpsData(requestData);
	if ((result == HTTP_OK) || (result == HTTP_ACCEPTED)) {
		int res = parse_cert_operation_state(response, certOperationResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Backup_Key(struct id_http_data * backupKey, struct simple_operation_response ** backOperationResponse)
{
	size_t size;
	if (backupKey->id == NULL) return -1;
	size = sizeof(char)*(strlen(backupKey->host) + strlen("/keys/") + strlen(backupKey->id) + strlen("/backup?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, backupKey->host);
	strcat(url, "/keys/");
	strcat(url, backupKey->id);
	strcat(url, "/backup?api-version=");
	strcat(url, APIVERSION);
	char* response;
	struct request_data *requestData = Store_HttpsData(url, "", backupKey->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	int result = Https_Request(requestData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "POST");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_simple_operation_response(response, backOperationResponse);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Restore_Key(struct value_http_data * restoreKey, struct key_data_response ** keyData)
{
	size_t size;
	size = sizeof(char)*(strlen(restoreKey->host) + strlen("/keys/restore?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, restoreKey->host);
	strcat(url, "/keys/restore?api-version=");
	strcat(url, APIVERSION);
	size = sizeof(char)*(strlen("{\"value\":\"") + strlen(restoreKey->value) + strlen("\"}") + 1);
	char *param = malloc(size);
	if (param == NULL) {
		free(url);
		return ALLOCATE_ERROR;
	}
	strcpy(param, "{\"value\":\"");
	strcat(param, restoreKey->value);
	strcat(param, "\"}");
	char* response;
	struct request_data *requestData = Store_HttpsData(url, param, restoreKey->token, TRUE_p);
	free(url);
	free(param);
	if (requestData == NULL) return ALLOCATE_ERROR;
	int result = Https_Request(requestData, &response, "POST");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "POST");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_create_key_response(response, keyData);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Get_ListSecrets(struct basic_http_data *petitionData, struct secret_items **secretList)
{
	BOOL validNextLink = TRUE;
	char *nextLink = NULL;
	char* response;
	struct request_data *requestData;;
	int result, res;
	size_t size;
	//Seting url to post request
	size = sizeof(char)*(strlen(petitionData->url) + strlen("/secrets?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, petitionData->url);
	strcat(url, "/secrets?api-version=");
	strcat(url, APIVERSION);
	while (validNextLink) {
		requestData = Store_HttpsData(url, NULL, petitionData->token, TRUE_p);
		free(url);
		if (requestData == NULL) return ALLOCATE_ERROR;
		result = Https_Request(requestData, &response, "GET");
		if (result == UNAUTHORIZED) {
			result = GetToken(&TOKEN);
			if (result == OK) {
				free(response);
				response = NULL;
				free(requestData->token);
				requestData->token = _strdup(TOKEN);
				result = Https_Request(requestData, &response, "GET");
			}
		}
		Free_HttpsData(requestData);
		if (result == HTTP_OK) {
			res = Parse_secret_list_response(response, secretList, &nextLink);
			free(response);
			if (res < 0) {
				if (nextLink != NULL) free(nextLink);
				return res;
			}
			else if (nextLink == NULL) return result;
			url = nextLink;
		}
		else {
			if (result > HTTP_OK) free(response);
			return result;
		}
	}
	return UNDEFINED_ERROR;
}

int Get_SecretData(struct id_http_data *petitionData, struct secret_item_data **secretData)
{
	int result;
	size_t size;
	char* exist;
	size = sizeof(char)*(strlen(petitionData->host) + strlen("/secrets/") + strlen(petitionData->id) + strlen("?api-version=") + strlen(APIVERSION) + 2);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, petitionData->host);
	strcat(url, "/secrets/");
	strcat(url, petitionData->id);
	exist = strstr(petitionData->id, "/"); // only if no version
	if (exist == NULL)
		strcat(url, "/");
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	char* response;
	struct request_data *requestData = Store_HttpsData(url, NULL, petitionData->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(requestData, &response, "GET");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "GET");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		int res = parse_secret_data_response(response, secretData);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Delete_Secret(struct id_http_data *petitionData)
{
	size_t size;
	size = sizeof(char)*(strlen(petitionData->host) + strlen("/secrets/") + strlen(petitionData->id) + strlen("?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, petitionData->host);
	strcat(url, "/secrets/");
	strcat(url, petitionData->id);
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	char* response;
	struct request_data *requestData = Store_HttpsData(url, NULL, petitionData->token, TRUE_p);
	free(url);
	if (requestData == NULL) return ALLOCATE_ERROR;
	int result = Https_Request(requestData, &response, "DELETE");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(requestData->token);
			requestData->token = _strdup(TOKEN);
			result = Https_Request(requestData, &response, "DELETE");
		}
	}
	Free_HttpsData(requestData);
	if (result == HTTP_OK) {
		free(response);
		return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Create_Secret(struct secret_creation_data *petitionData, struct secret_item_data **secretData)
{
	int result;
	size_t size;
	size = sizeof(char)*(strlen(petitionData->host) + strlen("/secrets/") + strlen(petitionData->id) + strlen("?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, petitionData->host);
	strcat(url, "/secrets/");
	strcat(url, petitionData->id);
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	char *param;
	param = CreateSecret2Json(petitionData);
	if (param == NULL) return PARSER_ERROR;
	char* response;
	struct request_data *postData;
	postData = Store_HttpsData(url, param, petitionData->token, TRUE_p);
	free(url);
	free(param);
	if (postData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(postData, &response, "PUT");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(postData->token);
			postData->token = _strdup(TOKEN);
			result = Https_Request(postData, &response, "PUT");
		}
	}
	Free_HttpsData(postData);
	if (result == HTTP_OK) {
		int res = parse_secret_data_response(response, secretData);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}

int Update_Secret(struct secret_creation_data *petitionData, struct secret_update_response **secretData)
{
	int result;
	size_t size;
	size = sizeof(char)*(strlen(petitionData->host) + strlen("/secrets/") + strlen(petitionData->id) + strlen("?api-version=") + strlen(APIVERSION) + 1);
	char *url = malloc(size);
	if (url == NULL) return ALLOCATE_ERROR;
	strcpy(url, petitionData->host);
	strcat(url, "/secrets/");
	strcat(url, petitionData->id);
	strcat(url, "?api-version=");
	strcat(url, APIVERSION);
	char *param;
	param = CreateSecret2Json(petitionData);
	if (param == NULL) return PARSER_ERROR;
	char* response;
	struct request_data *postData;
	postData = Store_HttpsData(url, param, petitionData->token, TRUE_p);
	free(url);
	free(param);
	if (postData == NULL) return ALLOCATE_ERROR;
	result = Https_Request(postData, &response, "PATCH");
	if (result == UNAUTHORIZED) {
		result = GetToken(&TOKEN);
		if (result == OK) {
			free(response);
			response = NULL;
			free(postData->token);
			postData->token = _strdup(TOKEN);
			result = Https_Request(postData, &response, "PATCH");
		}
	}
	Free_HttpsData(postData);
	if (result == HTTP_OK) {
		int res = parse_secret_data_update_response(response, secretData);
		free(response);
		if (res < 0) return res;
		else return result;
	}
	else {
		if (result > HTTP_OK) free(response);
		return result;
	}
}
