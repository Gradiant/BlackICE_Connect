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
#include <src/common.h>

//***************Parsers*******************/
int parse_create_key_response(char *response, struct key_data_response **keyResponse) {
	struct key_data_response *newKey;
	struct key_attributes *attributesPTR;
	char *pattern = "keys";
    char id[MAX_ID_SIZE], *auxKid, *keytype, *key_ops[MAX_OPS], *n, *e, *d, *dp, *dq, *qi, *p, *q, *k, *key_hsm, *tags, *crv, *x, *y;
	BOOL enabled = FALSE, managed = FALSE;
	long unsigned int nbf, exp, created, updated;
	cJSON *attributes, *node;
	cJSON *root = cJSON_Parse(response);
	if (root == NULL) {
		*keyResponse = NULL;
		return PARSER_ERROR;
	}
	cJSON *key = cJSON_GetObjectItem(root, "key");
	if (key != NULL)
	{
		if (cJSON_GetObjectItem(key, "kid") != NULL) { //stract kid frome response host/keys/kid/version
			auxKid = strstr(cJSON_GetObjectItem(key, "kid")->valuestring, pattern);
			if (auxKid != NULL)
			{
				for (int i = 0; i <= strlen(auxKid) - 5; i++) {
					if (auxKid[i + 5] == '/') break;
					id[i] = auxKid[i + 5];
					id[i + 1] = '\0';
				}
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
		}
		if (cJSON_GetObjectItem(key, "kty") != NULL) keytype = cJSON_GetObjectItem(key, "kty")->valuestring;
		else  keytype = NULL;
		if (cJSON_GetObjectItem(key, "key_ops") != NULL)
		{
			node = NULL;
			node = cJSON_GetObjectItem(key, "key_ops")->child;
			for (int i = 0; i < MAX_OPS; i++)
			{
				if (node != NULL)
				{
					key_ops[i] = node->valuestring;
					node = node->next;
				}
				else key_ops[i] = NULL;
			}
		}
		if (cJSON_GetObjectItem(key, "n") != NULL) n = cJSON_GetObjectItem(key, "n")->valuestring;
		else  n = NULL;
		if (cJSON_GetObjectItem(key, "e") != NULL) e = cJSON_GetObjectItem(key, "e")->valuestring;
		else  e = NULL;
		if (cJSON_GetObjectItem(key, "d") != NULL) d = cJSON_GetObjectItem(key, "d")->valuestring;
		else  d = NULL;
		if (cJSON_GetObjectItem(key, "dp") != NULL) dp = cJSON_GetObjectItem(key, "dp")->valuestring;
		else  dp = NULL;
		if (cJSON_GetObjectItem(key, "dq") != NULL) dq = cJSON_GetObjectItem(key, "dq")->valuestring;
		else  dq = NULL;
		if (cJSON_GetObjectItem(key, "qi") != NULL) qi = cJSON_GetObjectItem(key, "qi")->valuestring;
		else  qi = NULL;
		if (cJSON_GetObjectItem(key, "p") != NULL) p = cJSON_GetObjectItem(key, "p")->valuestring;
		else  p = NULL;
		if (cJSON_GetObjectItem(key, "q") != NULL) q = cJSON_GetObjectItem(key, "q")->valuestring;
		else  q = NULL;
		if (cJSON_GetObjectItem(key, "k") != NULL) k = cJSON_GetObjectItem(key, "k")->valuestring;
		else  k = NULL;
		if (cJSON_GetObjectItem(key, "key_hsm") != NULL) key_hsm = cJSON_GetObjectItem(key, "key_hsm")->valuestring;
		else  key_hsm = NULL;
        if (cJSON_GetObjectItem(key, "crv") != NULL) crv = cJSON_GetObjectItem(key, "crv")->valuestring;
        else  crv = NULL;
        if (cJSON_GetObjectItem(key, "x") != NULL) x = cJSON_GetObjectItem(key, "x")->valuestring;
        else  x = NULL;
        if (cJSON_GetObjectItem(key, "y") != NULL) y = cJSON_GetObjectItem(key, "y")->valuestring;
        else  y = NULL;
		if (cJSON_GetObjectItem(key, "tags") != NULL) tags = cJSON_GetObjectItem(key, "tags")->valuestring;
		else  tags = NULL;
		if (cJSON_GetObjectItem(root, "managed") != NULL) managed = cJSON_GetObjectItem(root, "managed")->valueint;
		else managed = FALSE;

		attributes = cJSON_GetObjectItem(root, "attributes");
		if (attributes != NULL)
		{
			if (cJSON_GetObjectItem(attributes, "enabled") != NULL) enabled = cJSON_GetObjectItem(attributes, "enabled")->valueint;
			else enabled = FALSE;
			if (cJSON_GetObjectItem(attributes, "nbf") != NULL) nbf = cJSON_GetObjectItem(attributes, "nbf")->valueint;
			else nbf = 0;
			if (cJSON_GetObjectItem(attributes, "exp") != NULL) exp = cJSON_GetObjectItem(attributes, "exp")->valueint;
			else exp = 0;
			if (cJSON_GetObjectItem(attributes, "created") != NULL) created = cJSON_GetObjectItem(attributes, "created")->valueint;
			else created = 0;
			if (cJSON_GetObjectItem(attributes, "updated") != NULL) updated = cJSON_GetObjectItem(attributes, "updated")->valueint;
			else updated = 0;
		}
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
		attributesPTR = NULL;
		attributesPTR = Store_KeyAttributes(enabled, nbf, exp, created, updated);
		if (attributesPTR == NULL) {
			cJSON_Delete(root);
			return ALLOCATE_ERROR;
		}
        newKey = Store_KeyDataResponse(id, keytype, key_ops, n, e, d, dp, dq, qi, p, q, k, key_hsm, attributesPTR, tags, managed, crv, x, y);
		if (newKey == NULL) {
			Free_KeyAttributes(attributesPTR);
			cJSON_Delete(root);
			return ALLOCATE_ERROR;
		}
		else {
			*keyResponse = newKey;
			cJSON_Delete(root);
			return OK;
		}
	}
	else {
		cJSON_Delete(root);
		return PARSER_ERROR;
	}

}

int parse_list_key_response(char *response, struct list_key **listkeyResponse, char **nextLink) {
	char *pattern = "keys";
	struct key_attributes *attributes = NULL;
	struct list_key *new;
	struct list_key *aux = NULL;
	cJSON *jsonAttributes, *root, *value;
	char kid[MAX_ID_SIZE], *tags, *auxKid;
	unsigned long int nbf, exp, created, updated;
	int keyHandler = 1;
	BOOL enabled = FALSE, managed = FALSE, first = TRUE;
	if (*listkeyResponse != NULL) {
		first = FALSE;
		aux = *listkeyResponse;
		while (aux->next != NULL) {
			aux = aux->next;
		}
		keyHandler = aux->keyHandler + 1;
	}
	if (response != NULL) {
		root = cJSON_Parse(response);
		if (root == NULL) {
			*listkeyResponse = NULL;
			return PARSER_ERROR;
		}
		value = cJSON_GetObjectItem(root, "value")->child;
		while (value != NULL) {
			if (cJSON_GetObjectItem(value, "kid") != NULL) { //stract keys/kid/version from response host/keys/kid/version
				auxKid = strstr(cJSON_GetObjectItem(value, "kid")->valuestring, pattern);
				if (auxKid != NULL)
				{
					for (int i = 0; i <= strlen(auxKid) - 5; i++) { // stract kid from keys/kid/version
						if (auxKid[i + 5] == '/') break;
						kid[i] = auxKid[i + 5];
						kid[i + 1] = '\0';
					}
				}
				else
				{
					cJSON_Delete(root);
					return PARSER_ERROR;
				}
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
			jsonAttributes = cJSON_GetObjectItem(value, "attributes");
			if (jsonAttributes != NULL)
			{
				if (cJSON_GetObjectItem(jsonAttributes, "enabled") != NULL) enabled = cJSON_GetObjectItem(jsonAttributes, "enabled")->valueint;
				else enabled = FALSE;
				if (cJSON_GetObjectItem(jsonAttributes, "nbf") != NULL) nbf = cJSON_GetObjectItem(jsonAttributes, "nbf")->valueint;
				else  nbf = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "exp") != NULL) exp = cJSON_GetObjectItem(jsonAttributes, "exp")->valueint;
				else  exp = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "created") != NULL) created = cJSON_GetObjectItem(jsonAttributes, "created")->valueint;
				else  created = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "updated") != NULL) updated = cJSON_GetObjectItem(jsonAttributes, "updated")->valueint;
				else  updated = 0;
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
			if (cJSON_GetObjectItem(value, "tags") != NULL)	tags = cJSON_GetObjectItem(value, "tags")->valuestring;
			else tags = NULL;
			if (cJSON_GetObjectItem(value, "managed") != NULL) managed = cJSON_GetObjectItem(value, "managed")->valueint;
			else managed = FALSE;
			attributes = Store_KeyAttributes(enabled, nbf, exp, created, updated);
			if (attributes == NULL)
			{
				cJSON_Delete(root);
				return ALLOCATE_ERROR;
			}
			new = Store_ListKey(kid, attributes, tags, managed);
			if (new == NULL) {
				free(attributes);
				cJSON_Delete(root);
				return ALLOCATE_ERROR;
			}

			new->next = NULL;
			new->keyHandler = keyHandler;
			keyHandler++;
			if (first == TRUE) {
				*listkeyResponse = new;
				aux = new;
				first = FALSE;
			}
			else {
				aux->next = new;
				aux = aux->next;
			}
			value = value->next;
		}
		*nextLink = _strdup(cJSON_GetObjectItem(root, "nextLink")->valuestring);
		cJSON_Delete(root);
		return OK;
	}
	return PARSER_ERROR;
}

int parse_operation_response(char *response, struct operation_response **opResponse) {
	char *keyid, *value;
	struct operation_response *parseResponse = NULL;
	cJSON *root = cJSON_Parse(response);
	if (root == NULL) {
		*opResponse = NULL;
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "kid") != NULL) keyid = cJSON_GetObjectItem(root, "kid")->valuestring;
	else
	{
		cJSON_Delete(root);
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "value") != NULL) value = cJSON_GetObjectItem(root, "value")->valuestring;
	else
	{
		cJSON_Delete(root);
		return PARSER_ERROR;
	}
	parseResponse = Store_OperationResponse(keyid, value);
	cJSON_Delete(root);
	if (parseResponse == NULL) return ALLOCATE_ERROR;
	*opResponse = parseResponse;
	return OK;
}

int parse_list_certificate_response(char *response, struct cert_list **listCertResponse, char **nextLink) {
	*listCertResponse = NULL;
	char *pattern = "certificates";
	struct cert_attributes *attributes;
	struct cert_data * certData;
	struct cert_list *new = NULL, *aux = NULL;
	cJSON *jsonAttributes, *root, *value;
	char certId[60], *tags, *auxId, *recoveryLevel, *x5t;
	unsigned long int nbf, exp, created, updated;
	int certHandler = 1;
	BOOL enabled = FALSE, first = TRUE;
	if (*listCertResponse != NULL) {
		first = FALSE;
		aux = *listCertResponse;
		while (aux->next != NULL) {
			aux = aux->next;
		}
		certHandler = aux->handler + 1;
	}
	if (response != NULL) {
		root = cJSON_Parse(response);
		if (root == NULL) {
			*listCertResponse = NULL;
			return PARSER_ERROR;
		}
		value = cJSON_GetObjectItem(root, "value")->child;
		while (value != NULL) {
			if (cJSON_GetObjectItem(value, "id") != NULL) { //stract keys/kid/version from response host/keys/kid/version
				auxId = strstr(cJSON_GetObjectItem(value, "id")->valuestring, pattern);
				if (auxId != NULL)
				{
					for (int i = 0; i <= strlen(auxId) - 13; i++) { // stract certificates from certificates/kid/version
						if (auxId[i + 13] == '/') break;
						certId[i] = auxId[i + 13];
						certId[i + 1] = '\0';
					}
				}
				else
				{
					cJSON_Delete(root);
					return PARSER_ERROR;
				}
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
			jsonAttributes = cJSON_GetObjectItem(value, "attributes");
			if (jsonAttributes != NULL)
			{
				if (cJSON_GetObjectItem(jsonAttributes, "recoveryLevel") != NULL) recoveryLevel = cJSON_GetObjectItem(jsonAttributes, "recoveryLevel")->valuestring;
				else recoveryLevel = NULL;
				if (cJSON_GetObjectItem(jsonAttributes, "enabled") != NULL) enabled = cJSON_GetObjectItem(jsonAttributes, "enabled")->valueint;
				else enabled = FALSE;
				if (cJSON_GetObjectItem(jsonAttributes, "nbf") != NULL) nbf = cJSON_GetObjectItem(jsonAttributes, "nbf")->valueint;
				else  nbf = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "exp") != NULL) exp = cJSON_GetObjectItem(jsonAttributes, "exp")->valueint;
				else  exp = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "created") != NULL) created = cJSON_GetObjectItem(jsonAttributes, "created")->valueint;
				else  created = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "updated") != NULL) updated = cJSON_GetObjectItem(jsonAttributes, "updated")->valueint;
				else  updated = 0;
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
			if (cJSON_GetObjectItem(value, "tags") != NULL)	tags = cJSON_GetObjectItem(value, "tags")->valuestring;
			else tags = NULL;
			if (cJSON_GetObjectItem(value, "x5t") != NULL) x5t = cJSON_GetObjectItem(value, "x5t")->valuestring;
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
			attributes = Store_CertAttributes(recoveryLevel, enabled, nbf, exp, created, updated);
			if (attributes == NULL) {
				cJSON_Delete(root);
				return ALLOCATE_ERROR;
			}
			certData = Store_CertData(attributes, certId, tags, x5t);
			if (certData == NULL) {
				Free_CertAttributes(attributes);
				cJSON_Delete(root);
				return ALLOCATE_ERROR;
			}
			new = Store_CertList(certHandler, certData, NULL);
			if (new == NULL) {
				Free_CertData(certData);
				cJSON_Delete(root);
				return ALLOCATE_ERROR;
			}
			certHandler++;
			if (first == TRUE) {
				*listCertResponse = new;
				aux = new;
				first = FALSE;
			}
			else {
				aux->next = new;
				aux = aux->next;
			}
			value = value->next;
		}
		*nextLink = _strdup(cJSON_GetObjectItem(root, "nextLink")->valuestring);
		cJSON_Delete(root);
		return OK;
	}
	return PARSER_ERROR;
}

int parse_cert_operation_state(char *response, struct cert_operation_response ** certOperationResponse) {
	char *id, *name = NULL, *cty = NULL, *csr, *status, *target, *request_id;
	BOOL cancellation_requested;
	struct cert_operation_response *parseResponse = NULL;
	cJSON *root = cJSON_Parse(response);
	if (root == NULL) {
		*certOperationResponse = NULL;
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "id") != NULL) id = cJSON_GetObjectItem(root, "id")->valuestring;
	else
	{
		cJSON_Delete(root);
		return PARSER_ERROR;
	}
	cJSON *jsonIssuer = cJSON_GetObjectItem(root, "issuer");
	if (jsonIssuer != NULL) {
		if (cJSON_GetObjectItem(jsonIssuer, "Name") != NULL) name = cJSON_GetObjectItem(jsonIssuer, "Name")->valuestring;
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
		if (cJSON_GetObjectItem(jsonIssuer, "cty") != NULL) cty = cJSON_GetObjectItem(jsonIssuer, "cty")->valuestring;
		else  cty = NULL;
	}
	else 
	{
		cJSON_Delete(root);
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "csr") != NULL) csr = cJSON_GetObjectItem(root, "csr")->valuestring;
	else  
	{
		cJSON_Delete(root);
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "cancellation_requested") != NULL) cancellation_requested = cJSON_GetObjectItem(root, "cancellation_requested")->valueint;
	else  
	{
		cJSON_Delete(root);
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "status") != NULL) status = cJSON_GetObjectItem(root, "status")->valuestring;
	else 
	{
		cJSON_Delete(root);
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "target") != NULL) target = cJSON_GetObjectItem(root, "target")->valuestring;
	else target = NULL;
	if (cJSON_GetObjectItem(root, "request_id") != NULL) request_id = cJSON_GetObjectItem(root, "request_id")->valuestring;
	else  request_id = NULL;
	struct issuer *issuer = Store_Issuer(name, cty);
	if (issuer == NULL) {
		cJSON_Delete(root);
		return ALLOCATE_ERROR;
	}
	parseResponse = Store_CertOperation(id, issuer, csr, cancellation_requested, status, target, request_id);
	if (parseResponse == NULL) {
		Free_Issuer(issuer);
		cJSON_Delete(root);
		return ALLOCATE_ERROR;
	}
	*certOperationResponse = parseResponse;
	cJSON_Delete(root);
	return OK;
}

int parse_delete_update_certificate_response(char *response, struct delete_update_cert_response **deleteCertResponse) {
	char id[150], kid[150], sid[150], *x5t, *cer, *pendingId;
	char *auxKid;
	struct cert_policy *cerPolicy = NULL;
	struct cert_key_prop *keyProp = NULL;
	struct x509_props *x509Props = NULL;
	struct lifetime_actions *lifeTimeActions = NULL;
	struct cert_attributes *certAttributes = NULL;
	struct cert_attributes *policyAttributes = NULL;
	struct issuer *issuer = NULL;
	struct delete_update_cert_response *parseResponse = NULL;
	char pattern[15] = { '\0' };
	cJSON *root = cJSON_Parse(response);
	if (root == NULL) {
		*deleteCertResponse = NULL;
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "id") != NULL) { //stract kid frome response host/keys/kid/version
		strcpy(pattern, "certificates");
		auxKid = strstr(cJSON_GetObjectItem(root, "id")->valuestring, pattern);
		if ((auxKid != NULL) && (strlen(auxKid) < 150))
		{
			for (int i = 0; i <= strlen(auxKid) - (strlen(pattern) + 1); i++) {
				if (auxKid[i + (strlen(pattern) + 1)] == '/') break;
				id[i] = auxKid[i + (strlen(pattern) + 1)];
				id[i + 1] = '\0';
			}
		}
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
	}
	else  id[0] = '\0';
	if (cJSON_GetObjectItem(root, "kid") != NULL) { //stract kid frome response host/keys/kid/version
		strcpy(pattern, "keys");
		auxKid = strstr(cJSON_GetObjectItem(root, "kid")->valuestring, pattern);
		if ((auxKid != NULL) && (strlen(auxKid) < 150))
		{
			for (int i = 0; i <= strlen(auxKid) - (strlen(pattern) + 1); i++) {
				if (auxKid[i + (strlen(pattern) + 1)] == '/') break;
				kid[i] = auxKid[i + (strlen(pattern) + 1)];
				kid[i + 1] = '\0';
			}
		}
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
	}
	else  kid[0] = '\0';
	if (cJSON_GetObjectItem(root, "sid") != NULL) { //stract kid/version frome response host/keys/kid/version
		strcpy(pattern, "secrets");
		auxKid = strstr(cJSON_GetObjectItem(root, "sid")->valuestring, pattern);
		if ((auxKid != NULL) && (strlen(auxKid) < 150))
		{
			for (int i = 0; i <= strlen(auxKid) - (strlen(pattern) + 1); i++) {
				if (auxKid[i + (strlen(pattern) + 1)] == '/') break;
				sid[i] = auxKid[i + (strlen(pattern) + 1)];
				sid[i + 1] = '\0';
			}
		}
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
	}
	else  sid[0] = '\0';
	if (cJSON_GetObjectItem(root, "x5t") != NULL) x5t = cJSON_GetObjectItem(root, "x5t")->valuestring;
	else  x5t = NULL;
	if (cJSON_GetObjectItem(root, "cer") != NULL) cer = cJSON_GetObjectItem(root, "cer")->valuestring;
	else  cer = NULL;
	char *recoveryLevel;
	BOOL enabled;
	long nbf, exp, created, updated;
	cJSON *jsonAttributes = cJSON_GetObjectItem(root, "attributes");
	if (jsonAttributes != NULL)
	{
		if (cJSON_GetObjectItem(jsonAttributes, "recoveryLevel") != NULL) recoveryLevel = cJSON_GetObjectItem(jsonAttributes, "recoveryLevel")->valuestring;
		else recoveryLevel = NULL;
		if (cJSON_GetObjectItem(jsonAttributes, "enabled") != NULL) enabled = cJSON_GetObjectItem(jsonAttributes, "enabled")->valueint;
		else enabled = 0;
		if (cJSON_GetObjectItem(jsonAttributes, "nbf") != NULL) nbf = cJSON_GetObjectItem(jsonAttributes, "nbf")->valueint;
		else  nbf = 0;
		if (cJSON_GetObjectItem(jsonAttributes, "exp") != NULL) exp = cJSON_GetObjectItem(jsonAttributes, "exp")->valueint;
		else  exp = 0;
		if (cJSON_GetObjectItem(jsonAttributes, "created") != NULL) created = cJSON_GetObjectItem(jsonAttributes, "created")->valueint;
		else  created = 0;
		if (cJSON_GetObjectItem(jsonAttributes, "updated") != NULL) updated = cJSON_GetObjectItem(jsonAttributes, "updated")->valueint;
		else  updated = 0;
		certAttributes = Store_CertAttributes(recoveryLevel, enabled, nbf, exp, created, updated);
	}
	else certAttributes = NULL;
	cJSON *jsonPolicy = cJSON_GetObjectItem(root, "policy");
	if (jsonPolicy != NULL)
	{
		char *polId;
		if (cJSON_GetObjectItem(jsonPolicy, "id") != NULL) polId = cJSON_GetObjectItem(jsonPolicy, "id")->valuestring;
		else  polId = NULL;
		cJSON *jsonSecretProps = cJSON_GetObjectItem(jsonPolicy, "secret_props");
		char * contentType = NULL;
		if (jsonSecretProps != NULL) {
			if (cJSON_GetObjectItem(jsonSecretProps, "contentType") != NULL) contentType = cJSON_GetObjectItem(jsonSecretProps, "contentType")->valuestring;
			else  contentType = NULL;
		}
		cJSON *jsonKeyProps = cJSON_GetObjectItem(jsonPolicy, "key_props");
		BOOL exportable, reuse_key;
		char *kty;
		int key_size;
		if (jsonKeyProps != NULL) {
			if (cJSON_GetObjectItem(jsonKeyProps, "exportable") != NULL) exportable = cJSON_GetObjectItem(jsonKeyProps, "exportable")->valueint;
			else  exportable = 0;
			if (cJSON_GetObjectItem(jsonKeyProps, "kty") != NULL) kty = cJSON_GetObjectItem(jsonKeyProps, "kty")->valuestring;
			else  kty = 0;
			if (cJSON_GetObjectItem(jsonKeyProps, "key_size") != NULL) key_size = cJSON_GetObjectItem(jsonKeyProps, "key_size")->valueint;
			else  key_size = 0;
			if (cJSON_GetObjectItem(jsonKeyProps, "reuse_key") != NULL) reuse_key = cJSON_GetObjectItem(jsonKeyProps, "reuse_key")->valueint;
			else  reuse_key = 0;
			keyProp = Store_CertKeyProp(exportable, kty, key_size, reuse_key, contentType);
		}
		else jsonKeyProps = NULL;
		cJSON *jsonX509_props = cJSON_GetObjectItem(jsonPolicy, "x509_props");
		char *subject, *ekus[MAXIMUM_PERMITED_PARAMETERS], *key_usage[MAXIMUM_PERMITED_PARAMETERS];
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			ekus[i] = NULL;
			key_usage[i] = NULL;
		}
		int validity_months;
		if (jsonX509_props != NULL) {
			if (cJSON_GetObjectItem(jsonX509_props, "subject") != NULL) subject = cJSON_GetObjectItem(jsonX509_props, "subject")->valuestring;
			else  subject = NULL;
			if (cJSON_GetObjectItem(jsonX509_props, "ekus") != NULL)
			{
				cJSON *node = NULL;
				node = cJSON_GetObjectItem(jsonX509_props, "ekus")->child;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++)
				{
					if (node != NULL)
					{	//funciona bien pero falta definir cuantos strings hay en el array
						ekus[i] = node->valuestring;
						node = node->next;
					}
					else ekus[i] = NULL;
				}
			}
			if (cJSON_GetObjectItem(jsonX509_props, "key_usage") != NULL) {
				cJSON *node2 = NULL;
				node2 = cJSON_GetObjectItem(jsonX509_props, "key_usage")->child;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++)
				{
					if (node2 != NULL)
					{	//funciona bien pero falta definir cuantos strings hay en el array
						key_usage[i] = node2->valuestring;
						node2 = node2->next;
					}
					else key_usage[i] = NULL;
				}
			}
			if (cJSON_GetObjectItem(jsonX509_props, "validity_months") != NULL) validity_months = cJSON_GetObjectItem(jsonX509_props, "validity_months")->valueint;
			else  validity_months = 0;
			x509Props = Store_X509Props(subject, ekus, NULL, NULL, NULL, key_usage, validity_months);
		}
		else jsonX509_props = NULL;
		cJSON *jsonlifeTimeActions = cJSON_GetObjectItem(jsonPolicy, "lifetime_actions")->child;
		int lifetime_percentage, days_before_expiry;
		char *action_type;
		if (jsonlifeTimeActions != NULL) {
			cJSON *jsonTrigger = cJSON_GetObjectItem(jsonlifeTimeActions, "trigger");
			if (jsonTrigger != NULL) {
				if (cJSON_GetObjectItem(jsonTrigger, "lifetime_percentage") != NULL) lifetime_percentage = cJSON_GetObjectItem(jsonTrigger, "lifetime_percentage")->valueint;
				else  lifetime_percentage = 0;
				if (cJSON_GetObjectItem(jsonTrigger, "days_before_expiry") != NULL) days_before_expiry = cJSON_GetObjectItem(jsonTrigger, "days_before_expiry")->valueint;
				else days_before_expiry = 0;
			}
			else {
				lifetime_percentage = 0;
				days_before_expiry = 0;
			}
			cJSON *jsonAction = cJSON_GetObjectItem(jsonlifeTimeActions, "action");
			if (jsonAction != NULL) {
				if (cJSON_GetObjectItem(jsonAction, "action_type") != NULL) action_type = cJSON_GetObjectItem(jsonAction, "action_type")->valuestring;
				else  action_type = NULL;
			}
			else action_type = NULL;
			lifeTimeActions = Store_LifeTimeActions(lifetime_percentage, days_before_expiry, action_type);
		}
		else jsonlifeTimeActions = NULL;
		cJSON *jsonIssuer = cJSON_GetObjectItem(jsonPolicy, "issuer");
		char *name, *cty;
		if (jsonIssuer != NULL) {
			if (cJSON_GetObjectItem(jsonIssuer, "Name") != NULL) name = cJSON_GetObjectItem(jsonIssuer, "Name")->valuestring;
			else  name = NULL;
			if (cJSON_GetObjectItem(jsonIssuer, "cty") != NULL) cty = cJSON_GetObjectItem(jsonIssuer, "cty")->valuestring;
			else  cty = NULL;
			issuer = Store_Issuer(name, cty);
		}
		else issuer = NULL;
		cJSON *jsonPolicyAttributes = cJSON_GetObjectItem(jsonPolicy, "attributes");
		if (jsonPolicyAttributes != NULL) {
			if (cJSON_GetObjectItem(jsonPolicyAttributes, "recoveryLevel") != NULL) recoveryLevel = cJSON_GetObjectItem(jsonPolicyAttributes, "recoveryLevel")->valuestring;
			else recoveryLevel = NULL;
			if (cJSON_GetObjectItem(jsonPolicyAttributes, "enabled") != NULL) enabled = cJSON_GetObjectItem(jsonPolicyAttributes, "enabled")->valueint;
			else enabled = 0;
			if (cJSON_GetObjectItem(jsonPolicyAttributes, "nbf") != NULL) nbf = cJSON_GetObjectItem(jsonPolicyAttributes, "nbf")->valueint;
			else  nbf = 0;
			if (cJSON_GetObjectItem(jsonPolicyAttributes, "exp") != NULL) exp = cJSON_GetObjectItem(jsonPolicyAttributes, "exp")->valueint;
			else  exp = 0;
			if (cJSON_GetObjectItem(jsonPolicyAttributes, "created") != NULL) created = cJSON_GetObjectItem(jsonPolicyAttributes, "created")->valueint;
			else  created = 0;
			if (cJSON_GetObjectItem(jsonPolicyAttributes, "updated") != NULL) updated = cJSON_GetObjectItem(jsonPolicyAttributes, "updated")->valueint;
			else  updated = 0;
			policyAttributes = Store_CertAttributes(recoveryLevel, enabled, nbf, exp, created, updated);
		}
		else policyAttributes = NULL;
		cerPolicy = Store_CertPolicy(polId, keyProp, x509Props, lifeTimeActions, policyAttributes, issuer);
	}
	else cerPolicy = NULL;
	cJSON *jsonPending = cJSON_GetObjectItem(root, "pending");
	if (jsonPending != NULL) {
		if (cJSON_GetObjectItem(jsonPending, "id") != NULL) pendingId = cJSON_GetObjectItem(jsonPending, "id")->valuestring;
		else  pendingId = NULL;
	}
	else pendingId = NULL;


	parseResponse = Store_DeleteUpdateCertResponse(id, kid, sid, x5t, cer, certAttributes, cerPolicy, pendingId);

	if (parseResponse == NULL) {
		cJSON_Delete(root);
		return ALLOCATE_ERROR;
	}
	else {
		*deleteCertResponse = parseResponse;
		cJSON_Delete(root);
		return OK;
	}

}

int parse_cert_operation_delete(char * response, struct cert_operation_delete ** certOperationDelete)
{
	char *id, *name = NULL, *cty = NULL, *csr, *status, *status_details, *target, *request_id, *code, *message, *innererror;
	BOOL cancellation_requested;
	struct issuer *issuer = NULL;
	struct error *error = NULL;
	struct cert_operation_delete *parseRepsonse = NULL;
	struct cert_operation_response *certOperationResponse = NULL;
	cJSON *root = cJSON_Parse(response);
	if (root == NULL) {
		*certOperationDelete = NULL;
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "id") != NULL) id = cJSON_GetObjectItem(root, "id")->valuestring;
	else  id = NULL;
	cJSON *jsonIssuer = cJSON_GetObjectItem(root, "issuer");
	if (jsonIssuer != NULL) {
		if (cJSON_GetObjectItem(jsonIssuer, "Name") != NULL) name = cJSON_GetObjectItem(jsonIssuer, "Name")->valuestring;
		else  name = NULL;
		if (cJSON_GetObjectItem(jsonIssuer, "cty") != NULL) cty = cJSON_GetObjectItem(jsonIssuer, "cty")->valuestring;
		else  cty = NULL;
		issuer = Store_Issuer(name, cty);
		if (issuer == NULL)
		{
			cJSON_Delete(root);
			return ALLOCATE_ERROR;
		}
	}
	else issuer = NULL;
	if (cJSON_GetObjectItem(root, "csr") != NULL) csr = cJSON_GetObjectItem(root, "csr")->valuestring;
	else  csr = NULL;
	if (cJSON_GetObjectItem(root, "cancellation_requested") != NULL) cancellation_requested = cJSON_GetObjectItem(root, "cancellation_requested")->valueint;
	else  cancellation_requested = 0;
	if (cJSON_GetObjectItem(root, "status") != NULL) status = cJSON_GetObjectItem(root, "status")->valuestring;
	else  status = NULL;
	if (cJSON_GetObjectItem(root, "status_details") != NULL) status_details = cJSON_GetObjectItem(root, "status_details")->valuestring;
	else  status_details = NULL;

	cJSON *jsonError = cJSON_GetObjectItem(root, "error");
	if (jsonError != NULL) {
		if (cJSON_GetObjectItem(jsonError, "code") != NULL) code = cJSON_GetObjectItem(jsonError, "code")->valuestring;
		else  code = NULL;
		if (cJSON_GetObjectItem(jsonError, "message") != NULL) message = cJSON_GetObjectItem(jsonError, "message")->valuestring;
		else  message = NULL;
		if (cJSON_GetObjectItem(jsonError, "innererror") != NULL) innererror = cJSON_GetObjectItem(jsonError, "innererror")->valuestring;
		else  innererror = NULL;
		error = Store_Error(code, message, innererror);
		if (error == NULL) goto cleanup;
	}
	else error = NULL;
	if (cJSON_GetObjectItem(root, "target") != NULL) target = cJSON_GetObjectItem(root, "target")->valuestring;
	else target = NULL;
	if (cJSON_GetObjectItem(root, "request_id") != NULL) request_id = cJSON_GetObjectItem(root, "request_id")->valuestring;
	else  request_id = NULL;
	certOperationResponse = Store_CertOperation(id, issuer, csr, cancellation_requested, status, target, request_id);
	if (certOperationResponse == NULL) goto cleanup;
	parseRepsonse = Store_CertOperationDelete(certOperationResponse, status_details, error);
	if (parseRepsonse == NULL) goto cleanup;
	*certOperationDelete = parseRepsonse;
	cJSON_Delete(root);
	return OK;
cleanup:
	if (issuer != NULL)
		Free_Issuer(issuer);
	if (error != NULL)
		Free_Error(error);
	if (certOperationResponse != NULL)
		certOperationResponse->issuer = NULL;
	Free_CertOperation(certOperationResponse);
	*certOperationDelete = NULL;
	cJSON_Delete(root);
	return ALLOCATE_ERROR;
}

int parse_policy(char *response, struct cert_policy **policy) {
	struct cert_policy *parseResponse = NULL;
	struct cert_key_prop *keyProp = NULL;
	struct x509_props *x509Props = NULL;
	struct lifetime_actions *lifeTimeActions = NULL;
	struct cert_attributes *policyAttributes = NULL;
	struct issuer *issuer = NULL;
	cJSON *root = cJSON_Parse(response);
	if (root == NULL) {
		*policy = NULL;
		return PARSER_ERROR;
	}
	char *recoveryLevel;
	BOOL enabled;
	long nbf, exp, created, updated;
	char *polId;
	if (cJSON_GetObjectItem(root, "id") != NULL) polId = cJSON_GetObjectItem(root, "id")->valuestring;
	else  polId = NULL;
	cJSON *jsonSecretProps = cJSON_GetObjectItem(root, "secret_props");
	char * contentType = NULL;
	if (jsonSecretProps != NULL) {
		if (cJSON_GetObjectItem(jsonSecretProps, "contentType") != NULL) contentType = cJSON_GetObjectItem(jsonSecretProps, "contentType")->valuestring;
		else  contentType = NULL;
	}
	cJSON *jsonKeyProps = cJSON_GetObjectItem(root, "key_props");
	BOOL exportable, reuse_key;
	char *kty;
	int key_size;
	if (jsonKeyProps != NULL) {
		if (cJSON_GetObjectItem(jsonKeyProps, "exportable") != NULL) exportable = cJSON_GetObjectItem(jsonKeyProps, "exportable")->valueint;
		else  exportable = 0;
		if (cJSON_GetObjectItem(jsonKeyProps, "kty") != NULL) kty = cJSON_GetObjectItem(jsonKeyProps, "kty")->valuestring;
		else  kty = NULL;
		if (cJSON_GetObjectItem(jsonKeyProps, "key_size") != NULL) key_size = cJSON_GetObjectItem(jsonKeyProps, "key_size")->valueint;
		else  key_size = 0;
		if (cJSON_GetObjectItem(jsonKeyProps, "reuse_key") != NULL) reuse_key = cJSON_GetObjectItem(jsonKeyProps, "reuse_key")->valueint;
		else  reuse_key = 0;
		keyProp = Store_CertKeyProp(exportable, kty, key_size, reuse_key, contentType);
		if (keyProp == NULL) goto cleanup;
	}
	else jsonKeyProps = NULL;
	cJSON *jsonX509_props = cJSON_GetObjectItem(root, "x509_props");
	char *subject, *ekus[MAXIMUM_PERMITED_PARAMETERS], *key_usage[MAXIMUM_PERMITED_PARAMETERS], *emails[MAXIMUM_PERMITED_PARAMETERS];
	char *dns_names[MAXIMUM_PERMITED_PARAMETERS], *upns[MAXIMUM_PERMITED_PARAMETERS];
	for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
		ekus[i] = NULL;
		key_usage[i] = NULL;
		emails[i] = NULL;
		dns_names[i] = NULL;
		upns[i] = NULL;
	}
	int validity_months;
	cJSON *node = NULL;
	if (jsonX509_props != NULL) {
		if (cJSON_GetObjectItem(jsonX509_props, "subject") != NULL) subject = cJSON_GetObjectItem(jsonX509_props, "subject")->valuestring;
		else  subject = NULL;
		if (cJSON_GetObjectItem(jsonX509_props, "ekus") != NULL)
		{
			node = NULL;
			node = cJSON_GetObjectItem(jsonX509_props, "ekus")->child;
			for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++)
			{
				if (node != NULL)
				{	//funciona bien pero falta definir cuantos strings hay en el array
					ekus[i] = node->valuestring;
					node = node->next;
				}
				else ekus[i] = NULL;
			}
		}
		cJSON *jsonSans = cJSON_GetObjectItem(jsonX509_props, "sans");
		if (jsonSans != NULL) {
			if (cJSON_GetObjectItem(jsonSans, "emails") != NULL)
			{
				node = NULL;
				node = cJSON_GetObjectItem(jsonSans, "emails")->child;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++)
				{
					if (node != NULL)
					{	//funciona bien pero falta definir cuantos strings hay en el array
						emails[i] = node->valuestring;
						node = node->next;
					}
					else emails[i] = NULL;
				}
			}
			if (cJSON_GetObjectItem(jsonSans, "dns_names") != NULL)
			{
				node = NULL;
				node = cJSON_GetObjectItem(jsonSans, "dns_names")->child;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++)
				{
					if (node != NULL)
					{	//funciona bien pero falta definir cuantos strings hay en el array
						dns_names[i] = node->valuestring;
						node = node->next;
					}
					else dns_names[i] = NULL;
				}
			}
			if (cJSON_GetObjectItem(jsonSans, "upns") != NULL)
			{
				node = NULL;
				node = cJSON_GetObjectItem(jsonSans, "upns")->child;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++)
				{
					if (node != NULL)
					{	//funciona bien pero falta definir cuantos strings hay en el array
						upns[i] = node->valuestring;
						node = node->next;
					}
					else upns[i] = NULL;
				}
			}
		}
		if (cJSON_GetObjectItem(jsonX509_props, "key_usage") != NULL) {
			cJSON *node2 = NULL;
			node2 = cJSON_GetObjectItem(jsonX509_props, "key_usage")->child;
			for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++)
			{
				if (node2 != NULL)
				{	//funciona bien pero falta definir cuantos strings hay en el array
					key_usage[i] = node2->valuestring;
					node2 = node2->next;
				}
				else key_usage[i] = NULL;
			}
		}
		if (cJSON_GetObjectItem(jsonX509_props, "validity_months") != NULL) validity_months = cJSON_GetObjectItem(jsonX509_props, "validity_months")->valueint;
		else  validity_months = 0;
		x509Props = Store_X509Props(subject, ekus, emails, dns_names, upns, key_usage, validity_months);
		if (x509Props == NULL) goto cleanup;
	}
	else jsonX509_props = NULL;
	if (cJSON_GetObjectItem(root, "lifetime_actions") != NULL) {
		cJSON *jsonlifeTimeActions = cJSON_GetObjectItem(root, "lifetime_actions")->child;
		int lifetime_percentage, days_before_expiry;
		char *action_type;
		if (jsonlifeTimeActions != NULL) {
			cJSON *jsonTrigger = cJSON_GetObjectItem(jsonlifeTimeActions, "trigger");
			if (jsonTrigger != NULL) {
				if (cJSON_GetObjectItem(jsonTrigger, "lifetime_percentage") != NULL) lifetime_percentage = cJSON_GetObjectItem(jsonTrigger, "lifetime_percentage")->valueint;
				else  lifetime_percentage = 0;
				if (cJSON_GetObjectItem(jsonTrigger, "days_before_expiry") != NULL) days_before_expiry = cJSON_GetObjectItem(jsonTrigger, "days_before_expiry")->valueint;
				else days_before_expiry = 0;
			}
			else {
				lifetime_percentage = 0;
				days_before_expiry = 0;
			}
			cJSON *jsonAction = cJSON_GetObjectItem(jsonlifeTimeActions, "action");
			if (jsonAction != NULL) {
				if (cJSON_GetObjectItem(jsonAction, "action_type") != NULL) action_type = cJSON_GetObjectItem(jsonAction, "action_type")->valuestring;
				else  action_type = NULL;
			}
			else action_type = NULL;
			lifeTimeActions = Store_LifeTimeActions(lifetime_percentage, days_before_expiry, action_type);
			if (lifeTimeActions == NULL) goto cleanup;
		}
		else jsonlifeTimeActions = NULL;
	}
	cJSON *jsonIssuer = cJSON_GetObjectItem(root, "issuer");
	char *name, *cty;
	if (jsonIssuer != NULL) {
		if (cJSON_GetObjectItem(jsonIssuer, "Name") != NULL) name = cJSON_GetObjectItem(jsonIssuer, "Name")->valuestring;
		else  name = NULL;
		if (cJSON_GetObjectItem(jsonIssuer, "cty") != NULL) cty = cJSON_GetObjectItem(jsonIssuer, "cty")->valuestring;
		else  cty = NULL;
		issuer = Store_Issuer(name, cty);
		if (issuer == NULL) goto cleanup;
	}
	else issuer = NULL;
	cJSON *jsonPolicyAttributes = cJSON_GetObjectItem(root, "attributes");
	if (jsonPolicyAttributes != NULL) {
		if (cJSON_GetObjectItem(jsonPolicyAttributes, "recoveryLevel") != NULL) recoveryLevel = cJSON_GetObjectItem(jsonPolicyAttributes, "recoveryLevel")->valuestring;
		else recoveryLevel = NULL;
		if (cJSON_GetObjectItem(jsonPolicyAttributes, "enabled") != NULL) enabled = cJSON_GetObjectItem(jsonPolicyAttributes, "enabled")->valueint;
		else enabled = 0;
		if (cJSON_GetObjectItem(jsonPolicyAttributes, "nbf") != NULL) nbf = cJSON_GetObjectItem(jsonPolicyAttributes, "nbf")->valueint;
		else  nbf = 0;
		if (cJSON_GetObjectItem(jsonPolicyAttributes, "exp") != NULL) exp = cJSON_GetObjectItem(jsonPolicyAttributes, "exp")->valueint;
		else  exp = 0;
		if (cJSON_GetObjectItem(jsonPolicyAttributes, "created") != NULL) created = cJSON_GetObjectItem(jsonPolicyAttributes, "created")->valueint;
		else  created = 0;
		if (cJSON_GetObjectItem(jsonPolicyAttributes, "updated") != NULL) updated = cJSON_GetObjectItem(jsonPolicyAttributes, "updated")->valueint;
		else  updated = 0;
		policyAttributes = Store_CertAttributes(recoveryLevel, enabled, nbf, exp, created, updated);
		if (policyAttributes == NULL) goto cleanup;
	}
	else policyAttributes = NULL;
	parseResponse = Store_CertPolicy(polId, keyProp, x509Props, lifeTimeActions, policyAttributes, issuer);
	if (parseResponse == NULL) {
		*policy = NULL;
		cJSON_Delete(root);
		return ALLOCATE_ERROR;
	}
	else {
		*policy = parseResponse;
		cJSON_Delete(root);
		return OK;
	}
cleanup:
	if (keyProp != NULL)
		Free_CertKeyProp(keyProp);
	if (x509Props != NULL)
		Free_X509Props(x509Props);
	if (lifeTimeActions != NULL)
		Free_LifeTimeActions(lifeTimeActions);
	if (issuer != NULL)
		Free_Issuer(issuer);
	if (policyAttributes != NULL)
		Free_CertAttributes(policyAttributes);
	*policy = NULL;
	cJSON_Delete(root);
	return ALLOCATE_ERROR;

}

int parse_token_response(char *response, struct token_response **tokenResponse) {
	cJSON *root = cJSON_Parse(response);
	if (root == NULL) {
		*tokenResponse = NULL;
		return PARSER_ERROR;
	}
	char* tkn_typ = cJSON_GetObjectItem(root, "token_type")->valuestring;
	char* rsc = cJSON_GetObjectItem(root, "resource")->valuestring;
	char* acc_tkn = cJSON_GetObjectItem(root, "access_token")->valuestring;
	unsigned long int exp_in = strtoul(cJSON_GetObjectItem(root, "expires_in")->valuestring, NULL, 10);
	unsigned long int ext_exp_in = strtoul(cJSON_GetObjectItem(root, "ext_expires_in")->valuestring, NULL, 10);
	unsigned long int exp_on = strtoul(cJSON_GetObjectItem(root, "expires_on")->valuestring, NULL, 10);
	unsigned long int not_bfr = strtoul(cJSON_GetObjectItem(root, "not_before")->valuestring, NULL, 10);
	*tokenResponse = Store_AccesTokenResponse(tkn_typ, rsc, acc_tkn, exp_in, ext_exp_in, exp_on, not_bfr);
	cJSON_Delete(root);
	if (*tokenResponse == NULL) return ALLOCATE_ERROR;
	return OK;
}

int parse_simple_operation_response(char *response, struct simple_operation_response **opResponse) {
	char *value;
	struct simple_operation_response *parseResponse = NULL;
	cJSON *root = cJSON_Parse(response);
	if (root == NULL) {
		*opResponse = NULL;
		return PARSER_ERROR;
	}
	if (cJSON_GetObjectItem(root, "value") != NULL) value = cJSON_GetObjectItem(root, "value")->valuestring;
	else
	{
		cJSON_Delete(root);
		return PARSER_ERROR;
	}
	parseResponse = Store_SimpleOperationResponse(value);
	cJSON_Delete(root);
	if (parseResponse == NULL) return ALLOCATE_ERROR;
	*opResponse = parseResponse;
	return OK;
}

int Parse_secret_list_response(char *response, struct secret_items **secretListResponse, char **nextLink) {
	char *pattern = "secrets";
	struct cert_attributes *attributes = NULL;
	struct secret_items *new, *aux = NULL;
	cJSON *jsonAttributes, *root, *value;
	char kid[MAX_ID_SIZE], *tags, *auxKid, contentType[MAX_CONTENT_TYPE], *recoveryLevel = NULL, *recoveryId;
	unsigned long int nbf, exp, created, updated, deleteDate, scheduledPurgeDate;
	BOOL enabled = FALSE, managed = FALSE, first = TRUE;
	if (response != NULL) {
		root = cJSON_Parse(response);
		if (root == NULL) {
			*secretListResponse = NULL;
			return PARSER_ERROR;
		}
		value = cJSON_GetObjectItem(root, "value")->child;
		while (value != NULL) {
			if (cJSON_GetObjectItem(value, "contentType") != NULL) strncpy(contentType, cJSON_GetObjectItem(value, "contentType")->valuestring, MAX_CONTENT_TYPE);
			if (cJSON_GetObjectItem(value, "id") != NULL) { //stract keys/kid/version from response host/keys/kid/version
				auxKid = strstr(cJSON_GetObjectItem(value, "id")->valuestring, pattern);
				if (auxKid != NULL)
				{
					for (int i = 0; i <= strlen(auxKid) - strlen(pattern) + 1; i++) { // stract kid from keys/kid/version
						if (auxKid[i + strlen(pattern) + 1] == '/') break;
						kid[i] = auxKid[i + strlen(pattern) + 1];
						kid[i + 1] = '\0';
					}
				}
				else
				{
					cJSON_Delete(root);
					return PARSER_ERROR;
				}
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
			jsonAttributes = cJSON_GetObjectItem(value, "attributes");
			if (jsonAttributes != NULL)
			{
				if (cJSON_GetObjectItem(jsonAttributes, "enabled") != NULL) enabled = cJSON_GetObjectItem(jsonAttributes, "enabled")->valueint;
				else enabled = FALSE;
				if (cJSON_GetObjectItem(jsonAttributes, "nbf") != NULL) nbf = cJSON_GetObjectItem(jsonAttributes, "nbf")->valueint;
				else  nbf = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "exp") != NULL) exp = cJSON_GetObjectItem(jsonAttributes, "exp")->valueint;
				else  exp = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "created") != NULL) created = cJSON_GetObjectItem(jsonAttributes, "created")->valueint;
				else  created = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "updated") != NULL) updated = cJSON_GetObjectItem(jsonAttributes, "updated")->valueint;
				else  updated = 0;
				if (cJSON_GetObjectItem(jsonAttributes, "recoveryLevel") != NULL) recoveryLevel = cJSON_GetObjectItem(jsonAttributes, "recoveryLevel")->valuestring;
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
			if (cJSON_GetObjectItem(value, "tags") != NULL)	tags = cJSON_GetObjectItem(value, "tags")->valuestring;
			else tags = NULL;
			if (cJSON_GetObjectItem(value, "managed") != NULL) managed = cJSON_GetObjectItem(value, "managed")->valueint;
			else managed = FALSE;
			if (cJSON_GetObjectItem(value, "scheduledPurgeDate") != NULL) scheduledPurgeDate = cJSON_GetObjectItem(value, "scheduledPurgeDate")->valueint;
			else scheduledPurgeDate = 0;
			if (cJSON_GetObjectItem(value, "deleteDate") != NULL) deleteDate = cJSON_GetObjectItem(value, "deleteDate")->valueint;
			else deleteDate = 0;
			if (cJSON_GetObjectItem(value, "recoveryId") != NULL)	recoveryId = cJSON_GetObjectItem(value, "recoveryId")->valuestring;
			else recoveryId = NULL;
			attributes = Store_CertAttributes(recoveryLevel, enabled, nbf, exp, created, updated);
			if (attributes == NULL)
			{
				cJSON_Delete(root);
				return ALLOCATE_ERROR;
			}
			new = Store_SecretItems(kid, contentType, attributes, tags, managed, deleteDate, recoveryId, scheduledPurgeDate);
			if (new == NULL) {
				Free_CertAttributes(attributes);
				cJSON_Delete(root);
				return ALLOCATE_ERROR;
			}
			new->next = NULL;
			if (first == TRUE) {
				*secretListResponse = new;
				aux = new;
				first = FALSE;
			}
			else {
				aux->next = new;
				aux = aux->next;
			}
			value = value->next;
		}
		*nextLink = _strdup(cJSON_GetObjectItem(root, "nextLink")->valuestring);
		cJSON_Delete(root);
		return OK;
	}
	return PARSER_ERROR;
}

int parse_secret_data_response(char *response, struct secret_item_data **secretItemDatatResponse) {
	char pattern[8];
	strcpy(pattern, "secrets");
	struct cert_attributes *attributes = NULL;
	struct secret_item_data *secretItemData = NULL;
	cJSON *jsonAttributes, *root;
	char id[MAX_ID_SIZE], *tags, *auxKid, contentType[MAX_CONTENT_TYPE], *recoveryLevel = NULL, *recoveryId, kid[MAX_ID_SIZE], *value;
	unsigned long int nbf, exp, created, updated, deleteDate, scheduledPurgeDate;
	BOOL enabled = FALSE, managed = FALSE, first = TRUE;
	if (response != NULL) {
		root = cJSON_Parse(response);
		if (root == NULL) {
			*secretItemDatatResponse = NULL;
			return PARSER_ERROR;
		}
		if (cJSON_GetObjectItem(root, "contentType") != NULL) strncpy(contentType, cJSON_GetObjectItem(root, "contentType")->valuestring, MAX_CONTENT_TYPE);
		if (cJSON_GetObjectItem(root, "id") != NULL) { //stract keys/kid/version from response host/keys/kid/version
			auxKid = strstr(cJSON_GetObjectItem(root, "id")->valuestring, pattern);
			if (auxKid != NULL)
			{
				for (int i = 0; i <= strlen(auxKid) - strlen(pattern) + 1; i++) { // stract kid from keys/kid/version
					if (auxKid[i + strlen(pattern) + 1] == '/') break;
					id[i] = auxKid[i + strlen(pattern) + 1];
					id[i + 1] = '\0';
				}
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
		}
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
		strcpy(pattern, "keys");
		if (cJSON_GetObjectItem(root, "kid") != NULL) { //stract keys/kid/version from response host/keys/kid/version
			auxKid = strstr(cJSON_GetObjectItem(root, "kid")->valuestring, pattern);
			if (auxKid != NULL)
			{
				for (int i = 0; i <= strlen(auxKid) - strlen(pattern) + 1; i++) { // stract kid from keys/kid/version
					if (auxKid[i + strlen(pattern) + 1] == '/') break;
					kid[i] = auxKid[i + strlen(pattern) + 1];
					kid[i + 1] = '\0';
				}
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
		}
		else kid[0] = '\0';
		if (cJSON_GetObjectItem(root, "value") != NULL) value = cJSON_GetObjectItem(root, "value")->valuestring;
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
		jsonAttributes = cJSON_GetObjectItem(root, "attributes");
		if (jsonAttributes != NULL)
		{
			if (cJSON_GetObjectItem(jsonAttributes, "enabled") != NULL) enabled = cJSON_GetObjectItem(jsonAttributes, "enabled")->valueint;
			else enabled = FALSE;
			if (cJSON_GetObjectItem(jsonAttributes, "nbf") != NULL) nbf = cJSON_GetObjectItem(jsonAttributes, "nbf")->valueint;
			else  nbf = 0;
			if (cJSON_GetObjectItem(jsonAttributes, "exp") != NULL) exp = cJSON_GetObjectItem(jsonAttributes, "exp")->valueint;
			else  exp = 0;
			if (cJSON_GetObjectItem(jsonAttributes, "created") != NULL) created = cJSON_GetObjectItem(jsonAttributes, "created")->valueint;
			else  created = 0;
			if (cJSON_GetObjectItem(jsonAttributes, "updated") != NULL) updated = cJSON_GetObjectItem(jsonAttributes, "updated")->valueint;
			else  updated = 0;
			if (cJSON_GetObjectItem(jsonAttributes, "recoveryLevel") != NULL) recoveryLevel = cJSON_GetObjectItem(jsonAttributes, "recoveryLevel")->valuestring;
		}
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
		if (cJSON_GetObjectItem(root, "tags") != NULL)	tags = cJSON_GetObjectItem(root, "tags")->valuestring;
		else tags = NULL;
		if (cJSON_GetObjectItem(root, "managed") != NULL) managed = cJSON_GetObjectItem(root, "managed")->valueint;
		else managed = FALSE;
		if (cJSON_GetObjectItem(root, "scheduledPurgeDate") != NULL) scheduledPurgeDate = cJSON_GetObjectItem(root, "scheduledPurgeDate")->valueint;
		else scheduledPurgeDate = 0;
		if (cJSON_GetObjectItem(root, "deleteDate") != NULL) deleteDate = cJSON_GetObjectItem(root, "deleteDate")->valueint;
		else deleteDate = 0;
		if (cJSON_GetObjectItem(root, "recoveryId") != NULL)	recoveryId = cJSON_GetObjectItem(root, "recoveryId")->valuestring;
		else recoveryId = NULL;
		attributes = Store_CertAttributes(recoveryLevel, enabled, nbf, exp, created, updated);
		if (attributes == NULL) return ALLOCATE_ERROR;
		secretItemData = Store_SecretItemsData(id, kid, value, contentType, attributes, tags, managed, deleteDate, recoveryId, scheduledPurgeDate);
		cJSON_Delete(root);
		if (secretItemData == NULL) {
			*secretItemDatatResponse = NULL;
			Free_CertAttributes(attributes);
			return PARSER_ERROR;
		}
		*secretItemDatatResponse = secretItemData;
		return OK;
	}
	return PARSER_ERROR;
}

int parse_secret_data_update_response(char *response, struct secret_update_response **secretUpdateResponse) {
	char pattern[8];
	strcpy(pattern, "secrets");
	struct cert_attributes *attributes = NULL;
	struct secret_update_response *secretItemData = NULL;
	cJSON *jsonAttributes, *root;
	char id[MAX_ID_SIZE], *tags, *auxKid, contentType[MAX_CONTENT_TYPE], *recoveryLevel = NULL;
	unsigned long int nbf, exp, created, updated;
	BOOL enabled = FALSE;
	*secretUpdateResponse = NULL;
	if (response != NULL) {
		root = cJSON_Parse(response);
		if (root == NULL) {
			return PARSER_ERROR;
		}
		if (cJSON_GetObjectItem(root, "contentType") != NULL) strncpy(contentType, cJSON_GetObjectItem(root, "contentType")->valuestring, MAX_CONTENT_TYPE);
		if (cJSON_GetObjectItem(root, "id") != NULL) { //stract keys/kid/version from response host/keys/kid/version
			auxKid = strstr(cJSON_GetObjectItem(root, "id")->valuestring, pattern);
			if (auxKid != NULL)
			{
				for (int i = 0; i <= strlen(auxKid) - strlen(pattern) + 1; i++) { // stract kid from keys/kid/version
					if (auxKid[i + strlen(pattern) + 1] == '/') break;
					id[i] = auxKid[i + strlen(pattern) + 1];
					id[i + 1] = '\0';
				}
			}
			else
			{
				cJSON_Delete(root);
				return PARSER_ERROR;
			}
		}
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
		jsonAttributes = cJSON_GetObjectItem(root, "attributes");
		if (jsonAttributes != NULL)
		{
			if (cJSON_GetObjectItem(jsonAttributes, "enabled") != NULL) enabled = cJSON_GetObjectItem(jsonAttributes, "enabled")->valueint;
			else enabled = FALSE;
			if (cJSON_GetObjectItem(jsonAttributes, "nbf") != NULL) nbf = cJSON_GetObjectItem(jsonAttributes, "nbf")->valueint;
			else  nbf = 0;
			if (cJSON_GetObjectItem(jsonAttributes, "exp") != NULL) exp = cJSON_GetObjectItem(jsonAttributes, "exp")->valueint;
			else  exp = 0;
			if (cJSON_GetObjectItem(jsonAttributes, "created") != NULL) created = cJSON_GetObjectItem(jsonAttributes, "created")->valueint;
			else  created = 0;
			if (cJSON_GetObjectItem(jsonAttributes, "updated") != NULL) updated = cJSON_GetObjectItem(jsonAttributes, "updated")->valueint;
			else  updated = 0;
			if (cJSON_GetObjectItem(jsonAttributes, "recoveryLevel") != NULL) recoveryLevel = cJSON_GetObjectItem(jsonAttributes, "recoveryLevel")->valuestring;
		}
		else
		{
			cJSON_Delete(root);
			return PARSER_ERROR;
		}
		if (cJSON_GetObjectItem(root, "tags") != NULL)	tags = cJSON_GetObjectItem(root, "tags")->valuestring;
		else tags = NULL;
		attributes = Store_CertAttributes(recoveryLevel, enabled, nbf, exp, created, updated);
		if (attributes == NULL)
		{
			cJSON_Delete(root);
			return ALLOCATE_ERROR;
		}
		secretItemData = Store_SecretUpdateResponse(id, attributes, contentType, tags);
		cJSON_Delete(root);
		if (secretItemData == NULL) {
			Free_CertAttributes(attributes);
			return PARSER_ERROR;
		}
		*secretUpdateResponse = secretItemData;
		return OK;
	}
	return PARSER_ERROR;
}
//************************** Data 2 JSON ********************************


char *CreateCertificate2Json(struct create_cert * CreateCert) {
	if (CreateCert == NULL) return NULL;
	cJSON *root, *policy, *issuer, *x509_props, *key_props, *secret_props, *sans = NULL, *lifetime_actions, *trigger = NULL, *action, *policyAttributes, *attributes;
	int count;
	root = cJSON_CreateObject();
	if (root == NULL) return NULL;
	cJSON_AddItemToObject(root, "policy", policy = cJSON_CreateObject());
	if (CreateCert->certPolicy->id != NULL)
		cJSON_AddStringToObject(policy, "id", CreateCert->certPolicy->id);
	if (CreateCert->certPolicy->keyProp != NULL) {
		cJSON_AddItemToObject(policy, "key_props", key_props = cJSON_CreateObject());
		/*if (CreateCert->certPolicy->keyProp->exportable != NULL)*/
		cJSON_AddBoolToObject(key_props, "exportable", CreateCert->certPolicy->keyProp->exportable);
		if (CreateCert->certPolicy->keyProp->kty != NULL)
			cJSON_AddStringToObject(key_props, "kty", CreateCert->certPolicy->keyProp->kty);
		if (CreateCert->certPolicy->keyProp->key_size != 0)
			cJSON_AddNumberToObject(key_props, "key_size", CreateCert->certPolicy->keyProp->key_size);
		/*	if (CreateCert->certPolicy->keyProp->reuse_key != NULL)*/
		cJSON_AddBoolToObject(key_props, "reuse_key", CreateCert->certPolicy->keyProp->reuse_key);

		if (CreateCert->certPolicy->keyProp->contentType != NULL) {
			cJSON_AddItemToObject(policy, "secret_props", secret_props = cJSON_CreateObject());
			if (CreateCert->certPolicy->keyProp->contentType != NULL)
				cJSON_AddStringToObject(secret_props, "contentType", CreateCert->certPolicy->keyProp->contentType);
		}
	}
	if (CreateCert->certPolicy->x509Props != NULL) {
		cJSON_AddItemToObject(policy, "x509_props", x509_props = cJSON_CreateObject());
		if (CreateCert->certPolicy->x509Props->subject != NULL)
			cJSON_AddStringToObject(x509_props, "subject", CreateCert->certPolicy->x509Props->subject);
		if (CreateCert->certPolicy->x509Props->ekus != NULL) {
			count = 0;
			for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
				if (CreateCert->certPolicy->x509Props->ekus[i] != NULL) count++;
			}
			if (count != 0)
				cJSON_AddItemToObject(x509_props, "ekus", cJSON_CreateStringArray((const char **)CreateCert->certPolicy->x509Props->ekus, count));
		}
		if (CreateCert->certPolicy->x509Props->emails != NULL) {
			if (sans == NULL) cJSON_AddItemToObject(x509_props, "sans", sans = cJSON_CreateObject());
			count = 0;
			for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
				if (CreateCert->certPolicy->x509Props->emails[i] != NULL) count++;
			}
			if (count != 0)
				cJSON_AddItemToObject(sans, "emails", cJSON_CreateStringArray((const char **)CreateCert->certPolicy->x509Props->emails, count));
		}
		if (CreateCert->certPolicy->x509Props->dnsNames != NULL) {
			if (sans == NULL) cJSON_AddItemToObject(x509_props, "sans", sans = cJSON_CreateObject());
			count = 0;
			for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
				if (CreateCert->certPolicy->x509Props->dnsNames[i] != NULL) count++;
			}
			if (count != 0)
				cJSON_AddItemToObject(sans, "dns_names", cJSON_CreateStringArray((const char **)CreateCert->certPolicy->x509Props->dnsNames, count));
		}
		if (CreateCert->certPolicy->x509Props->upns != NULL) {
			if (sans == NULL) cJSON_AddItemToObject(x509_props, "sans", sans = cJSON_CreateObject());
			count = 0;
			for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
				if (CreateCert->certPolicy->x509Props->upns[i] != NULL) count++;
			}
			if (count != 0)
				cJSON_AddItemToObject(sans, "upns", cJSON_CreateStringArray((const char **)CreateCert->certPolicy->x509Props->upns, count));
		}

		if (CreateCert->certPolicy->x509Props->keyUsage != NULL) {
			count = 0;
			for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
				if (CreateCert->certPolicy->x509Props->keyUsage[i] != NULL) count++;
			}
			if (count != 0)
				cJSON_AddItemToObject(x509_props, "key_usage", cJSON_CreateStringArray((const char **)CreateCert->certPolicy->x509Props->keyUsage, count));
		}
		if (CreateCert->certPolicy->x509Props->validityMonths != 0)
			cJSON_AddNumberToObject(x509_props, "validity_months", CreateCert->certPolicy->x509Props->validityMonths);

	}
	if (CreateCert->certPolicy->lifeTimeActions != NULL) {
		cJSON_AddItemToObject(policy, "lifetime_actions", lifetime_actions = cJSON_CreateObject());
		if (CreateCert->certPolicy->lifeTimeActions->lifetimePercentage != 0) {
			if (trigger == NULL) cJSON_AddItemToObject(lifetime_actions, "trigger", trigger = cJSON_CreateObject());
			cJSON_AddNumberToObject(trigger, "lifetime_percentage", CreateCert->certPolicy->lifeTimeActions->lifetimePercentage);
		}
		if (CreateCert->certPolicy->lifeTimeActions->daysBeforeExpiry != 0) {
			if (trigger == NULL) cJSON_AddItemToObject(lifetime_actions, "trigger", trigger = cJSON_CreateObject());
			cJSON_AddNumberToObject(trigger, "days_before_expiry", CreateCert->certPolicy->lifeTimeActions->daysBeforeExpiry);
		}
		if (CreateCert->certPolicy->lifeTimeActions->actionType != NULL) {
			cJSON_AddItemToObject(lifetime_actions, "action", action = cJSON_CreateObject());
			cJSON_AddStringToObject(action, "action_type", CreateCert->certPolicy->lifeTimeActions->actionType);
		}
	}
	if (CreateCert->certPolicy->issuer != NULL) {
		cJSON_AddItemToObject(policy, "issuer", issuer = cJSON_CreateObject());
		if (CreateCert->certPolicy->issuer->name != NULL)
			cJSON_AddStringToObject(issuer, "name", CreateCert->certPolicy->issuer->name);
		if (CreateCert->certPolicy->issuer->cty != NULL)
			cJSON_AddStringToObject(issuer, "cty", CreateCert->certPolicy->issuer->cty);
	}
	if (CreateCert->certPolicy->cerAttributes != NULL) {
		cJSON_AddItemToObject(policy, "attributes", policyAttributes = cJSON_CreateObject());
		if (CreateCert->certPolicy->cerAttributes->recoveryLevel != NULL)
			cJSON_AddStringToObject(policyAttributes, "recoveryLevel", CreateCert->certPolicy->cerAttributes->recoveryLevel);
		/*	if (CreateCert->certPolicy->cerAttributes->enabled != NULL)*/
		cJSON_AddBoolToObject(policyAttributes, "enabled", CreateCert->certPolicy->cerAttributes->enabled);
		if (CreateCert->certPolicy->cerAttributes->nbf != 0)
			cJSON_AddNumberToObject(policyAttributes, "nbf", CreateCert->certPolicy->cerAttributes->nbf);
		if (CreateCert->certPolicy->cerAttributes->exp != 0)
			cJSON_AddNumberToObject(policyAttributes, "exp", CreateCert->certPolicy->cerAttributes->exp);
		if (CreateCert->certPolicy->cerAttributes->created != 0)
			cJSON_AddNumberToObject(policyAttributes, "created", CreateCert->certPolicy->cerAttributes->created);
		if (CreateCert->certPolicy->cerAttributes->updated != 0)
			cJSON_AddNumberToObject(policyAttributes, "updated", CreateCert->certPolicy->cerAttributes->updated);
	}
	if (CreateCert->cerAttributes != NULL) {
		cJSON_AddItemToObject(root, "attributes", attributes = cJSON_CreateObject());
		if (CreateCert->cerAttributes->recoveryLevel != NULL)
			cJSON_AddStringToObject(attributes, "recoveryLevel", CreateCert->cerAttributes->recoveryLevel);
		/*	if (CreateCert->cerAttributes->enabled != NULL)*/
		cJSON_AddBoolToObject(attributes, "enabled", CreateCert->cerAttributes->enabled);
		if (CreateCert->cerAttributes->nbf != 0)
			cJSON_AddNumberToObject(attributes, "nbf", CreateCert->cerAttributes->nbf);
		if (CreateCert->cerAttributes->exp != 0)
			cJSON_AddNumberToObject(attributes, "exp", CreateCert->cerAttributes->exp);
		if (CreateCert->cerAttributes->created != 0)
			cJSON_AddNumberToObject(attributes, "created", CreateCert->cerAttributes->created);
		if (CreateCert->cerAttributes->updated != 0)
			cJSON_AddNumberToObject(attributes, "updated", CreateCert->cerAttributes->updated);
	}
	if (CreateCert->tags != NULL) {
		cJSON_AddStringToObject(root, "tags", CreateCert->tags);
	}
	char * jsonString = cJSON_Print(root);
	char *out = _strdup(jsonString);
	cJSON_Delete(root);
	return out;
}

char *CreateImport2Json(struct import_cert_data *importData) {
	if (importData == NULL) return NULL;
	cJSON *root, *policy, *issuer, *x509_props, *key_props, *secret_props, *sans = NULL, *lifetime_actions, *trigger = NULL, *action, *policyAttributes, *attributes;
	int count;
	root = cJSON_CreateObject();
	if (root == NULL) return NULL;
	if (importData->base64Value != NULL)
		cJSON_AddStringToObject(root, "value", importData->base64Value);
	if (importData->pwd != NULL)
		cJSON_AddStringToObject(root, "pwd", importData->pwd);
	if (importData->certPolicy != NULL) {
		cJSON_AddItemToObject(root, "policy", policy = cJSON_CreateObject());
		if (importData->certPolicy->id != NULL)
			cJSON_AddStringToObject(policy, "id", importData->certPolicy->id);
		if (importData->certPolicy->keyProp != NULL) {
			cJSON_AddItemToObject(policy, "key_props", key_props = cJSON_CreateObject());
			/*		if (importData->certPolicy->keyProp->exportable != NULL)*/
			cJSON_AddBoolToObject(key_props, "exportable", importData->certPolicy->keyProp->exportable);
			if (importData->certPolicy->keyProp->kty != NULL)
				cJSON_AddStringToObject(key_props, "kty", importData->certPolicy->keyProp->kty);
			if (importData->certPolicy->keyProp->key_size != 0)
				cJSON_AddNumberToObject(key_props, "key_size", importData->certPolicy->keyProp->key_size);
			//if (importData->certPolicy->keyProp->reuse_key != NULL)
			cJSON_AddBoolToObject(key_props, "reuse_key", importData->certPolicy->keyProp->reuse_key);

			if (importData->certPolicy->keyProp->contentType != NULL) {
				cJSON_AddItemToObject(policy, "secret_props", secret_props = cJSON_CreateObject());
				if (importData->certPolicy->keyProp->contentType != NULL)
					cJSON_AddStringToObject(secret_props, "contentType", importData->certPolicy->keyProp->contentType);
			}
		}
		if (importData->certPolicy->x509Props != NULL) {
			cJSON_AddItemToObject(policy, "x509_props", x509_props = cJSON_CreateObject());
			if (importData->certPolicy->x509Props->subject != NULL)
				cJSON_AddStringToObject(x509_props, "subject", importData->certPolicy->x509Props->subject);
			if (importData->certPolicy->x509Props->ekus != NULL) {
				count = 0;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
					if (importData->certPolicy->x509Props->ekus[i] != NULL) count++;
				}
				if (count != 0)
					cJSON_AddItemToObject(x509_props, "ekus", cJSON_CreateStringArray((const char **)importData->certPolicy->x509Props->ekus, count));
			}
			if (importData->certPolicy->x509Props->emails != NULL) {
				if (sans == NULL) cJSON_AddItemToObject(x509_props, "sans", sans = cJSON_CreateObject());
				count = 0;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
					if (importData->certPolicy->x509Props->emails[i] != NULL) count++;
				}
				if (count != 0)
					cJSON_AddItemToObject(sans, "emails", cJSON_CreateStringArray((const char **)importData->certPolicy->x509Props->emails, count));
			}
			if (importData->certPolicy->x509Props->dnsNames != NULL) {
				if (sans == NULL) cJSON_AddItemToObject(x509_props, "sans", sans = cJSON_CreateObject());
				count = 0;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
					if (importData->certPolicy->x509Props->dnsNames[i] != NULL) count++;
				}
				if (count != 0)
					cJSON_AddItemToObject(sans, "dns_names", cJSON_CreateStringArray((const char **)importData->certPolicy->x509Props->dnsNames, count));
			}
			if (importData->certPolicy->x509Props->upns != NULL) {
				if (sans == NULL) cJSON_AddItemToObject(x509_props, "sans", sans = cJSON_CreateObject());
				count = 0;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
					if (importData->certPolicy->x509Props->upns[i] != NULL) count++;
				}
				if (count != 0)
					cJSON_AddItemToObject(sans, "upns", cJSON_CreateStringArray((const char **)importData->certPolicy->x509Props->upns, count));
			}

			if (importData->certPolicy->x509Props->keyUsage != NULL) {
				count = 0;
				for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
					if (importData->certPolicy->x509Props->keyUsage[i] != NULL) count++;
				}
				if (count != 0)
					cJSON_AddItemToObject(x509_props, "key_usage", cJSON_CreateStringArray((const char **)importData->certPolicy->x509Props->keyUsage, count));
			}
			if (importData->certPolicy->x509Props->validityMonths != 0)
				cJSON_AddNumberToObject(x509_props, "validity_months", importData->certPolicy->x509Props->validityMonths);

		}
		if (importData->certPolicy->lifeTimeActions != NULL) {
			cJSON_AddItemToObject(policy, "lifetime_actions", lifetime_actions = cJSON_CreateObject());
			if (importData->certPolicy->lifeTimeActions->lifetimePercentage != 0) {
				if (trigger == NULL) cJSON_AddItemToObject(lifetime_actions, "trigger", trigger = cJSON_CreateObject());
				cJSON_AddNumberToObject(trigger, "lifetime_percentage", importData->certPolicy->lifeTimeActions->lifetimePercentage);
			}
			if (importData->certPolicy->lifeTimeActions->daysBeforeExpiry != 0) {
				if (trigger == NULL) cJSON_AddItemToObject(lifetime_actions, "trigger", trigger = cJSON_CreateObject());
				cJSON_AddNumberToObject(trigger, "days_before_expiry", importData->certPolicy->lifeTimeActions->daysBeforeExpiry);
			}
			if (importData->certPolicy->lifeTimeActions->actionType != NULL) {
				cJSON_AddItemToObject(lifetime_actions, "action", action = cJSON_CreateObject());
				cJSON_AddStringToObject(action, "action_type", importData->certPolicy->lifeTimeActions->actionType);
			}
		}
		if (importData->certPolicy->issuer != NULL) {
			cJSON_AddItemToObject(policy, "issuer", issuer = cJSON_CreateObject());
			if (importData->certPolicy->issuer->name != NULL)
				cJSON_AddStringToObject(issuer, "name", importData->certPolicy->issuer->name);
			if (importData->certPolicy->issuer->cty != NULL)
				cJSON_AddStringToObject(issuer, "cty", importData->certPolicy->issuer->cty);
		}
		if (importData->certPolicy->cerAttributes != NULL) {
			cJSON_AddItemToObject(policy, "attributes", policyAttributes = cJSON_CreateObject());
			if (importData->certPolicy->cerAttributes->recoveryLevel != NULL)
				cJSON_AddStringToObject(policyAttributes, "recoveryLevel", importData->certPolicy->cerAttributes->recoveryLevel);
			/*		if (importData->certPolicy->cerAttributes->enabled != NULL)*/
			cJSON_AddBoolToObject(policyAttributes, "enabled", importData->certPolicy->cerAttributes->enabled);
			if (importData->certPolicy->cerAttributes->nbf != 0)
				cJSON_AddNumberToObject(policyAttributes, "nbf", importData->certPolicy->cerAttributes->nbf);
			if (importData->certPolicy->cerAttributes->exp != 0)
				cJSON_AddNumberToObject(policyAttributes, "exp", importData->certPolicy->cerAttributes->exp);
			if (importData->certPolicy->cerAttributes->created != 0)
				cJSON_AddNumberToObject(policyAttributes, "created", importData->certPolicy->cerAttributes->created);
			if (importData->certPolicy->cerAttributes->updated != 0)
				cJSON_AddNumberToObject(policyAttributes, "updated", importData->certPolicy->cerAttributes->updated);
		}
	}
	if (importData->cerAttributes != NULL) {
		cJSON_AddItemToObject(root, "attributes", attributes = cJSON_CreateObject());
		if (importData->cerAttributes->recoveryLevel != NULL)
			cJSON_AddStringToObject(attributes, "recoveryLevel", importData->cerAttributes->recoveryLevel);
		//if (importData->cerAttributes->enabled != NULL)
		cJSON_AddBoolToObject(attributes, "enabled", importData->cerAttributes->enabled);
		if (importData->cerAttributes->nbf != 0)
			cJSON_AddNumberToObject(attributes, "nbf", importData->cerAttributes->nbf);
		if (importData->cerAttributes->exp != 0)
			cJSON_AddNumberToObject(attributes, "exp", importData->cerAttributes->exp);
		if (importData->cerAttributes->created != 0)
			cJSON_AddNumberToObject(attributes, "created", importData->cerAttributes->created);
		if (importData->cerAttributes->updated != 0)
			cJSON_AddNumberToObject(attributes, "updated", importData->cerAttributes->updated);
	}
	if (importData->tags != NULL) {
		cJSON_AddStringToObject(root, "tags", importData->tags);
	}
	char * jsonString = cJSON_Print(root);
	char *out = _strdup(jsonString);
	cJSON_Delete(root);
	return out;
}

char * CreateOperation2Json(struct operation_data * opData)
{
	if (opData == NULL) return NULL;
	cJSON *root;
	root = cJSON_CreateObject();
	if (root == NULL) return NULL;
	cJSON_AddStringToObject(root, "alg", opData->algorithm);
	if (opData->value != NULL)
		cJSON_AddStringToObject(root, "value", opData->value);
	char * jsonString = cJSON_Print(root);
	char *out = _strdup(jsonString);
	cJSON_Delete(root);
	return out;
}


char *CreateKey2Json(struct key_data *createKeyData) {
	if (createKeyData == NULL) return NULL;
    if ((createKeyData->keysize == NULL && createKeyData->crv == NULL) || createKeyData->keytype == NULL)  return NULL;
	cJSON *root, *attributes;
	root = cJSON_CreateObject();
	if (root == NULL) return NULL;
	if (createKeyData->attributes != NULL) {
		cJSON_AddItemToObject(root, "attributes", attributes = cJSON_CreateObject());
		if (attributes != NULL) {
			if (createKeyData->attributes->created != 0)
				cJSON_AddBoolToObject(attributes, "enabled", createKeyData->attributes->enabled);
			if (createKeyData->attributes->nbf != 0)
				cJSON_AddNumberToObject(attributes, "nbf", createKeyData->attributes->nbf);
			if (createKeyData->attributes->exp != 0)
				cJSON_AddNumberToObject(attributes, "exp", createKeyData->attributes->exp);
			if (createKeyData->attributes->created != 0)
				cJSON_AddNumberToObject(attributes, "created", createKeyData->attributes->created);
			if (createKeyData->attributes->updated != 0)
				cJSON_AddNumberToObject(attributes, "updated", createKeyData->attributes->updated);
		}
	}
	if (createKeyData->key_ops != NULL) {
		cJSON *keyOps;
		int i;
		for (i = 0; i < MAX_OPS; i++) {
			if (createKeyData->key_ops[i] == NULL) break;
		}
		keyOps = cJSON_CreateStringArray((const char **)createKeyData->key_ops, i);
		cJSON_AddItemToObject(root, "key_ops", keyOps);
	}
    if (createKeyData->keysize != NULL) {
        cJSON_AddStringToObject(root, "key_size", createKeyData->keysize);
    }
    if (createKeyData->crv != NULL) {
        cJSON_AddStringToObject(root, "crv", createKeyData->crv);
    }
	cJSON_AddStringToObject(root, "kty", createKeyData->keytype);
	if (createKeyData->tags != NULL) {
		cJSON_AddStringToObject(root, "tags", createKeyData->tags);
	}
	char * jsonString = cJSON_Print(root);
	char * out = _strdup(jsonString);
	cJSON_Delete(root);
	return out;
}

char * UpdateKey2Json(struct update_key * updateKey)
{
	if (updateKey == NULL) return NULL;
	cJSON *root, *attributes;
	root = cJSON_CreateObject();
	if (root == NULL) return NULL;
	if (updateKey->attributes != NULL) {
		cJSON_AddItemToObject(root, "attributes", attributes = cJSON_CreateObject());
		if (attributes != NULL) {
			if (updateKey->attributes->created != 0)
				cJSON_AddBoolToObject(attributes, "enabled", updateKey->attributes->enabled);
			if (updateKey->attributes->nbf != 0)
				cJSON_AddNumberToObject(attributes, "nbf", updateKey->attributes->nbf);
			if (updateKey->attributes->exp != 0)
				cJSON_AddNumberToObject(attributes, "exp", updateKey->attributes->exp);
			if (updateKey->attributes->created != 0)
				cJSON_AddNumberToObject(attributes, "created", updateKey->attributes->created);
			if (updateKey->attributes->updated != 0)
				cJSON_AddNumberToObject(attributes, "updated", updateKey->attributes->updated);
		}
	}
	if (updateKey->key_ops != NULL) {
		cJSON *keyOps;
		int i;
		for (i = 0; i < MAX_OPS; i++) {
			if (updateKey->key_ops[i] == NULL) break;
		}
		keyOps = cJSON_CreateStringArray((const char **)updateKey->key_ops, i);
		cJSON_AddItemToObject(root, "key_ops", keyOps);
	}
	char * jsonString = cJSON_Print(root);
	char * out = _strdup(jsonString);
	cJSON_Delete(root);
	return out;
}

char *CreateMergeCertificate2Json(struct merge_data * mergeData) {
	if (mergeData == NULL) return NULL;
	cJSON *root, *attributes;
	root = cJSON_CreateObject();
	if (root == NULL) return NULL;
	if (mergeData->cerAttributes != NULL) {
		cJSON_AddItemToObject(root, "attributes", attributes = cJSON_CreateObject());
		if (mergeData->cerAttributes->recoveryLevel != NULL)
			cJSON_AddStringToObject(attributes, "recoveryLevel", mergeData->cerAttributes->recoveryLevel);
		/*	if (CreateCert->cerAttributes->enabled != NULL)*/
		cJSON_AddBoolToObject(attributes, "enabled", mergeData->cerAttributes->enabled);
		if (mergeData->cerAttributes->nbf != 0)
			cJSON_AddNumberToObject(attributes, "nbf", mergeData->cerAttributes->nbf);
		if (mergeData->cerAttributes->exp != 0)
			cJSON_AddNumberToObject(attributes, "exp", mergeData->cerAttributes->exp);
		if (mergeData->cerAttributes->created != 0)
			cJSON_AddNumberToObject(attributes, "created", mergeData->cerAttributes->created);
		if (mergeData->cerAttributes->updated != 0)
			cJSON_AddNumberToObject(attributes, "updated", mergeData->cerAttributes->updated);
	}
	if (mergeData->tags != NULL) {
		cJSON_AddStringToObject(root, "tags", mergeData->tags);
	}
	if (mergeData->x5c != NULL) {
		cJSON *x5c;
		int i;
		for (i = 0; i < MAX_OPS; i++) {
			if (mergeData->x5c[i] == NULL) break;
		}
		x5c = cJSON_CreateStringArray((const char **)mergeData->x5c, i);
		cJSON_AddItemToObject(root, "x5c", x5c);
	}
	char * jsonString = cJSON_Print(root);
	char *out = _strdup(jsonString);
	cJSON_Delete(root);
	return out;
}

char *CreateSecret2Json(struct secret_creation_data *createSecretData) {
	if (createSecretData == NULL) return NULL;
	cJSON *root, *attributes;
	root = cJSON_CreateObject();
	if (root == NULL) return NULL;
	if (createSecretData->attributes != NULL) {
		cJSON_AddItemToObject(root, "attributes", attributes = cJSON_CreateObject());
		if (attributes != NULL) {
			if (createSecretData->attributes->recoveryLevel != NULL)
				cJSON_AddStringToObject(attributes, "recoveryLevel", createSecretData->attributes->recoveryLevel);
			/*	if (CreateCert->cerAttributes->enabled != NULL)*/
			cJSON_AddBoolToObject(attributes, "enabled", createSecretData->attributes->enabled);
			if (createSecretData->attributes->nbf != 0)
				cJSON_AddNumberToObject(attributes, "nbf", createSecretData->attributes->nbf);
			if (createSecretData->attributes->exp != 0)
				cJSON_AddNumberToObject(attributes, "exp", createSecretData->attributes->exp);
			if (createSecretData->attributes->created != 0)
				cJSON_AddNumberToObject(attributes, "created", createSecretData->attributes->created);
			if (createSecretData->attributes->updated != 0)
				cJSON_AddNumberToObject(attributes, "updated", createSecretData->attributes->updated);
		}
	}
	cJSON_AddStringToObject(root, "contentType", createSecretData->contentType);
	if (createSecretData->tags != NULL) {
		cJSON_AddStringToObject(root, "tags", createSecretData->tags);
	}
	if (createSecretData->value != NULL) cJSON_AddStringToObject(root, "value", createSecretData->value);
	char * jsonString = cJSON_Print(root);
	char * out = _strdup(jsonString);
	cJSON_Delete(root);
	return out;
}
