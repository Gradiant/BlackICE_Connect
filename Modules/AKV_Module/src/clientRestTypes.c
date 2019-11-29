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
#include <src/common.h>
#include <math.h>

struct id_http_data *Store_IdHttpData(char *token, char *host, char *id) {
	struct id_http_data * retval = malloc(sizeof(struct id_http_data));
	if (retval == NULL) return NULL;
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval);
		return NULL;
	}
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval->token);
		free(retval);
		return NULL;
	}
	if (id != NULL) {
		retval->id = _strdup(id);
		if (retval->id == NULL) {
			free(retval->token);
			free(retval->host);
			free(retval);
			return NULL;
		}
	}
	else retval->id = NULL;
	return retval;
}

void Free_IdHttpData(struct id_http_data *delData) {
	if (delData != NULL) {
		if (delData->token != NULL) free(delData->token);
		if (delData->host != NULL) free(delData->host);
		if (delData->id != NULL) free(delData->id);
		free(delData);
	}
}

struct value_http_data *Store_ValueHttpData(char *token, char *host, char *value) {
	struct value_http_data * retval = malloc(sizeof(struct value_http_data));
	if (retval == NULL) return NULL;
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval);
		return NULL;
	}
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval->token);
		free(retval);
		return NULL;
	}
	if (value != NULL) {
		retval->value = _strdup(value);
		if (retval->value == NULL) {
			free(retval->token);
			free(retval->host);
			free(retval);
			return NULL;
		}
	}
	else retval->value = NULL;
	return retval;
}

void Free_ValueHttpData(struct value_http_data *delData) {
	if (delData != NULL) {
		if (delData->token != NULL) free(delData->token);
		if (delData->host != NULL) free(delData->host);
		if (delData->value != NULL) free(delData->value);
		free(delData);
	}
}

struct request_data *Store_HttpsData(char *url, char *parameters, char *token, int sesion) {
	struct request_data * retval = malloc(sizeof(struct request_data));
	if (retval == NULL) return NULL;
	if (token != NULL) {
		retval->token = _strdup(token);
		if (retval->token == NULL) {
			free(retval);
			return NULL;
		}
	}
	else retval->token = NULL;
	retval->url = _strdup(url);
	if (retval->url == NULL) {
		free(retval->token);
		free(retval);
		return NULL;
	}
	if (parameters != NULL) {
		retval->parameters = _strdup(parameters);
		if (retval->parameters == NULL) {
			free(retval->token);
			free(retval->url);
			free(retval);
			return NULL;
		}
	}
	else retval->parameters = NULL;
	retval->sesion = sesion;
	return retval;
}

void Free_HttpsData(struct request_data *delData) {
	// Can safely assume vector is NULL or fully built.
	if (delData != NULL) {
		if (delData->token != NULL) free(delData->token);
		if (delData->url != NULL) free(delData->url);
		if (delData->parameters != NULL) free(delData->parameters);
		free(delData);
	}
}

struct token_response *Store_AccesTokenResponse(const char *token_type, const char *resource, const char *access_token, unsigned long int expires_in, unsigned long int ext_expires_in, unsigned long int expires_on, unsigned long int not_before) {
	struct token_response * retval = malloc(sizeof(struct token_response));
	if (retval == NULL) return NULL;
	retval->token_type = _strdup(token_type);
	if (retval->token_type == NULL) {
		free(retval);
		return NULL;
	}
	retval->resource = _strdup(resource);
	if (retval->resource == NULL) {
		free(retval->token_type);
		free(retval);
		return NULL;
	}
	retval->access_token = _strdup(access_token);
	if (retval->access_token == NULL) {
		free(retval->token_type);
		free(retval->resource);
		free(retval);
		return NULL;
	}
	retval->expires_in = expires_in;
	retval->ext_expires_in = ext_expires_in;
	retval->expires_on = expires_on;
	retval->not_before = not_before;
	return retval;
}

void Free_AccesTokenResponse(struct token_response *delData) {
	// Can safely assume vector is NULL or fully built.
	if (delData != NULL) {
		free(delData->token_type);
		free(delData->resource);
		free(delData->access_token);
		free(delData);
	}
}

struct client_data *Store_ClientData(char *password, char *authUrl, char *resource, char *clientId, char *tenantId) {
	struct client_data * retval = malloc(sizeof(struct client_data));
	if (retval == NULL) return NULL;
	retval->password = _strdup(password);
	if (retval->password == NULL) {
		free(retval);
		return NULL;
	}
	retval->AUTH_URL = _strdup(authUrl);
	if (retval->AUTH_URL == NULL) {
		free(retval->password);
		free(retval);
		return NULL;
	}
	retval->RESOURCE = _strdup(resource);
	if (retval->RESOURCE == NULL) {
		free(retval->password);
		free(retval->AUTH_URL);
		free(retval);
		return NULL;
	}
	retval->CLIENTID = _strdup(clientId);
	if (retval->RESOURCE == NULL) {
		free(retval->password);
		free(retval->AUTH_URL);
		free(retval->RESOURCE);
		free(retval);
		return NULL;
	}
	retval->TENANTID = _strdup(tenantId);
	if (retval->RESOURCE == NULL) {
		free(retval->password);
		free(retval->AUTH_URL);
		free(retval->RESOURCE);
		free(retval->CLIENTID);
		free(retval);
		return NULL;
	}
	return retval;
}

void Free_ClientData(struct client_data *delData) {
	// Can safely assume vector is NULL or fully built.
	if (delData != NULL) {
		free(delData->password);
		free(delData->AUTH_URL);
		free(delData->RESOURCE);
		free(delData->CLIENTID);
		free(delData->TENANTID);
		free(delData);
	}
}

struct basic_http_data *Store_BasicHttpData(char *token, char *url) {
	struct basic_http_data * retval = malloc(sizeof(struct basic_http_data));
	if (retval == NULL) return NULL;
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval);
		return NULL;
	}
	retval->url = _strdup(url);
	if (retval->url == NULL) {
		free(retval->token);
		free(retval);
		return NULL;
	}
	return retval;
}

void Free_BasicHttpData(struct basic_http_data *delData) {
	// Can safely assume vector is NULL or fully built.
	if (delData != NULL) {
		free(delData->token);
		free(delData->url);
		free(delData);
	}
}

struct key_attributes *Store_KeyAttributes(BOOL enabled, unsigned long int nbf, unsigned long int exp, unsigned long int created, unsigned long int updated) {
	struct key_attributes * retval = malloc(sizeof(struct key_attributes));
	if (retval == NULL) return NULL;
	retval->enabled = enabled;
	retval->nbf = nbf;
	retval->exp = exp;
	retval->created = created;
	retval->updated = updated;
	return retval;
}

void Free_KeyAttributes(struct key_attributes *delData) {
	if (delData != NULL) {
		free(delData);
	}
}

struct key_data *Store_KeyData(char *host, char *id, char *keytype, char *keysize, char *key_ops[], const char *token, struct key_attributes *attributes, char *tags, char *crv) {
	struct key_data * retval = malloc(sizeof(struct key_data));
	if (retval == NULL) return NULL;
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval);
		return NULL;
	}
	retval->id = _strdup(id);
	if (retval->id == NULL) {
		free(retval->host);
		free(retval);
		return NULL;
	}
	retval->keytype = _strdup(keytype);
	if (retval->keytype == NULL) {
		free(retval->host);
		free(retval->id);
		free(retval);
		return NULL;
	}
	if (keysize != NULL) {
		retval->keysize = _strdup(keysize);
		if (retval->keysize == NULL) {
			free(retval->host);
			free(retval->id);
			free(retval->keytype);
			free(retval);
			return NULL;
		}
	}
	else retval->keysize = NULL;
	if (tags != NULL) {
		retval->tags = _strdup(tags);
		if (retval->tags == NULL) {
			free(retval->host);
			free(retval->id);
			free(retval->keytype);
			free(retval->keysize);
			free(retval);
			return NULL;
		}
	}
	else retval->tags = NULL;
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval->host);
		free(retval->id);
		free(retval->keytype);
		free(retval->keysize);
		if (tags != NULL) free(retval->tags);
		free(retval);
		return NULL;
	}
	if (crv != NULL) {
		retval->crv = _strdup(crv);
		if (retval->crv == NULL) {
			free(retval->host);
			free(retval->id);
			free(retval->keytype);
			free(retval->keysize);
			if (tags != NULL) free(retval->tags);
			free(retval->token);
			free(retval);
		}
	}
	else retval->crv = NULL;
	if (key_ops != NULL) {
		for (int i = 0; i < MAX_OPS; i++) {
			if (key_ops[i] != NULL) {
				retval->key_ops[i] = _strdup(key_ops[i]);
				if (retval->key_ops[i] == NULL) {
					for (int j = 0; j < i; j++) {
						if (retval->key_ops[i] != NULL) free(retval->key_ops[j]);
					}
					free(retval->host);
					free(retval->id);
					free(retval->keytype);
					free(retval->keysize);
					free(retval->token);
					if (tags != NULL) free(retval->tags);
					if (retval->crv != NULL) free(retval->crv);
					free(retval);
					return NULL;
				}
			}
			else retval->key_ops[i] = NULL;
		}
	}
	//else {
	//	for (int i = 0; i < MAX_OPS; i++) {
	//		retval->key_ops[i] = NULL;
	//	}
	//}
	retval->attributes = attributes;
	return retval;
}

void Free_KeyData(struct key_data *delData) {
	// Can safely assume vector is NULL or fully built.
	if (delData != NULL) {
		if (delData->host != NULL) free(delData->host);
		if (delData->id != NULL) free(delData->id);
		if (delData->keytype != NULL) free(delData->keytype);
		if (delData->keysize != NULL) free(delData->keysize);
		if (delData->key_ops != NULL) {
			for (int i = 0; i < MAX_OPS; i++) {
				if (delData->key_ops[i] != NULL) free(delData->key_ops[i]);
			}
		}
		if (delData->token != NULL) free(delData->token);
		if (delData->tags != NULL) free(delData->tags);
		if (delData->attributes != NULL) Free_KeyAttributes(delData->attributes);
		if (delData->crv != NULL) free(delData->crv);
		free(delData);
	}
}

struct update_key * Store_UpdateKeyData(char * host, char * key_id, char * token, char * key_ops[], struct key_attributes * attributes)
{
	struct update_key * retval = malloc(sizeof(struct update_key));
	if (retval == NULL) return NULL;
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval);
		return NULL;
	}
	retval->key_id = _strdup(key_id);
	if (retval->key_id == NULL) {
		free(retval->host);
		free(retval);
		return NULL;
	}
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval->host);
		free(retval->key_id);
		free(retval);
		return NULL;
	}
	for (int i = 0; i < MAX_OPS; i++) {
		retval->key_ops[i] = NULL;
	}
	if (key_ops != NULL) {
		for (int i = 0; i < MAX_OPS; i++) {
			if (key_ops[i] != NULL) {
				retval->key_ops[i] = _strdup(key_ops[i]);
				if (retval->key_ops[i] == NULL) {
					for (int j = 0; j < i; j++) {
						if (retval->key_ops[i] != NULL) free(retval->key_ops[j]);
					}
					free(retval->host);
					free(retval->key_id);
					free(retval->token);
					free(retval);
					return NULL;
				}
			}
			else retval->key_ops[i] = NULL;
		}
	}
	retval->attributes = attributes;
	return retval;
}

void Free_UpdateKeyData(struct update_key * delData)
{
	if (delData != NULL) {
		if (delData->host != NULL) free(delData->host);
		if (delData->key_id != NULL) free(delData->key_id);
		if (delData->key_ops != NULL) {
			for (int i = 0; i < MAX_OPS; i++) {
				if (delData->key_ops[i] != NULL) free(delData->key_ops[i]);
			}
		}
		if (delData->token != NULL) free(delData->token);
		if (delData->attributes != NULL) Free_KeyAttributes(delData->attributes);
		free(delData);
	}
}

struct delete_key *Store_DeleteKey(char *host, char *id, const char *token) {
	struct delete_key * retval = malloc(sizeof(struct delete_key));
	if (retval == NULL) return NULL;
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval);
		return NULL;
	}
	retval->id = _strdup(id);
	if (retval->id == NULL) {
		free(retval->host);
		free(retval);
		return NULL;
	}
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval->host);
		free(retval->id);
		free(retval);
		return NULL;
	}
	return retval;
}

void Free_DeleteKey(struct delete_key *delData) {
	// Can safely assume vector is NULL or fully built.
	if (delData != NULL) {
		if (delData->host != NULL) free(delData->host);
		if (delData->id != NULL) free(delData->id);
		if (delData->token != NULL) free(delData->token);
		free(delData);
	}
}

struct list_key *Store_ListKey(char * id, struct key_attributes *attributes, char *tags, BOOL managed) {
	if (attributes == NULL) return NULL;
	struct list_key * retval = (struct list_key*) malloc(sizeof(struct list_key));
	if (retval == NULL) return NULL;
	retval->keyHandler = 0;
	strncpy(retval->id, id, MAX_ID_SIZE);
	if (tags != NULL) {
		retval->tags = _strdup(tags);
		if (retval->tags == NULL) {
			free(retval);
			return NULL;
		}
	}
	else retval->tags = NULL;
	retval->attributes = attributes;
	retval->managed = managed;
	retval->next = NULL;
	return retval;
}

void Free_ListKey(struct list_key *delData) {
	// Can safely assume vector is NULL or fully built.
	struct list_key *aux;
	if (delData != NULL) {
		while (delData != NULL) {
			aux = delData;
			delData = delData->next;
			if (aux->tags != NULL) free(aux->tags);
			Free_KeyAttributes(aux->attributes);
			free(aux);
		}
	}
}

struct verify_data *Store_VerifyData(char *id, char *token, char *host, char *signtype, char *hash, char *value) {
	struct verify_data * retval = malloc(sizeof(struct verify_data));
	if (retval == NULL) return NULL;
	retval->id = _strdup(id);
	if (retval->id == NULL) {
		free(retval);
		return NULL;
	}
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval->id);
		free(retval);
		return NULL;
	}
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval->id);
		free(retval->token);
		free(retval);
		return NULL;
	}
	retval->signtype = _strdup(signtype);
	if (retval->signtype == NULL) {
		free(retval->id);
		free(retval->token);
		free(retval->host);
		free(retval);
		return NULL;
	}
	retval->hash = _strdup(hash);
	if (retval->hash == NULL) {
		free(retval->id);
		free(retval->token);
		free(retval->host);
		free(retval->signtype);
		free(retval);
		return NULL;
	}
	if (value != NULL) {
		retval->value = _strdup(value);
		if (retval->value == NULL) {
			free(retval->id);
			free(retval->token);
			free(retval->host);
			free(retval->signtype);
			free(retval->hash);
			free(retval);
			return NULL;
		}
	}
	else retval->value = NULL;
	return retval;
}

void Free_VerifyData(struct verify_data *delData) {
	if (delData != NULL) {
		if (delData->id != NULL) free(delData->id);
		if (delData->token != NULL) free(delData->token);
		if (delData->host != NULL) free(delData->host);
		if (delData->signtype != NULL) free(delData->signtype);
		if (delData->hash != NULL) free(delData->hash);
		if (delData->value != NULL) free(delData->value);
		free(delData);
	}
}

struct operation_response *Store_OperationResponse(char *keyid, char *value) {
	struct operation_response * retval = malloc(sizeof(struct operation_response));
	if (retval == NULL) return NULL;
	retval->keyid = _strdup(keyid);
	if (retval->keyid == NULL) {
		free(retval);
		return NULL;
	}
	retval->value = _strdup(value);
	if (retval->value == NULL) {
		free(retval->keyid);
		free(retval);
		return NULL;
	}
	return retval;
}

void Free_OperationResponse(struct operation_response *delData) {
	// Can safely assume vector is NULL or fully built.
	if (delData != NULL) {
		if (delData->keyid != NULL) free(delData->keyid);
		if (delData->value != NULL) free(delData->value);
		free(delData);
	}
}

struct simple_operation_response *Store_SimpleOperationResponse(char *value) {
	struct simple_operation_response * retval = malloc(sizeof(struct simple_operation_response));
	if (retval == NULL) return NULL;
	retval->value = _strdup(value);
	if (retval->value == NULL) {
		free(retval);
		return NULL;
	}
	return retval;
}

void Free_SimpleOperationResponse(struct simple_operation_response *delData) {
	// Can safely assume vector is NULL or fully built.
	if (delData != NULL) {
		if (delData->value != NULL) free(delData->value);
		free(delData);
	}
}

struct key_data_response *Store_KeyDataResponse(char *id, char *keytype, char *key_ops[], char *n, char *e, char *d, char *dp, char *dq, char *qi, char *p, char *q, char *k, char *key_hsm, struct key_attributes *attributes, char *tags, BOOL managed, char *crv, char *x, char *y) {
	struct key_data_response * retval = malloc(sizeof(struct key_data_response));
	if (retval == NULL) return NULL;
	if (attributes == NULL) return NULL;
	strncpy(retval->id, id, MAX_ID_SIZE);
	retval->keytype = _strdup(keytype);
	if (retval->keytype == NULL) {
		free(retval);
		return NULL;
	}
	for (int i = 0; i < MAX_OPS; i++) {
		if (key_ops[i] != NULL) {
			retval->key_ops[i] = _strdup(key_ops[i]);
			if (retval->key_ops[i] == NULL) goto cleanup;
		}
		else retval->key_ops[i] = NULL;
	}
	if (n != NULL) {
		retval->n = _strdup(n);
		if (retval->n == NULL) goto cleanup;
	}
	else retval->n = NULL;
	if (e != NULL) {
		retval->e = _strdup(e);
		if (retval->e == NULL) goto cleanup;
	}
	else retval->e = NULL;
	if (d != NULL) {
		retval->d = _strdup(d);
		if (retval->d == NULL) goto cleanup;
	}
	else retval->d = NULL;
	if (dp != NULL) {
		retval->dp = _strdup(dp);
		if (retval->dp == NULL) goto cleanup;
	}
	else retval->dp = NULL;
	if (dq != NULL) {
		retval->dq = _strdup(dq);
		if (retval->dq == NULL) goto cleanup;
	}
	else retval->dq = NULL;
	if (qi != NULL) {
		retval->qi = _strdup(qi);
		if (retval->qi == NULL) goto cleanup;
	}
	else retval->qi = NULL;
	if (p != NULL) {
		retval->p = _strdup(p);
		if (retval->p == NULL) goto cleanup;
	}
	else retval->p = NULL;
	if (q != NULL) {
		retval->q = _strdup(q);
		if (retval->q == NULL) goto cleanup;
	}
	else retval->q = NULL;
	if (k != NULL) {
		retval->k = _strdup(k);
		if (retval->k == NULL) goto cleanup;
	}
	else retval->k = NULL;
	if (key_hsm != NULL) {
		retval->key_hsm = _strdup(key_hsm);
		if (retval->key_hsm == NULL) goto cleanup;
	}
	else retval->key_hsm = NULL;
	if (tags != NULL) {
		retval->tags = _strdup(tags);
		if (retval->tags == NULL) goto cleanup;
	}
	else retval->tags = NULL;
	retval->managed = managed;
	retval->attributes = attributes;
    if (crv != NULL) {
        retval->crv = _strdup(crv);
        if (retval->crv == NULL) goto cleanup;
    }
    if (x != NULL) {
        retval->x = _strdup(x);
        if (retval->x == NULL) goto cleanup;
    }
    if (y != NULL) {
        retval->y = _strdup(y);
        if (retval->y == NULL) goto cleanup;
    }
	return retval;
cleanup:
	for (int i = 0; i < MAX_OPS; i++) {
		if (retval->key_ops[i] != NULL) free(retval->key_ops[i]);
	}
	if (retval->keytype != NULL) free(retval->keytype);
	if (retval->n != NULL) free(retval->n);
	if (retval->e != NULL) free(retval->e);
	if (retval->d != NULL) free(retval->d);
	if (retval->dp != NULL) free(retval->dp);
	if (retval->dq != NULL) free(retval->dq);
	if (retval->qi != NULL) free(retval->qi);
	if (retval->p != NULL) free(retval->p);
	if (retval->q != NULL) free(retval->q);
	if (retval->k != NULL) free(retval->k);
	if (retval->key_hsm != NULL) free(retval->key_hsm);
	if (retval->tags != NULL) free(retval->tags);
    if (retval->crv != NULL) free(retval->crv);
    if (retval->x != NULL) free(retval->x);
    if (retval->y != NULL) free(retval->y);
	free(retval);
	return NULL;
}

void Free_KeyCreationResponse(struct key_data_response *delData) {
	if (delData != NULL) {
		for (int i = 0; i < MAX_OPS; i++) {
			if (delData->key_ops[i] != NULL) free(delData->key_ops[i]);
		}
		if (delData->keytype != NULL) free(delData->keytype);
		if (delData->n != NULL) free(delData->n);
		if (delData->e != NULL) free(delData->e);
		if (delData->d != NULL) free(delData->d);
		if (delData->dp != NULL) free(delData->dp);
		if (delData->dq != NULL) free(delData->dq);
		if (delData->qi != NULL) free(delData->qi);
		if (delData->p != NULL) free(delData->p);
		if (delData->q != NULL) free(delData->q);
		if (delData->k != NULL) free(delData->k);
		if (delData->key_hsm != NULL) free(delData->key_hsm);
		if (delData->tags != NULL) free(delData->tags);
		if (delData->attributes != NULL) Free_KeyAttributes(delData->attributes);
		free(delData);
	}
}

struct cert_attributes * Store_CertAttributes(char * recoveryLevel, BOOL enabled, unsigned long int nbf, unsigned long int exp, unsigned long int created, unsigned long int updated)
{
	struct cert_attributes * retval = malloc(sizeof(struct cert_attributes));
	if (retval == NULL) return NULL;
	if (recoveryLevel != NULL) {
		retval->recoveryLevel = _strdup(recoveryLevel);
		if (retval->recoveryLevel == NULL) {
			free(retval);
			return NULL;
		}
	}
	else retval->recoveryLevel = NULL;
	retval->enabled = enabled;
	retval->nbf = nbf;
	retval->exp = exp;
	retval->created = created;
	retval->updated = updated;
	return retval;
}

void Free_CertAttributes(struct cert_attributes *delData)
{
	if (delData != NULL) {
		if (delData->recoveryLevel != NULL) free(delData->recoveryLevel);
		/*for (int i = 0; i < MAX_RECOVERYLEVEL; i++) {
		if (delData->recoveryLevel[i] != NULL) free(delData->recoveryLevel[i]);
		}*/
		free(delData);
	}
}

struct import_cert_data * Store_ImportCertData(char * token, char *host, char *name, char * base64Value, char * pwd, struct cert_policy * certPolicy, struct cert_attributes * cerAttributes, char * tags)
{
	struct import_cert_data * retval = malloc(sizeof(struct import_cert_data));
	if (retval == NULL) return NULL;
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval);
		return NULL;
	}
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval->token);
		free(retval);
		return NULL;
	}
	retval->name = _strdup(name);
	if (retval->name == NULL) {
		free(retval->token);
		free(retval->host);
		free(retval);
		return NULL;
	}
	retval->base64Value = _strdup(base64Value);
	if (retval->base64Value == NULL) {
		free(retval->token);
		free(retval->host);
		free(retval->name);
		free(retval);
		return NULL;
	}
	retval->pwd = _strdup(pwd);
	if (retval->pwd == NULL) {
		free(retval->token);
		free(retval->host);
		free(retval->name);
		free(retval->base64Value);
		free(retval);
		return NULL;
	}
	if (retval->certPolicy != NULL) retval->certPolicy = certPolicy;
	if (retval->cerAttributes != NULL) retval->cerAttributes = cerAttributes;
	if (tags != NULL) {
		retval->tags = _strdup(tags);
		if (retval->tags == NULL) {
			free(retval->token);
			free(retval->host);
			free(retval->name);
			free(retval->base64Value);
			free(retval->pwd);
			free(retval);
			return NULL;
		}
	}
	else retval->tags = NULL;
	return retval;
}

void Free_ImportCertData(struct import_cert_data * delData)
{
	if (delData != NULL) {
		if (delData->token != NULL) free(delData->token);
		if (delData->host != NULL) free(delData->host);
		if (delData->name != NULL) free(delData->name);
		if (delData->base64Value != NULL) free(delData->base64Value);
		if (delData->pwd != NULL) free(delData->pwd);
		if (delData->tags != NULL) free(delData->tags);
		if (delData->cerAttributes != NULL) Free_CertAttributes(delData->cerAttributes);
		if (delData->certPolicy != NULL) Free_CertPolicy(delData->certPolicy);
		free(delData);
	}
}

struct cert_policy * Store_CertPolicy(char * id, struct cert_key_prop * keyProp, struct x509_props * x509Props, struct lifetime_actions * lifeTimeActions, struct cert_attributes * cerAttributes, struct issuer * issuer)
{
	struct cert_policy * retval = malloc(sizeof(struct cert_policy));
	if (retval == NULL) return NULL;
	if (id != NULL)
	{
		retval->id = _strdup(id);
		if (retval->id == NULL) {
			free(retval);
			return NULL;
		}
	}
	else retval->id = NULL;
	retval->keyProp = keyProp;
	retval->x509Props = x509Props;
	retval->lifeTimeActions = lifeTimeActions;
	retval->cerAttributes = cerAttributes;
	retval->issuer = issuer;
	return retval;
}

void Free_CertPolicy(struct cert_policy * delData)
{
	if (delData != NULL) {
		if (delData->id != NULL) free(delData->id);
		if (delData->x509Props != NULL) Free_X509Props(delData->x509Props);
		if (delData->issuer != NULL) Free_Issuer(delData->issuer);
		if (delData->cerAttributes != NULL) Free_CertAttributes(delData->cerAttributes);
		if (delData->keyProp != NULL) Free_CertKeyProp(delData->keyProp);
		if (delData->lifeTimeActions != NULL) Free_LifeTimeActions(delData->lifeTimeActions);
		free(delData);
	}
}

struct cert_key_prop * Store_CertKeyProp(BOOL exportable, char * kty, int key_size, BOOL reuse_key, char * contentType)
{
	struct cert_key_prop * retval = malloc(sizeof(struct cert_key_prop));
	if (retval == NULL) return NULL;
	retval->kty = _strdup(kty);
	if (retval->kty == NULL) {
		free(retval);
		return NULL;
	}
	retval->contentType = _strdup(contentType);
	if (retval->contentType == NULL) {
		free(retval->kty);
		free(retval);
		return NULL;
	}
	retval->exportable = exportable;
	retval->key_size = key_size;
	retval->reuse_key = reuse_key;
	return retval;
}

void Free_CertKeyProp(struct cert_key_prop * delData)
{
	if (delData != NULL) {
		if (delData->kty != NULL) free(delData->kty);
		if (delData->contentType != NULL) free(delData->contentType);
		free(delData);
	}
}

struct x509_props *Store_X509Props(char * subject, char *ekus[], char * emails[], char * dnsNames[], char * upns[], char * keyUsage[], int validityMonths)
{
	struct x509_props * retval = malloc(sizeof(struct x509_props));
	if (retval == NULL) return NULL;
	if (subject != NULL)
	{
		retval->subject = _strdup(subject);
		if (retval->subject == NULL) goto cleanup;
	}
	else retval->subject = NULL;
	if (ekus != NULL) {
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			if (ekus[i] != NULL) {
				retval->ekus[i] = _strdup(ekus[i]);
				if (retval->ekus[i] == NULL) goto cleanup;
			}
			else retval->ekus[i] = NULL;
		}
	}
	else {
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			retval->ekus[i] = NULL;
		}
	}
	if (emails != NULL)
	{
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			if (emails[i] != NULL) {
				retval->emails[i] = _strdup(emails[i]);
				if (retval->emails[i] == NULL) goto cleanup;
			}
			else retval->emails[i] = NULL;
		}
	}
	else {
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			retval->emails[i] = NULL;
		}
	}
	if (dnsNames != NULL)
	{
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			if (dnsNames[i] != NULL) {
				retval->dnsNames[i] = _strdup(dnsNames[i]);
				if (retval->dnsNames[i] == NULL) goto cleanup;
			}
			else retval->dnsNames[i] = NULL;
		}
	}
	else {
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			retval->dnsNames[i] = NULL;
		}
	}
	if (upns != NULL)
	{
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			if (upns[i] != NULL) {
				retval->upns[i] = _strdup(upns[i]);
				if (retval->upns[i] == NULL) goto cleanup;
			}
			else retval->upns[i] = NULL;
		}
	}
	else {
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			retval->upns[i] = NULL;
		}
	}

	if (keyUsage != NULL) {
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			if (keyUsage[i] != NULL) {
				retval->keyUsage[i] = _strdup(keyUsage[i]);
				if (retval->keyUsage[i] == NULL) goto cleanup;
			}
			else retval->keyUsage[i] = NULL;
		}
	}
	else {
		for (int i = 0; i < MAXIMUM_PERMITED_PARAMETERS; i++) {
			retval->keyUsage[i] = NULL;
		}
	}
	retval->validityMonths = validityMonths;
	return retval;

cleanup:
	if (retval->subject != NULL) free(retval->subject);
	if (retval->ekus != NULL) {
		for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
			if (retval->ekus[j] != NULL) free(retval->ekus[j]);
		}
	}
	if (retval->emails != NULL) {
		for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
			if (retval->emails[j] != NULL) free(retval->emails[j]);
		}
	}
	if (retval->dnsNames != NULL) {
		for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
			if (retval->dnsNames[j] != NULL) free(retval->dnsNames[j]);
		}
	}
	if (retval->keyUsage != NULL) {
		for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
			if (retval->keyUsage[j] != NULL) free(retval->keyUsage[j]);
		}
	}
	if (retval->upns != NULL) {
		for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
			if (retval->upns[j] != NULL) free(retval->upns[j]);
		}
	}
	free(retval);
	return NULL;

}

void Free_X509Props(struct x509_props * delData)
{
	if (delData != NULL) {
		if (delData->subject != NULL) free(delData->subject);
		if (delData->ekus != NULL) {
			for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
				if (delData->ekus[j] != NULL) free(delData->ekus[j]);
			}
		}
		if (delData->emails != NULL) {
			for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
				if (delData->emails[j] != NULL) free(delData->emails[j]);
			}
		}
		if (delData->dnsNames != NULL) {
			for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
				if (delData->dnsNames[j] != NULL) free(delData->dnsNames[j]);
			}
		}
		if (delData->keyUsage != NULL) {
			for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
				if (delData->keyUsage[j] != NULL) free(delData->keyUsage[j]);
			}
		}
		if (delData->upns != NULL) {
			for (int j = 0; j < MAXIMUM_PERMITED_PARAMETERS; j++) {
				if (delData->upns[j] != NULL) free(delData->upns[j]);
			}
		}
		free(delData);
	}
}

struct lifetime_actions *Store_LifeTimeActions(int lifetimePercentage, int daysBeforeExpiry, char * actionType)
{
	struct lifetime_actions * retval = malloc(sizeof(struct lifetime_actions));
	if (retval == NULL) return NULL;
	if (actionType != NULL)
	{
		retval->actionType = _strdup(actionType);
		if (retval->actionType == NULL) {
			free(retval);
			return NULL;
		}
	}
	else retval->actionType = NULL;
	retval->lifetimePercentage = lifetimePercentage;
	retval->daysBeforeExpiry = daysBeforeExpiry;
	return retval;
}

void Free_LifeTimeActions(struct lifetime_actions * delData)
{
	if (delData != NULL) {
		if (delData->actionType != NULL) free(delData->actionType);
		free(delData);
	}
}

struct issuer *Store_Issuer(char * name, char * cty)
{
	struct issuer * retval = malloc(sizeof(struct issuer));
	if (retval == NULL) return NULL;
	if (name != NULL)
	{
		retval->name = _strdup(name);
		if (retval->name == NULL) goto cleanup;
	}
	else retval->name = NULL;
	if (cty != NULL)
	{
		retval->cty = _strdup(cty);
		if (retval->cty == NULL) goto cleanup;
	}
	else retval->cty = NULL;
	return retval;
cleanup:
	if (retval->name != NULL) free(retval->name);
	if (retval->cty != NULL) free(retval->cty);
	free(retval);
	return NULL;
}

void Free_Issuer(struct issuer * delData)
{
	if (delData != NULL) {
		if (delData->name != NULL) free(delData->name);
		if (delData->cty != NULL) free(delData->cty);
		free(delData);
	}
}

struct cert_data *Store_CertData(struct cert_attributes *certAttributes, char *id, char *tags, char *x5t) {
	struct cert_data * retval = malloc(sizeof(struct cert_data));
	if (retval == NULL) return NULL;
	retval->id = _strdup(id);
	if (retval->id == NULL) {
		free(retval);
		return NULL;
	}
	retval->x5t = _strdup(x5t);
	if (retval->x5t == NULL) {
		free(retval->id);
		free(retval);
		return NULL;
	}
	if (tags != NULL) {
		retval->tags = _strdup(tags);
		if (retval->tags == NULL) {
			free(retval->id);
			free(retval->x5t);
			free(retval);
			return NULL;
		}
	}
	else retval->tags = NULL;
	retval->certAttributes = certAttributes;
	return retval;
}

void Free_CertData(struct cert_data * delData)
{
	if (delData != NULL) {
		if (delData->id != NULL) free(delData->id);
		if (delData->x5t != NULL) free(delData->x5t);
		if (delData->tags != NULL) free(delData->tags);
		if (delData->certAttributes != NULL) Free_CertAttributes(delData->certAttributes);
		free(delData);
	}
}

struct cert_list * Store_CertList(int handler, struct cert_data * certData, struct cert_list * next)
{
	struct cert_list * retval = malloc(sizeof(struct cert_list));
	if (retval == NULL) return NULL;
	retval->certData = certData;
	retval->handler = handler;
	retval->next = next;
	return retval;
}

void Free_CertList(struct cert_list * delData)
{
	if (delData != NULL) {
		if (delData->certData != NULL) Free_CertData(delData->certData);
		free(delData);
	}
}

struct cert_operation_response * Store_CertOperation(char *id, struct issuer *issuer, char *csr, BOOL cancellation_requested, char *status, char *target, char *request_id)
{
	struct cert_operation_response * retval = malloc(sizeof(struct cert_operation_response));
	if (retval == NULL) return NULL;
	retval->id = _strdup(id);
	if (retval->id == NULL) {
		free(retval);
		return NULL;
	}
	retval->csr = _strdup(csr);
	if (retval->csr == NULL) {
		free(retval->id);
		free(retval);
		return NULL;
	}
	retval->status = _strdup(status);
	if (retval->status == NULL) {
		free(retval->id);
		free(retval->csr);
		free(retval);
		return NULL;
	}
	retval->request_id = _strdup(request_id);
	if (retval->request_id == NULL) {
		free(retval->id);
		free(retval->csr);
		free(retval->status);
		free(retval);
		return NULL;
	}
	if (target != NULL) {
		retval->target = _strdup(target);
		if (retval->target == NULL) {
			free(retval->id);
			free(retval->csr);
			free(retval->status);
			free(retval->request_id);
			free(retval);
			return NULL;
		}
	}
	else retval->target = NULL;
	retval->issuer = issuer;
	retval->cancellation_requested = cancellation_requested;
	return retval;
}

void Free_CertOperation(struct cert_operation_response * delData)
{
	if (delData != NULL) {
		if (delData->id != NULL) free(delData->id);
		if (delData->csr != NULL) free(delData->csr);
		if (delData->status != NULL) free(delData->status);
		if (delData->target != NULL) free(delData->target);
		if (delData->request_id != NULL) free(delData->request_id);
		if (delData->issuer != NULL) Free_Issuer(delData->issuer);
		free(delData);
	}
}

struct create_cert * Store_CreateCertData(const char *token, char *host, struct cert_policy *certPolicy, struct cert_attributes *cerAttributes, char *tags, char *name) {
	struct create_cert * retval = malloc(sizeof(struct create_cert));
	if (retval == NULL) return NULL;
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval);
		return NULL;
	}
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval->token);
		free(retval);
		return NULL;
	}
	retval->name = _strdup(name);
	if (retval->name == NULL) {
		free(retval->token);
		free(retval->host);
		free(retval);
		return NULL;
	}
	if (tags != NULL) {
		retval->tags = _strdup(tags);
		if (retval->tags == NULL) {
			free(retval->token);
			free(retval->host);
			free(retval->name);
			free(retval);
			return NULL;
		}
	}

	else retval->tags = NULL;
	retval->certPolicy = certPolicy;
	retval->cerAttributes = cerAttributes;
	return retval;
}

void Free_CreateCertData(struct create_cert * delData)
{
	if (delData != NULL) {
		if (delData->token != NULL) free(delData->token);
		if (delData->host != NULL) free(delData->host);
		if (delData->tags != NULL) free(delData->tags);
		if (delData->name != NULL) free(delData->name);
		if (delData->cerAttributes != NULL) Free_CertAttributes(delData->cerAttributes);
		if (delData->certPolicy != NULL) Free_CertPolicy(delData->certPolicy);
		free(delData);
	}
}

struct delete_update_cert_response * Store_DeleteUpdateCertResponse(char * id, char * kid, char * sid, char * x5t, char * cer, struct cert_attributes * cerAttributes, struct cert_policy * cerPolicy, char * pendingId)
{
	struct delete_update_cert_response * retval = malloc(sizeof(struct delete_update_cert_response));
	if (retval == NULL) return NULL;
	if (id != NULL)
	{
		retval->id = _strdup(id);
		if (retval->id == NULL) goto cleanup;
	}
	else retval->id = NULL;
	if (kid != NULL)
	{
		retval->kid = _strdup(kid);
		if (retval->kid == NULL) goto cleanup;
	}
	else retval->kid = NULL;
	if (sid != NULL)
	{
		retval->sid = _strdup(sid);
		if (retval->sid == NULL) goto cleanup;
	}
	else retval->sid = NULL;
	if (x5t != NULL)
	{
		retval->x5t = _strdup(x5t);
		if (retval->x5t == NULL) goto cleanup;
	}
	else retval->x5t = NULL;
	if (cer != NULL)
	{
		retval->cer = _strdup(cer);
		if (retval->cer == NULL) goto cleanup;
	}
	else retval->cer = NULL;
	if (pendingId != NULL)
	{
		retval->pendingId = _strdup(pendingId);
		if (retval->pendingId == NULL) goto cleanup;
	}
	else retval->pendingId = NULL;
	retval->cerAttributes = cerAttributes;
	retval->cerPolicy = cerPolicy;
	return retval;

cleanup:
	if (retval->id != NULL) free(retval->id);
	if (retval->kid != NULL) free(retval->kid);
	if (retval->sid != NULL) free(retval->sid);
	if (retval->x5t != NULL) free(retval->x5t);
	if (retval->cer != NULL) free(retval->cer);
	if (retval->pendingId == NULL) free(retval->pendingId);
	free(retval);
	return NULL;
}

void Free_DeleteUpdateCertResponse(struct delete_update_cert_response * delData)
{
	if (delData != NULL) {
		if (delData->id != NULL) free(delData->id);
		if (delData->kid != NULL) free(delData->kid);
		if (delData->sid != NULL) free(delData->sid);
		if (delData->x5t != NULL) free(delData->x5t);
		if (delData->cer != NULL) free(delData->cer);
		if (delData->pendingId == NULL) free(delData->pendingId);
		if (delData->cerAttributes != NULL) Free_CertAttributes(delData->cerAttributes);
		if (delData->cerPolicy != NULL) Free_CertPolicy(delData->cerPolicy);
		free(delData);
	}
}

struct error * Store_Error(char * code, char * message, char * innererror)
{
	struct error * retval = malloc(sizeof(struct error));
	if (retval == NULL) return NULL;
	if (code != NULL)
	{
		retval->code = _strdup(code);
		if (retval->code == NULL) goto cleanup;
	}
	else retval->code = NULL;
	if (message != NULL)
	{
		retval->message = _strdup(message);
		if (retval->message == NULL) goto cleanup;
	}
	else retval->message = NULL;
	if (innererror != NULL)
	{
		retval->innererror = _strdup(innererror);
		if (retval->innererror == NULL) goto cleanup;
	}
	else retval->innererror = NULL;
	return retval;

cleanup:
	if (retval->code != NULL) free(retval->code);
	if (retval->message != NULL) free(retval->message);
	if (retval->innererror != NULL) free(retval->innererror);
	free(retval);
	return NULL;
}

void Free_Error(struct error * delData)
{
	if (delData != NULL) {
		if (delData->code != NULL) free(delData->code);
		if (delData->message != NULL) free(delData->message);
		if (delData->innererror != NULL) free(delData->innererror);
		free(delData);
	}
}

struct cert_operation_delete * Store_CertOperationDelete(struct cert_operation_response * certOperationResponse, char * status_details, struct error * error)
{
	struct cert_operation_delete * retval = malloc(sizeof(struct cert_operation_delete));
	if (retval == NULL) return NULL;
	if (status_details != NULL)
	{
		retval->status_details = _strdup(status_details);
		if (retval->status_details == NULL) {
			free(retval);
			return NULL;
		}
	}
	else retval->status_details = NULL;
	retval->certOperationResponse = certOperationResponse;
	retval->error = error;
	return retval;
}

void Free_CertOperationDelete(struct cert_operation_delete * delData)
{
	if (delData != NULL) {
		if (delData->status_details != NULL) free(delData->status_details);
		if (delData->certOperationResponse != NULL) Free_CertOperation(delData->certOperationResponse);
		if (delData->error != NULL) Free_Error(delData->error);
	}
}

struct operation_data * Store_OperationData(const char * token, char * keyid, char * host, char *algorithm, char * value)
{
	if (algorithm == NULL) return NULL;
	struct operation_data * retval = malloc(sizeof(struct operation_data));
	if (retval == NULL) return NULL;
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval);
		return NULL;
	}
	retval->keyid = _strdup(keyid);
	if (retval->keyid == NULL) {
		free(retval->token);
		free(retval);
		return NULL;
	}
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval->token);
		free(retval->keyid);
		free(retval);
		return NULL;
	}
	retval->value = _strdup(value);
	if (retval->value == NULL) {
		free(retval->token);
		free(retval->keyid);
		free(retval->host);
		free(retval);
		return NULL;
	}
	strncpy(retval->algorithm, algorithm, MAX_ALGORITHM_TYPE_LENGHT);
	return retval;
}

void Free_OperationData(struct operation_data * delData)
{
	if (delData != NULL) {
		free(delData->token);
		free(delData->host);
		free(delData->keyid);
		free(delData->value);
		free(delData);
	}

}

struct merge_data * Store_MergeData(char *token, char *host, char *certName, struct cert_attributes *cerAttributes, char *tags, char *x5c[])
{
	struct merge_data * retval = malloc(sizeof(struct merge_data));
	if (retval == NULL) return NULL;
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval);
		return NULL;
	}
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval->token);
		free(retval);
		return NULL;
	}
	retval->certName = _strdup(certName);
	if (retval->certName == NULL) {
		free(retval->token);
		free(retval->host);
		free(retval);
		return NULL;
	}
	if (x5c != NULL) {
		for (int i = 0; i < MAX_X5C_PARAMETERS; i++) {
			if (x5c[i] != NULL) {
				retval->x5c[i] = _strdup(x5c[i]);
				if (retval->x5c[i] == NULL) {
					for (int i = 0; i < MAX_X5C_PARAMETERS; i++) {
						if (retval->x5c[i] != NULL)	free(retval->x5c[i]);
					}
					free(retval->token);
					free(retval->host);
					free(retval->certName);
					free(retval);
					return NULL;
				}
			}
			else retval->x5c[i] = NULL;
		}
	}
	else {
		free(retval->token);
		free(retval->host);
		free(retval);
		return NULL;
	}
	if (tags != NULL) {
		retval->tags = _strdup(tags);
		if (retval->tags == NULL) {
			free(retval->token);
			free(retval->host);
			free(retval->certName);
			free(retval->x5c);
			free(retval);
			return NULL;
		}
	}
	else retval->tags = NULL;
	retval->cerAttributes = cerAttributes;
	return retval;
}

void Free_MergeData(struct merge_data * delData)
{
	if (delData != NULL) {
		if (delData->token != NULL) free(delData->token);
		if (delData->host != NULL) free(delData->host);
		if (delData->tags != NULL) free(delData->tags);
		if (delData->x5c != NULL) free(delData->x5c);
		if (delData->certName != NULL) free(delData->certName);
		if (delData->cerAttributes != NULL) Free_CertAttributes(delData->cerAttributes);
		free(delData);
	}
}

struct secret_items *Store_SecretItems(char * id, char* contentType, struct cert_attributes *attributes, char *tags, BOOL managed, int deletedDate, char *recoveryId, int scheduledPurgeDate) {
	struct secret_items * retval = malloc(sizeof(struct secret_items));
	if (retval == NULL) return NULL;
	if (recoveryId != NULL) {
		retval->secretCommonItem.recoveryId = _strdup(recoveryId);
		if (retval->secretCommonItem.recoveryId == NULL) {
			free(retval);
			return NULL;
		}
	}
	else retval->secretCommonItem.recoveryId = NULL;
	if (tags != NULL) {
		retval->secretCommonItem.tags = _strdup(tags);
		if (retval->secretCommonItem.tags == NULL) {
			if (retval->secretCommonItem.recoveryId != NULL) free(retval->secretCommonItem.recoveryId);
			free(retval);
			return NULL;
		}
	}
	else retval->secretCommonItem.tags = NULL;
	strncpy(retval->secretCommonItem.contentType, contentType, MAX_CONTENT_TYPE);
	strncpy(retval->secretCommonItem.id, id, MAX_ID_SIZE);
	retval->secretCommonItem.scheduledPurgeDate = scheduledPurgeDate;
	retval->secretCommonItem.deletedDate = deletedDate;
	retval->secretCommonItem.attributes = attributes;
	retval->secretCommonItem.managed = managed;
	retval->next = NULL;
	return retval;
}

void Free_SecretItems(struct secret_items *delData) {
	// Can safely assume vector is NULL or fully built.
	struct secret_items *aux;
	if (delData != NULL) {
		while (delData != NULL) {
			aux = delData;
			delData = delData->next;
			if (aux->secretCommonItem.tags != NULL) free(aux->secretCommonItem.tags);
			if (aux->secretCommonItem.recoveryId != NULL) free(aux->secretCommonItem.recoveryId);
			Free_CertAttributes(aux->secretCommonItem.attributes);
			free(aux);
		}
	}
}

struct secret_item_data *Store_SecretItemsData(char *id, char *kid, char *value, char *contentType, struct cert_attributes *attributes, char *tags, BOOL managed, int deletedDate, char *recoveryId, int scheduledPurgeDate) {
	struct secret_item_data * retval = malloc(sizeof(struct secret_item_data));
	if (retval == NULL) return NULL;
	retval->value = _strdup(value);
	if (retval->value == NULL) {
		free(retval);
		return NULL;
	}
	if (recoveryId != NULL) {
		retval->secretCommonItem.recoveryId = _strdup(recoveryId);
		if (retval->secretCommonItem.recoveryId == NULL) {
			free(retval->value);
			free(retval);
			return NULL;
		}
	}
	else retval->secretCommonItem.recoveryId = NULL;
	if (tags != NULL) {
		retval->secretCommonItem.tags = _strdup(tags);
		if (retval->secretCommonItem.tags == NULL) {
			free(retval->value);
			if (retval->secretCommonItem.recoveryId != NULL) free(retval->secretCommonItem.recoveryId);
			free(retval);
			return NULL;
		}
	}
	else retval->secretCommonItem.tags = NULL;
	if (kid != NULL) strncpy(retval->kid, kid, MAX_ID_SIZE);
	strncpy(retval->secretCommonItem.contentType, contentType, MAX_CONTENT_TYPE);
	strncpy(retval->secretCommonItem.id, id, MAX_ID_SIZE);
	retval->secretCommonItem.scheduledPurgeDate = scheduledPurgeDate;
	retval->secretCommonItem.deletedDate = deletedDate;
	retval->secretCommonItem.attributes = attributes;
	retval->secretCommonItem.managed = managed;
	return retval;
}

void Free_SecretItemsData(struct secret_item_data *delData) {
	if (delData != NULL) {
		if (delData->value != NULL) free(delData->value);
		if (delData->secretCommonItem.tags != NULL) free(delData->secretCommonItem.tags);
		if (delData->secretCommonItem.recoveryId != NULL) free(delData->secretCommonItem.recoveryId);
		Free_CertAttributes(delData->secretCommonItem.attributes);
		free(delData);
	}
}

struct secret_update_response *Store_SecretUpdateResponse(char *id, struct cert_attributes *attributes, char *contentType, char* tags) {
	struct secret_update_response * retval = malloc(sizeof(struct secret_update_response));
	if (retval == NULL) return NULL;
	if (tags != NULL) {
		retval->tags = _strdup(tags);
		if (retval->tags == NULL) {
			free(retval);
			return NULL;
		}
	}
	else retval->tags = NULL;
	strncpy(retval->contentType, contentType, MAX_CONTENT_TYPE);
	strncpy(retval->id, id, MAX_ID_SIZE);
	retval->attributes = attributes;
	return retval;
}

void Free_SecretUpdateResponse(struct secret_update_response *delData) {
	if (delData != NULL) {
		if (delData->tags != NULL) free(delData->tags);
		Free_CertAttributes(delData->attributes);
		free(delData);
	}
}

struct secret_creation_data *Store_SecretCreationData(char *token, char *host, char *id, struct cert_attributes *attributes, char *contentType, char* tags, char *value) {
	struct secret_creation_data * retval = malloc(sizeof(struct secret_creation_data));
	if (retval == NULL) return NULL;
	if (token == NULL) return NULL;
	retval->token = _strdup(token);
	if (retval->token == NULL) {
		free(retval);
		return NULL;
	}
	retval->host = _strdup(host);
	if (retval->host == NULL) {
		free(retval->token);
		free(retval);
		return NULL;
	}
	if (value != NULL) {
		retval->value = _strdup(value);
		if (retval->value == NULL) {
			free(retval->token);
			free(retval->host);
			free(retval);
			return NULL;
		}
	}
	else retval->value = NULL;
	if (tags != NULL) {
		retval->tags = _strdup(tags);
		if (retval->tags == NULL) {
			if (retval->value != NULL) free(retval->value);
			free(retval->token);
			free(retval->host);
			free(retval);
			return NULL;
		}
	}
	else retval->tags = NULL;
	strncpy(retval->contentType, contentType, MAX_CONTENT_TYPE);
	strncpy(retval->id, id, MAX_ID_SIZE);
	retval->attributes = attributes;
	return retval;
}

void Free_SecretCreationData(struct secret_creation_data *delData) {
	if (delData != NULL) {
		if (delData->token != NULL) free(delData->token);
		if (delData->host != NULL) free(delData->host);
		if (delData->value != NULL) free(delData->value);
		if (delData->tags != NULL) free(delData->tags);
		if (delData->attributes != NULL) Free_CertAttributes(delData->attributes);
		free(delData);
	}
}

void Free_SecretData() {
	if (TENANTID != NULL) free(TENANTID);
	if (HOST != NULL) free(HOST);
	if (PASSWORD != NULL) free(PASSWORD);
}
