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

#include <cryptoki.h>
#include <src/clientRest.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <time.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include <cryptokiTypes.h>
#include <Helpers/common.h>
#include <src/interface.h>


//********************************^********************************************//
//*                            Session Helper                                 *//
//*****************************************************************************//

CK_ULONG New_Session(CK_SESSION_HANDLE_PTR phSession, CK_FLAGS flags, struct sessions ** session) {
	struct sessions *newSession, *aux;
	newSession = malloc(sizeof(struct sessions));
	if (newSession == NULL) return CKR_HOST_MEMORY;
	else {
		newSession->findObjects.currentObjectHandler = 0;
		newSession->findObjects.sessionObjects = NULL_PTR;
		newSession->findObjects.numFound = 0;
		newSession->findObjects.numLeft = 0;
		newSession->findObjects.foundObjects = NULL_PTR;
		newSession->next = NULL_PTR;
		newSession->operationState = OPERATION_FREE;
		newSession->sessionState = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
		newSession->openTime = time(NULL);
		if (Is_User_Logged(*session)) {
			if (newSession->sessionState == CKS_RW_PUBLIC_SESSION) newSession->sessionState = CKS_RW_USER_FUNCTIONS;
			else if (newSession->sessionState == CKS_RO_PUBLIC_SESSION) newSession->sessionState = CKS_RO_USER_FUNCTIONS;
		}
		newSession->sessionHandler = 0;
		newSession->operationAlgorithm[0] = '\0';
	}
	if (*session == NULL_PTR) {
		newSession->sessionHandler = 1;
		*session = newSession;
		*phSession = 1;
	}
	else {
		aux = *session;
		while (aux->next != NULL_PTR) {
			aux = aux->next;
		}
		newSession->sessionHandler = aux->sessionHandler + 1;
		aux->next = newSession;
		*phSession = newSession->sessionHandler;
	}
	return CKR_OK;
}

struct sessions *Find_Current_Session(struct sessions *session, CK_ULONG hSession) {
	struct sessions *aux;
	if (session == NULL_PTR) return NULL_PTR;
	else {
		aux = session;
		while (aux != NULL_PTR) {
			if (aux->sessionHandler == hSession) return aux;
			aux = aux->next;
		}
		return NULL_PTR;
	}
}


void Free_Sessions(struct sessions **session) {
	if (*session == NULL_PTR) return;
	struct sessions *aux;
	aux = *session;
	while (aux != NULL_PTR) {
		aux = aux->next;
		Free_SessionObjects(*session);
		free(*session);
		*session = aux;
	}
}

void Delete_Session(CK_ULONG sessionHandler, struct sessions ** session) {
	struct sessions *aux, *previousAux;
	if (*session == NULL_PTR) return;
	aux = *session;
	if (aux->next == NULL_PTR || aux->sessionHandler == sessionHandler) {
		if (aux->sessionHandler == sessionHandler) {
			*session = aux->next;
			Free_SessionObjects(aux);
			free(aux);
			return;
		}
		return;
	}
	previousAux = *session;
	aux = aux->next;
	while (aux != NULL_PTR) {
		if (aux->sessionHandler == sessionHandler) {
			previousAux->next = aux->next;
			Free_SessionObjects(aux);
			free(aux);
			return;
		}
		previousAux = previousAux->next;
		aux = previousAux->next;
	}
}

BOOL Is_User_Logged(struct sessions *session) {
	struct sessions *aux = session;
	while (aux != NULL_PTR) {
		if (aux->sessionState == CKS_RW_USER_FUNCTIONS || aux->sessionState == CKS_RO_USER_FUNCTIONS) return TRUE;
		aux = aux->next;
	}
	return FALSE;
}

CK_ULONG Change_Session_State(struct sessions * session, BOOL userLogged, CK_ULONG userType)
{
	struct sessions *aux = session;
	while (aux != NULL_PTR) {
		switch (aux->sessionState) {
		case CKS_RO_PUBLIC_SESSION:
			if (userLogged) {
				if (userType == CKU_USER || userType == CKU_CONTEXT_SPECIFIC) aux->sessionState = CKS_RO_USER_FUNCTIONS;
				else if (userType == CKU_SO)  CKR_SESSION_READ_ONLY_EXISTS;
				else return CKR_FUNCTION_FAILED;
			}
			break;
		case CKS_RO_USER_FUNCTIONS:
			if (!userLogged) aux->sessionState = CKS_RO_PUBLIC_SESSION;
			break;
		case CKS_RW_PUBLIC_SESSION:
			if (userLogged) {
				if (userType == CKU_USER || userType == CKU_CONTEXT_SPECIFIC) aux->sessionState = CKS_RW_USER_FUNCTIONS;
				else if (userType == CKU_SO)  aux->sessionState = CKS_RW_SO_FUNCTIONS;
				else return CKR_FUNCTION_FAILED;
			}
			break;
		case CKS_RW_USER_FUNCTIONS:
			if (!userLogged) aux->sessionState = CKS_RW_PUBLIC_SESSION;
			break;
		case CKS_RW_SO_FUNCTIONS:
			if (!userLogged) aux->sessionState = CKS_RW_PUBLIC_SESSION;
			break;
		}
		aux = aux->next;
	}
	return CKR_OK;
}

CK_ULONG sessionCount(struct sessions * session, CK_ULONG sessionType) {
	if (session == NULL) return 0;
	struct sessions *aux = session;
	int count = 0;
	if (sessionType == (CKS_RW_SO_FUNCTIONS | CKS_RW_PUBLIC_SESSION | CKS_RW_USER_FUNCTIONS)) {
		while (aux != NULL) {
			if ((aux->sessionState == CKS_RW_SO_FUNCTIONS) || (aux->sessionState == CKS_RW_PUBLIC_SESSION) || (aux->sessionState == CKS_RW_USER_FUNCTIONS)) count++;
			aux = aux->next;
		}
	}
	else if (sessionType == CKS_ALL_SESSIONS) {
		while (aux != NULL) {
			count++;
			aux = aux->next;
		}
	}
	else {
		while (aux != NULL) {
			if (aux->sessionState == sessionType) count++;
			aux = aux->next;
		}
	}
	return count;
}

CK_ULONG Check_User_Type(struct sessions * session, CK_ULONG *userType) {
	struct sessions *aux = session;
	CK_ULONG user = 0, so = 0;
	while (aux != NULL_PTR) {
		switch (aux->sessionState) {
		case CKS_RO_PUBLIC_SESSION:
			break;
		case CKS_RO_USER_FUNCTIONS:
			user++;
			break;
		case CKS_RW_PUBLIC_SESSION:
			break;
		case CKS_RW_USER_FUNCTIONS:
			user++;
			break;
		case CKS_RW_SO_FUNCTIONS:
			so++;
			break;
		}
		aux = aux->next;
	}
	if (user > 0) {
		*userType = CKU_USER;
		if (so > 0) {
			return CKR_GENERAL_ERROR;
		}
	}
	else if (so > 0) {
		*userType = CKU_SO;
	}
	else {
		*userType = CKU_PUBLIC;
		return CKR_OK;
	}
	return CKR_OK;
}
//********************************^********************************************//
//*                            Find Object Helper                             *//
//*****************************************************************************//


void Free_Object(struct objects * object)
{
	if (object != NULL) {
		if (object->id != NULL) free(object->id);
		if (object->certObject != NULL) Free_CertificateObject(object->certObject);
		if (object->keyObject != NULL) Free_keyObject(object->keyObject);
		if (object->dataObject != NULL) Free_DataObject(object->dataObject);
		free(object);
	}
}

void Free_SessionObjects(struct sessions *session) {
	if (session == NULL_PTR) return;
	if (session->findObjects.sessionObjects == NULL_PTR) return;
	struct objects *aux;
	aux = session->findObjects.sessionObjects;
	session->findObjects.currentObjectHandler = 0;
	session->findObjects.numFound = 0;
	session->findObjects.numLeft = 0;
	while (aux != NULL_PTR) {
		aux = aux->next;
		if (session->findObjects.sessionObjects->id != NULL) free(session->findObjects.sessionObjects->id);
		if (session->findObjects.sessionObjects->certObject != NULL_PTR) Free_CertificateObject(session->findObjects.sessionObjects->certObject);
		if (session->findObjects.sessionObjects->keyObject != NULL_PTR) Free_keyObject(session->findObjects.sessionObjects->keyObject);
		if (session->findObjects.sessionObjects->dataObject != NULL_PTR) Free_DataObject(session->findObjects.sessionObjects->dataObject);
		free(session->findObjects.sessionObjects);
		session->findObjects.sessionObjects = aux;
	}
}

struct objects *New_SessionObject(struct sessions * session, CK_CHAR_PTR id, CK_ULONG type) {
	struct objects *aux, *newObject;
	newObject = malloc(sizeof(struct objects));
	if (newObject == NULL) return NULL_PTR;
	else {
		newObject->next = NULL_PTR;
		newObject->id = _strdup(id);
		if (newObject->id == NULL) {
			free(newObject);
			return NULL_PTR;
		}
		newObject->certObject = NULL_PTR;
		newObject->keyObject = NULL_PTR;
		newObject->dataObject = NULL_PTR;
		newObject->objectHandler = 0;
		newObject->type = type;
	}
	if (session->findObjects.sessionObjects == NULL_PTR) {
		newObject->objectHandler = 1;
		session->findObjects.currentObjectHandler = 1;
		session->findObjects.sessionObjects = newObject;
	}
	else {
		aux = session->findObjects.sessionObjects;
		while (aux->next != NULL_PTR) {
			aux = aux->next;
		}
		newObject->objectHandler = aux->objectHandler + 1;
		aux->next = newObject;
	}
	return newObject;
}

void Free_SessionObject(struct objects * object, struct sessions * session) {
	if (object == NULL) return;
	if (session == NULL) {
		Free_Object(object);
		return;
	}
	if (session->findObjects.sessionObjects == NULL) {
		Free_Object(object);
		return;
	}
	struct objects *aux, *prev;
	BOOL firstElement = TRUE;
	aux = session->findObjects.sessionObjects;
	prev = session->findObjects.sessionObjects;
	while (aux != NULL) {
		if (firstElement) {
			if (aux->objectHandler == object->objectHandler) {
				session->findObjects.sessionObjects = aux->next;
				Free_Object(object);
				return;
			}
			aux = aux->next;
			firstElement = FALSE;
		}
		else {
			if (aux->objectHandler == object->objectHandler) {
				prev->next = aux->next;
				Free_Object(object);
				return;
			}
			aux = aux->next;
			prev = prev->next;
		}
	}
}

struct objects *Find_Object(struct objects *cacheTokenObject, CK_ULONG objectHandler) {
	struct objects *currentObject = cacheTokenObject;
	while (currentObject != NULL) {
		if (currentObject->objectHandler == objectHandler) return currentObject;
		currentObject = currentObject->next;
	}
	return NULL_PTR;
}

void Free_FoundObjects(struct sessions *session) {
	if (session == NULL_PTR) return;
	if (session->findObjects.foundObjects == NULL_PTR) return;
	struct found_objects_list *aux;
	aux = session->findObjects.foundObjects;
	while (aux != NULL_PTR) {
		aux = aux->next;
		free(session->findObjects.foundObjects);
		session->findObjects.foundObjects = aux;
	}
	session->findObjects.numFound = 0;
	session->findObjects.numLeft = 0;
	session->findObjects.currentObjectHandler = 0;
}

BOOL Exist_SessionObject(struct sessions *session, char *id, CK_ULONG type, struct objects ** object) {
	if (session == NULL_PTR) return FALSE;
	if (session->findObjects.sessionObjects == NULL_PTR) return FALSE;
	struct objects *currentObject = session->findObjects.sessionObjects;
	while (currentObject != NULL_PTR) {
		if (type == currentObject->type && strcmp(id, currentObject->id) == 0) {
			*object = currentObject;
			return TRUE;
		}
		currentObject = currentObject->next;
	}
	*object = NULL;
	return FALSE;
}

CK_ULONG New_FoundObject(struct sessions * session, struct objects * object) {
	if (session == NULL_PTR || object == NULL) return CKR_FUNCTION_FAILED;
	struct found_objects_list *currentObject, *aux;
	currentObject = malloc(sizeof(struct found_objects_list));
	if (currentObject == NULL) return CKR_HOST_MEMORY;
	currentObject->object = object;
	currentObject->next = NULL_PTR;
	aux = session->findObjects.foundObjects;
	if (session->findObjects.foundObjects == NULL_PTR) {
		session->findObjects.foundObjects = currentObject;
		session->findObjects.currentObjectHandler = currentObject->object->objectHandler;
	}
	else {
		while (aux->next != NULL_PTR) {
			aux = aux->next;
		}
		aux->next = currentObject;
	}
	session->findObjects.numFound++;
	session->findObjects.numLeft++;
	return CKR_OK;
}

void Free_FoundObject(struct objects * object, struct sessions * session) {
	if (object == NULL) return;
	if (session == NULL) goto cleanObject;
	if (session->findObjects.foundObjects == NULL) goto cleanObject;
	struct found_objects_list *aux, *prev;
	BOOL firstElement = TRUE;
	aux = session->findObjects.foundObjects;
	prev = session->findObjects.foundObjects;
	while (aux != NULL) {
		if (firstElement) {
			if (aux->object->objectHandler == object->objectHandler) {
				session->findObjects.foundObjects = aux->next;
				goto cleanObject;
			}
			aux = aux->next;
			firstElement = FALSE;
		}
		else {
			if (aux->object->objectHandler == object->objectHandler) {
				prev->next = aux->next;
				goto cleanObject;
			}
			aux = aux->next;
			prev = prev->next;
		}
	}
cleanObject:
	free(object);
	return;
}

struct found_objects_list *Find_FoundObject(struct sessions *session, CK_ULONG objectHandler) {
	struct found_objects_list *currentObject = session->findObjects.foundObjects;
	while (currentObject != NULL_PTR) {
		if (currentObject->object->objectHandler == objectHandler) return currentObject;
		currentObject = currentObject->next;
	}
	return NULL_PTR;
}

struct objects * New_TokenObject(struct objects ** cacheTokenObjects, CK_CHAR_PTR id, CK_ULONG type) {
	struct objects *aux, *newObject;
	newObject = malloc(sizeof(struct objects));
	if (newObject == NULL) return NULL_PTR;
	else {
		newObject->next = NULL_PTR;
		newObject->id = _strdup(id);
		if (newObject->id == NULL) {
			free(newObject);
			return NULL_PTR;
		}
		newObject->certObject = NULL_PTR;
		newObject->keyObject = NULL_PTR;
		newObject->dataObject = NULL_PTR;
		newObject->objectHandler = 0;
		newObject->type = type;
	}
	if (*cacheTokenObjects == NULL_PTR) {
		newObject->objectHandler = 1;
		*cacheTokenObjects = newObject;
	}
	else {
		aux = *cacheTokenObjects;
		while (aux->next != NULL_PTR) {
			aux = aux->next;
		}
		newObject->objectHandler = aux->objectHandler + 1;
		aux->next = newObject;
	}
	return newObject;
}

void Free_TokenObject(struct objects ** cacheTokenObjects, struct objects * object) {
	if (object == NULL) return;
	if (*cacheTokenObjects == NULL) {
		Free_Object(object);
		return;
	}
	struct objects *aux, *prev;
	BOOL firstElement = TRUE;
	aux = *cacheTokenObjects;
	prev = *cacheTokenObjects;
	while (aux != NULL) {
		if (firstElement) {
			if (aux->objectHandler == object->objectHandler) {
				*cacheTokenObjects = aux->next;
				Free_Object(object);
				return;
			}
			aux = aux->next;
			firstElement = FALSE;
		}
		else {
			if (aux->objectHandler == object->objectHandler) {
				prev->next = aux->next;
				Free_Object(object);
				return;
			}
			aux = aux->next;
			prev = prev->next;
		}
	}
}

struct objects *Find_TokenObject(struct objects * cacheTokenObjects, CK_ULONG objectHandler) {
	struct objects *currentObject = cacheTokenObjects;
	while (currentObject != NULL_PTR) {
		if (currentObject->objectHandler == objectHandler) return currentObject;
		currentObject = currentObject->next;
	}
	return NULL_PTR;
}

BOOL Exist_TokenObject(struct objects * cacheTokenObjects, char * id, CK_ULONG type, struct objects ** object)
{
	if (cacheTokenObjects == NULL_PTR) return FALSE;
	struct objects *currentObject = cacheTokenObjects;
	while (currentObject != NULL_PTR) {
		if (type == currentObject->type && strcmp(id, currentObject->id) == 0) {
			*object = currentObject;
			return TRUE;
		}
		currentObject = currentObject->next;
	}
	*object = NULL;
	return FALSE;
}

void Free_All_TokenObject(struct objects ** cacheTokenObjects) {
	if (*cacheTokenObjects == NULL_PTR) return;
	struct objects *aux = *cacheTokenObjects;
	while (aux != NULL_PTR) {
		aux = aux->next;
		if ((*cacheTokenObjects)->id != NULL) free((*cacheTokenObjects)->id);
		if ((*cacheTokenObjects)->certObject != NULL_PTR) Free_CertificateObject((*cacheTokenObjects)->certObject);
		if ((*cacheTokenObjects)->keyObject != NULL_PTR) Free_keyObject((*cacheTokenObjects)->keyObject);
		if ((*cacheTokenObjects)->dataObject != NULL_PTR) Free_DataObject((*cacheTokenObjects)->dataObject);
		free(*cacheTokenObjects);
		*cacheTokenObjects = aux;
	}
}


void Free_CacheObject_By_Id(struct objects ** cacheTokenObjects, char * id, CK_ULONG type)
{
	char *internalId = _strdup(id);
	if (internalId == NULL) return;
	if (*cacheTokenObjects == NULL_PTR) {
		free(internalId);
		return;
	}
	struct objects *aux, *prev;
	BOOL firsTime = TRUE;
	aux = *cacheTokenObjects;
	prev = *cacheTokenObjects;
	while (aux != NULL) {
		if (firsTime && (strcmp(aux->id, internalId) == 0)) {
			*cacheTokenObjects = aux->next;
			if (aux->id != NULL) free(aux->id);
			if (aux->certObject != NULL_PTR) Free_CertificateObject(aux->certObject);
			if (aux->keyObject != NULL_PTR) Free_keyObject(aux->keyObject);
			if (aux->dataObject != NULL_PTR) Free_DataObject(aux->dataObject);
			free(aux);
			aux = *cacheTokenObjects;
			prev = *cacheTokenObjects;
		}
		else {
			if ((strcmp(aux->id, internalId) == 0) && ((type == aux->type) || (type == CKO_PUBLIC_KEY && aux->type == CKO_PRIVATE_KEY) || (type == CKO_PRIVATE_KEY && aux->type == CKO_PUBLIC_KEY) || (type == CKO_CERTIFICATE && aux->type == CKO_PRIVATE_KEY) || (type == CKO_CERTIFICATE && aux->type == CKO_PUBLIC_KEY))) {
				prev->next = aux->next;
				if (aux->id != NULL) free(aux->id);
				if (aux->certObject != NULL_PTR) Free_CertificateObject(aux->certObject);
				if (aux->keyObject != NULL_PTR) Free_keyObject(aux->keyObject);
				if (aux->dataObject != NULL_PTR) Free_DataObject(aux->dataObject);
				free(aux);
				aux = prev->next;
			}
			else {
				aux = aux->next;
				if (!firsTime) prev = prev->next;
			}
			firsTime = FALSE;
		}
	}
	free(internalId);
	return;
}
//********************************^********************************************//
//*                             Primitive Helper                              *//
//*****************************************************************************//


CK_ULONG Object_Searcher(struct sessions * session, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulcount, CK_ULONG type, CK_CHAR_PTR token, struct objects ** cacheTokenObjects)
{
	CK_ULONG error;
	int match;
	switch ((int)type)
	{
	case CKO_ALL_OBJECTS:
		error = Object_Collector(session, CKO_PRIVATE_KEY, token, cacheTokenObjects);
		if (error != CKR_OK) return error;
		error = Object_Collector(session, CKO_CERTIFICATE, token, cacheTokenObjects);
		if (error != CKR_OK) return error;
		error = Object_Collector(session, CKO_DATA, token, cacheTokenObjects);
		if (error != CKR_OK) return error;
		break;
	case CKO_CERTIFICATE:
		error = Object_Collector(session, CKO_CERTIFICATE, token, cacheTokenObjects);
		if (error != CKR_OK) return error;
		break;
	case CKO_PRIVATE_KEY:
	case CKO_PUBLIC_KEY:
		error = Object_Collector(session, CKO_PRIVATE_KEY, token, cacheTokenObjects);
		if (error != CKR_OK) return error;
		break;
	case CKO_DATA:
		error = Object_Collector(session, CKO_DATA, token, cacheTokenObjects);
		if (error != CKR_OK) return error;
		break;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	if (ulcount >= 1) {
		if (session->findObjects.numFound > 0) {
			struct found_objects_list *currentObject, *aux;
			currentObject = session->findObjects.foundObjects;
			aux = session->findObjects.foundObjects;
			while (currentObject != NULL_PTR) {
				match = TRUE;
				for (CK_ULONG i = 0; i < ulcount; i++) {
					error = Compare_Attributes(currentObject->object, pTemplate[i], &match, token);
					if (error != CKR_OK) return error;
					if (!match) break;
				}
				if (!match) {
					/*		if (session->findObjects.currentObjectHandler == currentObject->object->objectHandler) {
								if (currentObject->next != NULL_PTR) {
									session->findObjects.currentObjectHandler = currentObject->next->object->objectHandler;
								}
								else session->findObjects.currentObjectHandler = 0;
							}*/
					session->findObjects.numFound--;
					session->findObjects.numLeft--;
					if (session->findObjects.foundObjects->object->objectHandler == currentObject->object->objectHandler) {
						session->findObjects.foundObjects = session->findObjects.foundObjects->next;
						free(currentObject);
						currentObject = session->findObjects.foundObjects;
						aux = currentObject;
					}
					else {
						aux->next = currentObject->next;
						free(currentObject);
						currentObject = aux->next;
					}
				}
				else {
					if (aux->object->objectHandler != currentObject->object->objectHandler) {
						aux = aux->next;
					}
					currentObject = currentObject->next;
				}
			}
		}
	}
	return CKR_OK;
}

CK_ULONG Compare_CommonAttributes(struct objects * object, CK_ATTRIBUTE attribute, int * match, CK_CHAR_PTR token) {
	char buffer[MAX_ID_SIZE];
	switch (attribute.type) {
	case CKA_CLASS:
		if (attribute.ulValueLen != sizeof(CK_ULONG)) return CKR_ATTRIBUTE_VALUE_INVALID;
		if (object->type == *(CK_ULONG*)attribute.pValue) {
			*match = TRUE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_TOKEN:
		if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
		if (CK_TRUE == *(CK_BBOOL*)attribute.pValue) {
			*match = TRUE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_PRIVATE:
		if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
		if (CK_TRUE == *(CK_BBOOL*)attribute.pValue) {
			*match = TRUE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_MODIFIABLE:
		if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
		if (CK_TRUE == *(CK_BBOOL*)attribute.pValue) {
			*match = TRUE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_LABEL:
		if (attribute.ulValueLen <= 0) return CKR_ATTRIBUTE_VALUE_INVALID;
		char label[MAX_ID_SIZE];
		switch (object->type) { // TODO edit and store this label in the object memory
		case CKO_CERTIFICATE:
			strcpy(label, object->certObject->commonAtt.label);
			break;
		case CKO_PUBLIC_KEY:
		case CKO_PRIVATE_KEY:
			strcpy(label, object->keyObject->commonAtt.label);
			break;
		case CKO_DATA:
			strcpy(label, object->dataObject->commonAtt.label);
			break;
		}
		if (strlen(label) == attribute.ulValueLen) {
			memcpy(buffer, attribute.pValue, attribute.ulValueLen);
			buffer[attribute.ulValueLen] = '\0';
			if (!strcmp(label, buffer)) {
				*match = TRUE;
			}
			else *match = FALSE;
		}
		else *match = FALSE;
		return CKR_OK;
	}
	return CKR_FUNCTION_FAILED;
}

CK_ULONG Compare_CommonKeyAttributes(struct objects * object, CK_ATTRIBUTE attribute, int * match, CK_CHAR_PTR token) {
	CK_DATE *outputDate;
	switch (attribute.type) {
	case CKA_KEY_TYPE:
		if (attribute.ulValueLen != sizeof(CK_KEY_TYPE)) return CKR_ATTRIBUTE_VALUE_INVALID;
		if (object->keyObject->commonKeyAtt.keyType == *(CK_CERTIFICATE_TYPE*)attribute.pValue) {
			*match = TRUE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_ID:
		if (attribute.ulValueLen <= 0) return CKR_ATTRIBUTE_VALUE_INVALID;
		if (strlen((char*)object->id) == attribute.ulValueLen) {
			if (!strncmp((char*)object->id, attribute.pValue, strlen((char*)object->id))) {
				*match = TRUE;
			}
			else *match = FALSE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_START_DATE:
		if (attribute.ulValueLen != sizeof(CK_DATE))  return CKR_ATTRIBUTE_VALUE_INVALID;
		outputDate = (CK_DATE*)attribute.pValue;
		if ((outputDate->year == object->keyObject->commonKeyAtt.startDate.year) && (outputDate->month == object->keyObject->commonKeyAtt.startDate.month) && (outputDate->day == object->keyObject->commonKeyAtt.startDate.day))
		{
			*match = TRUE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_END_DATE:
		if (attribute.ulValueLen != sizeof(CK_DATE))  return CKR_ATTRIBUTE_VALUE_INVALID;
		outputDate = (CK_DATE*)attribute.pValue;
		if ((outputDate->year == object->keyObject->commonKeyAtt.endDate.year) && (outputDate->month == object->keyObject->commonKeyAtt.endDate.month) && (outputDate->day == object->keyObject->commonKeyAtt.endDate.day))
		{
			*match = TRUE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_DERIVE:
		if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
		if (CK_FALSE == *(CK_BBOOL*)attribute.pValue) {
			*match = TRUE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_LOCAL:
		if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
		if (CK_FALSE == *(CK_BBOOL*)attribute.pValue) {
			*match = TRUE;
		}
		else *match = FALSE;
		return CKR_OK;
	case CKA_KEY_GEN_MECHANISM:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	case CKA_ALLOWED_MECHANISMS:
		//TODO to implement
		*match = TRUE;
		return CKR_OK;
	}
	return CKR_FUNCTION_FAILED;
}

CK_ULONG Compare_Attributes(struct objects * object, CK_ATTRIBUTE attribute, int * match, CK_CHAR_PTR token)
{
	CK_DATE *outputDate;
	CK_ULONG res;
	int find;
	res = Compare_CommonAttributes(object, attribute, &find, token);
	if (res != CKR_FUNCTION_FAILED) {
		*match = find;
		return res;
	}
	switch (object->type) {
	case CKO_CERTIFICATE:
		switch (attribute.type) {
		case CKA_CERTIFICATE_TYPE:
			if (attribute.ulValueLen != sizeof(CK_CERTIFICATE_TYPE)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->certObject->commonCertificateAtt.certificateType == *(CK_CERTIFICATE_TYPE*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_ID:
			if (attribute.ulValueLen <= 0) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (strlen(object->id) == attribute.ulValueLen) {
				if (!strncmp(object->id, attribute.pValue, strlen(object->id))) {
					*match = TRUE;
				}
				else *match = FALSE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_VALUE:
			if (object->certObject->x509CertificateAtt.value.len != attribute.ulValueLen) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!strncmp(object->certObject->x509CertificateAtt.value.data, attribute.pValue, object->certObject->x509CertificateAtt.value.len)) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_SUBJECT:
			if (attribute.pValue == NULL) {
				*match = FALSE;
				return CKR_OK;
			}
			if (CompareSubjects(object->certObject->x509CertificateAtt.subject.data, object->certObject->x509CertificateAtt.subject.len, attribute.pValue, attribute.ulValueLen))
				*match = TRUE;
			else *match = FALSE;
			return CKR_OK;
		case CKA_ISSUER:
			if (object->certObject->x509CertificateAtt.issuer.len != attribute.ulValueLen) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!strncmp(object->certObject->x509CertificateAtt.issuer.data, attribute.pValue, object->certObject->x509CertificateAtt.issuer.len)) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_SERIAL_NUMBER:
			if (object->certObject->x509CertificateAtt.serailNumber.len != attribute.ulValueLen) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!strncmp(object->certObject->x509CertificateAtt.serailNumber.data, attribute.pValue, object->certObject->x509CertificateAtt.serailNumber.len)) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		case CKA_JAVA_MIDP_SECURITY_DOMAIN:
		case CKA_CERTIFICATE_CATEGORY:
		case CKA_CHECK_VALUE:
		case CKA_URL:
			*match = TRUE;
			return CKR_ATTRIBUTE_TYPE_INVALID;
		case CKA_START_DATE:
			if (attribute.ulValueLen != sizeof(CK_DATE))  return CKR_ATTRIBUTE_VALUE_INVALID;
			outputDate = (CK_DATE*)attribute.pValue;
			if ((outputDate->year == object->certObject->commonCertificateAtt.startDate.year) && (outputDate->month == object->certObject->commonCertificateAtt.startDate.month) && (outputDate->day == object->certObject->commonCertificateAtt.startDate.day))
			{
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_END_DATE:
			if (attribute.ulValueLen != sizeof(CK_DATE))  return CKR_ATTRIBUTE_VALUE_INVALID;
			outputDate = (CK_DATE*)attribute.pValue;
			if ((outputDate->year == object->certObject->commonCertificateAtt.endDate.year) && (outputDate->month == object->certObject->commonCertificateAtt.endDate.month) && (outputDate->day == object->certObject->commonCertificateAtt.endDate.day))
			{
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		default:
			*match = FALSE;
			return CKR_OK;
		}
		break;
	case CKO_PRIVATE_KEY:
		res = Compare_CommonKeyAttributes(object, attribute, &find, token);
		if (res != CKR_FUNCTION_FAILED) {
			*match = find;
			return res;
		}
		switch (attribute.type) {
		case CKA_SUBJECT:
			if (object->keyObject->commonPrivateKeyAtt.subject.len != attribute.ulValueLen) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!strncmp(object->keyObject->commonPrivateKeyAtt.subject.data, attribute.pValue, object->keyObject->commonPrivateKeyAtt.subject.len)) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_SENSITIVE:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.isSensitive == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_DECRYPT:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.canDecrypt == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_SIGN:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.canSign == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_SIGN_RECOVER:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.canSignRecover == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_UNWRAP:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.canUnwrap == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_EXTRACTABLE:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.isExtractable == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_ALWAYS_SENSITIVE:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.isAlwaysSensitive == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_NEVER_EXTRACTABLE:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.isNeverExtractable == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_WRAP_WITH_TRUSTED:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.beWrapWithTrusted == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_UNWRAP_TEMPLATE:
			// TODO
			*match = TRUE;
			return CKR_OK;
		case CKA_ALWAYS_AUTHENTICATE:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPrivateKeyAtt.isAlwaysAuthenticate == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_MODULUS:
			if (object->keyObject->RSAPrivateKeyObjectAtt.modulus.len != attribute.ulValueLen) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!strncmp(object->keyObject->RSAPrivateKeyObjectAtt.modulus.data, attribute.pValue, object->keyObject->RSAPrivateKeyObjectAtt.modulus.len)) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_PUBLIC_EXPONENT:
			if (attribute.pValue == NULL || attribute.ulValueLen < 3 || attribute.ulValueLen > sizeof(CK_ULONG)) {
				*match = FALSE;
				return CKR_OK;
			}
			CK_ULONG publicExponent = 0, publicStoredExponent = 0;
			memcpy(&publicExponent, attribute.pValue, attribute.ulValueLen);
			memcpy(&publicStoredExponent, object->keyObject->RSAPrivateKeyObjectAtt.publicExponent.data, object->keyObject->RSAPrivateKeyObjectAtt.publicExponent.len);
			if (publicExponent != publicStoredExponent) {
				*match = FALSE;
			}
			else *match = TRUE;
			return CKR_OK;
		case CKA_PRIVATE_EXPONENT:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		case CKA_PRIME_1:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		case CKA_PRIME_2:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		case CKA_EXPONENT_1:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		case CKA_EXPONENT_2:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		case CKA_COEFFICIENT:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		default:
			*match = FALSE;
			return CKR_OK;
		}
	case CKO_PUBLIC_KEY:
		res = Compare_CommonKeyAttributes(object, attribute, &find, token);
		if (res != CKR_FUNCTION_FAILED) {
			*match = find;
			return res;
		}
		switch (attribute.type) {
		case CKA_SUBJECT:
			if (object->keyObject->commonPublicKeyAtt.subject.len != attribute.ulValueLen) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!strncmp(object->keyObject->commonPublicKeyAtt.subject.data, attribute.pValue, object->keyObject->commonPublicKeyAtt.subject.len)) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_ENCRYPT:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPublicKeyAtt.canEncrypt == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_VERIFY:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPublicKeyAtt.canVerify == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_VERIFY_RECOVER:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPublicKeyAtt.canVerrifyRecover == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_WRAP:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPublicKeyAtt.canWrap == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_TRUSTED:
			if (attribute.ulValueLen != sizeof(CK_BBOOL)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->commonPublicKeyAtt.isTrusted == *(CK_BBOOL*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_WRAP_TEMPLATE:
			*match = TRUE;
			return CKR_ATTRIBUTE_TYPE_INVALID;
		case CKA_MODULUS:
			if (object->keyObject->RSApublicKeyObjectAtt.modulus.len != attribute.ulValueLen) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!strncmp(object->keyObject->RSApublicKeyObjectAtt.modulus.data, attribute.pValue, object->keyObject->RSApublicKeyObjectAtt.modulus.len)) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_MODULUS_BITS:
			if (attribute.ulValueLen != sizeof(CK_ULONG)) return CKR_ATTRIBUTE_VALUE_INVALID;
			if (object->keyObject->RSApublicKeyObjectAtt.modulusBits == *(CK_ULONG*)attribute.pValue) {
				*match = TRUE;
			}
			else *match = FALSE;
			return CKR_OK;
		case CKA_PUBLIC_EXPONENT:
			if (attribute.pValue == NULL || attribute.ulValueLen < 3 || attribute.ulValueLen > sizeof(CK_ULONG)) {
				*match = FALSE;
				return CKR_OK;
			}
			CK_ULONG publicExponent = 0, publicStoredExponent = 0;
			memcpy(&publicExponent, attribute.pValue, attribute.ulValueLen);
			memcpy(&publicStoredExponent, object->keyObject->RSApublicKeyObjectAtt.publicExponent.data, object->keyObject->RSApublicKeyObjectAtt.publicExponent.len);
			if (publicExponent != publicStoredExponent) {
				*match = FALSE;
			}
			else *match = TRUE;
			return CKR_OK;
		default:
			*match = FALSE;
			return CKR_OK;
		}
	case CKO_DATA:
		switch (attribute.type) {
		case CKA_APPLICATION:
			if (strlen(object->dataObject->application) != strlen(attribute.ulValueLen)) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!strcmp(object->dataObject->application, *(CK_CHAR*)attribute.pValue))
				*match = TRUE;
			else *match = FALSE;
			return CKR_OK;
		case CKA_OBJECT_ID:
			if (object->dataObject->objectId.len != attribute.ulValueLen) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!memcmp(object->dataObject->objectId.data, *(CK_BYTE*)attribute.pValue, object->dataObject->objectId.len))
				*match = TRUE;
			else *match = FALSE;
			return CKR_OK;
		case CKA_VALUE:
			if (object->dataObject->value.len != attribute.ulValueLen) {
				*match = FALSE;
				return CKR_OK;
			}
			if (!memcmp(object->dataObject->value.data, *(CK_BYTE*)attribute.pValue, object->dataObject->value.len))
				*match = TRUE;
			else *match = FALSE;
			return CKR_OK;
		default:
			*match = FALSE;
			return CKR_OK;
		}
	}
	return CKR_OK;
}

CK_ULONG Object_Collector(struct sessions * session, CK_ULONG type, CK_CHAR_PTR token, struct objects ** cacheTokenObjects) {
	struct secret_items *secretAux, *secretList = NULL;
	struct cert_list *certAux, *certList = NULL;
	struct list_key  *keyAux, *keyList = NULL;
	struct basic_http_data *petitionData = NULL;
	struct objects *object, *publicKeyObject;
	struct id_http_data * getParam;
	struct delete_update_cert_response * returnedCert = NULL_PTR;
	struct key_data_response * returnedKey = NULL_PTR;
	struct secret_item_data *secretItemData = NULL_PTR;
	time_t now;
	int result;
	BOOL existObject = FALSE, existPublicObject = FALSE;
	now = time(NULL);
	switch (type)
	{
	case CKO_CERTIFICATE:
		if (lastCallTimer.certificateListeTimer + CACHE_TIMER_SECS < now) {
			lastCallTimer.certificateListeTimer = now;
			petitionData = Store_BasicHttpData(token, HOST);
			if (petitionData == NULL) return CKR_HOST_MEMORY;
			result = Get_CertificateList(petitionData, &certList);
			Free_BasicHttpData(petitionData);
			if (result != HTTP_OK) {
				if (result != HTTP_OK) {
					if (result == UNAUTHORIZED) return CKR_PIN_EXPIRED;
					else if (result == FORBIDDEN) return CKR_FUNCTION_FAILED;
					else if (result == NOT_FOUND) return CKR_DEVICE_REMOVED;
					else if (result == BAD_REQUEST) return CKR_ARGUMENTS_BAD;
					else if (result < 0) return CKR_TOKEN_NOT_PRESENT;
					else return CKR_FUNCTION_FAILED;
				}
			}
			if (certList != NULL) {
				certAux = certList;
				if (certAux == NULL) return CKR_GENERAL_ERROR;
				while (certAux != NULL) {
					existObject = Exist_TokenObject(*cacheTokenObjects, certAux->certData->id, CKO_CERTIFICATE, &object);
					if (!existObject) {
						/* Create cert object and insert into object list*/
						object = New_TokenObject(cacheTokenObjects, certAux->certData->id, CKO_CERTIFICATE);
						if (object == NULL) return CKR_HOST_MEMORY;
						/* searh object information in Azure */
						returnedCert = NULL;
						getParam = Store_IdHttpData(token, HOST, certAux->certData->id);
						if (getParam == NULL) return CKR_HOST_MEMORY;
						result = Get_Certificate(getParam, &returnedCert);
						Free_IdHttpData(getParam);
						if (result != HTTP_OK) {
							Free_TokenObject(cacheTokenObjects, object);
							Free_CertList(certList);
							if (result < HTTP_OK) return CKR_TOKEN_NOT_PRESENT;
							else if (result == UNAUTHORIZED) return CKR_PIN_EXPIRED;
							else if (result == FORBIDDEN) return CKR_FUNCTION_FAILED;
							else if (result == NOT_FOUND) return CKR_DEVICE_REMOVED;
							else if (result == BAD_REQUEST) return CKR_ARGUMENTS_BAD;
							else return CKR_FUNCTION_FAILED;
						}
						if (returnedCert->cer == NULL) {
							Free_TokenObject(cacheTokenObjects, object);
							Free_DeleteUpdateCertResponse(returnedCert);
							Free_CertList(certList);
							return CKR_FUNCTION_FAILED;
						}
						object->certObject = AzurePKCS11CertificateTranslator(returnedCert);
						Free_DeleteUpdateCertResponse(returnedCert);
						if (object->certObject == NULL) {
							Free_TokenObject(cacheTokenObjects, object);
							Free_CertList(certList);
							return CKR_HOST_MEMORY;
						}
					}
					result = New_FoundObject(session, object);
					if (result != CKR_OK) {
						Free_CertList(certList);
						return result;
					}
					certAux = certAux->next;
					/* insert object information into object struct */
				}
				Free_CertList(certList);
			}
		}
		else {
			Collect_FoundObjects_From_Cache(session, *cacheTokenObjects, CKO_CERTIFICATE);
		}
		break;
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
		if (lastCallTimer.keyListTimer + CACHE_TIMER_SECS < now) {
			lastCallTimer.keyListTimer = now;
			petitionData = Store_BasicHttpData(token, HOST);
			if (petitionData == NULL) return CKR_HOST_MEMORY;
			result = Get_ListKeys(petitionData, &keyList);
			Free_BasicHttpData(petitionData);
			if (result != HTTP_OK) {
				if (result != HTTP_OK) {
					if (result == UNAUTHORIZED) return CKR_PIN_EXPIRED;
					else if (result == FORBIDDEN) return CKR_FUNCTION_FAILED;
					else if (result == NOT_FOUND) return CKR_DEVICE_REMOVED;
					else if (result == BAD_REQUEST) return CKR_ARGUMENTS_BAD;
					else if (result < 0) return CKR_TOKEN_NOT_PRESENT;
					else return CKR_FUNCTION_FAILED;
				}
			}
			if (keyList != NULL) {
				keyAux = keyList;
				if (keyAux == NULL) return CKR_GENERAL_ERROR;
				while (keyAux != NULL) {
					existObject = Exist_TokenObject(*cacheTokenObjects, keyAux->id, CKO_PRIVATE_KEY, &object);
					existPublicObject = Exist_TokenObject(*cacheTokenObjects, keyAux->id, CKO_PUBLIC_KEY, &publicKeyObject);
					if ((existObject && !existPublicObject) || (!existObject && existPublicObject)) {
						// Security function to eliminate asymmetric key isolated
						if (object != NULL) Free_TokenObject(&cacheTokenObjects, object);
						if (publicKeyObject != NULL) Free_TokenObject(&publicKeyObject, object);
						existObject = FALSE;
					}
					if (!existObject) {
						/* Create public and private key object and insert into object list*/
						object = New_TokenObject(cacheTokenObjects, (CK_CHAR_PTR)keyAux->id, CKO_PRIVATE_KEY);
						if (object == NULL) return CKR_HOST_MEMORY;
						publicKeyObject = New_TokenObject(cacheTokenObjects, (CK_CHAR_PTR)keyAux->id, CKO_PUBLIC_KEY);
						if (publicKeyObject == NULL) {
							Free_TokenObject(cacheTokenObjects, object);
							Free_ListKey(keyList);
							return CKR_HOST_MEMORY;
						}
						/* searh object information in Azure */
						returnedKey = NULL_PTR;
						getParam = Store_IdHttpData((char *)token, HOST, keyAux->id);
						if (getParam == NULL) return CKR_HOST_MEMORY;
						result = Get_Key(getParam, &returnedKey);
						Free_IdHttpData(getParam);
						if (result != HTTP_OK) {
							Free_TokenObject(cacheTokenObjects, object);
							Free_TokenObject(cacheTokenObjects, publicKeyObject);
							Free_ListKey(keyList);
							if (result != HTTP_OK) {
								if (result == UNAUTHORIZED) return CKR_PIN_EXPIRED;
								else if (result == FORBIDDEN) return CKR_FUNCTION_FAILED;
								else if (result == NOT_FOUND) return CKR_DEVICE_REMOVED;
								else if (result == BAD_REQUEST) return CKR_ARGUMENTS_BAD;
								else if (result < 0) return CKR_TOKEN_NOT_PRESENT;
								else return CKR_FUNCTION_FAILED;
							}
						}
						/* insert object information into object struct */
						object->keyObject = AzurePKCS11KeyTranslator(returnedKey, CKO_PRIVATE_KEY, token, cacheTokenObjects);
						if (object->keyObject == NULL_PTR) {
							Free_TokenObject(cacheTokenObjects, object);
							Free_TokenObject(cacheTokenObjects, publicKeyObject);
							Free_KeyCreationResponse(returnedKey);
							Free_ListKey(keyList);
							return CKR_HOST_MEMORY;
						}
						publicKeyObject->keyObject = AzurePKCS11KeyTranslator(returnedKey, CKO_PUBLIC_KEY, token, cacheTokenObjects);
						if (publicKeyObject->keyObject == NULL_PTR) {
							Free_TokenObject(cacheTokenObjects, object);
							Free_TokenObject(cacheTokenObjects, publicKeyObject);
							Free_KeyCreationResponse(returnedKey);
							Free_ListKey(keyList);
							return CKR_HOST_MEMORY;
						}
						Free_KeyCreationResponse(returnedKey);
					}
					result = New_FoundObject(session, object);
					if (result != CKR_OK) {
						Free_ListKey(keyList);
						return result;
					}
					result = New_FoundObject(session, publicKeyObject);
					if (result != CKR_OK) {
						Free_ListKey(keyList);
						return result;
					}
					keyAux = keyAux->next;
				}
				Free_ListKey(keyList);
			}
		}
		else {
			Collect_FoundObjects_From_Cache(session, *cacheTokenObjects, CKO_PUBLIC_KEY);
		}
		break;
	case CKO_DATA:
		if (lastCallTimer.secretListTimer + CACHE_TIMER_SECS < now) {
			lastCallTimer.secretListTimer = now;
			petitionData = Store_BasicHttpData((char *)token, HOST);
			if (petitionData == NULL) return CKR_HOST_MEMORY;
			result = Get_ListSecrets(petitionData, &secretList);
			Free_BasicHttpData(petitionData);
			if (result != HTTP_OK) {
				if (result != HTTP_OK) {
					if (result == UNAUTHORIZED) return CKR_PIN_EXPIRED;
					else if (result == FORBIDDEN) return CKR_FUNCTION_FAILED;
					else if (result == NOT_FOUND) return CKR_DEVICE_REMOVED;
					else if (result == BAD_REQUEST) return CKR_ARGUMENTS_BAD;
					else if (result < 0) return CKR_TOKEN_NOT_PRESENT;
					else return CKR_FUNCTION_FAILED;
				}
			}
			if (secretList != NULL) {
				secretAux = secretList;
				if (secretAux == NULL) return CKR_GENERAL_ERROR;
				while (secretAux != NULL) {
					if (secretAux->secretCommonItem.attributes->enabled != FALSE) {
						existObject = Exist_TokenObject(*cacheTokenObjects, secretAux->secretCommonItem.id, CKO_DATA, &object);
						if (!existObject) {
							/* Create cert object and insert into object list*/
							object = New_TokenObject(cacheTokenObjects, (CK_CHAR_PTR)secretAux->secretCommonItem.id, CKO_DATA);
							if (object == NULL) return CKR_HOST_MEMORY;
							/* searh object information in Azure */
							secretItemData = NULL_PTR;
							getParam = Store_IdHttpData(token, HOST, secretAux->secretCommonItem.id);
							if (getParam == NULL) return CKR_HOST_MEMORY;
							result = Get_SecretData(getParam, &secretItemData);
							Free_IdHttpData(getParam);
							if (result != HTTP_OK) {
								Free_TokenObject(cacheTokenObjects, object);
								Free_SecretItems(secretList);
								if (result != HTTP_OK) {
									if (result == UNAUTHORIZED) return CKR_PIN_EXPIRED;
									else if (result == FORBIDDEN) return CKR_FUNCTION_FAILED;
									else if (result == NOT_FOUND) return CKR_DEVICE_REMOVED;
									else if (result == BAD_REQUEST) return CKR_ARGUMENTS_BAD;
									else if (result < 0) return CKR_TOKEN_NOT_PRESENT;
									else return CKR_FUNCTION_FAILED;
								}
							}
							if (secretItemData->value == NULL) {
								Free_TokenObject(cacheTokenObjects, object);
								Free_SecretItemsData(secretItemData);
								Free_SecretItems(secretList);
								return CKR_FUNCTION_FAILED;
							}
							object->dataObject = AzurePKCS11DataObjectTranslator(secretItemData);
							Free_SecretItemsData(secretItemData);
							if (object->dataObject == NULL) {
								Free_TokenObject(cacheTokenObjects, object);
								Free_SecretItems(secretList);
								return CKR_HOST_MEMORY;
							}
						}
						result = New_FoundObject(session, object);
						if (result != CKR_OK) {
							Free_SecretItems(secretList);
							return result;
						}
					}
					secretAux = secretAux->next;
					///* insert object information into object struct */
				}
				Free_SecretItems(secretList);
			}
		}
		else {
			Collect_FoundObjects_From_Cache(session, *cacheTokenObjects, CKO_DATA);
		}
		break;
	}
	return CKR_OK;
}

void Collect_FoundObjects_From_Cache(struct sessions *session, struct objects * cacheTokenObjects, CK_ULONG type) {
	struct objects * aux = cacheTokenObjects;
	while (aux != NULL) {
		if (type == CKO_CERTIFICATE && aux->type == CKO_CERTIFICATE) {
			New_FoundObject(session, aux);
		}
		else if (type == CKO_PUBLIC_KEY) {
			if (aux->type == CKO_PUBLIC_KEY || aux->type == CKO_PRIVATE_KEY) {
				New_FoundObject(session, aux);
			}
		}
		aux = aux->next;
	}
	return;
}

CK_ULONG switch_common_attributes(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, struct context *context) {
	char label[MAX_ID_SIZE];
	//Write_debugData("                      El handler del objeto es: ", NULL, 0, &currentObject->objectHandler,1);
	//Write_debugData("\n", NULL, 0, NULL, 0);
	switch (pTemplate->type) {
	case CKA_CLASS:
		strcpy(context->dataIn, "CKA_CLASS");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_OBJECT_CLASS);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_OBJECT_CLASS)) {
				*(CK_OBJECT_CLASS*)pTemplate->pValue = currentObject->type;
				if (currentObject->type == CKO_PRIVATE_KEY) {
					strcpy(context->dataOut, "CKO_PRIVATE_KEY");
					Write_DebugData(*context, LOG_CONTEXT);
				}
				else if (currentObject->type == CKO_CERTIFICATE) {
					strcpy(context->dataOut, "CKO_CERTIFICATE");
					Write_DebugData(*context, LOG_CONTEXT);
				}
				else {
					strcpy(context->dataOut, "CKO_PUBLIC_KEY");
					Write_DebugData(*context, LOG_CONTEXT);
				}
				pTemplate->ulValueLen = sizeof(CK_OBJECT_CLASS);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_TOKEN:
		strcpy(context->dataIn, "CKA_TOKEN");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_BBOOL);
		}
		else {

			if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
				strcpy(context->dataOut, "CK_TRUE");
				Write_DebugData(*context, LOG_CONTEXT);
				*(CK_BBOOL*)pTemplate->pValue = CK_TRUE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_PRIVATE:
		strcpy(context->dataIn, "CKA_PRIVATE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_BBOOL);
		}
		else {

			if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
				strcpy(context->dataOut, "CK_TRUE");
				Write_DebugData(*context, LOG_CONTEXT);
				*(CK_BBOOL*)pTemplate->pValue = CK_TRUE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_MODIFIABLE:
		strcpy(context->dataIn, "CKA_MODIFIABLE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_BBOOL);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
				strcpy(context->dataOut, "CK_TRUE");
				Write_DebugData(*context, LOG_CONTEXT);
				*(CK_BBOOL*)pTemplate->pValue = CK_TRUE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_LABEL:
		strcpy(context->dataIn, "CKA_LABEL");
		Write_DebugData(*context, LOG_CONTEXT);
		switch (currentObject->type) {
		case CKO_CERTIFICATE: // TODO edit and store this label in the object memory
			strcpy(label, currentObject->certObject->commonAtt.label);
			break;
		case CKO_PUBLIC_KEY:
		case CKO_PRIVATE_KEY:
			strcpy(label, currentObject->keyObject->commonAtt.label);
			break;
		case CKO_DATA:
			strcpy(label, currentObject->dataObject->commonAtt.label);
			break;
		default:
			return CKR_OK;
		}
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = strlen(label) * sizeof(char);
		}
		else {
			if (pTemplate->ulValueLen >= strlen(label) * sizeof(char)) {
				strcpy(context->dataOut, label);
				Write_DebugData(*context, LOG_CONTEXT);
				memcpy(pTemplate->pValue, label, strlen(label) * sizeof(char));
				pTemplate->ulValueLen = strlen(label) * sizeof(char);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	}
	return CK_UNAVAILABLE_INFORMATION;
}

CK_ULONG switch_certificate_attributes(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, CK_CHAR_PTR token, struct context *context) {
	char * hexData = NULL;
	switch (pTemplate->type) {
	case CKA_CERTIFICATE_TYPE:
		strcpy(context->dataIn, "CKA_CERTIFICATE_TYPE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_CERTIFICATE_TYPE);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_CERTIFICATE_TYPE)) {
				strcpy(context->dataOut, "CKC_X_509");
				Write_DebugData(*context, LOG_CONTEXT);
				*(CK_CERTIFICATE_TYPE*)pTemplate->pValue = currentObject->certObject->commonCertificateAtt.certificateType;
				pTemplate->ulValueLen = sizeof(CK_CERTIFICATE_TYPE);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_TRUSTED:
		strcpy(context->dataIn, "CKA_TRUSTED");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_BBOOL);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
				strcpy(context->dataOut, "CK_TRUE");
				Write_DebugData(*context, LOG_CONTEXT);
				*(CK_BBOOL*)pTemplate->pValue = CK_TRUE;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_ID:
		strcpy(context->dataIn, "CKA_ID");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = strlen(currentObject->id) * sizeof(char);
		}
		else {
			if (pTemplate->ulValueLen >= (strlen(currentObject->id) * sizeof(char))) {
				strcpy(context->dataOut, currentObject->id);
				Write_DebugData(*context, LOG_CONTEXT);
				memcpy(pTemplate->pValue, currentObject->id, (strlen(currentObject->id) * sizeof(char)));;
				pTemplate->ulValueLen = strlen(currentObject->id) * sizeof(char);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_VALUE:
		strcpy(context->dataIn, "CKA_VALUE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = currentObject->certObject->x509CertificateAtt.value.len;
		}
		else {
			if (pTemplate->ulValueLen >= currentObject->certObject->x509CertificateAtt.value.len) {
				///* Debug */
				if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
					hexData = malloc((currentObject->certObject->x509CertificateAtt.value.len * 2) + 1);
					if (hexData != NULL) {
						memset(hexData, 0, currentObject->certObject->x509CertificateAtt.value.len * 2);
						hexData[currentObject->certObject->x509CertificateAtt.value.len] = '\0';
						for (int i = 0; i < currentObject->certObject->x509CertificateAtt.value.len; i++) {
							sprintf(&hexData[2 * i], "%02x", currentObject->certObject->x509CertificateAtt.value.data[i]);
						}
						context->dynamicOut = hexData;
						Write_DebugData(*context, LOG_CONTEXT);
						free(hexData);
						context->dynamicOut = NULL;
					}
				}
				///*     */
				memcpy(pTemplate->pValue, currentObject->certObject->x509CertificateAtt.value.data, currentObject->certObject->x509CertificateAtt.value.len);
				pTemplate->ulValueLen = currentObject->certObject->x509CertificateAtt.value.len;
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_SUBJECT:
		strcpy(context->dataIn, "CKA_SUBJECT");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = currentObject->certObject->x509CertificateAtt.subject.len;
		}
		else {
			if (pTemplate->ulValueLen >= currentObject->certObject->x509CertificateAtt.subject.len) {
				///* Debug */
				if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
					hexData = malloc((currentObject->certObject->x509CertificateAtt.subject.len * 2) + 1);
					if (hexData != NULL) {
						memset(hexData, 0, currentObject->certObject->x509CertificateAtt.subject.len * 2);
						hexData[currentObject->certObject->x509CertificateAtt.subject.len] = '\0';
						for (int i = 0; i < currentObject->certObject->x509CertificateAtt.subject.len; i++) {
							sprintf(&hexData[2 * i], "%02x", currentObject->certObject->x509CertificateAtt.subject.data[i]);
						}
						context->dynamicOut = hexData;
						Write_DebugData(*context, LOG_CONTEXT);
						free(hexData);
						context->dynamicOut = NULL;
					}
				}
				///*      */
				memcpy(pTemplate->pValue, currentObject->certObject->x509CertificateAtt.subject.data, currentObject->certObject->x509CertificateAtt.subject.len);
				pTemplate->ulValueLen = currentObject->certObject->x509CertificateAtt.subject.len;
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_ISSUER:
		strcpy(context->dataIn, "CKA_ISSUER");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = currentObject->certObject->x509CertificateAtt.issuer.len;
		}
		else {
			if (pTemplate->ulValueLen >= currentObject->certObject->x509CertificateAtt.issuer.len) {
				///* Debug */
				if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
					hexData = malloc((currentObject->certObject->x509CertificateAtt.issuer.len * 2) + 1);
					if (hexData != NULL) {
						memset(hexData, 0, currentObject->certObject->x509CertificateAtt.issuer.len * 2);
						hexData[currentObject->certObject->x509CertificateAtt.issuer.len] = '\0';
						for (CK_ULONG i = 0; i < currentObject->certObject->x509CertificateAtt.issuer.len; i++) {
							sprintf(&hexData[2 * i], "%02x", currentObject->certObject->x509CertificateAtt.issuer.data[i]);
						}
						context->dynamicOut = hexData;
						Write_DebugData(*context, LOG_CONTEXT);
						free(hexData);
						context->dynamicOut = NULL;
					}
				}
				///*      */
				memcpy(pTemplate->pValue, currentObject->certObject->x509CertificateAtt.issuer.data, currentObject->certObject->x509CertificateAtt.issuer.len);
				pTemplate->ulValueLen = currentObject->certObject->x509CertificateAtt.issuer.len;
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_SERIAL_NUMBER:
		strcpy(context->dataIn, "CKA_SERIAL_NUMBER");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = currentObject->certObject->x509CertificateAtt.serailNumber.len;
		}
		else {
			if (pTemplate->ulValueLen >= currentObject->certObject->x509CertificateAtt.serailNumber.len) {
				///* Debug */
				if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
					hexData = malloc((currentObject->certObject->x509CertificateAtt.serailNumber.len * 2) + 1);
					if (hexData != NULL) {
						memset(hexData, 0, currentObject->certObject->x509CertificateAtt.serailNumber.len * 2);
						hexData[currentObject->certObject->x509CertificateAtt.serailNumber.len] = '\0';
						for (CK_ULONG i = 0; i < currentObject->certObject->x509CertificateAtt.serailNumber.len; i++) {
							sprintf(&hexData[2 * i], "%02x", currentObject->certObject->x509CertificateAtt.serailNumber.data[i]);
						}
						context->dynamicOut = hexData;
						Write_DebugData(*context, LOG_CONTEXT);
						free(hexData);
						context->dynamicOut = NULL;
					}
				}
				///*      */
				memcpy(pTemplate->pValue, currentObject->certObject->x509CertificateAtt.serailNumber.data, currentObject->certObject->x509CertificateAtt.serailNumber.len);
				pTemplate->ulValueLen = currentObject->certObject->x509CertificateAtt.serailNumber.len;
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		strcpy(context->dataIn, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY");
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
		if (strlen(context->dataIn) == 0)
			strcpy(context->dataIn, "CKA_HASH_OF_ISSUER_PUBLIC_KEY");
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
		if (strlen(context->dataIn) == 0)
			strcpy(context->dataIn, "CKA_JAVA_MIDP_SECURITY_DOMAIN");
	case CKA_CERTIFICATE_CATEGORY:
		if (strlen(context->dataIn) == 0)
			strcpy(context->dataIn, "CKA_CERTIFICATE_CATEGORY");
	case CKA_CHECK_VALUE:
		if (strlen(context->dataIn) == 0)
			strcpy(context->dataIn, "CKA_CHECK_VALUE");
	case CKA_URL:
		if (strlen(context->dataIn) == 0)
			strcpy(context->dataIn, "CKA_URL");
		// TODO
		Write_DebugData(*context, LOG_CONTEXT);
		pTemplate->ulValueLen = (CK_ULONG)-1;
		return CKR_OK;
	case CKA_START_DATE:
		strcpy(context->dataIn, "CKA_START_DATE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_DATE);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_DATE)) {
				memcpy(pTemplate->pValue, &currentObject->certObject->commonCertificateAtt.startDate, sizeof(CK_DATE));
				pTemplate->ulValueLen = sizeof(CK_DATE);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_END_DATE:
		strcpy(context->dataIn, "CKA_END_DATE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_DATE);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_DATE)) {
				memcpy(pTemplate->pValue, &currentObject->certObject->commonCertificateAtt.endDate, sizeof(CK_DATE));
				pTemplate->ulValueLen = sizeof(CK_DATE);
			}
			else {
				;
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}


CK_ULONG  switch_public_private_key_attributes(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, CK_CHAR_PTR token, struct context *context) {
	char * hexData = NULL;
	char str[12];
	switch (pTemplate->type) {
	case CKA_KEY_TYPE:
		strcpy(context->dataIn, "CKA_KEY_TYPE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_KEY_TYPE);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_KEY_TYPE)) {
                if (currentObject->keyObject->commonKeyAtt.keyType == CKK_RSA) {
                    strcpy(context->dataOut, "CKK_RSA");
                } else {
                    strcpy(context->dataOut, "CKK_EC"); // We only have RSA an EC
                }

				Write_DebugData(*context, LOG_CONTEXT);
				*(CK_KEY_TYPE*)pTemplate->pValue = currentObject->keyObject->commonKeyAtt.keyType;
				pTemplate->ulValueLen = sizeof(CK_KEY_TYPE);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_ID:
		strcpy(context->dataIn, "CKA_ID");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = strlen(currentObject->id) * sizeof(char);
		}
		else {
			if (pTemplate->ulValueLen >= strlen(currentObject->id) * sizeof(char)) {
				strncpy(context->dataOut, currentObject->id, MAX_SMALL_DEBUG_BUFFER - 1);
				context->dataOut[MAX_SMALL_DEBUG_BUFFER - 1] = '\0';
				Write_DebugData(*context, LOG_CONTEXT);
				memcpy(pTemplate->pValue, currentObject->id, strlen(currentObject->id) * sizeof(char));
				pTemplate->ulValueLen = strlen(currentObject->id) * sizeof(char);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_START_DATE:
		strcpy(context->dataIn, "CKA_START_DATE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_DATE);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_DATE)) {
				memcpy(pTemplate->pValue, &currentObject->keyObject->commonKeyAtt.startDate, sizeof(CK_DATE));
				pTemplate->ulValueLen = sizeof(CK_DATE);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_END_DATE:
		strcpy(context->dataIn, "CKA_END_DATE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_DATE);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_DATE)) {
				memcpy(pTemplate->pValue, &currentObject->keyObject->commonKeyAtt.endDate, sizeof(CK_DATE));
				pTemplate->ulValueLen = sizeof(CK_DATE);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_DERIVE:
		strcpy(context->dataIn, "CKA_DERIVE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_BBOOL);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
				CK_BBOOL_To_String(currentObject->keyObject->commonKeyAtt.canDerive, context->dataOut);
				Write_DebugData(*context, LOG_CONTEXT);
				*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonKeyAtt.canDerive;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_LOCAL:
		strcpy(context->dataIn, "CKA_LOCAL");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_BBOOL);
		}
		else {
			if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
				CK_BBOOL_To_String(currentObject->keyObject->commonKeyAtt.isLocal, context->dataOut);
				Write_DebugData(*context, LOG_CONTEXT);
				*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonKeyAtt.isLocal;
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_KEY_GEN_MECHANISM:
		strcpy(context->dataIn, "CKA_KEY_GEN_MECHANISM");
		Write_DebugData(*context, LOG_CONTEXT);
		//TODO to implement
		pTemplate->ulValueLen = (CK_ULONG)-1;
		return CKR_OK;
	case CKA_ALLOWED_MECHANISMS:
		strcpy(context->dataIn, "CKA_ALLOWED_MECHANISMS");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = sizeof(CK_MECHANISM_TYPE) * 5; //automatizar size = numero de mechanisms para esta clave * size(CK_MECHANISM_TYPE)
		}
		else {
			CK_ULONG mechanisms[5] = { CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS };
			if (pTemplate->ulValueLen >= sizeof(CK_MECHANISM_TYPE) * 5) {
				strcpy(context->dataOut, "CKM_RSA_PKCS, CKM_RSA_PKCS_OAEP, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS, CKM_SHA512_RSA_PKCS");
				Write_DebugData(*context, LOG_CONTEXT);
				memcpy(pTemplate->pValue, mechanisms, sizeof(CK_MECHANISM_TYPE) * 5);
				pTemplate->ulValueLen = sizeof(CK_MECHANISM_TYPE) * 5;
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	}
	switch (currentObject->type) {
	case CKO_PUBLIC_KEY:
		switch (pTemplate->type) {
		case CKA_SUBJECT:
			strcpy(context->dataIn, "CKA_SUBJECT");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = currentObject->keyObject->commonPublicKeyAtt.subject.len;
			}
			else {
				if (pTemplate->ulValueLen >= currentObject->keyObject->commonPublicKeyAtt.subject.len) {
					///* Debug */
					if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
						hexData = malloc((currentObject->keyObject->commonPublicKeyAtt.subject.len * 2) + 1);
						if (hexData != NULL) {
							memset(hexData, 0, currentObject->keyObject->commonPublicKeyAtt.subject.len * 2);
							hexData[currentObject->keyObject->commonPublicKeyAtt.subject.len] = '\0';
							for (CK_ULONG i = 0; i < currentObject->keyObject->commonPublicKeyAtt.subject.len; i++) {
								sprintf(&hexData[2 * i], "%02x", currentObject->keyObject->commonPublicKeyAtt.subject.data[i]);
							}
							context->dynamicOut = hexData;
							Write_DebugData(*context, LOG_CONTEXT);
							free(hexData);
							context->dynamicOut = NULL;
						}
					}
					///*      */
					memcpy(pTemplate->pValue, currentObject->keyObject->commonPublicKeyAtt.subject.data, currentObject->keyObject->commonPublicKeyAtt.subject.len);
					pTemplate->ulValueLen = currentObject->keyObject->commonPublicKeyAtt.subject.len;
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_ENCRYPT:
			strcpy(context->dataIn, "CKA_ENCRYPT");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPublicKeyAtt.canEncrypt, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPublicKeyAtt.canEncrypt;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_VERIFY:
			strcpy(context->dataIn, "CKA_VERIFY");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {

				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPublicKeyAtt.canVerify, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPublicKeyAtt.canVerify;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_VERIFY_RECOVER:
			strcpy(context->dataIn, "CKA_VERIFY_RECOVER");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPublicKeyAtt.canVerrifyRecover, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPublicKeyAtt.canVerrifyRecover;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_WRAP:
			strcpy(context->dataIn, "CKA_WRAP");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPublicKeyAtt.canWrap, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPublicKeyAtt.canWrap;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_TRUSTED:
			strcpy(context->dataIn, "CKA_TRUSTED");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {

				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPublicKeyAtt.isTrusted, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPublicKeyAtt.isTrusted;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_WRAP_TEMPLATE:
			// TODO
			strcpy(context->dataIn, "CKA_WRAP_TEMPLATE");
			Write_DebugData(*context, LOG_CONTEXT);
			pTemplate->ulValueLen = (CK_ULONG)-1;
			return CKR_OK;
		case CKA_MODULUS:
			strcpy(context->dataIn, "CKA_MODULUS");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = currentObject->keyObject->RSApublicKeyObjectAtt.modulus.len;
			}
			else {
				if (pTemplate->ulValueLen >= currentObject->keyObject->RSApublicKeyObjectAtt.modulus.len) {
					///* Debug */
					if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
						hexData = malloc((currentObject->keyObject->RSApublicKeyObjectAtt.modulus.len * 2) + 1);
						if (hexData != NULL) {
							memset(hexData, 0, currentObject->keyObject->RSApublicKeyObjectAtt.modulus.len * 2);
							hexData[currentObject->keyObject->RSApublicKeyObjectAtt.modulus.len] = '\0';
							for (CK_ULONG i = 0; i < currentObject->keyObject->RSApublicKeyObjectAtt.modulus.len; i++) {
								sprintf(&hexData[2 * i], "%02x", currentObject->keyObject->RSApublicKeyObjectAtt.modulus.data[i]);
							}
							context->dynamicOut = hexData;
							Write_DebugData(*context, LOG_CONTEXT);
							free(hexData);
							context->dynamicOut = NULL;
						}
					}
					///*      */
					memcpy(pTemplate->pValue, currentObject->keyObject->RSApublicKeyObjectAtt.modulus.data, currentObject->keyObject->RSApublicKeyObjectAtt.modulus.len);
					pTemplate->ulValueLen = currentObject->keyObject->RSApublicKeyObjectAtt.modulus.len;
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_MODULUS_BITS:
			strcpy(context->dataIn, "CKA_MODULUS_BITS");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_ULONG);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_ULONG)) {
					if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
						sprintf(str, "%d", currentObject->keyObject->RSApublicKeyObjectAtt.modulusBits);
						strcpy(context->dataOut, str);
						Write_DebugData(*context, LOG_CONTEXT);
					}
					*(CK_ULONG*)pTemplate->pValue = currentObject->keyObject->RSApublicKeyObjectAtt.modulusBits;
					pTemplate->ulValueLen = sizeof(CK_ULONG);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_PUBLIC_EXPONENT:
			strcpy(context->dataIn, "CKA_PUBLIC_EXPONENT");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.len;
			}
			else {
				if (pTemplate->ulValueLen >= currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.len) {
					///* Debug */
					if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
						hexData = malloc((currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.len * 2) + 1);
						if (hexData != NULL) {
							memset(hexData, 0, currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.len * 2);
							hexData[currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.len] = '\0';
							for (CK_ULONG i = 0; i < currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.len; i++) {
								sprintf(&hexData[2 * i], "%02x", currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.data[i]);
							}
							context->dynamicOut = hexData;
							Write_DebugData(*context, LOG_CONTEXT);
							free(hexData);
							context->dynamicOut = NULL;
						}
					}
					///*      */
					memcpy(pTemplate->pValue, currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.data, currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.len);
					pTemplate->ulValueLen = currentObject->keyObject->RSApublicKeyObjectAtt.publicExponent.len;
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
        case CKA_EC_PARAMS:
            strcpy(context->dataIn, "CKA_EC_PARAMS");
            Write_DebugData(*context, LOG_CONTEXT);
            if (pTemplate->pValue == NULL) {
                pTemplate->ulValueLen = currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len;
            } else {
                if (pTemplate->ulValueLen >= currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len) {
                    ///* Debug */
                    if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
                        hexData = malloc((currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len * 2) + 1);
                        if (hexData != NULL) {
                            memset(hexData, 0, currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len * 2);
                            hexData[currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len] = '\0';
                            for (CK_ULONG i = 0; i < currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len; i++) {
                                sprintf(&hexData[2 * i], "%02x", currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.data[i]);
                            }
                            context->dynamicOut = hexData;
                            Write_DebugData(*context, LOG_CONTEXT);
                            free(hexData);
                            context->dynamicOut = NULL;
                        }
                    }
                    ///*      */
                    memcpy(pTemplate->pValue, currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.data, currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len);
                    pTemplate->ulValueLen = currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len;
                }
                else {
                    return CKR_BUFFER_TOO_SMALL;
                }
            }
            return CKR_OK;
		default:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	case CKO_PRIVATE_KEY:
		switch (pTemplate->type) {
		case CKA_SUBJECT:
			strcpy(context->dataIn, "CKA_SUBJECT");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = currentObject->keyObject->commonPrivateKeyAtt.subject.len;
			}
			else {
				if (pTemplate->ulValueLen >= currentObject->keyObject->commonPrivateKeyAtt.subject.len) {
					///* Debug */
					if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
						hexData = malloc((currentObject->keyObject->commonPrivateKeyAtt.subject.len * 2) + 1);
						if (hexData != NULL) {
							memset(hexData, 0, currentObject->keyObject->commonPrivateKeyAtt.subject.len * 2);
							hexData[currentObject->keyObject->commonPrivateKeyAtt.subject.len] = '\0';
							for (CK_ULONG i = 0; i < currentObject->keyObject->commonPrivateKeyAtt.subject.len; i++) {
								sprintf(&hexData[2 * i], "%02x", currentObject->keyObject->commonPrivateKeyAtt.subject.data[i]);
							}
							context->dynamicOut = hexData;
							Write_DebugData(*context, LOG_CONTEXT);
							free(hexData);
							context->dynamicOut = NULL;
						}
					}
					///*      */
					memcpy(pTemplate->pValue, currentObject->keyObject->commonPrivateKeyAtt.subject.data, currentObject->keyObject->commonPrivateKeyAtt.subject.len);
					pTemplate->ulValueLen = currentObject->keyObject->commonPrivateKeyAtt.subject.len;
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_SENSITIVE:
			strcpy(context->dataIn, "CKA_SENSITIVE");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.isSensitive, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.isSensitive;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_DECRYPT:
			strcpy(context->dataIn, "CKA_DECRYPT");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {

				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.canDecrypt, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.canDecrypt;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_SIGN:
			strcpy(context->dataIn, "CKA_SIGN");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.canSign, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.canSign;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_SIGN_RECOVER:
			strcpy(context->dataIn, "CKA_SIGN_RECOVER");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {

				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.canSignRecover, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.canSignRecover;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_UNWRAP:
			strcpy(context->dataIn, "CKA_UNWRAP");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.canUnwrap, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.canUnwrap;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_EXTRACTABLE:
			strcpy(context->dataIn, "CKA_EXTRACTABLE");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.isExtractable, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.isExtractable;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_ALWAYS_SENSITIVE:
			strcpy(context->dataIn, "CKA_ALWAYS_SENSITIVE");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.isAlwaysSensitive, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.isAlwaysSensitive;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_NEVER_EXTRACTABLE:
			strcpy(context->dataIn, "CKA_NEVER_EXTRACTABLE");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {

				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.isNeverExtractable, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.isNeverExtractable;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_WRAP_WITH_TRUSTED:
			strcpy(context->dataIn, "CKA_WRAP_WITH_TRUSTED");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {
				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.beWrapWithTrusted, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.beWrapWithTrusted;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_UNWRAP_TEMPLATE:
			strcpy(context->dataIn, "CKA_UNWRAP_TEMPLATE");
			Write_DebugData(*context, LOG_CONTEXT);
			pTemplate->ulValueLen = (CK_ULONG)-1;
			return CKR_OK;
		case CKA_ALWAYS_AUTHENTICATE:
			strcpy(context->dataIn, "CKA_ALWAYS_AUTHENTICATE");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = sizeof(CK_BBOOL);
			}
			else {

				if (pTemplate->ulValueLen >= sizeof(CK_BBOOL)) {
					CK_BBOOL_To_String(currentObject->keyObject->commonPrivateKeyAtt.isAlwaysAuthenticate, context->dataOut);
					Write_DebugData(*context, LOG_CONTEXT);
					*(CK_BBOOL*)pTemplate->pValue = currentObject->keyObject->commonPrivateKeyAtt.isAlwaysAuthenticate;
					pTemplate->ulValueLen = sizeof(CK_BBOOL);
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_MODULUS:
			strcpy(context->dataIn, "CKA_MODULUS");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.len;
			}
			else {
				if (pTemplate->ulValueLen >= currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.len) {
					/* Debug */
					if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
						hexData = malloc((currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.len * 2) + 1);
						if (hexData != NULL) {
							memset(hexData, 0, currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.len * 2);
							hexData[currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.len] = '\0';
							for (CK_ULONG i = 0; i < currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.len; i++) {
								sprintf(&hexData[2 * i], "%02x", currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.data[i]);
							}
							context->dynamicOut = hexData;
							Write_DebugData(*context, LOG_CONTEXT);
							free(hexData);
							context->dynamicOut = NULL;
						}
					}
					/*      */
					memcpy(pTemplate->pValue, currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.data, currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.len);
					pTemplate->ulValueLen = currentObject->keyObject->RSAPrivateKeyObjectAtt.modulus.len;
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_PUBLIC_EXPONENT:
			strcpy(context->dataIn, "CKA_PUBLIC_EXPONENT");
			Write_DebugData(*context, LOG_CONTEXT);
			if (pTemplate->pValue == NULL) {
				pTemplate->ulValueLen = currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.len;
			}
			else {
				if (pTemplate->ulValueLen >= currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.len) {
					/* Debug */
					if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
						hexData = malloc((currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.len * 2) + 1);
						if (hexData != NULL) {
							memset(hexData, 0, currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.len * 2);
							hexData[currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.len] = '\0';
							for (CK_ULONG i = 0; i < currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.len; i++) {
								sprintf(&hexData[2 * i], "%02x", currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.data[i]);
							}
							context->dynamicOut = hexData;
							Write_DebugData(*context, LOG_CONTEXT);
							free(hexData);
							context->dynamicOut = NULL;
						}
					}
					/*      */
					memcpy(pTemplate->pValue, currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.data, currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.len);
					pTemplate->ulValueLen = currentObject->keyObject->RSAPrivateKeyObjectAtt.publicExponent.len;
				}
				else {
					return CKR_BUFFER_TOO_SMALL;
				}
			}
			return CKR_OK;
		case CKA_PRIVATE_EXPONENT:
			strcpy(context->dataIn, "CKA_PUBLIC_EXPONENT");
			Write_DebugData(*context, LOG_CONTEXT);
			return CKR_ATTRIBUTE_SENSITIVE;
		case CKA_PRIME_1:
			strcpy(context->dataIn, "CKA_PRIME_1");
			Write_DebugData(*context, LOG_CONTEXT);
			return CKR_ATTRIBUTE_SENSITIVE;
		case CKA_PRIME_2:
			strcpy(context->dataIn, "CKA_PRIME_2");
			Write_DebugData(*context, LOG_CONTEXT);
			return CKR_ATTRIBUTE_SENSITIVE;
		case CKA_EXPONENT_1:
			strcpy(context->dataIn, "CKA_EXPONENT_1");
			Write_DebugData(*context, LOG_CONTEXT);
			return CKR_ATTRIBUTE_SENSITIVE;
		case CKA_EXPONENT_2:
			strcpy(context->dataIn, "CKA_EXPONENT_2");
			Write_DebugData(*context, LOG_CONTEXT);
			return CKR_ATTRIBUTE_SENSITIVE;
		case CKA_COEFFICIENT:
			strcpy(context->dataIn, "CKA_COEFFICIENT");
			Write_DebugData(*context, LOG_CONTEXT);
			return CKA_COEFFICIENT;
        case CKA_EC_PARAMS:
            strcpy(context->dataIn, "CKA_EC_PARAMS");
            Write_DebugData(*context, LOG_CONTEXT);
            if (pTemplate->pValue == NULL) {
                pTemplate->ulValueLen = currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len;
            } else {
                if (pTemplate->ulValueLen >= currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len) {
                    ///* Debug */
                    if (LOG_CONTEXT.DEBUG_LEVEL == TRACE) {
                        hexData = malloc((currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len * 2) + 1);
                        if (hexData != NULL) {
                            memset(hexData, 0, currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len * 2);
                            hexData[currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len] = '\0';
                            for (CK_ULONG i = 0; i < currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len; i++) {
                                sprintf(&hexData[2 * i], "%02x", currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.data[i]);
                            }
                            context->dynamicOut = hexData;
                            Write_DebugData(*context, LOG_CONTEXT);
                            free(hexData);
                            context->dynamicOut = NULL;
                        }
                    }
                    ///*      */
                    memcpy(pTemplate->pValue, currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.data, currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len);
                    pTemplate->ulValueLen = currentObject->keyObject->ECpublicKeyObjectAtt.ecParams.len;
                }
                else {
                    return CKR_BUFFER_TOO_SMALL;
                }
            }
            return CKR_OK;
		default:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	return CKR_ATTRIBUTE_TYPE_INVALID;
}


CK_ULONG  switch_secret_attributes(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, struct context *context) {
	switch (pTemplate->type) {
	case CKA_APPLICATION:
		strcpy(context->dataIn, "CKA_APPLICATION");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = strlen(currentObject->dataObject->application);
		}
		else {
			if (pTemplate->ulValueLen >= strlen(currentObject->dataObject->application)) {
				/* Debug */
				/*      */
				memcpy(pTemplate->pValue, currentObject->dataObject->application, strlen(currentObject->dataObject->application));
				pTemplate->ulValueLen = strlen(currentObject->dataObject->application);
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_OBJECT_ID:
		strcpy(context->dataIn, "CKA_OBJECT_ID");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = currentObject->dataObject->objectId.len;
		}
		else {
			if (pTemplate->ulValueLen >= currentObject->dataObject->objectId.len) {
				/* Debug */
				/*      */
				memcpy(pTemplate->pValue, currentObject->dataObject->objectId.data, currentObject->dataObject->objectId.len);
				pTemplate->ulValueLen = currentObject->dataObject->objectId.len;
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	case CKA_VALUE:
		strcpy(context->dataIn, "CKA_VALUE");
		Write_DebugData(*context, LOG_CONTEXT);
		if (pTemplate->pValue == NULL) {
			pTemplate->ulValueLen = currentObject->dataObject->value.len;
		}
		else {
			if (pTemplate->ulValueLen >= currentObject->dataObject->value.len) {
				/* Debug */
				/*      */
				memcpy(pTemplate->pValue, currentObject->dataObject->value.data, currentObject->dataObject->value.len);
				pTemplate->ulValueLen = currentObject->dataObject->value.len;
			}
			else {
				return CKR_BUFFER_TOO_SMALL;
			}
		}
		return CKR_OK;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}

CK_ULONG X509_cert_data(char* base64url_cer, X509  **cert) {
	int size_base64EncoderCer = sizeof(char) *(strlen("-----BEGIN CERTIFICATE-----\n") + strlen(base64url_cer) + strlen("\n-----END CERTIFICATE-----") + 1);
	char * base64EncodedCer = (char*)malloc(size_base64EncoderCer);
	if (base64EncodedCer == NULL) return CKR_FUNCTION_FAILED;
	strcpy(base64EncodedCer, "-----BEGIN CERTIFICATE-----\n");
	strcat(base64EncodedCer, base64url_cer);
	strcat(base64EncodedCer, "\n-----END CERTIFICATE-----");
	BIO   *reqbio = NULL;
	X509  *cert_aux = NULL;
	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.   *
	* ----------------------------------------------------------  */
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	/* ---------------------------------------------------------- *
	* Load the request data in a BIO, then in a x509_REQ struct.  *
	* ----------------------------------------------------------  */
	reqbio = BIO_new_mem_buf(base64EncodedCer, -1);
	if (!(cert_aux = PEM_read_bio_X509(reqbio, NULL, NULL, NULL))) {
		BIO_free_all(reqbio);
		return CKR_FUNCTION_FAILED;
	}
	*cert = cert_aux;
	/* ---------------------------------------------------------- *
	* Free up all structures                                      *
	* ----------------------------------------------------------  */
	//void EVP_cleanup(void);
	//X509_free(cert);
	BIO_free_all(reqbio);
	return CKR_OK;
}


CK_ULONG getAttributeInspector(CK_ATTRIBUTE_PTR pTemplate, struct objects *currentObject, CK_CHAR_PTR token, struct context *context) {
	CK_ULONG res;
	/* Common Object attributes */
	res = switch_common_attributes(pTemplate, currentObject, context);
	if (res != CKR_OK) {
		if (res == CKR_BUFFER_TOO_SMALL) return CKR_BUFFER_TOO_SMALL;
		/* Specific Object attributes */
		switch (currentObject->type) {
		case CKO_CERTIFICATE:
			res = switch_certificate_attributes(pTemplate, currentObject, token, context);
			if (res != CKR_OK)
				return res;
			break;
		case CKO_DATA:
			res = switch_secret_attributes(pTemplate, currentObject, context);
			if (res != CKR_OK)
				return res;
			break;
		case CKO_PUBLIC_KEY:
		case CKO_PRIVATE_KEY:
			res = switch_public_private_key_attributes(pTemplate, currentObject, token, context);
			if (res != CKR_OK)
				return res;
			break;
		default:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}
	return CKR_OK;
}

CK_ULONG objectUpdate(CK_ATTRIBUTE_PTR *pTemplate, CK_ULONG ulCount, struct objects *currentObject, struct objects ** cacheTokenObect, CK_CHAR_PTR token, struct context *context) {
	CK_ULONG result, error;
	struct update_key *updatekey;
	struct key_attributes *keyAttributes;
	struct key_data_response *keyDataResponse = NULL;
	struct secret_creation_data *secretUpdateData;
	struct secret_update_response *secretUpdatedResponse = NULL;
	struct cert_attributes *secretAttributes;
	switch (currentObject->type) {
		return CKR_ATTRIBUTE_TYPE_INVALID; // TODO Currently not supported
	case CKO_CERTIFICATE:
	case CKO_DATA:
		/*secretAttributes = calloc(1, sizeof(struct cert_attributes));*/
		/*if (secretAttributes == NULL) return CKR_HOST_MEMORY;*/
		secretAttributes = NULL;
		secretUpdateData = Store_SecretCreationData(token, HOST, currentObject->id, secretAttributes, "", NULL, NULL);
		if (secretUpdateData == NULL) return CKR_HOST_MEMORY;
		for (int i = 0; i < ulCount; i++) {
			result = UpdateSecret(*pTemplate[i], secretUpdateData, currentObject, FALSE);
			if (result != CKR_OK) {
				Free_SecretCreationData(secretUpdateData);
				return result;
			}
		}
		result = Update_Secret(secretUpdateData, &secretUpdatedResponse);
		Free_SecretUpdateResponse(secretUpdatedResponse);
		if (result != HTTP_OK) {
			Free_SecretCreationData(secretUpdateData);
			if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
			else if (result < HTTP_OK) error = CKR_DEVICE_REMOVED;
			else if (result == UNAUTHORIZED) error = CKR_USER_NOT_LOGGED_IN;
			else if (result == FORBIDDEN) error = CKR_GENERAL_ERROR;
			else if (result == NOT_FOUND) error = CKR_DEVICE_REMOVED;
			else if (result == BAD_REQUEST) error = CKR_DATA_INVALID;
			else error = CKR_FUNCTION_FAILED;
			return error;
		}
		for (int i = 0; i < ulCount; i++) {
			result = UpdateSecret(*pTemplate[i], secretUpdateData, currentObject, TRUE);
		}
		Free_SecretCreationData(secretUpdateData);
		return CKR_OK;
	case CKO_PUBLIC_KEY:
	case CKO_PRIVATE_KEY:
		keyAttributes = calloc(1, sizeof(struct key_attributes));
		if (keyAttributes == NULL) return CKR_HOST_MEMORY;
		updatekey = Store_UpdateKeyData(HOST, currentObject->id, token, NULL, keyAttributes);
		if (updatekey == NULL) return CKR_HOST_MEMORY;
		result = fillKeyOps(updatekey->key_ops, currentObject, cacheTokenObect);
		if (result != CKR_OK) {
			Free_UpdateKeyData(updatekey);
			return result;
		}
		for (int i = 0; i < ulCount; i++) {
			result = UpdateKey(*pTemplate[i], updatekey, currentObject, FALSE);
			if (result != CKR_OK) {
				Free_UpdateKeyData(updatekey);
				return result;
			}
		}
		result = Update_key(updatekey, &keyDataResponse);
		Free_KeyCreationResponse(keyDataResponse);
		if (result != HTTP_OK) {
			Free_UpdateKeyData(updatekey);
			if (result == ALLOCATE_ERROR) error = CKR_HOST_MEMORY;
			else if (result < HTTP_OK) error = CKR_DEVICE_REMOVED;
			else if (result == UNAUTHORIZED) error = CKR_USER_NOT_LOGGED_IN;
			else if (result == FORBIDDEN) error = CKR_GENERAL_ERROR;
			else if (result == NOT_FOUND) error = CKR_DEVICE_REMOVED;
			else if (result == BAD_REQUEST) error = CKR_DATA_INVALID;
			else error = CKR_FUNCTION_FAILED;
			return error;
		}
		for (int i = 0; i < ulCount; i++) {
			result = UpdateKey(*pTemplate[i], updatekey, currentObject, TRUE);
		}
		Free_UpdateKeyData(updatekey);
		return CKR_OK;
	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}

CK_ULONG fillKeyOps(char *key_ops[], struct objects *currentObject, struct objects ** cacheTokenObect) {
	BOOL exist = FALSE;
	short indexOps = 0;
	short index;
	char operation[15];
	static const char string[] = "sign verify encrypt decrypt wrapKey unwrapKey ";
	char ops[STRLEN(string)] = "";
	struct objects * otherKeyPart;
	if (currentObject->type == CKO_PRIVATE_KEY) {
		exist = Exist_TokenObject(*cacheTokenObect, currentObject->id, CKO_PUBLIC_KEY, &otherKeyPart);
		if (!exist) return CKR_FUNCTION_FAILED;
		if (currentObject->keyObject->commonPrivateKeyAtt.canSign == TRUE) {
			strcat(ops, "sign ");
		}
		if (otherKeyPart->keyObject->commonPublicKeyAtt.canVerify == TRUE) {
			strcat(ops, "verify ");
		}
		if (otherKeyPart->keyObject->commonPublicKeyAtt.canEncrypt == TRUE) {
			strcat(ops, "encrypt ");
		}
		if (currentObject->keyObject->commonPrivateKeyAtt.canDecrypt == TRUE) {
			strcat(ops, "decrypt ");
		}
		if (otherKeyPart->keyObject->commonPublicKeyAtt.canWrap == TRUE) {
			strcat(ops, "wrapKey ");
		}
		if (currentObject->keyObject->commonPrivateKeyAtt.canUnwrap == TRUE) {
			strcat(ops, "unwrapKey ");
		}
	}
	else {
		exist = Exist_TokenObject(*cacheTokenObect, currentObject->id, CKO_PRIVATE_KEY, &otherKeyPart);
		if (!exist) return CKR_FUNCTION_FAILED;
		if (otherKeyPart->keyObject->commonPrivateKeyAtt.canSign == TRUE) {
			strcat(ops, "sign ");
		}
		if (currentObject->keyObject->commonPublicKeyAtt.canVerify == TRUE) {
			strcat(ops, "verify ");
		}
		if (currentObject->keyObject->commonPublicKeyAtt.canEncrypt == TRUE) {
			strcat(ops, "encrypt ");
		}
		if (otherKeyPart->keyObject->commonPrivateKeyAtt.canDecrypt == TRUE) {
			strcat(ops, "decrypt ");
		}
		if (currentObject->keyObject->commonPublicKeyAtt.canWrap == TRUE) {
			strcat(ops, "wrapKey ");
		}
		if (otherKeyPart->keyObject->commonPrivateKeyAtt.canUnwrap == TRUE) {
			strcat(ops, "unwrapKey ");
		}
	}
	if (strlen(ops) > 0) {
		for (int i = 0; i < MAX_OPS; i++) {
			memset(operation, 0, 15);
			index = 0;
			while (ops[indexOps] != ' ' && ops[indexOps] != '\0') {
				operation[index] = ops[indexOps];
				index++;
				indexOps++;
			}
			operation[index] = '\0';
			key_ops[i] = _strdup(operation);
			if (key_ops[i] == NULL) goto cleanup;
			indexOps++;
			if (ops[indexOps] == '\0') break;
		}
	}
	return CKR_OK;
cleanup:
	for (int i = 0; i < MAX_OPS; i++) {
		if (key_ops[i] != NULL) free(key_ops[i]);
	}
	return CKR_HOST_MEMORY;
}

CK_ULONG UpdateKey(CK_ATTRIBUTE pTemplate, struct update_key *updateKey, struct objects *currentObject, BOOL consolidate) {
	int index;
	BOOL exist = FALSE;
	switch (currentObject->type) {
	case CKO_PRIVATE_KEY:
		switch (pTemplate.type) {
		case CKA_DECRYPT:
			if (consolidate) {
				currentObject->keyObject->commonPrivateKeyAtt.canDecrypt = *(CK_BBOOL*)pTemplate.pValue;
				return CKR_OK;
			}
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (updateKey->key_ops[i] == NULL) break;
					if (!strcmp(updateKey->key_ops[i], "decrypt")) {
						exist = TRUE;
						break;
					}
					index++;
				}
				if ((*(CK_BBOOL*)pTemplate.pValue == CK_FALSE) && exist == TRUE) {
					free(updateKey->key_ops[index]);
					while (index < MAX_OPS) {
						updateKey->key_ops[index] = updateKey->key_ops[index + 1];
						index++;
					}
					updateKey->key_ops[index - 1] = NULL;
				}
				else if ((*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) && exist == FALSE) {
					updateKey->key_ops[index] = _strdup("decrypt");
					if (updateKey->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_SIGN:
			if (consolidate) {
				currentObject->keyObject->commonPrivateKeyAtt.canSign = *(CK_BBOOL*)pTemplate.pValue;
				return CKR_OK;
			}
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (updateKey->key_ops[i] == NULL) break;
					if (!strcmp(updateKey->key_ops[i], "sign")) {
						exist = TRUE;
						break;
					}
					index++;
				}
				if ((*(CK_BBOOL*)pTemplate.pValue == CK_FALSE) && exist == TRUE) {
					free(updateKey->key_ops[index]);
					while (index < MAX_OPS) {
						updateKey->key_ops[index] = updateKey->key_ops[index + 1];
						index++;
					}
					updateKey->key_ops[index - 1] = NULL;
				}
				else if ((*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) && exist == FALSE) {
					updateKey->key_ops[index] = _strdup("sign");
					if (updateKey->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_UNWRAP:
			if (consolidate) {
				currentObject->keyObject->commonPrivateKeyAtt.canUnwrap = *(CK_BBOOL*)pTemplate.pValue;
				return CKR_OK;
			}
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (updateKey->key_ops[i] == NULL) break;
					if (!strcmp(updateKey->key_ops[i], "unwrapKey")) {
						exist = TRUE;
						break;
					}
					index++;
				}
				if ((*(CK_BBOOL*)pTemplate.pValue == CK_FALSE) && exist == TRUE) {
					free(updateKey->key_ops[index]);
					while (index < MAX_OPS) {
						updateKey->key_ops[index] = updateKey->key_ops[index + 1];
						index++;
					}
					updateKey->key_ops[index - 1] = NULL;
				}
				else if ((*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) && exist == FALSE) {
					updateKey->key_ops[index] = _strdup("unwrapKey");
					if (updateKey->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		}
	case CKO_PUBLIC_KEY:
		switch (pTemplate.type) {
		case CKA_ENCRYPT:
			if (consolidate) {
				currentObject->keyObject->commonPublicKeyAtt.canEncrypt = *(CK_BBOOL*)pTemplate.pValue;
				return CKR_OK;
			}
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (updateKey->key_ops[i] == NULL) break;
					if (!strcmp(updateKey->key_ops[i], "encrypt")) {
						exist = TRUE;
						break;
					}
					index++;
				}
				if ((*(CK_BBOOL*)pTemplate.pValue == CK_FALSE) && exist == TRUE) {
					free(updateKey->key_ops[index]);
					while (index < MAX_OPS) {
						updateKey->key_ops[index] = updateKey->key_ops[index + 1];
						index++;
					}
					updateKey->key_ops[index - 1] = NULL;
				}
				else if ((*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) && exist == FALSE) {
					updateKey->key_ops[index] = _strdup("encrypt");
					if (updateKey->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_VERIFY:
			if (consolidate) {
				currentObject->keyObject->commonPublicKeyAtt.canVerify = *(CK_BBOOL*)pTemplate.pValue;
				return CKR_OK;
			}
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (updateKey->key_ops[i] == NULL) break;
					if (!strcmp(updateKey->key_ops[i], "verify")) {
						exist = TRUE;
						break;
					}
					index++;
				}
				if ((*(CK_BBOOL*)pTemplate.pValue == CK_FALSE) && exist == TRUE) {
					free(updateKey->key_ops[index]);
					while (index < MAX_OPS) {
						updateKey->key_ops[index] = updateKey->key_ops[index + 1];
						index++;
					}
					updateKey->key_ops[index - 1] = NULL;
				}
				else if ((*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) && exist == FALSE) {
					updateKey->key_ops[index] = _strdup("verify");
					if (updateKey->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_WRAP:
			if (consolidate) {
				currentObject->keyObject->commonPublicKeyAtt.canWrap = *(CK_BBOOL*)pTemplate.pValue;
				return CKR_OK;
			}
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (updateKey->key_ops[i] == NULL) break;
					if (!strcmp(updateKey->key_ops[i], "wrapKey")) {
						exist = TRUE;
						break;
					}
					index++;
				}
				if ((*(CK_BBOOL*)pTemplate.pValue == CK_FALSE) && exist == TRUE) {
					free(updateKey->key_ops[index]);
					while (index < MAX_OPS) {
						updateKey->key_ops[index] = updateKey->key_ops[index + 1];
						index++;
					}
					updateKey->key_ops[index - 1] = NULL;
				}
				else if ((*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) && exist == FALSE) {
					updateKey->key_ops[index] = _strdup("wrapKey");
					if (updateKey->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		}
	}
	switch (pTemplate.type) {
	case CKA_START_DATE:
		if (consolidate) {
			currentObject->keyObject->commonKeyAtt.startDate = *(CK_DATE*)pTemplate.pValue;
			return CKR_OK;
		}
		updateKey->attributes->nbf = Ck_Date2unixtime(*(CK_DATE*)pTemplate.pValue);
		return CKR_OK;
	case CKA_END_DATE:
		if (consolidate) {
			currentObject->keyObject->commonKeyAtt.endDate = *(CK_DATE*)pTemplate.pValue;
			return CKR_OK;
		}
		updateKey->attributes->exp = Ck_Date2unixtime(*(CK_DATE*)pTemplate.pValue);
		return CKR_OK;
	default:
		return CKR_ATTRIBUTE_READ_ONLY;
	}
}

CK_ULONG UpdateSecret(CK_ATTRIBUTE pTemplate, struct secret_creation_data *updateSecret, struct objects *currentObject, BOOL consolidate) {
	int index;
	BOOL exist = FALSE;
	if (currentObject->type != CKO_DATA) return CKR_ARGUMENTS_BAD;
	switch (pTemplate.type) {
	case CKA_DECRYPT:
	case CKA_TOKEN:
	case CKA_PRIVATE:
	case CKA_MODIFIABLE:
		return CKR_OK;
	case CKA_LABEL: //The label is created by de library
		return CKR_OK;
	case CKA_APPLICATION:
		if ((pTemplate.pValue == NULL) || (pTemplate.ulValueLen <= 0) || (pTemplate.ulValueLen > (MAX_CONTENT_TYPE - 1))) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		if (consolidate) {
			if (currentObject->dataObject->application != NULL) {
				free(currentObject->dataObject->application);
			}
			currentObject->dataObject->application = malloc(pTemplate.ulValueLen + 1);
			if (currentObject->dataObject->application == NULL) return CKR_HOST_MEMORY;
			memcpy(currentObject->dataObject->application, (CK_CHAR*)pTemplate.pValue, pTemplate.ulValueLen);
			currentObject->dataObject->application[pTemplate.ulValueLen] = '\0';
			return CKR_OK;
		}
		else {
			strncpy(updateSecret->contentType, (CK_CHAR*)pTemplate.pValue, pTemplate.ulValueLen);
			updateSecret->contentType[pTemplate.ulValueLen] = '\0';
		}
		return CKR_OK;
	case CKA_OBJECT_ID:
		return CKR_ATTRIBUTE_READ_ONLY;
	case CKA_VALUE:
		return CKR_ATTRIBUTE_READ_ONLY;
	default:
		return CKR_TEMPLATE_INCONSISTENT;
	}
}

CK_ULONG ObjectCreator(struct objects **newObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_ULONG type, CK_CHAR_PTR token, struct objects ** cacheTokenObect) {
	CK_ULONG result;
	switch (type) {
	case CKO_CERTIFICATE:
		break;
	case CKO_PRIVATE_KEY:
		break;
	case CKO_PUBLIC_KEY:
		break;
	case CKO_DATA:
		result = CKR_OK;
		struct dataObject *dataObject;
		struct secret_item_data *secretData = NULL_PTR;
		struct secret_creation_data* petitionData = calloc(1, sizeof(struct secret_creation_data));
		if (petitionData == NULL) return CKR_HOST_MEMORY;
		for (int i = 0; i < ulCount; i++) {
			result = Template2JWS(&pTemplate[i], &petitionData);
			if (result != CKR_OK) {
				Free_SecretCreationData(petitionData);
				return result;
			}
		}
		result = SecretMetadata_Checker(petitionData);
		if (result != CKR_OK) {
			Free_SecretCreationData(petitionData);
			return result;
		}
		petitionData->token = _strdup(token);
		if (petitionData->token == NULL) {
			Free_SecretCreationData(petitionData);
			return CKR_HOST_MEMORY;
		}
		petitionData->host = _strdup(HOST);
		if (petitionData->token == NULL) {
			Free_SecretCreationData(petitionData);
			return CKR_HOST_MEMORY;
		}
		result = Create_Secret(petitionData, &secretData);
		Free_SecretCreationData(petitionData);
		if (result != HTTP_OK) {
			Free_SecretItemsData(secretData);
			if (result == ALLOCATE_ERROR) result = CKR_HOST_MEMORY;
			else if (result < HTTP_OK) result = CKR_TOKEN_NOT_PRESENT;
			else if (result == UNAUTHORIZED) result = CKR_PIN_INCORRECT;
			else if (result == FORBIDDEN) result = CKR_GENERAL_ERROR;
			else if (result == NOT_FOUND) result = CKR_TOKEN_NOT_PRESENT;
			else if (result == BAD_REQUEST) result = CKR_TEMPLATE_INCONSISTENT;
			else result = CKR_FUNCTION_FAILED;
			return result;
		}
		dataObject = AzurePKCS11DataObjectTranslator(secretData);
		if (dataObject == NULL) {
			Free_SecretItemsData(secretData);
			return CKR_HOST_MEMORY;
		}
		struct objects *pkcs11DataObject = New_TokenObject(cacheTokenObect, secretData->secretCommonItem.id, CKO_DATA);
		Free_SecretItemsData(secretData);
		if (pkcs11DataObject == NULL) {
			Free_DataObject(dataObject);
			return CKR_HOST_MEMORY;
		}
		pkcs11DataObject->dataObject = dataObject;
		*newObject = pkcs11DataObject;
		break;
	default:
		return CKR_TEMPLATE_INCONSISTENT;
	}
	return CKR_OK;
}

CK_ULONG Template2JWS(CK_ATTRIBUTE_PTR pTemplate, struct secret_creation_data **secretCreationData) {
	switch (pTemplate->type) {
	case CKA_CLASS:
		if (pTemplate->pValue == NULL || pTemplate->ulValueLen != sizeof(CK_OBJECT_CLASS)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			if (*(CK_OBJECT_CLASS*)pTemplate->pValue != CKO_DATA)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		return CKR_OK;
	case CKA_TOKEN:
		/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
		return CKR_ATTRIBUTE_VALUE_INVALID;
		}*/
		return CKR_OK;
	case CKA_PRIVATE:
		/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
		return CKR_ATTRIBUTE_VALUE_INVALID;
		}*/
		return CKR_OK;
	case CKA_MODIFIABLE:
		/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
		return CKR_ATTRIBUTE_VALUE_INVALID;
		}*/
		return CKR_OK;
	case CKA_LABEL: //The label is created by de library
		if ((pTemplate->pValue == NULL) || (pTemplate->ulValueLen <= 0) || (pTemplate->ulValueLen > (MAX_ID_SIZE - 1))) {
			return CKR_TEMPLATE_INCONSISTENT;
		}
		else {
			if ((*secretCreationData)->id[0] == '\0') {
				strncpy((*secretCreationData)->id, pTemplate->pValue, pTemplate->ulValueLen);
				(*secretCreationData)->id[pTemplate->ulValueLen] = '\0';
			}
		}
		return CKR_OK;
	case CKA_APPLICATION:
		if ((pTemplate->pValue == NULL) || (pTemplate->ulValueLen <= 0) || (pTemplate->ulValueLen > (MAX_CONTENT_TYPE - 1))) {
			return CKR_TEMPLATE_INCONSISTENT;
		}
		else {
			strncpy((*secretCreationData)->contentType, pTemplate->pValue, pTemplate->ulValueLen);
			(*secretCreationData)->contentType[pTemplate->ulValueLen] = '\0';
		}
		return CKR_OK;
	case CKA_OBJECT_ID:
		if ((pTemplate->pValue == NULL) || (pTemplate->ulValueLen <= 0) || (pTemplate->ulValueLen > (MAX_ID_SIZE - 1))) {
			return CKR_TEMPLATE_INCONSISTENT;
		}
		else {
			strncpy((*secretCreationData)->id, pTemplate->pValue, pTemplate->ulValueLen);
			(*secretCreationData)->contentType[pTemplate->ulValueLen] = '\0';
		}
		return CKR_OK;
	case CKA_VALUE:
		if ((pTemplate->pValue == NULL) || (pTemplate->ulValueLen <= 0) || (pTemplate->ulValueLen > (MAX_SECRET_SIZE - 1))) {
			return CKR_TEMPLATE_INCONSISTENT;
		}
		else {
			(*secretCreationData)->value = malloc(pTemplate->ulValueLen + 1);
			if ((*secretCreationData)->value == NULL) return CKR_HOST_MEMORY;
			strncpy((*secretCreationData)->value, pTemplate->pValue, pTemplate->ulValueLen);
			(*secretCreationData)->value[pTemplate->ulValueLen] = '\0';
		}
		return CKR_OK;
	default:
		return CKR_TEMPLATE_INCONSISTENT;
	}
}

CK_ULONG Template2JWK(CK_ATTRIBUTE pTemplate, struct key_data *keyData, CK_ULONG type, CK_MECHANISM_TYPE mechanism) {
	int index;
	char * stringInt;
	time_t date;
	//common storage object attributes
	switch (pTemplate.type) {
	case CKA_CLASS:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_OBJECT_CLASS)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			if (*(CK_OBJECT_CLASS*)pTemplate.pValue != type)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		return CKR_OK;
	case CKA_TOKEN:
		/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}*/
		return CKR_OK;
	case CKA_PRIVATE:
		/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}*/
		return CKR_OK;
	case CKA_MODIFIABLE:
		/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}*/
		return CKR_OK;
	case CKA_LABEL: //The label is created by de library
		return CKR_OK;
	}
	//Common Key Attributes
	switch (pTemplate.type) {
	case CKA_KEY_TYPE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_KEY_TYPE)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			if (*(CK_KEY_TYPE*)pTemplate.pValue == CKK_RSA) {
				if (HSM_PROCESSED == FALSE) {
					keyData->keytype = _strdup("RSA");
					if (keyData->keytype == NULL) return CKR_HOST_MEMORY;
				}
				else {
					keyData->keytype = _strdup("RSA-HSM");
					if (keyData->keytype == NULL) return CKR_HOST_MEMORY;
				}
			}
			else return CKR_TEMPLATE_INCONSISTENT;
		}
		return CKR_OK;
	case CKA_ID:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen <= 0) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
        else {// Another possibility is to read the id as an hex string and convert each hex byte to its string representation
			keyData->id = malloc(pTemplate.ulValueLen + 1);
			if (keyData->id == NULL) return CKR_HOST_MEMORY;
			memcpy(keyData->id, pTemplate.pValue, pTemplate.ulValueLen);
			keyData->id[pTemplate.ulValueLen] = '\0';
		}
		return CKR_OK;
	case CKA_START_DATE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_DATE)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			date = Ck_Date2unixtime(*(CK_DATE*)pTemplate.pValue);
			keyData->attributes->nbf = date;
		}
		return CKR_OK;
	case CKA_END_DATE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_DATE)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			date = Ck_Date2unixtime(*(CK_DATE*)pTemplate.pValue);
			keyData->attributes->exp = date;
		}
		return CKR_OK;
	case CKA_DERIVE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			if (*(CK_BBOOL*)pTemplate.pValue != CK_FALSE)
				return CKR_TEMPLATE_INCONSISTENT;
		}
		return CKR_OK;
	case CKA_LOCAL:
		/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			if (*(CK_BBOOL*)pTemplate.pValue != CK_TRUE)
				return CKR_TEMPLATE_INCONSISTENT;
		}*/
		return CKR_OK;
    case CKA_KEY_GEN_MECHANISM:// TODO: consider also EC Mechanism
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_MECHANISM_TYPE)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			if ((*(CK_ULONG*)pTemplate.pValue != CKM_RSA_PKCS_KEY_PAIR_GEN) && (*(CK_ULONG*)pTemplate.pValue != CKM_RSA_PKCS))
				return CKR_TEMPLATE_INCONSISTENT;
		}
		return CKR_OK;
	case CKA_ALLOWED_MECHANISMS:
		/*if (pTemplate.pValue == NULL) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}*/
		return CKR_OK;
	}
	if (type == CKO_PUBLIC_KEY) {
		//Common Public Key Attributes
		switch (pTemplate.type) {
		case CKA_SUBJECT:
			return CKR_OK;
        case CKA_ENCRYPT: // TODO: incompatible with EC keys, consider this when completing support to EC Keys
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (keyData->key_ops[i] == NULL) break;
					index++;
				}
				if (*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) {
					keyData->key_ops[index] = _strdup("encrypt");
					if (keyData->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_VERIFY:
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (keyData->key_ops[i] == NULL) break;
					index++;
				}
				if (*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) {
					keyData->key_ops[index] = _strdup("verify");
					if (keyData->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_VERIFY_RECOVER:
			/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else if (*(CK_BBOOL*)pTemplate.pValue != CK_TRUE) return CKR_TEMPLATE_INCONSISTENT;*/
			return CKR_OK;
        case CKA_WRAP: // TODO: incompatible with EC keys, consider this when completing support to EC Keys
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (keyData->key_ops[i] == NULL) break;
					index++;
				}
				if (*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) {
					keyData->key_ops[index] = _strdup("wrapKey");
					if (keyData->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_TRUSTED:
			/*	if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				else if (*(CK_BBOOL*)pTemplate.pValue != CK_FALSE) return CKR_TEMPLATE_INCONSISTENT;*/
			return CKR_OK;
		case CKA_WRAP_TEMPLATE:
			return CKR_OK;
		}
		//RSA Public Key Object Attributes
		switch (pTemplate.type) {
		case CKA_MODULUS:
			return CKR_TEMPLATE_INCONSISTENT;
        case CKA_MODULUS_BITS: // TODO: incompatible with EC keys, consider this when completing support to EC Keys
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen < 2 || pTemplate.ulValueLen > sizeof(CK_ULONG)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				stringInt = calloc(1, 12);
				if (stringInt == NULL) return CKR_HOST_MEMORY;
				sprintf(stringInt, "%d", *(CK_ULONG*)pTemplate.pValue);
				keyData->keysize = stringInt;
			}
			return CKR_OK;
        case CKA_PUBLIC_EXPONENT: // TODO: incompatible with EC keys, consider this when completing support to EC Keys
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen < 3 || pTemplate.ulValueLen > sizeof(CK_ULONG)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				CK_ULONG pPublicExponent = 0;
				memcpy(&pPublicExponent, pTemplate.pValue, pTemplate.ulValueLen);
				if (pPublicExponent != PERMITED_PUBLIC_EXPONENT) {
					return CKR_TEMPLATE_INCONSISTENT;
				}
			}
			return CKR_OK;
		}
        //EC Public Key Object Attributes
        switch (pTemplate.type) {
        case CKA_ECDSA_PARAMS:
            if (pTemplate.pValue == NULL || pTemplate.ulValueLen< 3) {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else {
                if (((unsigned char*)pTemplate.pValue)[0] != 0x06) { // Not an object identifier
                    return CKR_TEMPLATE_INCONSISTENT;
                } else {
                    unsigned char* object_data = malloc(pTemplate.ulValueLen);
                    memcpy(object_data, pTemplate.pValue, pTemplate.ulValueLen);
                    long xlen;
                    int tag, xclass;
                    ASN1_get_object(&object_data,  &xlen, &tag, &xclass, pTemplate.ulValueLen);
                    if (xclass != V_ASN1_UNIVERSAL || tag != V_ASN1_OBJECT) {
                        return CKR_TEMPLATE_INCONSISTENT;
                    }
                    //V_ASN1_OBJECT
                    unsigned char* object = object_data -2;
                    //ASN1_OBJECT *oid = d2i_ASN1_OBJECT(NULL, &casa, xlen+2);
                    ASN1_OBJECT *oid = NULL;
                    d2i_ASN1_OBJECT(&oid, &object, xlen+2);

                    /*
                    BIO *bio_out;
                    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
                    i2a_ASN1_OBJECT(bio_out, oid);
                    BIO_flush(bio_out);
                    BIO_free(bio_out);*/

                    /*char buff[100];
                    int i = i2t_ASN1_OBJECT(buff, 100, oid);
                    printf("int i: %d\n", i);
                    printf("value: %s\n", buff);*/

                    int nid = OBJ_obj2nid(oid);

                    printf("nid: %d\n", nid);

                    switch (nid) {
                    case NID_X9_62_prime256v1:
                        keyData->crv = _strdup("P-256");
                        return CKR_OK;
                    case NID_secp256k1:
                        keyData->crv = _strdup("P-256K");
                        return CKR_OK;
                    case NID_secp384r1:
                        keyData->crv = _strdup("P-384");
                        return CKR_OK;
                    case NID_secp521r1:
                        keyData->crv = _strdup("P-521");
                        return CKR_OK;
                    default:

                        return CKR_TEMPLATE_INCONSISTENT;
                    }


                }
            }
            return CKR_OK;
        }
	}
	else if (type == CKO_PRIVATE_KEY) {
		//Common Private Key Attributes
		switch (pTemplate.type) {
		case CKA_SUBJECT:
			return CKR_OK;
		case CKA_SENSITIVE:
			/*	if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				else {
					if (*(CK_BBOOL*)pTemplate.pValue != CK_TRUE)
						return CKR_TEMPLATE_INCONSISTENT;
				}*/
			return CKR_OK;
		case CKA_DECRYPT:
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (keyData->key_ops[i] == NULL) break;
					index++;
				}
				if (*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) {
					keyData->key_ops[index] = _strdup("decrypt");
					if (keyData->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_SIGN:
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (keyData->key_ops[i] == NULL) break;
					index++;
				}
				if (*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) {
					keyData->key_ops[index] = _strdup("sign");
					if (keyData->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_SIGN_RECOVER:
			/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				if (*(CK_BBOOL*)pTemplate.pValue == CK_TRUE)
					return CKR_TEMPLATE_INCONSISTENT;
			}*/
			return CKR_OK;
		case CKA_UNWRAP:
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				index = 0;
				for (int i = 0; i < MAX_OPS; i++) {
					if (keyData->key_ops[i] == NULL) break;
					index++;
				}
				if (*(CK_BBOOL*)pTemplate.pValue == CK_TRUE) {
					keyData->key_ops[index] = _strdup("unwrapKey");
					if (keyData->key_ops[index] == NULL) return CKR_HOST_MEMORY;
				}
			}
			return CKR_OK;
		case CKA_EXTRACTABLE:
			/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				if (*(CK_BBOOL*)pTemplate.pValue == CK_TRUE)
					return CKR_TEMPLATE_INCONSISTENT;
			}*/
			return CKR_OK;
		case CKA_ALWAYS_SENSITIVE:
			/*	if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
					return CKR_ATTRIBUTE_VALUE_INVALID;
				}
				else {
					if (*(CK_BBOOL*)pTemplate.pValue == CK_FALSE)
						return CKR_TEMPLATE_INCONSISTENT;
				}*/
			return CKR_OK;
		case CKA_NEVER_EXTRACTABLE:
			/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				if (*(CK_BBOOL*)pTemplate.pValue == CK_FALSE)
					return CKR_TEMPLATE_INCONSISTENT;
			}*/
			return CKR_OK;
		case CKA_WRAP_WITH_TRUSTED:
			/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				if (*(CK_BBOOL*)pTemplate.pValue == CK_FALSE)
					return CKR_TEMPLATE_INCONSISTENT;
			}*/
			return CKR_OK;
		case CKA_UNWRAP_TEMPLATE:
			return CKR_OK;
		case CKA_ALWAYS_AUTHENTICATE:
			/*if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				if (*(CK_BBOOL*)pTemplate.pValue == CK_FALSE)
					return CKR_TEMPLATE_INCONSISTENT;
			}*/
			return CKR_OK;
		}
		//RSA Private Key Object Attributes
		switch (pTemplate.type) {
		case CKA_MODULUS:
			return CKR_TEMPLATE_INCONSISTENT;
		case CKA_PUBLIC_EXPONENT:
			if (pTemplate.pValue == NULL || pTemplate.ulValueLen < 3 || pTemplate.ulValueLen > sizeof(CK_ULONG)) {
				return CKR_ATTRIBUTE_VALUE_INVALID;
			}
			else {
				CK_ULONG pPublicExponent = 0;
				memcpy(&pPublicExponent, pTemplate.pValue, pTemplate.ulValueLen);
				if (pPublicExponent != PERMITED_PUBLIC_EXPONENT) {
					return CKR_TEMPLATE_INCONSISTENT;
				}
			}
			return CKR_OK;
		case CKA_PRIVATE_EXPONENT:
		case CKA_PRIME_1:
		case CKA_PRIME_2:
		case CKA_EXPONENT_1:
		case CKA_EXPONENT_2:
		case CKA_COEFFICIENT:
			return CKR_TEMPLATE_INCONSISTENT;
		}
	}
	return CKR_TEMPLATE_INCONSISTENT;
}

CK_ULONG KeyMaterial_Checker(struct key_data *keyData) {
	if (keyData == NULL) return CKR_FUNCTION_FAILED;
	if (keyData->id == NULL) return CKR_TEMPLATE_INCOMPLETE;
    if ((keyData->keysize == NULL) && (keyData->crv == NULL)) return CKR_TEMPLATE_INCOMPLETE;
	if (keyData->keytype == NULL) return CKR_TEMPLATE_INCOMPLETE;
	return CKR_OK;
}

CK_ULONG SecretMetadata_Checker(struct secret_creation_data *secretData) {
	if (secretData == NULL) return CKR_FUNCTION_FAILED;
	if (secretData->id[0] == '\0') return CKR_TEMPLATE_INCOMPLETE;
	if (secretData->value == NULL) return CKR_TEMPLATE_INCOMPLETE;
	return CKR_OK;
}

CK_ULONG Template2JWCert(CK_ATTRIBUTE pTemplate, struct import_cert_data * certData)
{
	time_t date;
	//common storage object attributes
	switch (pTemplate.type) {
	case CKA_TOKEN:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		return CKR_OK;
	case CKA_PRIVATE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		return CKR_OK;
	case CKA_MODIFIABLE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		return CKR_OK;
	case CKA_LABEL:
		if (pTemplate.pValue == NULL) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		return CKR_OK;
	}
	//Certificate attributes
	switch (pTemplate.type) {
	case CKA_CERTIFICATE_TYPE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_CERTIFICATE_TYPE)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			if (*(CK_CERTIFICATE_TYPE*)pTemplate.pValue != CKC_X_509) {
				return CKR_TEMPLATE_INCONSISTENT;
			}
		}
		return CKR_OK;
	case CKA_TRUSTED:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_BBOOL)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			if (*(CK_BBOOL*)pTemplate.pValue == CK_FALSE)
				return CKR_TEMPLATE_INCONSISTENT;
		}
		return CKR_OK;
	case CKA_ID:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen == 0) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			certData->name = malloc(pTemplate.ulValueLen + 1);
			if (certData->name == NULL) return CKR_HOST_MEMORY;
			memcpy(certData->name, pTemplate.pValue, pTemplate.ulValueLen);
			certData->name[pTemplate.ulValueLen] = '\0';
		}
		return CKR_OK;
	case CKA_VALUE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen == 0) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			char* base64Encoded = NULL;
			base64Encoded = base64encode(pTemplate.pValue, pTemplate.ulValueLen);
			if (base64Encoded != NULL) {
				certData->base64Value = base64Encoded;
			}
			else return CKR_HOST_MEMORY;
		}
		return CKR_OK;
	case CKA_SUBJECT:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen == 0) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			certData->certPolicy->x509Props->subject = malloc(pTemplate.ulValueLen + 1);
			if (certData->certPolicy->x509Props->subject == NULL) return CKR_HOST_MEMORY;
			memcpy(certData->certPolicy->x509Props->subject, pTemplate.pValue, pTemplate.ulValueLen);
			certData->certPolicy->x509Props->subject[pTemplate.ulValueLen] = '\0';
		}
		return CKR_OK;
	case CKA_ISSUER:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen == 0) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			certData->certPolicy->issuer->name = malloc(pTemplate.ulValueLen + 1);
			if (certData->certPolicy->issuer->name == NULL) return CKR_HOST_MEMORY;
			memcpy(certData->certPolicy->issuer->name, pTemplate.pValue, pTemplate.ulValueLen);
			certData->certPolicy->issuer->name[pTemplate.ulValueLen] = '\0';
		}
		return CKR_OK;
	case CKA_SERIAL_NUMBER:

		return CKR_OK;
	case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
	case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
	case CKA_JAVA_MIDP_SECURITY_DOMAIN:
	case CKA_CERTIFICATE_CATEGORY:
	case CKA_CHECK_VALUE:
	case CKA_URL:
		return CKR_OK;
	case CKA_START_DATE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_DATE)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			date = Ck_Date2unixtime(*(CK_DATE*)pTemplate.pValue);
			certData->cerAttributes->nbf = date;
		}
		return CKR_OK;
	case CKA_END_DATE:
		if (pTemplate.pValue == NULL || pTemplate.ulValueLen != sizeof(CK_DATE)) {
			return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else {
			date = Ck_Date2unixtime(*(CK_DATE*)pTemplate.pValue);
			certData->cerAttributes->exp = date;
		}
		return CKR_OK;
	}
	return CKR_TEMPLATE_INCONSISTENT;
}


CK_ULONG CertificateMaterial_Checker(struct import_cert_data * certData) {
	if (certData == NULL) return CKR_FUNCTION_FAILED;
	if (certData->base64Value) return CKR_TEMPLATE_INCOMPLETE;
	return CKR_OK;
}
struct certificateObject * AzurePKCS11CertificateTranslator(struct delete_update_cert_response *certData) {
	int len;
	struct certificateObject * retval = calloc(1, sizeof(struct certificateObject));
	if (retval == NULL) return NULL_PTR;
	//* Initialitation *//
	Initialize_CertObject(retval);
	retval->commonCertificateAtt.checkValue = NULL;
	retval->x509CertificateAtt.hashOfIssuerPublicKey = NULL;
	retval->x509CertificateAtt.hashOfSubjectPublicKey = NULL;
	retval->x509CertificateAtt.id = NULL;
	retval->x509CertificateAtt.url = NULL;
	retval->x509CertificateAtt.issuer.data = NULL;
	retval->x509CertificateAtt.serailNumber.data = NULL;
	retval->x509CertificateAtt.subject.data = NULL;
	retval->commonAtt.isModifiable = CK_TRUE;
	retval->commonAtt.isPrivate = CK_TRUE;
	retval->commonAtt.isToken = CK_TRUE;
	strcpy(retval->commonAtt.label, "X509 Certificate ");
	len = strlen(retval->commonAtt.label + 1);
	for (int i = 0; i < strlen(certData->id); i++) {
		if (i >= MAX_LABEL_SIZE - 2 - len || certData->id[i] == '/') break;
		retval->commonAtt.label[len + 1 + i] = certData->id[i];
	}
	len = 0;
	retval->commonCertificateAtt.certificateType = CKC_X_509;
	retval->commonCertificateAtt.isTrusted = CK_TRUE;
	retval->commonCertificateAtt.startDate = Unixtime2CK_DATE(certData->cerAttributes->nbf);
	retval->commonCertificateAtt.endDate = Unixtime2CK_DATE(certData->cerAttributes->exp);
	retval->commonCertificateAtt.isTrusted = CK_TRUE;
	retval->commonCertificateAtt.certificateCategory = 0;
	retval->x509CertificateAtt.id = _strdup(certData->id);
	if (retval->x509CertificateAtt.id == NULL) goto cleanup;
	retval->x509CertificateAtt.issuer.data = ExtractCertData(certData->cer, CKA_ISSUER, &len);
	retval->x509CertificateAtt.issuer.len = len;
	if (retval->x509CertificateAtt.issuer.data == NULL) goto cleanup;
	retval->x509CertificateAtt.javaMidpSecurityDomain = 0;
	retval->x509CertificateAtt.serailNumber.data = ExtractCertData((CK_CHAR_PTR)certData->cer, CKA_SERIAL_NUMBER, &len);
	retval->x509CertificateAtt.serailNumber.len = len;
	if (retval->x509CertificateAtt.serailNumber.data == NULL) goto cleanup;
	retval->x509CertificateAtt.subject.data = ExtractCertData((CK_CHAR_PTR)certData->cer, CKA_SUBJECT, &len);
	retval->x509CertificateAtt.subject.len = len;
	if (retval->x509CertificateAtt.subject.data == NULL) goto cleanup;
	retval->x509CertificateAtt.value.data = CertifiacteDERencode((CK_CHAR_PTR)certData->cer, &len);
	retval->x509CertificateAtt.value.len = len;
	if (retval->x509CertificateAtt.value.data == NULL) goto cleanup;
	return retval;
cleanup:
	if (retval->commonCertificateAtt.checkValue != NULL) free(retval->commonCertificateAtt.checkValue);
	if (retval->x509CertificateAtt.hashOfIssuerPublicKey != NULL) free(retval->x509CertificateAtt.hashOfIssuerPublicKey);
	if (retval->x509CertificateAtt.hashOfSubjectPublicKey != NULL) free(retval->x509CertificateAtt.hashOfSubjectPublicKey);
	if (retval->x509CertificateAtt.id != NULL) free(retval->x509CertificateAtt.id);
	if (retval->x509CertificateAtt.url != NULL) free(retval->x509CertificateAtt.url);
	if (retval->x509CertificateAtt.issuer.data != NULL) free(retval->x509CertificateAtt.issuer.data);
	if (retval->x509CertificateAtt.serailNumber.data != NULL) free(retval->x509CertificateAtt.serailNumber.data);
	if (retval->x509CertificateAtt.subject.data != NULL) free(retval->x509CertificateAtt.subject.data);
	free(retval);
	return NULL;
}


struct keyObject * AzurePKCS11KeyTranslator(struct key_data_response *keyData, CK_ULONG type, CK_CHAR_PTR token, struct objects ** cacheTokenObjects) {
    size_t len = 0, modulusLen = 0, publicExponentLen = 0, xLen = 0, yLen = 0, ecParamsLen = 0;
	char base64urldecoded[512];
	CK_ULONG modulusBit = 0, res;
    CK_CHAR_PTR modulus = NULL, publicExponent = NULL, x = NULL, y = NULL, ecParams = NULL;
	struct delete_update_cert_response *certData = NULL;
	struct id_http_data * getParam;
	struct keyObject * retval = calloc(1, sizeof(struct keyObject));
	if (retval == NULL) return NULL_PTR;
	Initialize_KeyObject(retval);
	retval->commonAtt.isModifiable = CK_TRUE;
	retval->commonAtt.isToken = CK_TRUE;
	retval->commonKeyAtt.canDerive = CK_FALSE;
	retval->commonKeyAtt.isLocal = CK_TRUE;
	//retval->commonKeyAtt.allowedMechanisms
	//retval->commonKeyAtt.mechanismType
	struct objects *object;
	retval->commonKeyAtt.id = _strdup(keyData->id);
	if (retval->commonKeyAtt.id == NULL) goto cleanup;
	if (keyData->managed == CK_TRUE) { // in azure public private keys from a certificate have set TRUE managed flag 
		BOOL existObject = Exist_TokenObject(*cacheTokenObjects, keyData->id, CKO_CERTIFICATE, &object);
		if (!existObject) {
			getParam = Store_IdHttpData(token, HOST, keyData->id);
			if (getParam != NULL) {
				int res = Get_Certificate(getParam, &certData);
				Free_IdHttpData(getParam);
				if (res == HTTP_OK) {
					retval->commonKeyAtt.startDate = Unixtime2CK_DATE(certData->cerAttributes->nbf);
					retval->commonKeyAtt.endDate = Unixtime2CK_DATE(certData->cerAttributes->exp);
					retval->commonPublicKeyAtt.subject.data = ExtractCertData(certData->cer, CKA_SUBJECT, &len);
					retval->commonPublicKeyAtt.subject.len = len;
					retval->commonPrivateKeyAtt.subject.data = ExtractCertData(certData->cer, CKA_SUBJECT, &len);
					retval->commonPrivateKeyAtt.subject.len = len;
					Free_DeleteUpdateCertResponse(certData);
				}
			}
		}
		else {
			retval->commonKeyAtt.startDate = object->certObject->commonCertificateAtt.startDate;
			retval->commonKeyAtt.endDate = object->certObject->commonCertificateAtt.endDate;
			retval->commonPublicKeyAtt.subject.data = malloc(object->certObject->x509CertificateAtt.subject.len);
			if (retval->commonPublicKeyAtt.subject.data != NULL) {
				memcpy(retval->commonPublicKeyAtt.subject.data, object->certObject->x509CertificateAtt.subject.data, object->certObject->x509CertificateAtt.subject.len);
				retval->commonPublicKeyAtt.subject.len = object->certObject->x509CertificateAtt.subject.len;
			}
			else retval->commonPublicKeyAtt.subject.len = 0;
			retval->commonPrivateKeyAtt.subject.data = malloc(object->certObject->x509CertificateAtt.subject.len);
			if (retval->commonPrivateKeyAtt.subject.data != NULL) {
				memcpy(retval->commonPrivateKeyAtt.subject.data, object->certObject->x509CertificateAtt.subject.data, object->certObject->x509CertificateAtt.subject.len);
				retval->commonPrivateKeyAtt.subject.len = object->certObject->x509CertificateAtt.subject.len;
			}
			else retval->commonPrivateKeyAtt.subject.len = 0;
		}
	}
	if ((!strcmp(keyData->keytype, "RSA")) || (!strcmp(keyData->keytype, "RSA-HSM"))) {
		retval->commonKeyAtt.keyType = CKK_RSA;
		memset(base64urldecoded, 0, 512);
		res = base64url_decode(base64urldecoded, 512, keyData->n, strlen(keyData->n), &len);
		if (res == 0) {
			modulusBit = len * 8;
			modulus = malloc(len + 1);
			if (modulus == NULL) goto cleanup;
			modulusLen = len;
			if (modulus != NULL) {
				memcpy(modulus, base64urldecoded, len);
				modulus[len] = '\0';
			}
		}
		memset(base64urldecoded, 0, 512);
		res = base64url_decode(base64urldecoded, 512, keyData->e, strlen(keyData->e), &len);
		if (res == 0) {
			publicExponent = malloc(len + 1);
			if (publicExponent == NULL) goto cleanup;
			publicExponentLen = len;
			if (publicExponent != NULL) {
				memcpy(publicExponent, base64urldecoded, len);
				publicExponent[len] = '\0';
			}
		}
	}
    if ((!strcmp(keyData->keytype, "EC")) || (!strcmp(keyData->keytype, "EC-HSM"))) {
        retval->commonKeyAtt.keyType = CKK_EC;
        memset(base64urldecoded, 0, 512);
        res = base64url_decode(base64urldecoded, 512, keyData->x, strlen(keyData->x), &len);
        if (res == 0) {
            x = malloc(len + 1);
            if (x == NULL) goto cleanup;
            xLen = len;
            if (x != NULL) {
                memcpy(x, base64urldecoded, len);
                x[len] = '\0';
            }
        }
        memset(base64urldecoded, 0, 512);
        res = base64url_decode(base64urldecoded, 512, keyData->y, strlen(keyData->y), &len);
        if (res == 0) {
            y = malloc(len + 1);
            if (y == NULL) goto cleanup;
            xLen = len;
            if (y != NULL) {
                memcpy(y, base64urldecoded, len);
                y[len] = '\0';
            }
        }
        if (!strcmp(keyData->crv, "P-256")) {
            ASN1_OBJECT *oid = OBJ_nid2obj(NID_X9_62_prime256v1);
            if (oid != NULL) {
                ecParams = malloc(oid->length+2);
                unsigned char *aux = ecParams;
                ecParamsLen = i2d_ASN1_OBJECT(oid, &aux);
            }
        }
    }
	if (type == CKO_PRIVATE_KEY) {
		retval->commonAtt.isPrivate = CK_TRUE;
		retval->commonPrivateKeyAtt.isSensitive = CK_TRUE;
		retval->commonPrivateKeyAtt.canDecrypt = CK_FALSE;
		retval->commonPrivateKeyAtt.canSign = CK_FALSE;
		retval->commonPrivateKeyAtt.canSignRecover = CK_FALSE;
		retval->commonPrivateKeyAtt.canUnwrap = CK_FALSE;
		if (keyData->key_ops != NULL) {
			for (int i = 0; i < MAX_OPS; i++) {
				if (keyData->key_ops[i] != NULL) {
					if (!strcmp(keyData->key_ops[i], "decrypt"))
						retval->commonPrivateKeyAtt.canDecrypt = CK_TRUE;
					if (!strcmp(keyData->key_ops[i], "sign")) {
						retval->commonPrivateKeyAtt.canSign = CK_TRUE;
						retval->commonPrivateKeyAtt.canSignRecover = CK_TRUE;
					}
					if (!strcmp(keyData->key_ops[i], "unwrapKey"))
						retval->commonPrivateKeyAtt.canUnwrap = CK_TRUE;
				}
			}
		}
		retval->commonPrivateKeyAtt.isExtractable = CK_FALSE;
		retval->commonPrivateKeyAtt.isAlwaysSensitive = CK_TRUE;
		retval->commonPrivateKeyAtt.isNeverExtractable = CK_TRUE;
		retval->commonPrivateKeyAtt.beWrapWithTrusted = CK_TRUE;
		//retval->commonPrivateKeyAtt.unwrapTemplate
		retval->commonPrivateKeyAtt.isAlwaysAuthenticate = CK_TRUE;
		if ((!strcmp(keyData->keytype, "RSA")) || (!strcmp(keyData->keytype, "RSA-HSM"))) {
			strcpy(retval->commonAtt.label, "RSA Private Key ");
			len = strlen(retval->commonAtt.label + 1);
			for (int i = 0; i < strlen(keyData->id); i++) {
				if (i >= MAX_LABEL_SIZE - 2 - len || keyData->id[i] == '/') break;
				retval->commonAtt.label[len + 1 + i] = keyData->id[i];
			}
			len = 0;
			retval->RSAPrivateKeyObjectAtt.modulus.data = modulus;
			retval->RSAPrivateKeyObjectAtt.modulus.len = modulusLen;
			retval->RSAPrivateKeyObjectAtt.publicExponent.data = publicExponent;
			retval->RSAPrivateKeyObjectAtt.publicExponent.len = publicExponentLen;
		}
        if ((!strcmp(keyData->keytype, "EC")) || (!strcmp(keyData->keytype, "EC-HSM"))) {
            strcpy(retval->commonAtt.label, "EC Private Key ");
            len = strlen(retval->commonAtt.label + 1);
            for (int i = 0; i < strlen(keyData->id); i++) {
                if (i >= MAX_LABEL_SIZE - 2 - len || keyData->id[i] == '/') break;
                retval->commonAtt.label[len + 1 + i] = keyData->id[i];
            }
            len = 0;
            retval->ECprivateKeyObjectAtt.ecParams.data = ecParams;
            retval->ECprivateKeyObjectAtt.ecParams.len = ecParamsLen;
        }
	}
	else if (type == CKO_PUBLIC_KEY) {
		retval->commonAtt.isPrivate = CK_FALSE;
		retval->commonPublicKeyAtt.isTrusted = CK_TRUE;
		retval->commonPublicKeyAtt.canEncrypt = CK_FALSE;
		retval->commonPublicKeyAtt.canVerify = CK_FALSE;
		retval->commonPublicKeyAtt.canVerrifyRecover = CK_FALSE;
		retval->commonPublicKeyAtt.canWrap = CK_FALSE;
		if (keyData->key_ops != NULL) {
			for (int i = 0; i < MAX_OPS; i++) {
				if (keyData->key_ops[i] != NULL) {
					if (!strcmp(keyData->key_ops[i], "encrypt"))
						retval->commonPublicKeyAtt.canEncrypt = CK_TRUE;
					if (!strcmp(keyData->key_ops[i], "verify")) {
						retval->commonPublicKeyAtt.canVerify = CK_TRUE;
						retval->commonPublicKeyAtt.canVerrifyRecover = CK_TRUE;
					}
					if (!strcmp(keyData->key_ops[i], "wrapKey"))
						retval->commonPublicKeyAtt.canWrap = CK_TRUE;
				}
			}
		}
		if ((!strcmp(keyData->keytype, "RSA")) || (!strcmp(keyData->keytype, "RSA-HSM"))) {
			strcpy(retval->commonAtt.label, "RSA Public Key ");
			len = strlen(retval->commonAtt.label + 1);
			for (int i = 0; i < strlen(keyData->id); i++) {
				if (i >= MAX_LABEL_SIZE - 2 - len || keyData->id[i] == '/') break;
				retval->commonAtt.label[len + 1 + i] = keyData->id[i];
			}
			len = 0;
			retval->RSApublicKeyObjectAtt.modulus.data = modulus;
			retval->RSApublicKeyObjectAtt.modulus.len = modulusLen;
			retval->RSApublicKeyObjectAtt.modulusBits = modulusBit;
			retval->RSApublicKeyObjectAtt.publicExponent.data = publicExponent;
			retval->RSApublicKeyObjectAtt.publicExponent.len = publicExponentLen;
		}
        if ((!strcmp(keyData->keytype, "EC")) || (!strcmp(keyData->keytype, "EC-HSM"))) {
            strcpy(retval->commonAtt.label, "EC Public Key ");
            len = strlen(retval->commonAtt.label + 1);
            for (int i = 0; i < strlen(keyData->id); i++) {
                if (i >= MAX_LABEL_SIZE - 2 - len || keyData->id[i] == '/') break;
                retval->commonAtt.label[len + 1 + i] = keyData->id[i];
            }
            len = 0;
            retval->ECpublicKeyObjectAtt.ecParams.data = ecParams;
            retval->ECpublicKeyObjectAtt.ecParams.len = ecParamsLen;

            /*if (!strcmp(keyData->crv, "P-256")) {
                ASN1_OBJECT *oid = OBJ_nid2obj(NID_X9_62_prime256v1);
                oid->length+2
                unsigned char* temp = NULL;

                retval->ECpublicKeyObjectAtt.ecParams.len = i2d_ASN1_OBJECT(oid, &temp);
                if (retval->ECpublicKeyObjectAtt.ecParams.len > 0) {
                    retval->ECpublicKeyObjectAtt.ecParams.data = *temp;
                }
            }*/
            retval->ECpublicKeyObjectAtt.x.data = x;
            retval->ECpublicKeyObjectAtt.x.len = xLen;
            retval->ECpublicKeyObjectAtt.y.data = y;
            retval->ECpublicKeyObjectAtt.y.len = yLen;
        }
		//retval->commonPublicKeyAtt.wrapTemplate
	}
	return retval;
cleanup:
	if (retval->commonKeyAtt.id != NULL) free(retval->commonKeyAtt.id);
	if (retval->commonPrivateKeyAtt.subject.data != NULL) free(retval->commonPrivateKeyAtt.subject.data);
	if (retval->commonPublicKeyAtt.subject.data != NULL) free(retval->commonPublicKeyAtt.subject.data);
	if (retval->RSAPrivateKeyObjectAtt.coeficient.data != NULL) free(retval->RSAPrivateKeyObjectAtt.coeficient.data);
	if (retval->RSAPrivateKeyObjectAtt.exponent1.data != NULL) free(retval->RSAPrivateKeyObjectAtt.exponent1.data);
	if (retval->RSAPrivateKeyObjectAtt.exponent2.data != NULL) free(retval->RSAPrivateKeyObjectAtt.exponent2.data);
	if (retval->RSAPrivateKeyObjectAtt.modulus.data != NULL) free(retval->RSAPrivateKeyObjectAtt.modulus.data);
	if (retval->RSAPrivateKeyObjectAtt.prime1.data != NULL) free(retval->RSAPrivateKeyObjectAtt.prime1.data);
	if (retval->RSAPrivateKeyObjectAtt.prime2.data != NULL) free(retval->RSAPrivateKeyObjectAtt.prime2.data);
	if (retval->RSAPrivateKeyObjectAtt.privateExponent.data != NULL) free(retval->RSAPrivateKeyObjectAtt.privateExponent.data);
	if (retval->RSAPrivateKeyObjectAtt.publicExponent.data != NULL) free(retval->RSAPrivateKeyObjectAtt.publicExponent.data);
	if (retval->RSApublicKeyObjectAtt.modulus.data != NULL) free(retval->RSApublicKeyObjectAtt.modulus.data);
	if (retval->RSApublicKeyObjectAtt.publicExponent.data != NULL) free(retval->RSApublicKeyObjectAtt.publicExponent.data);
	free(retval);
	return NULL;
}

struct dataObject * AzurePKCS11DataObjectTranslator(struct secret_item_data *secretData) {
	struct dataObject * retval = calloc(1, sizeof(struct dataObject));
	retval->application = _strdup(secretData->secretCommonItem.contentType);
	if (retval->application == NULL) return NULL;
	retval->objectId.data = malloc(strlen(secretData->secretCommonItem.id));
	if (retval->objectId.data == NULL) {
		if (retval->application != NULL) free(retval->application);
		return NULL;
	}
	memcpy(retval->objectId.data, secretData->secretCommonItem.id, strlen(secretData->secretCommonItem.id));
	retval->objectId.len = strlen(secretData->secretCommonItem.id);
	retval->value.data = malloc(strlen(secretData->value));
	if (retval->value.data == NULL) {
		if (retval->application != NULL) free(retval->application);
		free(retval->objectId.data);
		retval->objectId.len = 0;
		return NULL;
	}
	memcpy(retval->value.data, secretData->value, strlen(secretData->value));
	retval->value.len = strlen(secretData->value);
	retval->commonAtt.isModifiable = CK_TRUE;
	retval->commonAtt.isPrivate = CK_TRUE;
	retval->commonAtt.isToken = CK_TRUE;
	strcpy(retval->commonAtt.label, "CK_DATA ");
	strcat(retval->commonAtt.label, secretData->secretCommonItem.id);
	return retval;
}


int Convert2Int(const char *p, int size)
{
	const char *endp;
	int intval = 0;
	endp = p + size;
	while (p < endp)
	{
		intval = intval * 10 + *p - '0';
		p++;
	}
	return intval;
}
static time_t String2epoch(char *yyyymmdd)
{
	struct tm epoch;
	memset(&epoch, 0, sizeof(epoch));
	epoch.tm_year = Convert2Int(yyyymmdd + 0, 4) - 1900;
	epoch.tm_mon = Convert2Int(yyyymmdd + 4, 2) - 1;
	epoch.tm_mday = Convert2Int(yyyymmdd + 6, 2);
	epoch.tm_hour = 1;
	epoch.tm_min = 0;
	epoch.tm_sec = 0;
	return mktime(&epoch);
}
time_t Ck_Date2unixtime(CK_DATE date) {
	char time_string[11];
	strcpy(time_string, date.year);
	strcat(time_string, date.month);
	strcat(time_string, date.day);
	strcat(time_string, "\0");
	return String2epoch(time_string);

}

CK_DATE Unixtime2CK_DATE(time_t date) {
	char buffer[10];
	struct tm  timeStamp;
	CK_DATE outputDate;
	timeStamp = *localtime(&date);
	strftime(buffer, sizeof(buffer), "%Y", &timeStamp);
	memcpy(outputDate.year, buffer, 4);
	strftime(buffer, sizeof(buffer), "%m", &timeStamp);
	memcpy(outputDate.month, buffer, 2);
	strftime(buffer, sizeof(buffer), "%d", &timeStamp);
	memcpy(outputDate.day, buffer, 2);
	return outputDate;
}


CK_CHAR_PTR * ExtractCertData(CK_CHAR_PTR * certValue, CK_ULONG type, CK_ULONG * size) {
	CK_CHAR_PTR buf, returnValue;
	X509_NAME *issuerName, *subjectName;
	ASN1_INTEGER * serial;
	X509 *cert;
	int len = 0;
	if (certValue == NULL) {
		*size = 0;
		return NULL;
	}
	CK_ULONG res = X509_cert_data(certValue, &cert);
	if (res != CKR_OK) {
		return NULL;
	}
	switch (type) {
	case CKA_ISSUER:
		issuerName = X509_get_issuer_name(cert);
		if (issuerName == NULL) {
			X509_free(cert);
			return NULL;
		}
		buf = NULL;
		len = i2d_X509_NAME(issuerName, &buf);
		break;
	case CKA_SUBJECT:
		subjectName = X509_get_subject_name(cert);
		if (subjectName == NULL) {
			X509_free(cert);
			return NULL;
		}
		buf = NULL;
		len = i2d_X509_NAME(subjectName, &buf);
		break;
	case CKA_SERIAL_NUMBER:
		serial = X509_get_serialNumber(cert);
		if (serial == NULL) {
			X509_free(cert);
			return NULL;
		}
		buf = NULL;
		len = i2d_ASN1_INTEGER(serial, &buf);
		break;
	default:
		X509_free(cert);
		return NULL;
	}
	X509_free(cert);
	if (len <= 0) {
		return NULL;
	}
	returnValue = malloc(len);
	if (returnValue == NULL) {
		OPENSSL_free(buf);
		return NULL;
	}
	memcpy(returnValue, buf, len);
	*size = len;
	OPENSSL_free(buf);
	return returnValue;
}

CK_CHAR_PTR *CertifiacteDERencode(CK_CHAR_PTR value, CK_ULONG * size) {
	X509 *cert;
	CK_CHAR_PTR buf, returnValue;
	cert = NULL;
	if (value == NULL) {
		*size = 0;
		return NULL;
	}
	CK_ULONG res = X509_cert_data(value, &cert);
	if (res != CKR_OK) {
		return NULL;
	}
	buf = NULL;
	int len = i2d_X509(cert, &buf);
	X509_free(cert);
	cert = NULL;
	if (len < 0) {
		return NULL;
	}
	returnValue = malloc(len);
	if (returnValue == NULL) {
		OPENSSL_free(buf);
		return NULL;
	}
	memcpy(returnValue, buf, len);
	OPENSSL_free(buf);
	*size = len;
	return returnValue;
}

BOOL CompareSubjects(char* storedSubject, CK_ULONG storedSubjectSize, char* searchSubject, CK_ULONG searchSubjectSize) {
	BOOL match;
	unsigned char *p;
	p = storedSubject;
	X509_NAME *formatedStoredSubject = d2i_X509_NAME(NULL, &p, storedSubjectSize);
	if (formatedStoredSubject == NULL) return NULL;
	p = searchSubject;
	X509_NAME *formatedSearchSubjectSize = d2i_X509_NAME(NULL, &p, searchSubjectSize);
	if (formatedSearchSubjectSize == NULL) return NULL;
	for (int i = 0; i < X509_NAME_entry_count(formatedSearchSubjectSize); i++) {
		match = FALSE;
		X509_NAME_ENTRY *searchSubjectX509Entry = X509_NAME_get_entry(formatedSearchSubjectSize, i);
		if (searchSubjectX509Entry == NULL) return FALSE;
		ASN1_STRING *searchSubjectASN1String = X509_NAME_ENTRY_get_data(searchSubjectX509Entry);
		if (searchSubjectASN1String == NULL) return FALSE;
		char *searchSubjectData = ASN1_STRING_data(searchSubjectASN1String);
		if (searchSubjectData == NULL) return FALSE;
		for (int j = 0; j < X509_NAME_entry_count(formatedStoredSubject); j++) {
			X509_NAME_ENTRY *storedSubjectX509Entry = X509_NAME_get_entry(formatedStoredSubject, j);
			if (storedSubjectX509Entry == NULL) return FALSE;
			ASN1_STRING *storedSubjectString = X509_NAME_ENTRY_get_data(storedSubjectX509Entry);
			if (storedSubjectString == NULL) return FALSE;
			char *storedSubjectData = ASN1_STRING_data(storedSubjectString);
			if (storedSubjectData == NULL) return FALSE;
			if (!strcmp(searchSubjectData, storedSubjectData)) {
				match = TRUE;
				break;
			}
		}
		if (match == FALSE) return FALSE;
	}
	return match;
}

unsigned char * DecodeASN1Hash(CK_BYTE_PTR pData, CK_ULONG ulDataLen, int *ASN1HashType, int *hashLen) {
	if (ulDataLen < 49) return NULL; // Whith types and headers the minimun size of the asn1 encoded hash256 size are 49 bytes
	const unsigned char *dataDerEncoded = (const unsigned char *)pData;
	int sizeByte = 0, hashType = 0, hashSize = 0;
	sizeByte = (int)dataDerEncoded[1];
	if (sizeByte < 47) return NULL; // Whith types and headers the minimun size of the asn1 encoded hash256 size are 47 bytes plus 2 bytes first header

	char type[HASH_TYPE + 1];
	for (int i = 4; i < (HASH_TYPE / 2 + 4); i++) { //start at 4 to remove the asn1 headers and only collect the type
		sprintf(&type[(2 * i) - (2 * 4)], "%02x", dataDerEncoded[i]);
	}
	if (!strcmp(type, SHA256_ASN1)) {
		hashType = SHA_256;
		hashSize = 32;
	}
	else if (!strcmp(type, SHA384_ASN1)) {
		hashType = SHA_384;
		hashSize = 48;
	}
	else if (!strcmp(type, SHA512_ASN1)) {
		hashType = SHA_512;
		hashSize = 64;
	}
	else {
		return NULL;
	}
	sizeByte = (int)dataDerEncoded[3];
	int shaStartIndex = 4 + 11 + (sizeByte - 11) + 2;//4 bytes headers 11 bytes sha type (sizeByte - 11) possible NULL + 2 bytes header  
	int decodedHashSize = (int)dataDerEncoded[shaStartIndex - 1]; // -1 for the header
	if (decodedHashSize != hashSize) return NULL;
	unsigned char * returnedHash = calloc(1, hashSize);
	if (returnedHash == NULL) return NULL;
	for (int i = 0; i < hashSize; i++) {
		returnedHash[i] = dataDerEncoded[i + shaStartIndex];
	}
	*ASN1HashType = hashType;
	*hashLen = hashSize;
	return returnedHash;
}

//int HashSHA256(unsigned char *hashed, const unsigned char *plain, size_t plen) {
//	EVP_MD_CTX *mdctx;
//	int md_len = 0;
//	if (!(mdctx = EVP_MD_CTX_create())) return 0;
//	if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
//		if (mdctx) EVP_MD_CTX_destroy(mdctx);
//		return 0;
//	}
//	if (1 != EVP_DigestUpdate(mdctx, plain, plen)) {
//		if (mdctx) EVP_MD_CTX_destroy(mdctx);
//		return 0;
//	}
//	if (1 != EVP_DigestFinal_ex(mdctx, hashed, &md_len)) {
//		if (mdctx) EVP_MD_CTX_destroy(mdctx);
//		return 0;
//	}
//	if (mdctx) EVP_MD_CTX_destroy(mdctx);
//	return md_len;
//}
//
//CK_ULONG DeriveKey(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_CHAR **configurationKey, const unsigned char *salt, CK_ULONG saltSize) {
//	unsigned char *out = malloc(sizeof(unsigned char) * KEK_KEY_LEN);
//	if (out == NULL) return CKR_HOST_MEMORY;
//	if (PKCS5_PBKDF2_HMAC(pPin, ulPinLen, salt, saltSize, ITERATION, EVP_sha256(), KEK_KEY_LEN, out) != 0)
//	{
//		*configurationKey = out;
//		return CKR_OK;
//	}
//	else
//	{
//		*configurationKey = NULL_PTR;
//		return CKR_PIN_INCORRECT;
//	}
//}
//
//CK_ULONG IVCalculator(const unsigned char *iv, CK_CHAR_PTR id, CK_CHAR_PTR suffix) {
//	if (id == NULL || suffix == NULL) return 0;
//	size_t plainSize = strlen(id) + strlen(suffix);
//	const unsigned char *plain = malloc(plainSize + 1);
//	if (plain == NULL) return 0;
//	strcpy(plain, id);
//	strcat(plain, suffix);
//	unsigned char hash256[SHA256_DIGEST_LENGTH] = "";
//	int sha256Size = HashSHA256(&hash256, plain, plainSize);
//	free(plain);
//	if (sha256Size <= EVP_MAX_IV_LENGTH) return 0;
//	memcpy(iv, hash256, EVP_MAX_IV_LENGTH);
//	return 1;
//}
//
//CK_ULONG EncryptParameter(CK_CHAR *parameter, CK_CHAR **cipherData, const unsigned char *iv, CK_CHAR *configurationKey) {
//	EVP_CIPHER_CTX *ctx;
//	int len;
//	int ciphertext_len;
//
//	/* Create and initialise the context */
//	if (!(ctx = EVP_CIPHER_CTX_new())) {
//		*cipherData = NULL;
//		return CKR_OK;
//	}
//	/* Initialise the encryption operation.
//	* We are using 256 bit AES (i.e. a 256 bit key). The
//	* IV size for *most* modes is the same as the block size. For AES this
//	* is 128 bits */
//	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, configurationKey, iv)) {
//		*cipherData = NULL;
//		return CKR_OK;
//	}
//	// The output buffer size needs to be bigger to accomodate incomplete blocks
//	// See EVP_EncryptUpdate documentation for explanation:
//	//https://www.openssl.org/docs/man1.0.2/crypto/EVP_EncryptUpdate.html
//	int cipher_block_size = EVP_CIPHER_block_size(ctx->cipher);
//	int outsize = strlen(parameter) + (cipher_block_size - 1);
//	unsigned char *ciphertext = malloc(outsize);
//	if (ciphertext == NULL) {
//		*cipherData = NULL;
//		return CKR_OK;
//	}
//	/* Provide the message to be encrypted, and obtain the encrypted output.
//	* EVP_EncryptUpdate can be called multiple times if necessary
//	*/
//	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, parameter, strlen(parameter))) {
//		*cipherData = NULL;
//		return CKR_OK;
//	}
//	ciphertext_len = len;
//	/* Finalise the encryption. Further ciphertext bytes may be written at
//	* this stage.
//	*/
//	if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
//		*cipherData = NULL;
//		return CKR_OK;
//	}
//	ciphertext_len += len;
//	/* Clean up */
//	EVP_CIPHER_CTX_free(ctx);
//	*cipherData = ciphertext;
//	return ciphertext_len;
//}
//
//CK_ULONG DecryptParameter(unsigned char *ciphertext, int ciphertext_len, CK_CHAR *configurationKey, unsigned char *iv, CK_CHAR **plainData)
//{
//	EVP_CIPHER_CTX *ctx;
//	int len;
//	int plaintext_len;
//
//	/* Create and initialise the context */
//	if (!(ctx = EVP_CIPHER_CTX_new())) {
//		*plainData = NULL;
//		return 0;
//	}
//	/* Initialise the decryption operation.
//	* We are using 256 bit AES (i.e. a 256 bit key). The
//	* IV size for *most* modes is the same as the block size. For AES this
//	* is 128 bits */
//	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, configurationKey, iv)) {
//		*plainData = NULL;
//		return 0;
//	}
//	/* Provide the message to be decrypted, and obtain the plaintext output.
//	* EVP_DecryptUpdate can be called multiple times if necessary
//	*/
//	unsigned char *plaintext = malloc(ciphertext_len + 1);
//	if (ciphertext == NULL) {
//		*plainData = NULL;
//		return 0;
//	}
//	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
//		free(plaintext);
//		*plainData = NULL;
//		return 0;
//	}
//	plaintext_len = len;
//	/* Finalise the decryption. Further plaintext bytes may be written at
//	* this stage.
//	*/
//	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
//		free(plaintext);
//		*plainData = NULL;
//		return 0;
//	}
//	plaintext_len += len;
//	/* Clean up */
//	EVP_CIPHER_CTX_free(ctx);
//	plaintext[plaintext_len] = '\0';
//	*plainData = plaintext;
//	return plaintext_len;
//}
//
//CK_ULONG EncryptConfigurationData(CK_CHAR_PTR *parameter, CK_CHAR_PTR parameterName, CK_CHAR_PTR configurationKey) {
//	if (*parameter == NULL) return CKR_GENERAL_ERROR;
//	const unsigned char iv[EVP_MAX_IV_LENGTH] = "";
//	if (!IVCalculator(&iv, (CK_CHAR_PTR)CLIENTID, parameterName)) {
//		return CKR_GENERAL_ERROR;
//	}
//	CK_CHAR *cipherData = NULL_PTR;
//	CK_ULONG encryptDataSize = EncryptParameter(*parameter, &cipherData, iv, configurationKey);
//	if (encryptDataSize <= 0) {
//		return CKR_GENERAL_ERROR;
//	}
//	char* base64Data = NULL;
//	base64Data = base64encode(cipherData, encryptDataSize);
//	if (base64Data == NULL) {
//		free(cipherData);
//		return CKR_GENERAL_ERROR;
//	}
//	free(cipherData);
//	free(*parameter);
//	*parameter = base64Data;
//	return CKR_OK;
//}
//
//CK_ULONG EncryptAllConfigurationData(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
//	if (CLIENTID != NULL) {
//		CK_CHAR_PTR  configurationKey = NULL_PTR;
//		CK_ULONG result = DeriveKey(pPin, ulPinLen, &configurationKey, CLIENTID, strlen(CLIENTID));
//		if (result != CKR_OK) return CKR_GENERAL_ERROR;
//		result = EncryptConfigurationData((CK_CHAR_PTR)&TENANTID, (CK_CHAR_PTR)&"TENANTID", configurationKey);
//		if (result != CKR_OK) {
//			free(configurationKey);
//			return result;
//		}
//		result = EncryptConfigurationData((CK_CHAR_PTR)&HOST, (CK_CHAR_PTR)&"HOST", configurationKey);
//		if (result != CKR_OK) {
//			free(configurationKey);
//			return result;
//		}
//		result = EncryptConfigurationData((CK_CHAR_PTR)&PASSWORD, (CK_CHAR_PTR)&"PASSWORD", configurationKey);
//		if (result != CKR_OK) {
//			free(configurationKey);
//			return result;
//		}
//		free(configurationKey);
//		result = EncryptConfFile();
//		if (result != OK) {
//			if (result == HOST_MEMORY) {
//				return CKR_HOST_MEMORY;
//			}
//			else {
//				return CKR_GENERAL_ERROR;
//			}
//		}
//		else return CKR_OK;
//	}
//	else return CKR_GENERAL_ERROR;
//}
//
//CK_ULONG DecryptConfigurationData(CK_CHAR_PTR *parameter, CK_CHAR_PTR parameterName, CK_CHAR_PTR configurationKey) {
//	if (*parameter == NULL) return CKR_GENERAL_ERROR;
//	const unsigned char iv[EVP_MAX_IV_LENGTH] = "";
//	if (!IVCalculator(&iv, CLIENTID, parameterName)) {
//		return CKR_GENERAL_ERROR;
//	}
//	char* cipherData = NULL;
//	size_t cipherDataLength;
//	if (base64Decode(*parameter, &cipherData, &cipherDataLength))
//		return CKR_USER_PIN_NOT_INITIALIZED;
//	CK_CHAR *plainData = NULL_PTR;
//	CK_ULONG decryptDataSize = DecryptParameter(cipherData, cipherDataLength, configurationKey, iv, &plainData);
//	if (decryptDataSize <= 0) {
//		return CKR_PIN_INCORRECT;
//	}
//	free(cipherData);
//	if (*parameter != NULL) free(*parameter);
//	*parameter = plainData;
//	return CKR_OK;
//}
//
//CK_ULONG DecryptAllConfigurationData(CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen) {
//	CK_CHAR_PTR  configurationKey = NULL_PTR;
//	CK_ULONG result = DeriveKey(pPin, ulPinLen, &configurationKey, CLIENTID, strlen(CLIENTID));
//	if (result != CKR_OK) return CKR_GENERAL_ERROR;
//	result = DecryptConfigurationData(&TENANTID, &"TENANTID", configurationKey);
//	if (result != CKR_OK) {
//		return result;
//	}
//	result = DecryptConfigurationData(&HOST, &"HOST", configurationKey);
//	if (result != CKR_OK) {
//		return result;
//	}
//	result = DecryptConfigurationData(&PASSWORD, (CK_CHAR_PTR)&"PASSWORD", configurationKey);
//	if (result != CKR_OK) {
//		return result;
//	}
//	return result;
//}

//CK_ULONG GetAzureToken(CK_CHAR **azureToken) {
//	struct token_response *tokenResponse = NULL;
//	struct client_data *clientData = NULL;
//	clientData = Store_ClientData(PASSWORD, AUTH_URL, RESOURCE, CLIENTID, TENANTID);
//	int result = Get_AccesToken(clientData, &tokenResponse);
//	Free_ClientData(clientData);
//	if (result != HTTP_OK) {
//		Free_AccesTokenResponse(tokenResponse);
//		if (result < HTTP_OK) {
//			return CKR_TOKEN_NOT_PRESENT;
//		}
//		else {
//			switch (result) {
//			case ALLOCATE_ERROR:
//				return CKR_HOST_MEMORY;
//			case UNAUTHORIZED:
//				return CKR_PIN_INCORRECT;
//			case FORBIDDEN:
//				return CKR_GENERAL_ERROR;
//			case NOT_FOUND:
//				return CKR_TOKEN_NOT_PRESENT;
//			default:
//				return CKR_FUNCTION_FAILED;
//			}
//		}
//	}
//	else {
//		CK_CHAR_PTR token = (CK_CHAR_PTR)_strdup(tokenResponse->access_token);
//		Free_AccesTokenResponse(tokenResponse);
//		if (token == NULL) return CKR_HOST_MEMORY;
//		*azureToken = token;
//		return CKR_OK;
//	}
//}

CK_ULONG BackUp_Old_Credentials(CK_CHAR **old_TenantID, CK_CHAR **old_host, CK_CHAR **old_Password) {
	CK_CHAR_PTR tempTenant, tempHost, tempPassword;
	tempTenant = (CK_CHAR_PTR)_strdup(TENANTID);
	if (tempTenant == NULL) return CKR_HOST_MEMORY;
	tempHost = (CK_CHAR_PTR)_strdup(HOST);
	if (tempHost == NULL) {
		free(tempTenant);
		return CKR_HOST_MEMORY;
	}
	tempPassword = (CK_CHAR_PTR)_strdup(PASSWORD);
	if (tempPassword == NULL) {
		free(tempTenant);
		free(tempHost);
		return CKR_HOST_MEMORY;
	}
	*old_TenantID = tempTenant;
	*old_host = tempHost;
	*old_Password = tempPassword;
	return CKR_OK;
}

void Free_Old_Credentials(CK_CHAR *old_TenantID, CK_CHAR *old_Host, CK_CHAR *old_Password) {
	if (old_TenantID != NULL) free(old_TenantID);
	if (old_Host != NULL) free(old_Host);
	if (old_Password != NULL) free(old_Password);
}

BOOL Session_Timeout(time_t session_opened) {
	if (SESSION_TIMEOUT == TIMEOUT_INFINITE) return FALSE;
	/*else if (SESSION_TIMEOUT == TIMEOUT_DEFAULT) return FALSE;*/
	time_t now = time(NULL);
	time_t diff = now - session_opened;
	if (diff > SESSION_TIMEOUT * 60)
		return TRUE;
	else return FALSE;
}
