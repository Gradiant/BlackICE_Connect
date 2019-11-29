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

#define MAX_LINE_LENGHT 512

/*
 * Function:  open_config_file
 * --------------------
 * Reads 'CRYPTOKI_CNF' or 'CRYPTOKI_CNF_64' environment variable depending on the Connector architecture and
 * returns a file descriptor to the configuration file.
 *
 *  mode: File open mode. 'r' for read and 'w' for write.
 *
 *  returns: The confguration file descriptor if successfull, a NULL pointer otherwise
 */
FILE* open_config_file(char* mode) {
	FILE* fd = NULL;
	if (mode == NULL) return fd;
	if (strcmp(mode, "r") != 0 && strcmp(mode, "w") != 0) return fd;

	// Retrieve configuration path from the environment variable
	char* strConfigEnvVarName = "CRYPTOKI_CNF";
#if defined _WIN64 || defined __x86_64__ || defined __powerpc64__ || defined __aarch64__ || defined __ia64__
	strConfigEnvVarName = "CRYPTOKI_CNF_64";
#endif
	char* configFilePath = getenv(strConfigEnvVarName);

	// Retrieve the file descriptor
	if (configFilePath == NULL) {
		fprintf(stderr, "The environment variable '%s' must to be created and configured with the location of the configuration file!\n", strConfigEnvVarName);
	}
	else {
		fd = fopen(configFilePath, mode);
		if (fd == NULL) {
			fprintf(stderr, "Can't open configuration file '%s' !\n", configFilePath);
		}
	}
	return fd;
}

/*
 * Function:  fill_configuration_field
 * --------------------
 * Copies data into a given parameter. This functions is responsible of allocating necessary memory.
 *
 *  parameter: The target parameter.
 *  data: The data to be copied.
 *
 *  returns: OK if successfull, HOST_MEMORY if it was not possible to allocate memory.
 */
int fill_configuration_field(char** parameter, char* data) {
	if (*parameter != NULL) {
		free(*parameter);
	}
	*parameter = (char*)malloc((strlen(data) + 1) * sizeof(char*));
	if (*parameter == NULL) {
		return HOST_MEMORY;
	}
	strcpy(*parameter, data);
	return OK;
}


/*
 * Function:  enlarge_buffer
 * --------------------
 * Enlarges a given buffer to the specified length.
 *
 *  buffer: The buffer to enlage.
 *  length: The new size of the buffer.
 *
 *  returns: OK if successfull, HOST_MEMORY if it was not possible to allocate memory.
 */
int enlarge_buffer(char** buffer, int length) {
	int retVal = OK;
	if (length == 0) {
		if (*buffer != NULL) {
			free(*buffer);
			*buffer = NULL;
		}
		return retVal;
	}
	if (*buffer == NULL) {
		*buffer = (unsigned char*)malloc(length * sizeof(char*));
		if (*buffer == NULL) {
			fprintf(stderr, "Memory allocation failed!\n");
			retVal = HOST_MEMORY;
		}
	}
	else {
		unsigned char* reallocatedBuffer = (unsigned char*)realloc(*buffer, length * sizeof(char*));
		if (reallocatedBuffer == NULL) {
			fprintf(stderr, "Memory re-allocation failed!\n");
			free(buffer);
			retVal = HOST_MEMORY;
		}
		else {
			*buffer = reallocatedBuffer;
		}
	}
	return retVal;
}

/*
 * Function:  ConfigureApplication
 * --------------------
 * Fills global variables with configuration file values.
 *
 *  returns: OK if successfull.
 *           CONF_FILE_NOT_FOUND if configuration file can not be found.
 *           BAD_CONF_FILE if configuration file can not be successfully parsed.
 *           HOST_MEMORY if an allocation memory error happens.
 */
int ConfigureApplication() {
	// Fill Global variables with default values
	ClearGlobalData();
	APIVERSION							= _strdup("2016-10-01");
	AUTH_APIVERSION						= _strdup("1.0");
	AUTH_URL							= _strdup("https://login.windows.net");
	RESOURCE							= _strdup("https://vault.azure.net");
	AUTH_METHOD							= _strdup("SecureLogin");
	if (APIVERSION == NULL || AUTH_APIVERSION == NULL || AUTH_URL == NULL || RESOURCE == NULL || AUTH_METHOD == NULL) {
		ClearGlobalData();
		return HOST_MEMORY;
	}
	
	CIPHER								= FALSE;
	LOG_CONTEXT.DEBUG_LEVEL				= 0;
	LOG_CONTEXT.MAX_LOG_BYTES			= 0x100000; //1MB by default
	LOG_CONTEXT.LOG_MODE_SAVE_HISTORY	= TRUE;
	SESSION_TIMEOUT						= TIMEOUT_DEFAULT;
	HSM_PROCESSED						= FALSE;
	CLIENTID							= NULL;
	TENANTID							= NULL;
	HOST								= NULL;
	
	
	errno_t err;
	int i, j, numQuots;
	char line[MAX_LINE_LENGHT], parameter[MAX_CONF_PARAMETER_SIZE], data[450], mask = 0x0F, *token1;
	int optionalMask = 0xffffffff;
	BOOL duplicatedKeyword = 0;
	int retVal = OK;


	FILE* fp = open_config_file("r");
	if (fp == NULL) {
		return CONF_FILE_NOT_FOUND;
	}

	while (feof(fp) == 0)
	{
		line[0] = '\0';
		// Read a line from the file
		fgets(line, MAX_LINE_LENGHT, fp);

		if (strcmp(line, "") == 0) {
			continue;
		}

		// Strip prefixed spaces from line
		while (line[0] == ' ') {
			unsigned long int len = strlen(line);
			for (i = 0; i <= len; i++) line[i] = line[i + 1];
		}

		// Ignore coments and endline
		if (line[0] != '#' && line[0] != '\n') {
			i = 0;
			j = 0;
			while ((i < MAX_CONF_PARAMETER_SIZE - 1) && line[i] != '=' && line[i] != '\n' && line[i] != '#') {
				if (line[i] != ' ') {//ignore spaces
					parameter[j] = line[i];
					j++;
				}
				i++;
			}
			parameter[j] = '\0';
			if (strcmp(parameter, "[CIPHER]") == 0) {
				if (((optionalMask & 0x01) == 0x0)) {
					duplicatedKeyword = 1;
					ClearGlobalData();
					break;
				}
				CIPHER = TRUE;
				optionalMask &= ~0x01;
				continue;
			}
			// Count the number of QUOT characters. Al least two quot characters are required.
			numQuots = 0;
			for (i = 0; i <= strlen(line); i++) {
				if (line[i] == '"') numQuots++;
			}

			if (numQuots < 2) {
				retVal = BAD_CONF_FILE;
				break;
			}
						
			token1 = strtok(line, "\"");
			if (token1 != NULL) {
				token1 = strtok(NULL, "\"");
				if (token1 != NULL && strcmp(token1, "\n") != 0) {
					if (strlen(token1) + 1 > sizeof data / sizeof *data) {
						ClearGlobalData();
						retVal = BAD_CONF_FILE;
						break;
					}
					strcpy(data, token1);
					if (strcmp(parameter, "APIVERSION") == 0) {
						if (((optionalMask & 0x02) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x02;
						free(APIVERSION);
						APIVERSION = _strdup(data);
						if (APIVERSION == NULL) {
							ClearGlobalData();
							retVal = HOST_MEMORY;
							break;
						}
					}
					else if (strcmp(parameter, "AUTH_APIVERSION") == 0) {
						if (((optionalMask & 0x04) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x04;
						free(AUTH_APIVERSION);
						AUTH_APIVERSION = _strdup(data);
						if (AUTH_APIVERSION == NULL) {
							ClearGlobalData();
							retVal = HOST_MEMORY;
							break;
						}
					}
					else if (strcmp(parameter, "AUTH_URL") == 0) {
						if (((optionalMask & 0x08) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x08;
						free(AUTH_URL);
						AUTH_URL = _strdup(data);
						if (AUTH_URL == NULL) {
							ClearGlobalData();
							retVal = HOST_MEMORY;
							break;
						}
					}
					else if (strcmp(parameter, "RESOURCE") == 0) {
						if (((optionalMask & 0x10) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x10;
						free(RESOURCE);
						RESOURCE = _strdup(data);
						if (RESOURCE == NULL) {
							ClearGlobalData();
							retVal = HOST_MEMORY;
							break;
						}
					}
					else if (strcmp(parameter, "CLIENTID") == 0) {
						if (((mask & 0x08) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						CLIENTID = _strdup(data);
						if (CLIENTID == NULL) {
							ClearGlobalData();
							retVal = HOST_MEMORY;
							break;
						}
						mask = mask & ~0x08;
					}
					else if (strcmp(parameter, "TENANTID") == 0) {
						if (((mask & 0x04) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						TENANTID = _strdup(data);
						if (TENANTID == NULL) {
							ClearGlobalData();
							retVal = HOST_MEMORY;
							break;
						}
						mask = mask & ~0x04;
					}
					else if (strcmp(parameter, "HOST") == 0) {
						if (((mask & 0x02) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						HOST = _strdup(data);
						if (HOST == NULL) {
							ClearGlobalData();
							retVal = HOST_MEMORY;
							break;
						}
						if (strlen(HOST) > 1) {
							if (HOST[strlen(HOST) - 1] == '/') HOST[strlen(HOST) - 1] = '\0';
						}
						mask = mask & ~0x02;
					}
					else if (strcmp(parameter, "PASSWORD") == 0) {
						if (((mask & 0x01) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						PASSWORD = _strdup(data);
						if (PASSWORD == NULL) {
							ClearGlobalData();
							retVal = HOST_MEMORY;
							break;
						}
						mask = mask & ~0x01;
					}
					else if (strcmp(parameter, "LogPath") == 0) {
						if (((optionalMask & 0x20) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x20;
						LOG_CONTEXT.LOGS_PATH = _strdup(data);
						if (LOG_CONTEXT.LOGS_PATH == NULL) {
							ClearGlobalData();
							retVal = HOST_MEMORY;
							break;
						}
					}
					else if (strcmp(parameter, "LogLevel") == 0) {
						if (((optionalMask & 0x40) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x40;
						if (strlen(data) == 1) {
							LOG_CONTEXT.DEBUG_LEVEL = data[0] - '0';
						}
					}
					else if (strcmp(parameter, "LogSize") == 0) {
						if (((optionalMask & 0x80) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x80;
						unsigned char powerPos = strlen(data) - 1;
						int max_log_bytes = 0; // Invalid
						switch (data[powerPos]) {
						case 'K':
							max_log_bytes = 0x400; // 1024 = 1K
							break;
						case 'M':
							max_log_bytes = 0x100000; // 0x100000 = 1M
							break;
						case 'G':
							max_log_bytes = 0x40000000; // 0x40000000 = 1G
							break;
						default:
							max_log_bytes = 0x1; // 1 byte
							break;
						}
						data[powerPos] = 0;
						LOG_CONTEXT.MAX_LOG_BYTES = atoi(data);
						LOG_CONTEXT.MAX_LOG_BYTES *= max_log_bytes;
					}
					else if (strcmp(parameter, "SaveLogHistory") == 0) {
						if (((optionalMask & 0x100) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x100;
						if (data[1] != '\0') {
							retVal = BAD_CONF_FILE;
							break;
						}
						else if (data[0] == '1') {
							LOG_CONTEXT.LOG_MODE_SAVE_HISTORY = TRUE;
						}
						else if (data[0] == '0') {
							LOG_CONTEXT.LOG_MODE_SAVE_HISTORY = FALSE;
						}
						else {
							retVal = BAD_CONF_FILE;
							break;
						}
					}
					else if (strcmp(parameter, "SessionTimeout") == 0) {
						if (((optionalMask & 0x200) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x200;
						char* c;
						long int converted = strtol(data, &c, 10);
						if (*c != '\0') {
							//strtol will leave c pointing to the next char in the string that
							//couldn't be converted. If that's not a \0 it means that input
							//contains some non-numeric character.
							ClearGlobalData();
							retVal = BAD_CONF_FILE;
							break;
						}
						else {
							SESSION_TIMEOUT = converted;
						}
					}
					else if (strcmp(parameter, "HSM_PROCESSED") == 0) {
						if (((optionalMask & 0x400) == 0x0)) {
							duplicatedKeyword = 1;
							ClearGlobalData();
							break;
						}
						optionalMask &= ~0x400;
						if (strcmp(data, "true") == 0)
							HSM_PROCESSED = TRUE;
					}
				}
			}
			
		}
	}
	if (fp) {
		err = fclose(fp);
		if (err != 0) {
			printf("The file 'BlackICEconnect.cnf' was not closed\n");
		}
	}
	if (duplicatedKeyword) {
		fprintf(stderr, "Duplicated configuration keyword '%s'!\n", parameter);
		retVal = BAD_CONF_FILE;
	}
	if (mask) {
		ClearGlobalData();
		retVal = BAD_CONF_FILE;
	}
	return retVal;
}

/*
 * Function:  ClearGlobalData
 * --------------------
 * Free the memory of global variables.
 */
void ClearGlobalData() {
	if (APIVERSION				!= NULL) free(APIVERSION);				APIVERSION = NULL;
	if (AUTH_APIVERSION			!= NULL) free(AUTH_APIVERSION);			AUTH_APIVERSION = NULL;
	if (AUTH_URL				!= NULL) free(AUTH_URL);				AUTH_URL = NULL;
	if (RESOURCE				!= NULL) free(RESOURCE);				RESOURCE = NULL;
	if (CLIENTID				!= NULL) free(CLIENTID);				CLIENTID = NULL;
	if (TENANTID				!= NULL) free(TENANTID);				TENANTID = NULL;
	if (HOST					!= NULL) free(HOST);					HOST = NULL;
	if (PASSWORD				!= NULL) free(PASSWORD);				PASSWORD = NULL;
	if (LOG_CONTEXT.LOGS_PATH	!= NULL) free(LOG_CONTEXT.LOGS_PATH);	LOG_CONTEXT.LOGS_PATH = NULL;
	if (AUTH_METHOD				!= NULL) free(AUTH_METHOD);				AUTH_METHOD = NULL;
}

/*
 * Function:  EncryptConfFile
 * --------------------
 * Fills the configuration file with global variable TENANTID, HOST and PASSWORD values which are spected to be encrypted
 * and sets a TAG indicating the config file is encrypted.
 *
 *  returns: OK if successfull.
 *           CONF_FILE_NOT_FOUND if configuration file can not be found.
 *           BAD_CONF_FILE if configuration file can not be successfully parsed.
 *           HOST_MEMORY if an allocation memory error happens.
 */
int EncryptConfFile() {
	char mask = 0x07;
	const char* strTenantId = "[CIPHER] #User credentials have been encrypted for security. "
		"This operation is irreversible. To change them, delete this tag and enter them again.\n"
		"TENANTID = \"%s\"\n";
	const char* strHost = "HOST = \"%s\"\n";
	const char* strPassword = "PASSWORD = \"%s\"\n";

	int retVal = OK;

	// Check global variables are initialized
	if (TENANTID == NULL || HOST == NULL || PASSWORD == NULL) {
		retVal = HOST_MEMORY;
		return retVal;
	}

	// Read configuration file
	FILE* fp = open_config_file("r");
	if (fp == NULL) {
		retVal = CONF_FILE_NOT_FOUND;
		return retVal;
	}

	// Allocate memory for the temporal buffer
	int outputTemporalBufferLength = 0;
	unsigned char* outputTemporalBuffer = NULL;
	unsigned char* prtOutputTemporalBuffer = outputTemporalBuffer;

	while (feof(fp) == 0)
	{
		// Read a line from the configuration file
		char line[256] = { 0 };
		fgets(line, 256, fp);
		if (line == NULL) {
			retVal = BAD_CONF_FILE;
			break;
		}

		// Remove spaces and tabs at the beginnig of the line
		while (line[0] == ' ' || line[0] == '\t') {
			unsigned long int len = strlen(line);
			for (unsigned long int i = 0; i <= len; i++) {
				line[i] = line[i + 1];
			}
		}

		// If it is a comment or a newline character, then copy the line into the buffer and continue
		if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
			int previousTemporalBufferLength = outputTemporalBufferLength;
			outputTemporalBufferLength += strlen(line);
			int allocationResult;
			if ((allocationResult = enlarge_buffer(&outputTemporalBuffer, outputTemporalBufferLength + 1)) != OK) { // +1 for the \0
				retVal = allocationResult;
				break;
			}
			prtOutputTemporalBuffer = outputTemporalBuffer + previousTemporalBufferLength;
			sprintf(prtOutputTemporalBuffer, "%s", line);
			prtOutputTemporalBuffer = outputTemporalBuffer + outputTemporalBufferLength;
			continue;
		}

		int i = 0;
		int j = 0;
		BOOL duplicatedKeyword = 0;
		char parameter[MAX_CONF_PARAMETER_SIZE];
		while ((i < MAX_CONF_PARAMETER_SIZE - 1) && line[i] != '=' && line[i] != '\n' && line[i] != '#') {
			if (line[i] != ' ') { //ignore spaces
				parameter[j] = line[i];
				j++;
			}
			i++;
		}
		parameter[j] = '\0';
		if (strcmp(parameter, "TENANTID") == 0) {
			if ((mask & 0x04) == 0x4) {
				mask &= ~0x04;
				int previousTemporalBufferLength = outputTemporalBufferLength;
				outputTemporalBufferLength += snprintf(NULL, 0, strTenantId, TENANTID);
				int allocationResult;
				if ((allocationResult = enlarge_buffer(&outputTemporalBuffer, outputTemporalBufferLength + 1)) != OK) { // +1 for the \0
					retVal = allocationResult;
					break;
				}
				prtOutputTemporalBuffer = outputTemporalBuffer + previousTemporalBufferLength;
				int numBytesWritten = sprintf(prtOutputTemporalBuffer, strTenantId, TENANTID);
				prtOutputTemporalBuffer = outputTemporalBuffer + numBytesWritten;
			}
			else {
				duplicatedKeyword = 1;
			}
		}
		else if (strcmp(parameter, "HOST") == 0) {
			if ((mask & 0x02) == 0x2) {
				mask &= ~0x02;
				int previousTemporalBufferLength = outputTemporalBufferLength;
				outputTemporalBufferLength += snprintf(NULL, 0, strHost, HOST);
				int allocationResult;
				if ((allocationResult = enlarge_buffer(&outputTemporalBuffer, outputTemporalBufferLength + 1)) != OK) { // +1 for the \0
					retVal = allocationResult;
					break;
				}
				prtOutputTemporalBuffer = outputTemporalBuffer + previousTemporalBufferLength;
				int numBytesWritten = sprintf(prtOutputTemporalBuffer, strHost, HOST);
				prtOutputTemporalBuffer = outputTemporalBuffer + numBytesWritten;
			}
			else {
				duplicatedKeyword = 1;
			}
		}
		else if (strcmp(parameter, "PASSWORD") == 0) {
			if ((mask & 0x01) == 0x1) {
				mask &= ~0x01;
				int previousTemporalBufferLength = outputTemporalBufferLength;
				outputTemporalBufferLength += snprintf(NULL, 0, strPassword, PASSWORD);
				int allocationResult;
				if ((allocationResult = enlarge_buffer(&outputTemporalBuffer, outputTemporalBufferLength + 1)) != OK) { // +1 for the \0
					retVal = allocationResult;
					break;
				}
				prtOutputTemporalBuffer = outputTemporalBuffer + previousTemporalBufferLength;
				int numBytesWritten = sprintf(prtOutputTemporalBuffer, strPassword, PASSWORD);
				prtOutputTemporalBuffer = outputTemporalBuffer + numBytesWritten;
			}
			else {
				duplicatedKeyword = 1;
			}
		}
		else if (strcmp(parameter, "[CIPHER]") == 0) {
		}
		else {
			int previousTemporalBufferLength = outputTemporalBufferLength;
			outputTemporalBufferLength += strlen(line);
			int allocationResult;
			if ((allocationResult = enlarge_buffer(&outputTemporalBuffer, outputTemporalBufferLength + 1)) != OK) {
				retVal = allocationResult;
				break;
			}
			prtOutputTemporalBuffer = outputTemporalBuffer + previousTemporalBufferLength;
			sprintf(prtOutputTemporalBuffer, "%s", line);
			prtOutputTemporalBuffer = outputTemporalBuffer + outputTemporalBufferLength;
		}
		if (duplicatedKeyword) {
			fprintf(stderr, "Duplicated configuration keyword '%s'!\n", parameter);
			retVal = BAD_CONF_FILE;
			break;
		}
	}
	fclose(fp);

	if (mask == 0) {
		FILE* newfp = open_config_file("w");
		if (newfp == NULL) {
			retVal = CONF_FILE_NOT_FOUND;
		}
		else {
			fwrite(outputTemporalBuffer, sizeof(char), outputTemporalBufferLength, newfp);
			fclose(newfp);
		}
	}
	else {
		retVal = BAD_CONF_FILE;
	}
	free(outputTemporalBuffer);
	return retVal;
}

/*
 * Function:  GetToken
 * --------------------
 * Gets azure token.
 *
 *  azureToken: Pointer reference where the token will be stored.
 *
 *  returns: OK if successfull.
 *           HOST_MEMORY if an allocation memory error happens.
 *           UNDEFINED_ERROR if it is not possible to retrieve client data for some reason.
 */
int GetToken(char **azureToken) {
	struct token_response *tokenResponse = NULL;
	struct client_data *clientData = NULL;
	int result = UNDEFINED_ERROR;
	clientData = Store_ClientData(PASSWORD, AUTH_URL, RESOURCE, CLIENTID, TENANTID);
	if (clientData != NULL) {
		int http_result = Get_AccesToken(clientData, &tokenResponse);
		Free_ClientData(clientData);
		if (http_result == HTTP_OK) {
			if ((*azureToken = _strdup(tokenResponse->access_token)) != NULL) {
				result = OK;
			}
			else {
				result = HOST_MEMORY;
			}
		}
		Free_AccesTokenResponse(tokenResponse);
	}
	return result;
}