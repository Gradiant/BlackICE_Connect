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

#include <../AKV_Module/src/clientRest.h>
#include "Debug.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#ifdef _WIN32
#include <io.h> // For access().
#else
#include <sys/io.h>
#include <unistd.h>	
#endif
#include <sys/types.h>  // For stat().
#include <sys/stat.h>   // For stat().
#include "common.h"

#define LOG_LINE_ESTIMATED_LENGTH 120
#define LOG_MARKER_CHARACTER '\n'
#define LOG_MARKER_SEPARATOR_COUNT 3

static long int gCurrentBytesFromStart = 0;

BOOL FolderExists(const char* const absolutePath) {
#ifdef _WIN32
	if (_access(absolutePath, F_OK) == 0) {
#else
	if (access(absolutePath, F_OK) == 0) {
#endif
		struct stat status;
		stat(absolutePath, &status);
		unsigned long int debug = S_IFDIR;
		return (status.st_mode & S_IFDIR) != 0;
	}
	return FALSE;
}

void RetrieveCurrentTimeInfo(struct tm** const timeInfo) {
	time_t rawtime;
	time(&rawtime);
	*timeInfo = localtime(&rawtime);
}

void WriteMarker(FILE* const f) {
	for (unsigned char i = 0; i < LOG_MARKER_SEPARATOR_COUNT; ++i) {
		fprintf(f, "%c", LOG_MARKER_CHARACTER);
	}
}

void DeleteMarker(FILE* const f) {
	char buffer[LOG_LINE_ESTIMATED_LENGTH];
	long int markerPos = 0;
	unsigned char consecutiveMarkerChars = 0;
	BOOL markerFound = FALSE;
	unsigned short int i;
	char* line;

	do {
		if (consecutiveMarkerChars == 0) {
			markerPos = ftell(f);
		}
		line = fgets(buffer, LOG_LINE_ESTIMATED_LENGTH, f);
		i = 0;
		while (i < LOG_LINE_ESTIMATED_LENGTH) {
			if (buffer[i] == LOG_MARKER_CHARACTER) {
				++consecutiveMarkerChars;
				if (consecutiveMarkerChars >= LOG_MARKER_SEPARATOR_COUNT) {
					markerFound = TRUE;
					break;
				}
			}
			else if (buffer[i] == '\0') {
				break;
			}
			else if (buffer[i] != '\r') {
				consecutiveMarkerChars = 0;
				break;
			}
			++i;
		}
	} while (line != NULL && !markerFound);

	if (markerFound) {
		gCurrentBytesFromStart = markerPos;
	}
	else {
		fseek(f, 0, SEEK_END);
		gCurrentBytesFromStart = ftell(f);
	}
}

void FormatLogFileTimestamp(struct tm* const timeInfo, char* const dest) {
	unsigned char i = 0;
	dest[i++] = '_';
	sprintf(&dest[i], "%.4i", timeInfo->tm_year + 1900);
	i += 4;
	dest[i++] = '-';
	sprintf(&dest[i], "%.2i", timeInfo->tm_mon + 1);
	i += 2;
	dest[i++] = '-';
	sprintf(&dest[i], "%.2i", timeInfo->tm_mday);
	i += 2;
	dest[i++] = '_';
	sprintf(&dest[i], "%.2i", timeInfo->tm_hour);
	i += 2;
	dest[i++] = '-';
	sprintf(&dest[i], "%.2i", timeInfo->tm_min);
	i += 2;
	dest[i++] = '-';
	sprintf(&dest[i], "%.2i", timeInfo->tm_sec);
}

void RenameLogFileWithTimestamp(char* const filename) {
	gCurrentBytesFromStart = 0;

	struct tm* timeInfo;
	RetrieveCurrentTimeInfo(&timeInfo);
	char timestamp[21];
	FormatLogFileTimestamp(timeInfo, timestamp);

	size_t filenameLen = strlen(filename);
	size_t timestampLen = strlen(timestamp);
	char* newName = malloc(filenameLen + timestampLen + 1);
	strcpy(newName, filename);
	char* extensionPos = strrchr(newName, '.');
	char* extension = _strdup(extensionPos);
	strcpy(extensionPos, timestamp);
	strcpy(extensionPos + timestampLen, extension);

	rename(filename, newName);

	free(newName);
}

FILE* OpenLogFile(const char* const mode, struct log_info logInfo) {
	FILE* f;
	if (logInfo.LOGS_PATH == NULL) return NULL;
	size_t logsPathSize = strlen(logInfo.LOGS_PATH);
	size_t logsSeparatorSize = strlen(LOGS_PATH_SEPARATOR);
	size_t logsFilenameSize = strlen(LOGS_FILE_NAME);
	size_t logsFileExtensionSize = strlen(LOGS_FILE_EXTENSION);
	char* completePath = malloc(logsPathSize + logsSeparatorSize + logsFilenameSize + logsFileExtensionSize + 1);
	strcpy(completePath, logInfo.LOGS_PATH);
	if (!FolderExists(completePath)) {
		free(completePath);
		return NULL;
	}
	strcat(completePath, LOGS_PATH_SEPARATOR);
	strcat(completePath, LOGS_FILE_NAME);
	strcat(completePath, LOGS_FILE_EXTENSION);
	if (logInfo.LOG_MODE_SAVE_HISTORY && !CanAppendToLogFile(logInfo)) {
		RenameLogFileWithTimestamp(completePath);
	}
	f = fopen(completePath, mode);
	if (f == NULL) {
		//It means the file does not exist because it has just been renamed so open it for writing
		f = fopen(completePath, "w+");
	}
	free(completePath);
	if (f != NULL) {
		if (!logInfo.LOG_MODE_SAVE_HISTORY) {
			DeleteMarker(f);
			if (!CanAppendToLogFile(logInfo)) {
				gCurrentBytesFromStart = 0;
			}
		}
		else {
			fseek(f, 0, SEEK_END);
			gCurrentBytesFromStart = ftell(f);
		}
		fseek(f, gCurrentBytesFromStart, SEEK_SET);
	}
	return f;
}

void UpdateLogCursorPosition(FILE* const f) {
	gCurrentBytesFromStart = ftell(f); //current - previous cursor
}

int CloseLogFile(FILE* const f, struct log_info logInfo) {
	UpdateLogCursorPosition(f);

	if (!logInfo.LOG_MODE_SAVE_HISTORY) {
		WriteMarker(f);
	}

	return fclose(f);
}

BOOL CanAppendToLogFile(struct log_info logInfo) {
	if (gCurrentBytesFromStart >= logInfo.MAX_LOG_BYTES) {
		return FALSE;
	}
	return TRUE;
}

int InitializeLogs(struct log_info logInfo) {
	FILE *f;
	if (logInfo.LOGS_PATH == NULL) {
		logInfo.DEBUG_LEVEL = 0; //Deactivate logs
		return -1;
	}

	f = OpenLogFile("r+", logInfo);
	if (f == NULL) {
		//It does not exist, create it
		f = OpenLogFile("w", logInfo);
		if (f == NULL) {
			//If still NULL, there's some problem
			fprintf(stderr, "Can't open log file\n");
			return -1;
		}
	}
	CloseLogFile(f, logInfo);

	return 0;
}

void Write_HexData(char* string, FILE *f, BOOL Template) {
	int multx8 = 1;
	int multx4 = 0;
	for (int i = 0; i < strlen(string); i++) {
		fprintf(f, "%c", string[i]);
		if (multx8 == 8) {
			multx8 = 0;
			fprintf(f, " ");
			multx4++;
			if (multx4 == 4) {
				multx4 = 0;
				fprintf(f, "\n");
				if (Template)
					for (int j = 0; j < 100; j++) { fprintf(f, " "); }
				else
					for (int j = 0; j < 65; j++) { fprintf(f, " "); }
			}
		}
		multx8++;
	}
}

void Write_DebugData(struct context context, struct log_info logInfo) {
	if (logInfo.DEBUG_LEVEL == NONE) return;
	int i;
	FILE *f;
	char * timeStamp;

	f = OpenLogFile("r+", logInfo);
	if (f == NULL) {
		fprintf(stderr, "Can't open log file\n");
		return;
	}

	time_t rawtime;
	struct tm * timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	timeStamp = asctime(timeinfo);
	for (i = 0; i < strlen(timeStamp) - 1; i++) {
		fprintf(f, "%c", timeStamp[i]);
	}
	fprintf(f, " |");
	if (logInfo.DEBUG_LEVEL == ERRORS || logInfo.DEBUG_LEVEL == TRACE) {
		fprintf(f, " %s", context.primitive);
		for (i = 0; i < 30 - strlen(context.primitive); i++) { fprintf(f, " "); }
		fprintf(f, "|");
		if (strlen(context.error) != 0) {
			fprintf(f, " Exit: %s\n", context.error);
			CloseLogFile(f, logInfo);
			return;
		}
		else if (logInfo.DEBUG_LEVEL == TRACE) {
			if (strlen(context.dataOut) != 0 || context.dynamicOut != NULL) {
				fprintf(f, " OUT:  ");
				if (context.dynamicOut != NULL) {
					Write_HexData(context.dynamicOut, f, FALSE);
				}
				else
					fprintf(f, "%s", context.dataOut);
			}
			else if (strlen(context.dataIn) != 0) {
				fprintf(f, " IN:   %s", context.dataIn);
			}

		}
	}
	fprintf(f, "\n");
	CloseLogFile(f, logInfo);
	return;
}

void Context_Initialization(char* initialValue, struct context* context) {
	strcpy(context->primitive, initialValue);
	strcat(context->primitive, ": ");
	context->error[0] = '\0';
	context->dataIn[0] = '\0';
	context->dataOut[0] = '\0';
	context->dynamicOut = NULL;
}

void Write_Debug_Call(char* call, struct log_info logInfo) {
	if (logInfo.DEBUG_LEVEL != TRACE) return;
	int i;
	FILE *f;
	char * timeStamp;

	f = OpenLogFile("r+", logInfo);
	if (f == NULL) {
		fprintf(stderr, "Can't open log file\n");
		return;
	}

	time_t rawtime;
	struct tm * timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	timeStamp = asctime(timeinfo);
	for (i = 0; i < strlen(timeStamp) - 1; i++) {
		fprintf(f, "%c", timeStamp[i]);
	}
	fprintf(f, " |");
	fprintf(f, " Connecting to: %s", call);
	fprintf(f, "\n");

	CloseLogFile(f, logInfo);

	return;
}

void Write_Debug_Template(struct context context, char* const type, char* const staticValue, char* dynamicValue, struct log_info logInfo) {
	if (logInfo.DEBUG_LEVEL != TRACE) return;
	int i;
	FILE *f;
	char * timeStamp;

	f = OpenLogFile("r+", logInfo);
	if (f == NULL) {
		fprintf(stderr, "Can't open log file\n");
		return;
	}

	time_t rawtime;
	struct tm * timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	timeStamp = asctime(timeinfo);
	for (i = 0; i < strlen(timeStamp) - 1; i++) {
		fprintf(f, "%c", timeStamp[i]);
	}
	fprintf(f, " |");
	fprintf(f, " %s", context.primitive);
	for (i = 0; i < 30 - strlen(context.primitive); i++) { fprintf(f, " "); }
	fprintf(f, "|");
	fprintf(f, " [ENTRY TEMPLATE]    %s", type);
	if (strlen(staticValue) > 0) {
		if (strlen(type) < 20)
			for (i = 0; i < 21 - strlen(type); i++) { fprintf(f, " "); }
		fprintf(f, "%s", staticValue);
	}
	else if (dynamicValue != NULL) {
		if (strlen(type) < 20)
			for (i = 0; i < 21 - strlen(type); i++) { fprintf(f, " "); }
		Write_HexData(dynamicValue, f, TRUE);
	}
	fprintf(f, "\n");

	CloseLogFile(f, logInfo);

	return;
}

void Write_Free_Text(const char* const text, struct log_info logInfo) {
	FILE *f;

	f = OpenLogFile("r+", logInfo);
	if (f == NULL) {
		fprintf(stderr, "Can't open log file\n");
		return;
	}

	fprintf(f, "%s\n", text);
	CloseLogFile(f, logInfo);
	return;
}
