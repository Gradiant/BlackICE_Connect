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

#ifndef DEBUG_H_INCLUDED
#define DEBUG_H_INCLUDED

#include "common.h"//necessary for BOOL

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif


#define MAX_ARG 150
#define NONE 0
#define ERRORS 1
#define WARNING 2
#define INFO 3
#define TRACE 4
#define MAX_SMALL_DEBUG_BUFFER (30 + 1)
#define MAX_MEDIUM_DEBUG_BUFFER (50 + 1)
#define MAX_BIG_DEBUG_BUFFER (100 + 1)

#ifdef _WIN32
#define LOGS_PATH_SEPARATOR "\\"
#define F_OK 0
#else
#define LOGS_PATH_SEPARATOR "/"
#endif
#if defined _WIN64 || defined __x86_64__ || defined __powerpc64__ || defined __aarch64__ || defined __ia64__
#ifdef PKCS11
#define LOGS_FILE_NAME "PKCS11_BlackICEconnect_x64"
#endif
#if defined CNG_KSP || defined CNG_INSTALLER
#define LOGS_FILE_NAME "CNG_BlackICEconnect_x64"
#endif
#else
#ifdef PKCS11
#define LOGS_FILE_NAME "PKCS11_BlackICEconnect_x86"
#endif
#if defined CNG_KSP || defined CNG_INSTALLER
#define LOGS_FILE_NAME "CNG_BlackICEconnect_x86"
#endif
#endif
#define LOGS_FILE_EXTENSION ".log"

typedef struct context {
	char primitive[MAX_SMALL_DEBUG_BUFFER];
	char dataIn[MAX_SMALL_DEBUG_BUFFER];
	char dataOut[MAX_BIG_DEBUG_BUFFER];
	char * dynamicOut;
	char error[MAX_MEDIUM_DEBUG_BUFFER];
}context;

#ifndef STRUCT_LOG_INFO
#define STRUCT_LOG_INFO
struct log_info {
	char *LOGS_PATH;
	int  DEBUG_LEVEL;
	long int MAX_LOG_BYTES;
	BOOL DELETE_PREV_LOG_FILE;
	BOOL LOG_MODE_SAVE_HISTORY;
};
#endif /* STRUCT_LOG_INFO */

void Write_DebugData(struct context context, struct log_info logInfo);
void Context_Initialization(char * initialValue, struct context * context);

/**
 * @brief Checks whether the folder exists or not.
 *
 * @param absolutePath Path to the folder that must be checked.
 *
 * @return TRUE if folder exists. FALSE if folder does not exist.
 */
BOOL FolderExists(const char* const absolutePath);

/**
 * @brief Stores current local time inside the tm provided.
 *
 * @struct timeInfo [In, Out] Time struct to be filled.
 */
void RetrieveCurrentTimeInfo(struct tm** const timeInfo);

/**
 * @brief Writes the 3 whitespace lines used as a marker of the last line written
 * to the log file.
 *
 * The marker is useful when !LOG_MODE_SAVE_HISTORY, because it marks where to begin
 * writing logs when they're being rotated in the same file.
 *
 * @param f [In] file already opened in r+ mode.
 */
void WriteMarker(FILE* const f);

/**
 * @brief Deletes the 3 whitespace lines used as a marker of the last line written
 * to the log file.
 *
 * The marker is useful when !LOG_MODE_SAVE_HISTORY, because it marks where to begin
 * writing logs when they're being rotated in the same file.
 *
 * @param f [In] file already opened in r+ mode.
 */
void DeleteMarker(FILE* const f);

/**
 * @brief It formats the timestamp to the format desired for Logs file names (YYYY-MM-DD_hh-mm-ss)
 *
 * @param timeInfo [In] tm holding the time struct to be formatted.
 * @param dest [Out] destination buffer in which to put the formatted timestamp.
 */
void FormatLogFileTimestamp(struct tm* const timeInfo, char* const dest);

/**
 * @brief It renames the current log file to save it with a timestamp and creates a new
 * log file.
 *
 * If logHistory is true in .cnf file, log files already filled to MAX_LOG_BYTES will be stored like:
 * "log_YYYY-MM-DD_hh-mm-ss.txt"
 *
 * @param f [In, Out] FILE* to be changed from old to new log file.
 * @param filename [In] name of the current log file with full path.
 */
void RenameLogFileWithTimestamp(char* const filename);

/**
 * @brief Opens the log file in the requested mode.
 *
 * It handles automatically how logs are stored/rotated, as configured in .cnf file.
 *
 * @param mode [In] how the file is opened.
 *
 * @param logInfo [In] log properties.
 *
 * @return pointer to the file. It could be NULL.
 */
FILE* OpenLogFile(const char* const mode, struct log_info logInfo);

/**
 * @brief Updates current position of the cursor in the log file to make circular logs with max file size.
 *
 * @param f [in] pointer to the file, already opened.
 */
void UpdateLogCursorPosition(FILE* const f);

/**
 * @brief Closes the log file and updates current log file cursor with last bytes written.
 *
 * @param f file to be closed.
 *
 * @param logInfo [In] log properties.
 *
 * @return error code returned from the fclose() call.
 */
int CloseLogFile(FILE* const f, struct log_info logInfo);

/**
 * @brief Checks whether the file has more than MAX_LOG_BYTES or not.
 *
 * NOTE that file size limit is not exact, since there's no checking of how many bytes are going to
 * be written, and we simply check whether we have passed the limit with the last writing or not.
 *
 * @param logInfo [In] log properties.
 *
 * @return boolean indicating whether it can be appended or not.
 */
BOOL CanAppendToLogFile(struct log_info logInfo);

/**
 * @brief Deletes the log file if it already exists.
 *
 * @return Error code of the operation. 0 = OK, -1 = file not found.
 */
int InitializeLogs(struct log_info logInfo);
void Write_HexData(char* string, FILE *f, BOOL Template);
void Write_Debug_Call(char* call, struct log_info logInfo);
void Write_Debug_Template(struct context context, char* const type, char* const staticValue, char* dynamicValue, struct log_info logInfo);
void Write_Free_Text(const char* const text, struct log_info logInfo);

#endif // DEBUG_H_INCLUDED
