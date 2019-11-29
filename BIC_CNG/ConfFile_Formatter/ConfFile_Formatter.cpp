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


constexpr auto CONF_PATH = 1;
constexpr auto BIC_CLIENTID = 2;
constexpr auto BIC_TENANTID = 3;
constexpr auto BIC_HOST = 4;
constexpr auto BIC_PASSWORD = 5;
constexpr auto BIC_LOGPATH = 6;
constexpr auto BIC_LOGLEVEL = 7;
constexpr auto BIC_SAVELOGHISTORY = 8;
constexpr auto BIC_SESSIONTIMEOUT = 9;
constexpr auto MAX_ENV_SIZE = 2048;
#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream>
#include <streambuf>
#include <Windows.h>

using namespace std;

void FindAndReplaceAll(std::string & data, std::string toSearch, std::string replaceStr)
{
	// Get the first occurrence
	size_t pos = data.find(toSearch);
	// Repeat till end is reached
	while (pos != std::string::npos)
	{
		// Replace this occurrence of Sub String
		data.replace(pos, toSearch.size(), replaceStr);
		// Get the next occurrence from the current position
		pos = data.find(toSearch, pos + toSearch.size());
	}
}

int main(int argc, char *argv[])
{
	int                   err = 0;
	if (argc != 10) {
		return -1;
	}

	char pathLogs[MAX_ENV_SIZE] = "";
	strcpy(pathLogs, argv[CONF_PATH]);
	if ((strlen(argv[CONF_PATH]) - strlen("BlackICEconnect_win.cnf") - strlen("\\")) > 0) {
		pathLogs[strlen(argv[CONF_PATH]) - strlen("BlackICEconnect_win.cnf") - strlen("\\")] = '\0'; //delete \BlackICEconnect_win.cnf and get the path 
	}
	std::ifstream inputFile(argv[CONF_PATH]);
	std::string strInputFile((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
	if (strcmp(argv[BIC_CLIENTID], "null") != 0)
	{
		FindAndReplaceAll(strInputFile, "MY_CLIENTID", argv[BIC_CLIENTID]);
		FindAndReplaceAll(strInputFile, "MY_TENANTID", argv[BIC_TENANTID]);
		FindAndReplaceAll(strInputFile, "MY_HOST", argv[BIC_HOST]);
		FindAndReplaceAll(strInputFile, "MY_PASSWORD", argv[BIC_PASSWORD]);
	}
	if (strcmp(argv[BIC_LOGPATH],"default") == 0) 
	{
		FindAndReplaceAll(strInputFile, "LOG_PATH", pathLogs);
	}
	else
	{
		FindAndReplaceAll(strInputFile, "LOG_PATH", argv[BIC_LOGPATH]);
	}
	FindAndReplaceAll(strInputFile, "LOG_LEVEL", argv[BIC_LOGLEVEL]);
	FindAndReplaceAll(strInputFile, "SAVE_LOG", argv[BIC_SAVELOGHISTORY]);
	FindAndReplaceAll(strInputFile, "TIME_OUT", argv[BIC_SESSIONTIMEOUT]);

	std::ofstream outputFile(argv[CONF_PATH]);
	outputFile << strInputFile;

	outputFile.close();

	//update enviroment variables
	SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 1000, NULL);
	return 0;
}

