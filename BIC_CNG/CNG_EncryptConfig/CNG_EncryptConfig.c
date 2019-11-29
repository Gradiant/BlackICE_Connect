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

#include <stdlib.h>
#include <src/interface.h>
#define MAX_ENV_SIZE 2048
int main(int argc, char *argv[])
{
	int                   err = 0;
	long				  result = 0;
#if defined _WIN64 || defined __x86_64__ || defined __powerpc64__ || defined __aarch64__ || defined __ia64__
	#define ENV_LABEL "CRYPTOKI_CNF_64"
#else
	#define ENV_LABEL "CRYPTOKI_CNF"
#endif
	if (argc < 3 || argc > 4) {
		printf("[Usage]: %s <CONF_FILE_PATH> <PIN> [NEW_PIN]  \n", argv[0]);
		return -1;
	}
	if (strlen(argv[1]) + strlen(ENV_LABEL) >= MAX_ENV_SIZE) return -2;
	char env[MAX_ENV_SIZE] = "";
	strcpy(env, ENV_LABEL);
	strcat(env, "=");
	strcat(env, argv[1]);
	err = putenv(env); // using this function instead of err = _putenv_s(ENV_LABEL,argv[1]); because the second one need aditional library in the SO
	if (err != 0) {
		printf("[Initialize]: The environment variable could not be set.\n");
		return -2;
	}
	int res = ConfigureApplication();
	if (res != 0) {
		printf("[Error]: Configuration file error!.\n");
		return -3;
	}
	if (argc == 3) {
		long result = EncryptAllConfigurationData(argv[2], strlen(argv[2]));
		if (result == 0) {
			printf("[InitPin]: User PIN initialized!.\n");
		}
		else {
			printf("[Error]: User PIN could not be initialized!.\n");
			return -3;
		}
	}
	else if (argc == 4) {
		result = DecryptAllConfigurationData(argv[2], strlen(argv[2]));
		if (err != 0) {
			printf("[Error]: User PIN could not be initialized!.\n");
			return -3;
		}
		result = EncryptAllConfigurationData(argv[3], strlen(argv[3]));
		if (err == 0) {
			printf("[SetPIN]: User PIN changed correctly!.\n");
		}
		else {
			printf("[Error]: User PIN could not be initialized!.\n");
			return -3;
		}
	}
	else printf("[Usage]: %s <CONF_FILE_PATH> <PIN> [newPin]  \n", argv[0]);
	
	return err;
}