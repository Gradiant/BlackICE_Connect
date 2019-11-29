#!/bin/bash
#This is the installer for BlackIceConnect under Linux systems. It will create an env var and prepare the configuration file.

echo "******************************************************************************
**** Copyright (c) 2018 BlackIceConnect by Gradiant. All rights reserved. ****
**** Read the README.txt for more information on the installation process ****
**** and an explanation of the fields which are required, as well as a *******
**** list of the default values for all fields. ******************************
******************************************************************************"

confFilename="BlackICEconnect"
confFile="${confFilename}.cnf"
arch="64"
envVarName="CRYPTOKI_CNF"
libraryFile=""
tmpConfFile="tmp.cnf"

installationType=0 # 0 = DEFAULT, 1 = CUSTOM

usage="Usage: $(basename "${0}") [OPTIONS]

Options:
    -h, --help, --usage     Show this help.
    --custom                Do a custom installation, asking for the values of all the configuration options.
    --default               Do a default installation, asking only for the necessary values of configuration \
options (AKV credentials and User PIN) and using the current installation files as default location. \
(Used by DEFAULT if --custom is not specified).
    -x86, -m32              Perform 32-bit installation instead of 64-bit."

## ARGUMENTS PARSING ##
while [ $# -gt 0 ]; do
	case $1 in
	-x86 | -m32)
		arch="32"
		shift
		;;
	--default)
		installationType=0
		shift
		;;
	--custom)
		installationType=1
		shift
		;;
	--help | -h | --usage)
		printf "%s\n" "${usage}" 1>&2
		exit -1
		;;
	*)
		printf "Unrecognized option: %s.\n%s\n" "${1}" "${usage}" 1>&2
		exit -1
		;;
	esac
done

if [ "${arch}" = "64" ]; then
	envVarName+="_64"
fi

printf "Installing %sbit version\n" "${arch}" 1>&2

## LIBRARY PATH ##
if [ ${installationType} -eq 1 ]; then
	libraryInstallFilePath=$(read -p "Library installation path (default ./): " temp_var; echo ${temp_var} | envsubst)
else
	libraryInstallFilePath=""
fi
if [ -z "${libraryInstallFilePath}" ]; then
	libraryInstallFilePath=${PWD}
elif [ ! -d "${libraryInstallFilePath}" ]; then
	printf "Not a directory: %s\n" "${libraryInstallFilePath}" 1>&2
	exit -1
elif [ ! -r "${libraryInstallFilePath}" ]; then
	printf "Not -r permission for ${USER}: %s\n" "${libraryInstallFilePath}" 1>&2
	exit -1
elif [ ! -w "${libraryInstallFilePath}" ]; then
	printf "Not -w permission for ${USER}: %s\n" "${libraryInstallFilePath}" 1>&2
	exit -1
elif [ ! -x "${libraryInstallFilePath}" ]; then
	printf "Not -x permission for ${USER}: %s\n" "${libraryInstallFilePath}" 1>&2
	exit -1
fi

## CONF FILE PATH ##
if [ ${installationType} -eq 1 ]; then
	confInstallFilePath=$(read -p "Configuration file installation path (default ./): " temp_var; echo ${temp_var} | envsubst)
else
	confInstallFilePath=""
fi
if [ -z "${confInstallFilePath}" ]; then
	confInstallFilePath=${PWD}
elif [ ! -d "${confInstallFilePath}" ]; then
	printf "Not a directory: %s\n" "${confInstallFilePath}" 1>&2
	exit -1
elif [ ! -r "${confInstallFilePath}" ]; then
	printf "Not -r permission for ${USER}: %s\n" "${confInstallFilePath}" 1>&2
	exit -1
elif [ ! -w "${confInstallFilePath}" ]; then
	printf "Not -w permission for ${USER}: %s\n" "${confInstallFilePath}" 1>&2
	exit -1
elif [ ! -x "${confInstallFilePath}" ]; then
	printf "Not -x permission for ${USER}: %s\n" "${confInstallFilePath}" 1>&2
	exit -1
fi

## AKV CLIENTID ##
correctInput=0
while [ ${correctInput} -ne 1 ]; do
	akvClientId=$(read -p "AKV Client ID: " temp_var; echo ${temp_var} | envsubst)
	if [ -z "${akvClientId}" ]; then
		printf "Client ID can't be empty.\n" 1>&2
	else
		correctInput=1
	fi
done

## AKV TENANTID ##
correctInput=0
while [ ${correctInput} -ne 1 ]; do
	akvTenantId=$(read -p "AKV Tenant ID: " temp_var; echo ${temp_var} | envsubst)
	if [ -z "${akvTenantId}" ]; then
		printf "Tenant ID can't be empty.\n" 1>&2
	else
		correctInput=1
	fi
done

## AKV HOST ##
correctInput=0
while [ ${correctInput} -ne 1 ]; do
	akvHost=$(read -p "AKV Host: " temp_var; echo ${temp_var} | envsubst)
	if [ -z "${akvHost}" ]; then
		printf "Host can't be empty.\n" 1>&2
	else
		correctInput=1
	fi
done

## AKV PASSWORD ##
correctInput=0
while [ ${correctInput} -ne 1 ]; do
	akvPassword=$(read -sp "AKV Password: " temp_var; echo ${temp_var} | envsubst)
	printf "\n"
	if [ -z "${akvPassword}" ]; then
		printf "Password can't be empty.\n" 1>&2
	else
		correctInput=1
	fi
done

## USER PIN ##
correctInput=0
while [ ${correctInput} -ne 1 ]; do
	read -sp 'User PIN: ' userPin
	printf "\n"
	pinLength=${#userPin}
	if [ ${pinLength} -lt 4 ]; then
		printf "Pin must be at least 4 characters long\n" 1>&2
	else
		read -sp 'Please, confirm User PIN: ' userPinConfirmation
		printf "\n"
		if [ "${userPin}" = "${userPinConfirmation}" ]; then
			correctInput=1
		else
			printf "Pins do not match, please repeat.\n" 1>&2
		fi
	fi
done

## LOGS PATH ##
if [ ${installationType} -eq 1 ]; then
	logsPath=$(read -p "Log files installation path (default ./): " temp_var; echo ${temp_var} | envsubst)
else
	logsPath=""
fi
if [ -z "${logsPath}" ]; then
	logsPath=${PWD}
elif [ ! -d "${logsPath}" ]; then
	printf "Not a directory: %s\n" "${logsPath}" 1>&2
	exit -1
elif [ ! -r "${logsPath}" ]; then
	printf "Not -r permission for ${USER}: %s\n" "${logsPath}" 1>&2
	exit -1
elif [ ! -w "${logsPath}" ]; then
	printf "Not -w permission for ${USER}: %s\n" "${logsPath}" 1>&2
	exit -1
elif [ ! -x "${logsPath}" ]; then
	printf "Not -x permission for ${USER}: %s\n" "${logsPath}" 1>&2
	exit -1
fi

## LOG LEVEL ##
correctInput=0
while [ ${correctInput} -ne 1 ]; do
	if [ ${installationType} -eq 1 ]; then
		read -p 'Log level (0 = NONE (default); 1 = ERROR; 2 = WARNING; 3 = INFO; 4 = TRACE): ' logLevel
	else
		logLevel=""
	fi
	if [ -z "${logLevel}" ]; then
		logLevel=0
		correctInput=1
	else
		logLevelLength=${#logLevel}
		if [ ${logLevelLength} -gt 1 ]; then
			printf "Log Level is only 1 character long\n" 1>&2
		elif [[ "${logLevel}" =~ ^[0-9]$ ]]; then
			correctInput=1
		else
			printf "Incorrect input, please use only numbers.\n"
		fi
	fi
done

## LOG FILE SIZE ##
correctInput=0
while [ ${correctInput} -ne 1 ]; do
	if [ ${installationType} -eq 1 ]; then
		read -p 'Log files size (default 10M): ' logSize
	else
		logSize=""
	fi
	if [ -z ${logSize} ]; then
		logSize="10M"
		correctInput=1
	else
		logSizeLength=${#logSize}
		if [ ${logSizeLength} -lt 2 ]; then
			printf "Log files size must be at least 2 characters long\n" 1>&2
		elif [[ "$(cut -c -$((${logSizeLength} - 1)) <<<"${logSize}")" =~ ^[0-9]+$ ]] && [[ "$(cut -c ${logSizeLength} <<<"${logSize}")" =~ ^[KMG]$ ]]; then
			correctInput=1
		else
			printf "Incorrect value, please repeat (examples: 10M, 200K, 1G).\n"
		fi
	fi
done

## LOG HISTORY ##
correctInput=0
while [ ${correctInput} -ne 1 ]; do
	if [ ${installationType} -eq 1 ]; then
		read -p 'Save log history (0 = rotative (default); 1 = historical): ' saveLogHistory
	else
		saveLogHistory=""
	fi
	if [ -z ${saveLogHistory} ]; then
		saveLogHistory="0"
		correctInput=1
	else
		saveLogHistoryLength=${#saveLogHistory}
		if [ ${saveLogHistoryLength} -gt 1 ]; then
			printf "Save Log history is only 1 character long.\n" 1>&2
		elif [[ "${saveLogHistory}" =~ ^[01]$ ]]; then
			correctInput=1
		else
			printf "Incorrect input, please use only 0 or 1.\n"
		fi
	fi
done

## SESSION TIMEOUT ##
correctInput=0
while [ ${correctInput} -ne 1 ]; do
	if [ ${installationType} -eq 1 ]; then
		read -p 'Session timeout (-1 = AKV'"'s"' timeout (default); 0 = infinity; >0 = minutes): ' sessionTimeout
	else
		sessionTimeout=""
	fi
	if [ -z ${sessionTimeout} ]; then
		sessionTimeout="-1"
		correctInput=1
	elif [[ "${sessionTimeout}" =~ ^-1$|^[0-9]+$ ]]; then
		correctInput=1
	else
		printf "Incorrect value, please use only numbers, starting at -1.\n"
	fi
done

# Remove // from paths if any and change it for a /
libraryInstallFilePath=${libraryInstallFilePath/\/\//\/}
confInstallFilePath=${confInstallFilePath/\/\//\/}
logsPath=${logsPath/\/\//\/}

## FILL CONFIGURATION FILE ##
templateConfFile=$(find . -iname "BlackICEConnect_template.cnf")

cp ${templateConfFile} ${tmpConfFile}
sed -ri 's,^CLIENTID ?= ?".*",CLIENTID = "'"${akvClientId}"'",' ${tmpConfFile}
sed -ri 's,^TENANTID ?= ?".*",TENANTID = "'"${akvTenantId}"'",' ${tmpConfFile}
sed -ri 's,^HOST ?= ?".*",HOST = "'"${akvHost}"'",' ${tmpConfFile}
sed -ri 's,^PASSWORD ?= ?".*",PASSWORD = "'"${akvPassword}"'",' ${tmpConfFile}
sed -ri 's,^LogPath ?=.*,LogPath = "'"${logsPath}"'",' ${tmpConfFile}
sed -ri 's,^LogLevel ?=.*,LogLevel = "'"${logLevel}"'",' ${tmpConfFile}
sed -ri 's,^LogSize ?=.*,LogSize = "'"${logSize}"'",' ${tmpConfFile}
sed -ri 's,^SaveLogHistory ?=.*,SaveLogHistory = "'"${saveLogHistory}"'",' ${tmpConfFile}
sed -ri 's,^SessionTimeout ?=.*,SessionTimeout = "'"${sessionTimeout}"'",' ${tmpConfFile}

## ENVIRONMENT VAR ##
exportEnvVar="export ${envVarName}"
envVarCommand="${exportEnvVar}=${confInstallFilePath}/${confFile}"
homeProfileFile="${HOME}/.profile"
homeBashrcFile="${HOME}/.bashrc"
homeBashProfileFile="${HOME}/.bash_profile"
grepErrorRedirection="2> /dev/null"
# With the grep part we avoid multiple lines with the same export in case it's already present
# See https://stackoverflow.com/a/3557165/3459662 and https://unix.stackexchange.com/a/159514
grep -qs "^${exportEnvVar}=.*" ${homeProfileFile} ${grepErrorRedirection} && sed -ri "s,^${exportEnvVar}=.*,${envVarCommand}," ${homeProfileFile} || echo "${envVarCommand}" >> ${homeProfileFile}
grep -qs "^${exportEnvVar}=.*" ${homeBashrcFile} ${grepErrorRedirection} && sed -ri "s,^${exportEnvVar}=.*,${envVarCommand}," ${homeBashrcFile} || echo "${envVarCommand}" >> ${homeBashrcFile}
grep -qs "^${exportEnvVar}=.*" ${homeBashProfileFile} ${grepErrorRedirection} && sed -ri "s,^${exportEnvVar}=.*,${envVarCommand}," ${homeBashProfileFile} || echo "${envVarCommand}" >> ${homeBashProfileFile}
#Execute it as well
${envVarCommand}

## COPY LIB ##
libraryFile=$(find . -type f -regextype sed -regex "./GradiantBlackICEConnect_\(debug\|release\)_x\(64\|86\)\.so" | sed "s,^\./,,")
if [ -z "${libraryFile}" ]; then
	printf "Library GradiantBlackICEConnect_<compilation>_<arch>.so could not be found in installation directory\n" 1>&2
	exit
fi

if ! [ "${PWD}" = "${libraryInstallFilePath}" ]; then
	cp ${libraryFile} ${libraryInstallFilePath}
fi

## ENCRYPTION ##
# Call EncryptConfig using ${pin} and all other required variables (<CONF_FILE_PATH> <DLL_PATH> <PIN>)
encryptExe=$(find . -regextype sed -regex "./GradiantEncryptConfig_\(debug\|release\)_x\(64\|86\)")
${encryptExe} ${tmpConfFile} ${libraryInstallFilePath}/${libraryFile} ${userPin}

## COPY CONFIGURATION FILE ##
if ! [ "${confInstallFilePath}/${confFile}" = "${tmpConfFile}" ]; then
	mv ${tmpConfFile} ${confInstallFilePath}/${confFile}
fi

## SUMMARY ##
printf "\n** INSTALLATION SUMMARY **\n" 1>&2
printf "Library installed in %s/%s\n" "${libraryInstallFilePath}" "${libraryFile}" 1>&2
printf "Configuration file installed in %s/%s\n" "${confInstallFilePath}" "${confFile}" 1>&2
printf "Environment variable (${envVarName}) configured for current user (${USER})\n" 1>&2
printf "\n** IMPORTANT **\nIn order to make sure the environment variable is available, please do the following:\
\n1 - If you want to use the library from an application launched from \
your Desktop environment (GUI), please re-login.\n2 - If you want to use the library from shell, either\n\t\
2.1 - Perform a source of your .bashrc ('$ source \$HOME/.bashrc').\n\t2.2 - Restart this terminal.\n\t2.3 - Open a new terminal.\n"
