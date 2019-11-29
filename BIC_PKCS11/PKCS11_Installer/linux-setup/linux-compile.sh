#!/bin/bash

# In order to use colors: ${COLOR_CODE}text${NC}
HIGHLIGHT='\033[1;33m'
RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
NC='\033[0m'
ERROR="${RED}ERROR${NC}"

debug="debug"
release="release"
compilation=$debug
arch64bit="x64"
arch32bit="x86"
arch=$arch64bit
compilationCount=0

SETUP_PATH="$(pwd -P)"
ROOT_PATH="${SETUP_PATH}/.."
linuxBuildPath="${ROOT_PATH}/linux-build"
linuxInstallerPath="${ROOT_PATH}/linux-installer"
linuxInstallerCompletePath=""
distributionNamePath="${ROOT_PATH}/GradiantBlackIceConnect"
distributionLibraryName="BlackICEConnect"
readmeFilePath="${SETUP_PATH}/README.txt"
installScriptName="setup"
installScriptPath="${SETUP_PATH}/${installScriptName}.sh"
confTemplateFilename="BlackICEconnect_template"
confTemplateFile="${confTemplateFilename}.cnf"

## ARGUMENTS PARSING ##
# TODO: Improve with getopts?
while [ $# -gt 0 ]; do
	case $1 in
	-d | --debug)
		compilation=$debug
		((compilationCount++))
		shift
		;;
	-r | --release)
		compilation=$release
		((compilationCount++))
		shift
		;;
	-c | --clean)
		clean=true
		shift
		;;
	-t | --trace)
		trace=--trace
		shift
		;;
	-x86 | -m32)
		arch=$arch32bit
		shift
		;;
	*)
		printf "${ERROR}: Option not recognized: %s\n" "$1" 1>&2
		exit
		;;
	esac
done

## COMPILATION TYPE CHECKINGS ##
if ((compilationCount > 1)); then
	printf "${ERROR}: Specify only 1 of debug (-d) or release (-r)\n" 1>&2
	exit
elif ((compilationCount = 0)); then
	printf "${HIGHLIGHT}Selected %s (default)${NC} since no option were specified (use either -d or -r)\n" "$compilation" 1>&2
fi

if [ $compilation ]; then
	linuxInstallerCompletePath=${linuxInstallerPath}/${compilation}/${arch}
	## CLEAN ##
	printf "Creating Makefile in %s\n" "$linuxBuildPath"
	if [ $clean ]; then
		## CLEAN INSTALLER FOLDER ##
		printf "${HIGHLIGHT}Cleaning %s since --clean was specified${NC}\n" "$linuxInstallerCompletePath" 1>&2
		rm -rf ${linuxInstallerCompletePath}/*

		## CLEAN BUILD FOLDER ##
		printf "${HIGHLIGHT}Cleaning %s since --clean was specified${NC}\n" "$linuxInstallerCompletePath" 1>&2
		rm -rf ${linuxBuildPath}/*
	fi

	## CREATE INSTALLER/BUILD FOLDERS ##
	mkdir -p ${linuxInstallerCompletePath}
	mkdir -p ${linuxBuildPath}

	printf "${HIGHLIGHT}Compiling${NC} in ${HIGHLIGHT}%s${NC} mode\n" "$compilation"

	## CMAKE ##
	cd $linuxBuildPath
	printf "Running cmake from %s\n" $(pwd)
	# "shell_color" should be false if compiled from VS
	cmake ${trace} -DCMAKE_BUILD_TYPE=${compilation} -Dshell_color=true -Darch=${arch} ..
	make
	cd -
fi

## GRAB .SO ##
releasePath="linux-release"
debugPath="linux-debug"
soLocation="${ROOT_PATH}/../PKCS11_Connector/bin/$releasePath/x64/lib${distributionLibraryName}_$arch64bit.so"
if [ "$compilation" = "$debug" ]; then
	soLocation=${soLocation/$releasePath/$debugPath}
fi
if [ "$arch" = "$arch32bit" ]; then
	soLocation=${soLocation//$arch64bit/$arch32bit}
fi

## PACK ALL THE NECESSARY STUFF ##
mkdir -p $linuxInstallerCompletePath

cp $soLocation ${linuxInstallerCompletePath}/Gradiant${distributionLibraryName}_${compilation}_${arch}.so

chmod u+x $installScriptPath
cp $installScriptPath $linuxInstallerCompletePath
cp $readmeFilePath $linuxInstallerCompletePath

cp $confTemplateFile $linuxInstallerCompletePath

cp $ROOT_PATH/bin/linux-$compilation/$arch/* $linuxInstallerCompletePath

distributionNamePath+="_${compilation}_${arch}"

mv $linuxInstallerCompletePath $distributionNamePath
tar -czvf $distributionNamePath/GradiantBlackIceConnect_${compilation}_${arch}.tar.gz $distributionNamePath/*
mv $distributionNamePath $linuxInstallerCompletePath
