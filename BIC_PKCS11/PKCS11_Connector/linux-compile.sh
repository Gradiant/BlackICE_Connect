#!/bin/bash

# Upper-case is used for 'const' variables. Variables which might be changed at some point are lower-case
HIGHLIGHT='\033[1;33m'
RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
NC='\033[0m'
DEBUG="Debug"
RELEASE="Release"
ERROR="${RED}ERROR${NC}"

ROOT_PATH="$(pwd -P)/"
build_path="${ROOT_PATH}linux-build/"

mkdir -p ${build_path}

# Compilation type (debug, release). Used to pass arguments to CMake
while [ $# -gt 0 ]
do
    case $1 in
        -d|--debug)
            debug=$DEBUG
            shift
            ;;
        -r|--release)
            release=$RELEASE
            shift
            ;;
        -c|--clean)
            clean=true
            shift
            ;;
        -t|--trace)
            trace=--trace
            shift
            ;;
        -x86|-m32)
            x86=x86
            shift
            ;;
        *)
            printf "${ERROR}: Option not recognized: %s\n" "$1" 1>&2
            exit
            ;;
    esac
done

compilation=$DEBUG
if [[ $debug && $release ]] ; then
    printf "${ERROR}: Can't specify both debug (-d) and release (-r)\n" 1>&2
    exit
elif [[ $release && ! $debug ]] ; then
    compilation=$RELEASE
elif [[ ! $debug ]] ; then
    printf "${CYAN}Selected %s (default) since no option were specified (use either -d or -r)${NC}\n" "$compilation" 1>&2
fi

printf "Creating Makefile in %s\n" "${build_path}"
cd ${build_path}
if [[ $clean ]] ; then
    printf "Cleaning %s since --clean was specified\n" "${build_path}" 1>&2
    rm -r *
fi
printf "${GREEN}Compiling in %s mode${NC}\n" "${compilation}"
# "shell_color" should be false if compiled from VS
printf "Running cmake from %s\n" $(pwd)
cmake ${trace} -DCMAKE_BUILD_TYPE=${compilation} -Dshell_color=true -D${x86}=${x86} ..
make
cd -
