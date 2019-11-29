#!/bin/bash

base_path="$(pwd -P)"
build_path="$base_path/build"
source_path="$base_path/src"
lib_path="$base_path/lib/"
console_runner="$HOME/software/nunit-3.9/tools/NUnit.ConsoleRunner/tools/nunit3-console.exe"

test_filename="akv_pkcs11LibraryTest"
net_test_file="$source_path/${test_filename}.cs"
mono_test_file="$source_path/${test_filename}_mono.cs"
net_utils_file="$source_path/PKCS11Utils.cs"
mono_utils_file="$source_path/PKCS11Utils_mono.cs"
net_definitions_file="$source_path/PKCS11Definitions.cs"
mono_definitions_file="$source_path/PKCS11Definitions_mono.cs"
tmp_conversion_file="$source_path/tmp.cs"

test_lib_output="$build_path/${test_filename}.dll"
utils_file="$source_path/PKCS11Utils.cs"
net_rest_client_file="$source_path/RestClient.cs"
mono_rest_client_file="$source_path/RestClient_mono.cs"
nunit_lib_name="nunit.framework.dll"
newtonsoft_lib_name="Newtonsoft.Json.dll"

###################
## Conversions from .NET to Mono
###################
rm -f -- $source_path/*_mono.cs
#### mainTests file .NET -> Mono
touch ${tmp_conversion_file}
sed 's/TestMethod/Test/;s/TestClass/TestFixture/;s/ClassInitialize()/OneTimeSetUp/;s/TestContext testContext//;s/Microsoft.*/NUnit\.Framework\;/;s/c_ulong.*System\.UInt32/c_ulong\ =\ System\.UInt64/;s/c_long.*System\.Int32/c_long\ =\ System\.Int64/' ${net_test_file} > ${tmp_conversion_file} && mv ${tmp_conversion_file} ${mono_test_file}

#### Utils file .NET -> Mono
touch ${tmp_conversion_file}
sed 's/c_ulong.*System\.UInt32/c_ulong\ =\ System\.UInt64/;s/c_long.*System\.Int32/c_long\ =\ System\.Int64/' ${net_utils_file} > ${tmp_conversion_file} && mv ${tmp_conversion_file} ${mono_utils_file}

#### Definitions file .NET -> Mono
touch ${tmp_conversion_file}
sed 's/c_ulong.*System\.UInt32/c_ulong\ =\ System\.UInt64/;s/c_long.*System\.Int32/c_long\ =\ System\.Int64/' ${net_definitions_file} > ${tmp_conversion_file} && mv ${tmp_conversion_file} ${mono_definitions_file}

#### RestClient file .NET -> Mono
touch ${tmp_conversion_file}
sed 's/Microsoft.*/NUnit\.Framework\;/' ${net_rest_client_file} > ${tmp_conversion_file} && mv ${tmp_conversion_file} ${mono_rest_client_file}
###################

blackICE_lib_path="${base_path}/../../BIC_PKCS11/PKCS11_Connector/bin/linux-debug/x64"

mkdir -p $build_path

cd $build_path

while [ $# -gt 0 ]
do
    case $1 in
        -t|--test)
            test=1
            shift
            ;;
        -c|--clean)
            clean=1
            shift
            ;;
        -d|--debug)
            debug=1
            shift
            ;;
        -v|--verbose)
            verbose=1
            shift
            ;;
        *)
            printf "${ERROR}: Option not recognized: %s\n" "$1" 1>&2
            exit
            ;;
    esac
done

if [[ $clean ]] ; then
    printf "Cleaning %s since --clean was specified\n" "${build_path}" 1>&2
    rm -r *
fi

cp $lib_path* .

if [[ $test ]] ; then
    if [ ! -f ${base_path}/BlackICEconnect.cnf ]; then
        echo "File BlackICEconnect.cnf not found. You need to create it from the template BlackICEconnect_win.cnf and fill in all the fields."
        exit
    else
        cp ${base_path}/BlackICEconnect.cnf ${build_path}/.
    fi
    mcs -unsafe -define:LINUX ${mono_test_file} ${mono_definitions_file} ${mono_rest_client_file} ${mono_utils_file} -target:library -r:${nunit_lib_name} -r:${newtonsoft_lib_name} -out:${test_lib_output} -debug
    if [[ $debug ]] ; then
        LD_LIBRARY_PATH=${blackICE_lib_path} gdb --args mono ${console_runner} ${test_lib_output}
    elif [[ $verbose ]] ; then
        LD_LIBRARY_PATH=${blackICE_lib_path} MONO_LOG_LEVEL=debug mono ${console_runner} ${test_lib_output}
    else
        LD_LIBRARY_PATH=${blackICE_lib_path} mono ${console_runner} ${test_lib_output}
    fi
fi
