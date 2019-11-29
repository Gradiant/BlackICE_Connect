Copyright (c) 2018 BlackIceConnect by Gradiant. All rights reserved.

NOTES
    - Bash or equivalent interpreter is required to run the install script, due to some bash
    functionalities used.
    - <arch> stands for Architecture and it can be one of "x86" or "x64".
    - <compilation> stands for the type of compilation and can be one of "debug" or "release".
    - AKV stands for Azure Key Vault.
    - Any field (excluding AKV's and PIN) with an empty input will be set to its default value. These
    default values are listed below.
    - Each Path's length can't exceed 450 characters.

DEFAULT VALUES
    - AKV credentials and User PIN are MANDATORY.
    - For library, log files and configuration file paths, the default value is the folder where all
    installation files are currently placed.
    - Log level defaults to "4".
    - Maximum log file size defaults to "10M".
    - Save log history defaults to "1".
    - Session timeout defaults to "-1".

DISTRIBUTION
This product is distributed as a .tar.gz file which contains the following files:
    - README.txt: this file.
    - libBlackICEConnect_<arch>.so file: the shared library.
    - BlackIceConnect_template.cnf: A template of the configuration file which will be used by
    the library.
    - GradiantEncryptConfig_<arch>: This executable encrypts the configuration file in order to
    protect AKV's credentials. It should be executed if configuration file is modified manually
    (please don't forget to remove the "[CIPHER]" tag from the file).
    - GradiantBlackIceConnect_install.sh: The script which must be executed to proceed with the
    installation. Use "-x86" or "-m32" interchangeably to force a 32-bit installation.

INSTALLATION
To install BlackIceConnect, the script "setup.sh" must be executed. It accepts parameters to configure
whether to install 32/64bit version and whether the user wants to perform a custom (fill all
CONFIGURATION FIELDS that are necessary) or default (it will use default paths and values, except
for mandatory parameters). Please use like this to see the detailed usage:
$ ./setup.sh --help

CONFIGURATION FIELDS
During the installation, user will be asked to provide values for multiple fields:
    - Library file path: Where to store the library (.so) file.
    - Configuration file path: Where to store the configuration (.cnf) file.
    - AKV clientID: The Client ID of the AKV service.
    - AKV tenantID: The Tenant ID of the AKV service.
    - AKV host: The host of the AKV service. This is where AKV requests are going to be sent to.
    - AKV password: The password of the AKV service.
    - User PIN for the library: It will be used to encrypt the sensitive fields of the
    configuration file (AKV  tenant, host and password).
    - Log files path: This is where log files are going to be stored.
    - Log level: This is the level of verbosity of library's logging (0 = NONE (default); 1 = ERROR;
    2 = WARNING; 3 = INFO; 4 = TRACE).
    - Maximum log file size: This is the maximum size of the logfile in (K/M/G)Bytes. Note that this
    threshold can be exceeded for a few KB.
    - Save log history: Whether logging is historical or rotative. That is, if Logsize is reached
    the library can:
        (0) overwrite the same file.
        (1) Save current file as history and create a new one.
    - Session timeout: Defines how long the library should keep connected to AKV at most. 0 means
    forever and -1 means to use AKV's default session timeout.
    