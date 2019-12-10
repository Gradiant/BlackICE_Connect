# Testing BlackICE Connect CNG KSP provider

To run the tests for the BlackICE Connect CNG KSP provider it is necessary to have the provider installed. Refer to [Install_BIC_KSP_Windows.md](Install_BIC_KSP_Windows.md) for the installation procedure. After installing the KSP provider restart Visual Studio before running the tests.

Open the Test Explorer in Visual Studio (`Test->Test Explorer`). Select X64 architecture under `Test->Processor Architecture for AnyCPU projects`. Under the Test Explorer windows select `akv_CNG.Test` and click the run button to run the tests. Some of the tests will open a pop-up dialog asking for the password used for encrypt the configuration file of the provider (refer to [Install_BIC_KSP_Windows.md](Install_BIC_KSP_Windows.md))