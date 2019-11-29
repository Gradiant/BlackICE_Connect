# Testing BlackICE Connect PKCS#11 provider Windows

To run the tests for the BlackICE Connect PKCS#11 provider it is necessary to have the provider installed. Refer to [Install_BIC_PKCS11_Windows.md](Install_BIC_PKCS11_Windows.md) for the installation procedure. The PKCS#11 tests assume the user PIN is "1234" for this reason it is necessary to set that PIN during the installation procedure to be able to run the tests. After installing the PKCS11 provider restart Visual Studio before running the tests.

Open the Test Explorer in Visual Studio (`Test->Test Explorer`). Select X64 architecture under `Test->Processor Architecture for AnyCPU projects`. Under the Test Explorer windows select `akv_pkcs11.Test` and click the run button to run the tests.