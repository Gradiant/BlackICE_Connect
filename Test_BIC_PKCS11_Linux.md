# Testing BlackICE Connect PKCS#11 provider Linux

To run the tests for the BlackICE Connect PKCS#11 provider it is necessary to have the provider installed. Refer to [Install_BIC_PKCS11_Linux.md](Install_BIC_PKCS11_Linux.md) for the installation procedure. The PKCS#11 tests assume the user PIN is "1234" for this reason it is necessary to set that PIN during the installation procedure to be able to run the tests.  After installing the PKCS#11 provider open a new terminal before running the tests.

The test are written in C# so in order to run them under Linux it is necessary to have Mono and NUnit installed. In order to install them the following commands can be run in Debian based distributions:

```bash
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 3FA7E0328081BFF6A14DA29AA6A19B38D3D831EF
echo "deb http://download.mono-project.com/repo/ubuntu stable-trusty main" | sudo tee /etc/apt/sources.list.d/mono-official-stable.list
sudo apt-get update
sudo apt-get install -y mono-devel
mkdir $HOME/software # Directory where nunit will be installed, change to your own needs. In case of changing it you need to change the variable console_runner from the script compilation.sh
cd $HOME/software
wget https://github.com/nunit/nunit/archive/3.9.tar.gz
tar xzvf 3.9.tar.gz
cd nunit-3.9/
./build.sh
```

The directory `Test_Projects/akv_pcks11.Test` has the script `compilation.sh` that allows to build and run the tests. To build the tests it is necessary to create the file `Test_Projects\akv_pkcs11.Test\BlackICEconnect.cnf` from the template `Test_Projects\akv_pkcs11.Test\BlackICEconnect_win.cnf` and fill in all the required fields. This file is used by the tests in order to access the AKV vault.

To compile and run the tests use the following command:
```bash
./compilation.sh -c -t # -c to clean previous compilation, -t to run the tests
```