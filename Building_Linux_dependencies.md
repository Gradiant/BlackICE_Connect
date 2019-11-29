# Building Linux dependencies

This document explain how to build Linux dependencies (zlib, OpenSSL and libCurl). These dependencies must be installed in the provided order. After building them they will be installed in the necessary directory tree used to build the Linux PKCS#11 provider.

## Building zlib
### Download and extract zlib

```bash
$ wget https://zlib.net/zlib-1.2.11.tar.gz
$ tar -xzvf zlib-1.2.11.tar.gz
$ cd zlib-1.2.11/
```

### Configure and build the library

#### x64-release
Configure:
```bash
$ CFLAGS=-fPIC ./configure --static -prefix=<project_dir>/libs/linux/zlib/release/x64 --64
```
Where `<project_dir>` is the directory where the repository was cloned.

Build:
```bash
$ make clean
$ make -j4 CC="gcc -m32" V=1   
$ make test #(optional)
$ make -j4 install V=1
```

#### x86-release
Configure:
```bash
$ CFLAGS="-m32 -fPIC" ./configure --static -prefix=<project_dir>/libs/linux/zlib/release/x64
```
Build:
```bash
$ make clean
$ make -j4 CC="gcc -m32" V=1   
$ make test #(optional)
$ make -j4 install V=1
```

## Building OpenSSL
### Download and extract OpenSSL

```bash
$ wget https://www.openssl.org/source/openssl-1.0.2n.tar.gz
$ tar xzvf openssl-1.0.2n.tar.gz
$ cd openssl-1.0.2n
```

### Configure and build the library

#### x64-release
Configure:
```bash
$ ./config -fPIC -static --with-zlib-include=<project_dir>/libs/linux/zlib/release/x64/include --with-zlib-lib=<project_dir>/libs/linux/zlib/release/x64/lib zlib no-zlib-dynamic --prefix=<project_dir>/libs/linux/openssl/release/x64 --openssldir=<project_dir>/libs/linux/openssl/release/x64/openssl no-shared no-threads no-tests
```
Build:
```bash
$ make clean
$ make -j4 V=1
$ make test #(optional)
$ make -j4 install V=1
```

#### x64-debug
Configure:
```bash
$ ./config -fPIC -static --debug --with-zlib-include=<project_dir>/libs/linux/zlib/release/x64/include --with-zlib-lib=<project_dir>/libs/linux/zlib/release/x64/lib zlib no-zlib-dynamic --prefix=<project_dir>/libs/linux/openssl/debug/x64 --openssldir=<project_dir>/libs/linux/openssl/debug/x64/openssl no-shared no-threads no-tests
```
Build:
```bash
$ make clean
$ make -j4 V=1
$ make test #(optional)
$ make -j4 install V=1
```

#### x86-release
Configure:
```bash
$ setarch i386 ./config -m32 -fPIC -static --with-zlib-include=<project_dir>/libs/linux/zlib/release/x86/include --with-zlib-lib=<project_dir>/libs/linux/zlib/release/x86/lib zlib no-zlib-dynamic --prefix=<project_dir>/libs/linux/openssl/release/x86 --openssldir=<project_dir>/libs/linux/openssl/release/x86/openssl no-shared no-threads no-tests
```
Build:
```bash
$ make clean
$ make -j4 CC="gcc -m32" V=1   
$ make test #(optional)
$ make -j4 install V=1
```

#### x86-debug
Configure:
```bash
$ setarch i386 ./config -m32 -fPIC -static --with-zlib-include=<project_dir>/libs/linux/zlib/release/x86/include --with-zlib-lib=<project_dir>/libs/linux/zlib/release/x86/lib zlib no-zlib-dynamic zlib no-zlib-dynamic --prefix=<project_dir>/libs/linux/openssl/debug/x86 --openssldir=<project_dir>/libs/linux/openssl/debug/x86/openssl no-shared no-threads no-tests
```
Build:
```bash
$ make clean
$ make -j4 CC="gcc -m32" V=1   
$ make test #(optional)
$ make -j4 install V=1
```

## Building libCurl
### Download and extract libCurl

```bash
$ wget https://curl.haxx.se/download/curl-7.54.0.tar.gz
$ tar xzvf curl-7.54.0.tar.gz
$ cd curl-7.54.0
```

### Configure and build the library

#### x64-release
Configure:
```bash
$ LIBS="-ldl" LDFLAGS="-static" ./configure --disable-shared --with-zlib=<project_dir>/libs/linux/zlib/release/x64 --with-ssl=<project_dir>/libs/linux/openssl/release/x64 --prefix=<project_dir>/libs/linux/libcurl/release/x64 --without-librtmp --without-ca-bundle --disable-ldap --disable-pthreads --disable-threaded-resolver
```
Build:
```bash
$ make clean
$ make -j4 V=1
$ make test #(optional)
$ make -j4 install V=1
```

#### x64-debug
Configure:
```bash
$ LIBS="-ldl" LDFLAGS="-static" ./configure --disable-shared --enable-debug --with-zlib=<project_dir>/libs/linux/zlib/release/x64 --with-ssl=<project_dir>/libs/linux/openssl/debug/x64 --prefix=<project_dir>/libs/linux/libcurl/debug/x64 --without-librtmp --without-ca-bundle --disable-ldap --disable-pthreads --disable-threaded-resolver
```
Build:
```bash
$ make clean
$ make -j4 V=1
$ make test #(optional)
$ make -j4 install V=1
```

#### x86-release
Configure:
```bash
$ LIBS="-ldl" LDFLAGS="-static" ./configure --host=i686-pc-linux-gnu CFLAGS="-m32" --disable-shared --with-zlib=<project_dir>/libs/linux/zlib/release/x86 --with-ssl=<project_dir>/libs/linux/openssl/release/x86 --prefix=<project_dir>/libs/linux/libcurl/release/x86 --without-librtmp --without-ca-bundle --disable-ldap --disable-pthreads --disable-threaded-resolver
```
Build:
```bash
$ make clean
$ make -j4 CC="gcc -m32" V=1   
$ make test #(optional)
$ make -j4 install V=1
```

#### x86-debug
Configure:
```bash
$ LIBS="-ldl" LDFLAGS="-static" ./configure --host=i686-pc-linux-gnu CFLAGS="-m32" --disable-shared --enable-debug --with-zlib=<project_dir>/libs/linux/zlib/release/x86 --with-ssl=<project_dir>/libs/linux/openssl/debug/x86 --prefix=<project_dir>/libs/linux/libcurl/debug/x86 --without-librtmp --without-ca-bundle --disable-ldap --disable-pthreads --disable-threaded-resolver
```
Build:
```bash
$ make clean
$ make -j4 CC="gcc -m32" V=1   
$ make test #(optional)
$ make -j4 install V=1
```

It's important to check the info provided after configuring libcurl

```
configure: Configured to build curl/libcurl:
 
  curl version:     7.54.0
  Host setup:       x86_64-pc-linux-gnu
  Install prefix:   /home/jjimenez/code/BlackICE/pkcs11_wrapper/cs_pkcs11_R2/src/RestClient/libcurl64-linux/release
  Compiler:         gcc
  SSL support:      enabled (OpenSSL)
  SSH support:      no      (--with-libssh2)
  zlib support:     enabled
  GSS-API support:  no      (--with-gssapi)
  TLS-SRP support:  enabled
  resolver:         default (--enable-ares / --enable-threaded-resolver)
  IPv6 support:     enabled
  Unix sockets support: enabled
  IDN support:      no      (--with-{libidn2,winidn})
  Build libcurl:    Shared=no, Static=yes
  Built-in manual:  enabled
  --libcurl option: enabled (--disable-libcurl-option)
  Verbose errors:   enabled (--disable-verbose)
  SSPI support:     no      (--enable-sspi)
  ca cert bundle:   no
  ca cert path:     /etc/ssl/certs/
  ca fallback:      no
  LDAP support:     no      (--enable-ldap / --with-ldap-lib / --with-lber-lib)
  LDAPS support:    no      (--enable-ldaps)
  RTSP support:     enabled
  RTMP support:     no      (--with-librtmp)
  metalink support: no      (--with-libmetalink)
  PSL support:      no      (libpsl not found)
  HTTP2 support:    disabled (--with-nghttp2)
  Protocols:        DICT FILE FTP FTPS GOPHER HTTP HTTPS IMAP IMAPS POP3 POP3S RTSP SMB SMBS SMTP SMTPS TELNET TFTP
```

It should be checked that `SSH` is not activated (since the library is not linking to libssh2), and that the field protocols includes `HTTPS`.



