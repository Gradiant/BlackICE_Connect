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

#ifndef __KSP_H__
#define __KSP_H__

#include <ncrypt_provider.h>
#include <bcrypt_provider.h>
#include <src/clientRest.h>
#include <openssl/asn1.h>
#include <src/Debug.h>
#include <src/librb64u.h>
#include "../resource.h"

#define KSP_INTERFACE_VERSION BCRYPT_MAKE_INTERFACE_VERSION(1,0) //version of the KSP interface
#define KSP_VERSION 0x00010000                         //version of the KSP
#define KSP_SUPPORT_SECURITY_DESCRIPTOR   0x00000000             //This KSP supports security descriptor
#define GRADIANT_KSP_PROVIDER_NAME           L"Gradiant Key Storage Provider" //name of the KSP provider
#define KSP_PROVIDER_MAGIC          0x53504C50      // SPLP
#define KSP_KEY_MAGIC               0x53504C4b      // SPLK
#define KSP_KEY_FILE_VERSION        1               // version of the key file
#define KSP_RSA_ALGID					  1               // Algorithm ID RSA
#define KSP_DEFAULT_KEY_LENGTH			  2048            // default key length
#define KSP_RSA_MIN_LENGTH				  2048             // minimal key length
#define KSP_RSA_MAX_LENGTH				  4096           // maximal key length
#define KSP_RSA_INCREMENT		          2              // increment of key length
//property ID
#define KSP_IMPL_TYPE_PROPERTY      1
#define KSP_MAX_NAME_LEN_PROPERTY   2
#define KSP_NAME_PROPERTY           3
#define KSP_VERSION_PROPERTY        4
#define KSP_SECURITY_DESCR_SUPPORT_PROPERTY     5
#define KSP_ALGORITHM_PROPERTY      6
#define KSP_BLOCK_LENGTH_PROPERTY   7
#define KSP_EXPORT_POLICY_PROPERTY  8
#define KSP_KEY_USAGE_PROPERTY      9
#define KSP_KEY_TYPE_PROPERTY       10
#define KSP_LENGTH_PROPERTY         11
#define KSP_LENGTHS_PROPERTY        12
#define KSP_SECURITY_DESCR_PROPERTY 13
#define KSP_ALGORITHM_GROUP_PROPERTY 14
#define KSP_USE_CONTEXT_PROPERTY    15
#define KSP_UNIQUE_NAME_PROPERTY    16
#define KSP_UI_POLICY_PROPERTY      17
#define KSP_WINDOW_HANDLE_PROPERTY  18
#define KSP_SHA1 L"SHA1"
#define KSP_SHA256 L"SHA256"
#define KSP_SHA384 L"SHA384"
#define KSP_SHA512 L"SHA512"
//const
#define MAXUSHORT   0xffff
#define MAX_NUM_PROPERTIES  100
#define MAXPINLEN 80


//error handling
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_INTERNAL_ERROR           ((NTSTATUS)0xC00000E5L)
#define STATUS_INVALID_SIGNATURE        ((NTSTATUS)0xC000A000L)

#define STATUS_LOGON_FAILURE			((NTSTATUS)0xC000006D)
#define STATUS_DECRYPTION_FAILED		((NTSTATUS)0xC000028B)
#define STATUS_NO_SUCH_DEVICE			((NTSTATUS)0xC000000E)
#define	STATUS_DEVICE_REMOVED			((NTSTATUS)0xC00002B6)
#define STATUS_DEVICE_UNREACHABLE		((NTSTATUS)0xC0000464)
#define STATUS_INVALID_TOKEN			((NTSTATUS)0xC0000465)
#define STATUS_NO_MORE_ENTRIES			((NTSTATUS)0x8000001A)
#endif
#define STATUS_BUFFERED					((NTSTATUS)0x11111111L)

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif

//provider handle
typedef __struct_bcount(sizeof(KSP_PROVIDER)) struct _KSP_PROVIDER
{
    DWORD               cbLength;   //length of the whole data struct
    DWORD               dwMagic;    //type of the provider
    DWORD               dwFlags;    //reserved flags
    LPWSTR              pszName;    //name of the KSP
    BCRYPT_ALG_HANDLE   hRsaAlgorithm;    //bcrypt rsa algorithm handle
    LPWSTR              pszContext;       //context
}KSP_PROVIDER;
//typedef __struct_bcount(sizeof(KSP_PROVIDER_LIST)) struct _KSP_PROVIDER_LIST
//{
//	KSP_PROVIDER provider;
//	KSP_PROVIDER_LIST *next;
//
//}KSP_PROVIDER_LIST;
//property struct stored in the key file
typedef __struct_bcount(sizeof(KSP_NAMED_PROPERTY) +cbPropertyName+cbPropertyData) struct _KSP_NAMED_PROPERTY
{
    DWORD cbLength;         //length of the whole data blob
    DWORD cbPropertyName;   //length of the property name
    DWORD cbPropertyData;   //length of the property data
    BOOL  fBuildin;         //Whether it is a build-in property or not
    // property name
    // property data
} KSP_NAMED_PROPERTY;

//property struct in the key handle
typedef __struct_bcount(sizeof(KSP_PROPERTY) + cbPropertyData) struct _KSP_PROPERTY
{
    DWORD               cbLength;         //length of the whole data blob
    BOOL                fPersisted;       //is this a persisted property
    WCHAR               szName[NCRYPT_MAX_PROPERTY_NAME + 1];   //name of the property
    DWORD               cbPropertyData;                         //property data
    LIST_ENTRY          ListEntry;                              //ListEntry node
    BOOL                fBuildin;         //whether it is a build-in property or not
    // property data
} KSP_PROPERTY;

//key file header stored in the key file
typedef __struct_bcount(sizeof(KSP_KEYFILE_HEADER)+cbProperties+cbPrivateKey) struct _KSP_KEYFILE_HEADER
{
    DWORD cbLength;         //length of the whole data blob
    DWORD dwVersion;        //the version of the key
    DWORD dwAlgorithm;      //Algorithm ID

    DWORD cbProperties;     //length of the properties
    DWORD cbPrivateKey;     //length of the private key
    DWORD cbName;           //length of the key name

    //properties data
    //private key
    //name of the key
} KSP_KEYFILE_HEADER;

//key handle
typedef __struct_bcount(sizeof(KSP_KEY)) struct KSP_KEY
{
	DWORD               cbLength;           //length of the whole data blob
	DWORD               dwMagic;            //type of the key
	LPWSTR              pszKeyName;         //name of the key (key file)
	DWORD               dwAlgID;            //Algorithm ID
	DWORD               dwKeyBitLength;     //length of the key
	DWORD               dwExportPolicy;     //export policy
	DWORD               dwKeyUsagePolicy;   //key usage policy
	BOOL				managed;			//Key life cicle managed by the provider
	BOOL                fFinished;          //Whether the key is finalized
	// handle to cryptography providers needed to perform operations with
	// the key.
	BCRYPT_ALG_HANDLE   hProvider;

	//// handle to key objects.
	//BCRYPT_KEY_HANDLE   hPublicKey;
	//BCRYPT_KEY_HANDLE   hPrivateKey;
	//public key information
	LPWSTR              pszKeyBlobType;     //Blob used to store public key
	PVOID				pbPubKeyInfo;
	DWORD				cbPubKeyInfo;
	// security descriptor to be set on the private key file.
	DWORD               dwSecurityFlags;
	__field_bcount(cbSecurityDescr) PBYTE               pbSecurityDescr;
	DWORD               cbSecurityDescr;

	//context
	LPWSTR              pszContext;

	// list of properties.
	LIST_ENTRY          PropertyList;

	// multi-read/single write lock can be added here to support synchronization for multi-threading
} KSP_KEY;


typedef struct _KSP_ENUM_STATE
{
	DWORD  dwIndex;
	HANDLE hFind;
} KSP_ENUM_STATE;



//list of buffer allocated for enum keys / enum providers
typedef struct _KSP_MEMORY_BUFFER
{
    PVOID pvBuffer;
    LIST_ENTRY List;
} KSP_MEMORY_BUFFER;

//this algorithm handle can be shared by all key handles
static BCRYPT_ALG_HANDLE g_hRSAProvider;

NTSTATUS
WINAPI
GetKeyStorageInterface(
    __in   LPCWSTR pszProviderName,
    __out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in   DWORD dwFlags);


SECURITY_STATUS
WINAPI
KSPOpenProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider);

SECURITY_STATUS
WINAPI
KSPOpenKey(
    __inout NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
KSPGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
KSPGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS
WINAPI
KSPFreeBuffer(
    __deref PVOID   pvInput);

__success(return == 0)
SECURITY_STATUS
WINAPI
KSPEncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
KSPDecrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);


SECURITY_STATUS
WINAPI
KSPIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD   dwFlags);


SECURITY_STATUS
WINAPI
KSPEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgOperations, // this is the crypto operations that are to be enumerated
    __out   DWORD * pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID * ppEnumState,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD   cbData,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
KSPExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
KSPSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID  *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPPromptUser(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR  pszOperation,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
KSPSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
    __in    DWORD   dwFlags);


SECURITY_STATUS
WINAPI
KSPDeriveKey(
    __in        NCRYPT_PROV_HANDLE   hProvider,
    __in_opt    NCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    NCryptBufferDesc     *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    __in        DWORD                cbDerivedKey,
    __out       DWORD                *pcbResult,
    __in        ULONG                dwFlags);

SECURITY_STATUS
WINAPI
KSPFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret);

SECURITY_STATUS
WINAPI
CreateNewKeyObject(
	__in_opt LPCWSTR pszKeyName,
	__deref_out KSP_KEY **ppKey);

SECURITY_STATUS
WINAPI
DeleteKeyObject(
     __inout KSP_KEY *pKey);

DWORD
ProtectPrivateKey(
    __in KSP_KEY *pKey,
    __deref_out PBYTE *ppbEncPrivateKey,
    __out DWORD *pcbEncPrivateKey);


SECURITY_STATUS
RemoveKeyFromStore(
    __in KSP_KEY *pKey);

SECURITY_STATUS
WriteKeyToStore(
    __inout KSP_KEY *pKey
    );

SECURITY_STATUS
CreateSecurityDescriptor(__in    KSP_KEY *pKey,
	__in    DWORD   dwSecurityFlags,
	__out	PSECURITY_DESCRIPTOR *pSD,
	__out	DWORD *szPSD);

SECURITY_STATUS
NormalizeNteStatus(
    __in NTSTATUS NtStatus);

KSP_PROVIDER *
KspValidateProvHandle(
    __in    NCRYPT_PROV_HANDLE hProvider);

KSP_KEY *
KspValidateKeyHandle(
    __in    NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS
CreateNewProperty(
    __in_opt                LPCWSTR pszProperty,
    __in_bcount(cbProperty) PBYTE   pbProperty,
    __in                    DWORD   cbProperty,
    __in                    DWORD   dwFlags,
    __deref_out             KSP_PROPERTY    **ppProperty);

SECURITY_STATUS
SetBuildinKeyProperty(
    __inout     KSP_KEY  *pKey,
    __in        LPCWSTR pszProperty,
    __in_bcount(cbInput)    PBYTE pbInput,
    __in                    DWORD   cbInput,
    __inout    DWORD*   dwFlags);

SECURITY_STATUS
ProtectAndSetPrivateKey(
    __in LPCWSTR pszBlobType,
    __in_bcount(cbKeyBlob) PBYTE  pbKeyBlob,
    __in DWORD  cbKeyBlob,
    __inout KSP_KEY* pKey);

KSP_MEMORY_BUFFER *
RemoveMemoryBuffer(
    __in LIST_ENTRY *pBufferList,
    __in PVOID pvBuffer);

KSP_MEMORY_BUFFER *
LookupMemoryBuffer(
    __in LIST_ENTRY *pBufferList,
    __in PVOID pvBuffer);

SECURITY_STATUS
LookupExistingKeyProperty(
    __in    KSP_KEY *pKey,
    __in    LPCWSTR pszProperty,
    __out   KSP_PROPERTY **ppProperty);

SECURITY_STATUS
CreateNewProperty(
    __in_opt                LPCWSTR pszProperty,
    __in_bcount(cbProperty) PBYTE   pbProperty,
    __in                    DWORD   cbProperty,
    __in                    DWORD   dwFlags,
    __deref_out             KSP_PROPERTY    **ppProperty);

SECURITY_STATUS
BcryptAlgorithmTranscriptor(
	__in DWORD dwAlgID,
	__out LPWSTR* pszKeyName);

void 
Error_Writter(
	__out struct context * context,
	__in  SECURITY_STATUS cngError);


NTSTATUS AuthDisplay(HINSTANCE hinst, char** pin);

//macro for list operation
#define InitializeListHead(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define RemoveHeadList(ListHead) \
    (ListHead)->Flink;\
    {RemoveEntryList((ListHead)->Flink)}

#define RemoveEntryList(Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_Flink;\
    _EX_Flink = (Entry)->Flink;\
    _EX_Blink = (Entry)->Blink;\
    _EX_Blink->Flink = _EX_Flink;\
    _EX_Flink->Blink = _EX_Blink;\
    }

#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }
#endif //__KSP_H__
