using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;

namespace akv_pkcs11.Test
{

    [TestClass]
    public unsafe class Akv_pkcs11LibraryTest
    {
        #region dllImports
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_Initialize(object inVar);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_Finalize(uint* invar);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetInfo(ref CK_Info pInfo);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetInfo(IntPtr pInfo);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetSlotList(bool tokenPresent, uint* pSlotList, uint* pulCount);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetSlotInfo(uint slotID, ref CK_SLOT_INFO pInfo);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetSlotInfo(uint slotID, IntPtr pInfo);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetTokenInfo(uint slotID, ref CK_TOKEN_INFO pInfo);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetTokenInfo(uint slotID, IntPtr pInfo);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetMechanismList(uint slotID, uint* pMechanismList, uint* pulCount);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetMechanismInfo(uint slotID, uint type, ref CK_MECHANISM_INFO pInfo);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetMechanismInfo(uint slotID, uint type, IntPtr pInfo);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_OpenSession(uint slotID, uint flags, void* pApplication, void* Notify, uint* phSession);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_CloseSession(uint hSession);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_CloseAllSessions(uint* slotID);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_Login(uint hSession, uint userType, [MarshalAs(UnmanagedType.LPStr)]string pPin, uint ulPinLen);

        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_Logout(uint hSession);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetSessionInfo(uint hSession, ref CK_SESSION_INFO pInfo);

        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GenerateKeyPair(uint hSession, ref CK_MECHANISM pMechanism, [In] CK_ATTRIBUTE[] pPublicKeyTemplate, uint ulPublicKeyAttributeCount, [In] CK_ATTRIBUTE[] pPrivateKeyTemplate, uint ulPrivateKeyAttributeCount, uint* phPublicKey, uint* phPrivateKey);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GenerateKeyPair(uint hSession, ref CK_MECHANISM pMechanism, IntPtr pPublicKeyTemplate, uint ulPublicKeyAttributeCount, IntPtr pPrivateKeyTemplate, uint ulPrivateKeyAttributeCount, uint* phPublicKey, uint* phPrivateKey);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_CreateObject(uint hSession, IntPtr pTemplate, uint ulCount, uint* phObject);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_CreateObject(uint hSession, [In] CK_ATTRIBUTE[] pTemplate, uint ulCount, uint* phObject);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_GetAttributeValue(uint hSession, uint hObject, [In]  CK_ATTRIBUTE* pTemplate, uint ulCount);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_FindObjectsInit(uint hSession, [In] CK_ATTRIBUTE[] pTemplate, uint ulCount);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_FindObjectsInit(uint hSession, IntPtr pTemplate, uint ulCount);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_FindObjects(uint hSession, uint* phObject, uint ulMaxObjectCount, uint* pulObjectCount);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_FindObjectsFinal(uint hSession);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_DestroyObject(uint hSession, uint phObject);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_EncryptInit(uint hSession, ref CK_MECHANISM pMechanism, uint hKey);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_Encrypt(uint hSession, IntPtr pData, uint ulDataLen, IntPtr pEncryptedData, uint* pulEncryptedDataLen);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_DecryptInit(uint hSession, ref CK_MECHANISM pMechanism, uint hKey);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_Decrypt(uint hSession, IntPtr pEncryptedData, uint ulEncryptedDataLen, IntPtr pData, uint* pulDataLen);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_SignInit(uint hSession, ref CK_MECHANISM pMechanism, uint hKey);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_Sign(uint hSession, IntPtr pData, uint ulDataLen, IntPtr pSignature, uint* pulSignatureLen);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_VerifyInit(uint hSession, ref CK_MECHANISM pMechanism, uint hKey);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_Verify(uint hSession, IntPtr pData, uint ulDataLen, IntPtr pSignature, uint ulSignatureLen);

        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_SetAttributeValue(uint hSession, uint hObject, [In]  CK_ATTRIBUTE[] pTemplate, uint ulCount);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_WrapKey(uint hSession, ref CK_MECHANISM pMechanism, uint hWrappingKey, uint hKey, IntPtr pWrappedKey, uint* pulWrappedKeyLen);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_UnwrapKey(uint hSession, ref CK_MECHANISM pMechanism, uint hUnwrappingKey, IntPtr pWrappedKey, uint pulWrappedKeyLen, IntPtr pTemplate, uint ulAttributeCount, uint* hKey);
        [DllImport("BlackICEConnect_x64.dll", SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_SetPIN(uint hSession, [MarshalAs(UnmanagedType.LPStr)]string pOldPin, uint ulOldLen, [MarshalAs(UnmanagedType.LPStr)]string pNewPin, uint ulNewLen);


        #endregion DLLIMPORTS
        [TestMethod]
        public void Test_C_Initialize_noConfigFile()
        {
            //try //comentado mientras no se decida donde poner el fichero de configuracion
            //{
            //    File.Delete("c:\\temp\\cs_pkcs11_R2.cnf");
            //}
            //catch
            //{
            //    // doesn't matter
            //}

            //uint uintptr = C_Initialize(null);
            //Assert.AreEqual(PKCS11Definitions.CKR_GENERAL_ERROR, uintptr);
            //try
            //{
            //    File.Copy("C:\\Users\\ilopez/Documents\\Visual Studio 2015\\Projects/cs_pkcs11_R2\\TestResults\\config_file\\cs_pkcs11_R2.cnf", "c:\\temp\\cs_pkcs11_R2.cnf");
            //}
            //catch (FileNotFoundException ae)
            //{
            //    Assert.Fail("The config file couldn't be copy.", ae.Message);
            //}
            //catch (Exception e)
            //{
            //    Assert.Fail(
            //         string.Format("Unexpected exception of type {0} caught: {1}",
            //                        e.GetType(), e.Message)
            //    );
            //}
        }

        [TestMethod]
        public void Test_C_Initialize_C_Finalize_correct_config_file()
        {

            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Initialize_is_already_initialize()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_ALREADY_INITIALIZED, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }


        [TestMethod]
        public void Test_C_Finalize_without_call_C_Initialize()
        {
            uint result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_Finalize_without_pReserved_not_NULL_PTR()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint* pReserved = stackalloc uint[1];
            result = C_Finalize(pReserved);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetInfo_without_call_C_Initialize()
        {
            CK_Info pInfo = new CK_Info();
            uint result = C_GetInfo(ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_GetInfo_correct()
        {
            uint resultFin = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, resultFin);

            CK_Info pInfo = new CK_Info();
            uint result = C_GetInfo(ref pInfo);
            Assert.AreEqual(PKCS11Definitions.cryptokiVersion_major, pInfo.cryptokiVersion.major);
            Assert.AreEqual(PKCS11Definitions.cryptokiVersion_minor, pInfo.cryptokiVersion.minor);
            Assert.AreEqual(PKCS11Definitions.libraryVersion_major, pInfo.libraryVersion.major);
            Assert.AreEqual(PKCS11Definitions.libraryVersion_minor, pInfo.libraryVersion.minor);
            Assert.AreEqual((uint)0, pInfo.flags);
            Assert.AreEqual(PKCS11Definitions.LIBRARY_DESCRIPTION, pInfo.libraryDescription.Trim());
            Assert.AreEqual(PKCS11Definitions.MANUFACTURER_ID, pInfo.manufacturerID.Trim());
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            resultFin = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, resultFin);
        }

        [TestMethod]
        public void Test_C_GetInfo_Bad_Arguments()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_GetInfo(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetSlotList_correct()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            bool tokenPresent = true;
            uint* pulCount = stackalloc uint[1];
            result = C_GetSlotList(tokenPresent, null, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint* pSlotList = stackalloc uint[Convert.ToInt32(*pulCount)];
            result = C_GetSlotList(tokenPresent, pSlotList, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetSlotList_Bad_Arguments()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            bool tokenPresent = true;
            result = C_GetSlotList(tokenPresent, null, null);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetSlotList_Buffer_To_Small()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            bool tokenPresent = true;
            uint* pulCount = stackalloc uint[1];
            *pulCount = 0;
            uint* pSlotList = stackalloc uint[(Int32)1];
            result = C_GetSlotList(tokenPresent, pSlotList, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_BUFFER_TOO_SMALL, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetSlotList_Cryptoki_Not_Initialized()
        {
            bool tokenPresent = true;
            uint* pulCount = stackalloc uint[1];
            uint result = C_GetSlotList(tokenPresent, null, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_GetSlotInfo_Cryptoki_Not_Initialized()
        {
            uint slotID = 1;
            CK_SLOT_INFO pInfo = new CK_SLOT_INFO();
            uint result = C_GetSlotInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_GetSlotInfo_Correct()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            CK_SLOT_INFO pInfo = new CK_SLOT_INFO();
            result = C_GetSlotInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual(PKCS11Definitions.firmwareVersion_major, pInfo.firmwareVersion.major);
            Assert.AreEqual(PKCS11Definitions.firmwareVersion_minor, pInfo.firmwareVersion.minor);
            Assert.AreEqual(PKCS11Definitions.hardwareVersion_major, pInfo.hardwareVersion.major);
            Assert.AreEqual(PKCS11Definitions.hardwareVersion_minor, pInfo.hardwareVersion.minor);
            Assert.AreEqual(PKCS11Definitions.SLOT_DESCRIPTION, pInfo.slotDescription.Trim());
            Assert.AreEqual(PKCS11Definitions.SLOT_MANUFACTURER_ID, pInfo.manufacturerID.Trim());
            Assert.AreEqual((uint)1, pInfo.flags);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetSlotInfo_Bad_Arguments()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            result = C_GetSlotInfo(slotID, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetTokenInfo_Cryptoki_Not_Initialized()
        {
            uint slotID = 1;
            uint result = C_GetTokenInfo(slotID, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_GetTokenInfo_Bad_Arguments()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            result = C_GetTokenInfo(slotID, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetTokenInfo_Correct()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_LABEL, pInfo.label.Trim());
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_MANUFACTURER_ID, pInfo.manufacturerID.Trim());
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_MODEL, pInfo.model.Trim());
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_SERIAL_NUMBER, pInfo.serialNumber.Trim());
            Assert.AreEqual(PKCS11Definitions.CKF_LOGIN_REQUIRED | PKCS11Definitions.CKF_USER_PIN_INITIALIZED | PKCS11Definitions.CKF_TOKEN_INITIALIZED, pInfo.flags);
            Assert.AreEqual(PKCS11Definitions.CK_EFFECTIVELY_INFINITE, pInfo.ulMaxSessionCount);
            Assert.AreEqual((uint)0, pInfo.ulSessionCount);
            Assert.AreEqual(PKCS11Definitions.CK_EFFECTIVELY_INFINITE, pInfo.ulMaxRwSessionCount);
            Assert.AreEqual((uint)0, pInfo.ulRwSessionCount);
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_MAX_PIN_LEN, pInfo.ulMaxPinLen);
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_MIN_PIN_LEN, pInfo.ulMinPinLen);
            Assert.AreEqual(PKCS11Definitions.CK_UNAVAILABLE_INFORMATION, pInfo.ulTotalPublicMemory);
            Assert.AreEqual(PKCS11Definitions.CK_UNAVAILABLE_INFORMATION, pInfo.ulTotalPrivateMemory);
            Assert.AreEqual(PKCS11Definitions.CK_UNAVAILABLE_INFORMATION, pInfo.ulFreePrivateMemory);
            Assert.AreEqual(PKCS11Definitions.hardwareVersion_major, pInfo.hardwareVersion.major);
            Assert.AreEqual(PKCS11Definitions.hardwareVersion_minor, pInfo.hardwareVersion.minor);
            Assert.AreEqual(PKCS11Definitions.firmwareVersion_major, pInfo.firmwareVersion.major);
            Assert.AreEqual(PKCS11Definitions.firmwareVersion_minor, pInfo.firmwareVersion.minor);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismList_Correct()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint* pulCount = stackalloc uint[1];
            *pulCount = 0;
            result = C_GetMechanismList(slotID, null, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)7, *pulCount);
            uint* pMechanismList = stackalloc uint[Convert.ToInt32(*pulCount)];
            result = C_GetMechanismList(slotID, pMechanismList, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)7, *pulCount);
            Assert.AreEqual(PKCS11Definitions.CKM_RSA_PKCS_KEY_PAIR_GEN, pMechanismList[0]);
            Assert.AreEqual(PKCS11Definitions.CKM_RSA_PKCS, pMechanismList[1]);
            Assert.AreEqual(PKCS11Definitions.CKM_RSA_PKCS_OAEP, pMechanismList[2]);
            Assert.AreEqual(PKCS11Definitions.CKM_SHA256_RSA_PKCS, pMechanismList[3]);
            Assert.AreEqual(PKCS11Definitions.CKM_SHA384_RSA_PKCS, pMechanismList[4]);
            Assert.AreEqual(PKCS11Definitions.CKM_SHA512_RSA_PKCS, pMechanismList[5]);
            Assert.AreEqual(PKCS11Definitions.CKM_VENDOR_DEFINED, pMechanismList[6]);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismList_Bad_Arguments()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint* pulCount = stackalloc uint[1];
            *pulCount = 0;
            result = C_GetMechanismList(slotID, null, null);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismList_Buffer_Too_Small()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint* pulCount = stackalloc uint[1];
            *pulCount = 0;
            result = C_GetMechanismList(slotID, null, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            *pulCount = 3;
            uint* pMechanismList = stackalloc uint[Convert.ToInt32(*pulCount)];
            result = C_GetMechanismList(slotID, pMechanismList, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_BUFFER_TOO_SMALL, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismList_Cryptoki_Not_Initialized()
        {
            uint slotID = 1;
            uint* pulCount = stackalloc uint[1];
            *pulCount = 0;
            uint result = C_GetMechanismList(slotID, null, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);

        }

        [TestMethod]
        public void Test_C_GetMechanismInfo_Correct()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            CK_MECHANISM_INFO pInfo = new CK_MECHANISM_INFO();
            result = C_GetMechanismInfo(slotID, PKCS11Definitions.CKM_RSA_PKCS, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)2048, pInfo.ulMinKeySize);
            Assert.AreEqual((uint)2048, pInfo.ulMaxKeySize);
            Assert.AreEqual(PKCS11Definitions.CKF_ENCRYPT | PKCS11Definitions.CKF_DECRYPT | PKCS11Definitions.CKF_HW, pInfo.flags);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismInfot_Bad_Arguments()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            result = C_GetMechanismInfo(slotID, PKCS11Definitions.CKM_RSA_PKCS, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismInfo_MECHANISM_INVALID()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            CK_MECHANISM_INFO pInfo = new CK_MECHANISM_INFO();
            result = C_GetMechanismInfo(slotID, PKCS11Definitions.CKM_RSA_9796, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_MECHANISM_INVALID, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismInfo_Cryptoki_Not_Initialized()
        {
            uint slotID = 1;
            CK_MECHANISM_INFO pInfo = new CK_MECHANISM_INFO();
            uint result = C_GetMechanismInfo(slotID, PKCS11Definitions.CKM_RSA_PKCS, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_OpenSession_Cryptoki_Not_Initialized()
        {
            uint slotID = 1;
            uint flags = PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION;
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            uint result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_OpenSession_Correct_1_Serial_Session()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)1, *phSession);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_OpenSession_Correct_10_Serial_Session()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            for (int i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual((uint)i + 1, *phSession);
            }
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)10, pInfo.ulSessionCount);
            Assert.AreEqual((uint)10, pInfo.ulRwSessionCount);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_OpenSession_Correct_100_Serial_Session()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            for (int i = 0; i < 100; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual((uint)i + 1, *phSession);
            }
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)100, pInfo.ulSessionCount);
            Assert.AreEqual((uint)100, pInfo.ulRwSessionCount);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_OpenSession_Arguments_Bad()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            result = C_OpenSession(slotID, flags, pApplication, Notify, null);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            Assert.AreEqual((uint)0, *phSession);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_OpenSession_Session_Paralell_Not_Suported()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_PARALLEL_NOT_SUPPORTED, result);
            Assert.AreEqual((uint)0, *phSession);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_CloseSession_Cryptoki_Not_Initialized()
        {
            uint result = C_CloseSession(1);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_CloseSession_Not_Opened()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint* phSession = stackalloc uint[1];
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_CLOSED, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_CloseSession_Not_Exist()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)1, *phSession);
            result = C_CloseSession(2);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_HANDLE_INVALID, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }


        [TestMethod]
        public void Test_C_CloseSession_Session_1()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)1, *phSession);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_CloseSession_10_Sessions_Close_Number_3()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            for (int i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual((uint)i + 1, *phSession);
            }
            result = C_CloseSession((uint)3);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)9, pInfo.ulSessionCount);
            Assert.AreEqual((uint)9, pInfo.ulRwSessionCount);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_CloseSession_10_Sessions_Close_all_disorderly()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            for (int i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual((uint)i + 1, *phSession);
            }
            uint j;
            for (uint i = 1; i <= 5; i++)
            {
                j = (2 * i);
                result = C_CloseSession((uint)j);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            for (uint i = 0; i <= 4; i++)
            {
                j = (2 * i) + 1;
                result = C_CloseSession((uint)j);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)0, pInfo.ulSessionCount);
            Assert.AreEqual((uint)0, pInfo.ulRwSessionCount);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_CloseSession_10_Sessions_Back_To_Front()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            for (int i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual((uint)i + 1, *phSession);
            }
            for (uint i = 10; i > 0; i--)
            {
                result = C_CloseSession((uint)i);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)0, pInfo.ulSessionCount);
            Assert.AreEqual((uint)0, pInfo.ulRwSessionCount);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }


        [TestMethod]
        public void Test_C_CloseAllSession_10_Sessions_open()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            for (int i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual((uint)i + 1, *phSession);
            }
            result = C_CloseAllSessions((uint*)1);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)0, pInfo.ulSessionCount);
            Assert.AreEqual((uint)0, pInfo.ulRwSessionCount);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_CloseAllSession_Cryptoki_Not_Initialized()
        {
            uint result = C_CloseAllSessions((uint*)1);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_CloseAllSession_SLOT_ID_INVALID()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            for (int i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual((uint)i + 1, *phSession);
            }
            result = C_CloseAllSessions((uint*)2);
            Assert.AreEqual(PKCS11Definitions.CKR_SLOT_ID_INVALID, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_CloseAllSession_Bad_Arguments()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            for (int i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual((uint)i + 1, *phSession);
            }
            result = C_CloseAllSessions((uint*)0);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Login_Cryptoki_Not_Initialized()
        {
            uint result = C_Login(1, PKCS11Definitions.CKS_RO_USER_FUNCTIONS, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_Login_Not_Session_Initialized()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKS_RO_USER_FUNCTIONS, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_CLOSED, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

        }

        [TestMethod]
        public void Test_C_Login_Invalid_User_Type()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, 3, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_USER_TYPE_INVALID, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Login_SO()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_SO, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Login_User()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "12345", 5);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Login_Invalid_Session_Handler()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(0, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_HANDLE_INVALID, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Logout_Not_Session_Initialized()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Logout(1);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_CLOSED, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Logout_User_Not_Logged_In()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            result = C_Logout(1);
            Assert.AreEqual(PKCS11Definitions.CKR_USER_NOT_LOGGED_IN, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetSessionInfo()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_SESSION_INFO pInfo = new CK_SESSION_INFO();
            result = C_GetSessionInfo(*phSession, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)1, pInfo.slotID);
            Assert.AreEqual(PKCS11Definitions.CKS_RW_PUBLIC_SESSION, pInfo.state);
            Assert.AreEqual((uint)0, pInfo.ulDeviceError);
            Assert.AreEqual((uint)0x0000000C, pInfo.flags); //0x00000004 This flag is provided for backward compatibility, and should always be set to true. 0x00000001 True if the session is read/write
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_GenerateKeyPair()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags;
            flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1]; ;
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            byte[] CKA_ENCRYPT = new byte[1];
            CKA_ENCRYPT[0] = 1;
            byte[] CKA_VERIFY = new byte[1];
            CKA_VERIFY[0] = 1;
            byte[] modulusbits = BitConverter.GetBytes(2048);
            //            byte[] publicExponent = BitConverter.GetBytes(0x10001);
            byte[] publicExponent = { 1, 0, 1 };
            Tuple<uint, byte[], int>[] publicTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, Marshal.SizeOf(modulusbits[0]) * modulusbits.Length),
                Tuple.Create(PKCS11Definitions.CKA_PUBLIC_EXPONENT, publicExponent, Marshal.SizeOf(publicExponent[0]) * publicExponent.Length)
            };
            CK_ATTRIBUTE[] pPublicKeyTemplate = PKCS11Definitions.InsertAttributes(publicTuple);
            // ****** Private template ****** //
            byte[] CKA_DECRYPT = new byte[1];
            CKA_DECRYPT[0] = 1;
            byte[] CKA_SIGN = new byte[1];
            CKA_SIGN[0] = 1;
            byte[] CKA_ID = Encoding.ASCII.GetBytes("GENKEYHSM");
            Tuple<uint, byte[], int>[] privateTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pPrivateKeyTemplate = PKCS11Definitions.InsertAttributes(privateTuple);
            // **************************** //
            uint* phPublicKey = stackalloc uint[1];
            uint* phPrivateKey = stackalloc uint[1];
            result = C_GenerateKeyPair(*phSession, ref pMechanism, pPublicKeyTemplate, (uint)publicTuple.Length, pPrivateKeyTemplate, (uint)privateTuple.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)2, *phPublicKey);
            Assert.AreEqual((uint)1, *phPrivateKey);
            PKCS11Definitions.FreeAttributes(pPublicKeyTemplate);
            PKCS11Definitions.FreeAttributes(pPrivateKeyTemplate);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }


        [TestMethod]
        public unsafe void Test_C_CreateObject()
        {
            //uint result = C_Initialize(null);
            //Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //uint slotID = 1;
            //uint flags;
            //flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            //void* pApplication = null;
            //void* Notify = null;
            //uint* phSession = stackalloc uint[1]; ;
            //result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            //Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            //Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //// ******  template ****** //
            //uint ulCount = 1;
            //CK_ATTRIBUTE[] pTemplate = new CK_ATTRIBUTE[ulCount];
            //pTemplate[0].type = PKCS11Definitions.CKA_VALUE;
            //byte[] CKA_VALUE = new byte[1];
            //CKA_ENCRYPT[0] = 1;
            //IntPtr pValue = Marshal.AllocHGlobal(Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length);
            //pTemplate[0].pValue = pValue;
            //pTemplate[0].ulValueLen = Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length;



            //// **************************** //
            //uint* phObject = stackalloc uint[1];

            //result = C_CreateObject(*phSession, pTemplate, ulCount, phObject);
            //Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //Assert.AreEqual((uint)1, *phObject);
            //Marshal.FreeHGlobal(pTemplate[0].pValue);
            //result = C_CloseSession(*phSession);
            //Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //result = C_Finalize(null);
            //Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_FindObjectsInit_Alone_NULL_Template()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_FindObjectsInit(*phSession, IntPtr.Zero, 0);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_FindObject_C_GetattributeValue_Template_Exploration_Adobe()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Tuple<uint, byte[], int>[] tuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(tuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)tuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //** C_GetAttributeValues **//
            //**** Template *****//
            uint ulCount = 1;
            CK_ATTRIBUTE pTemplateG = new CK_ATTRIBUTE
            {
                type = PKCS11Definitions.CKA_ID,
                pValue = IntPtr.Zero,
                ulValueLen = 0
            };
            /************************/
            result = C_GetAttributeValue(*phSession, *phObjects, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, *phObjects, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //** C_FindObject **//
            //**** Template *****//
            byte[] CKA_SERIAL_NUMBER = Encoding.ASCII.GetBytes("0123456789asddddddddddddddddmlmlñmdlqwemdlmqlñmwqqmddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddqlñqmwdlñqmwdlñqmdlñqwmldñmqñlwqmdñlqmwñdlmqwñlmdqñlwmdñlqmlñqwmdlqmwdlqñwdmqwlqwd");
            Tuple<uint, byte[], int>[] pTemplateTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_SERIAL_NUMBER, CKA_SERIAL_NUMBER, Marshal.SizeOf(CKA_SERIAL_NUMBER[0]) * CKA_SERIAL_NUMBER.Length)
            };
            pTemplate = PKCS11Definitions.InsertAttributes(pTemplateTuple);
            /**************/
            result = C_FindObjectsInit(*phSession, pTemplate, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

        }

        [TestMethod]
        public unsafe void Test_C_FindObject_C_GetattributeValue_Template_Exploration_Firefox()
        {
            string[] certificates = { "testCert1", "testCert2", "testCert3" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_TOKEN = new byte[1];
            CKA_TOKEN[0] = 1;
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_CERTIFICATE);
            Tuple<uint, byte[], int>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_TOKEN, CKA_TOKEN, Marshal.SizeOf(CKA_TOKEN[0]) * CKA_TOKEN.Length),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //** C_GetAttributeValues **//
            //**** Template *****//
            uint ulCount = 1;
            CK_ATTRIBUTE pTemplateG = new CK_ATTRIBUTE
            {
                type = PKCS11Definitions.CKA_ID,
                pValue = IntPtr.Zero,
                ulValueLen = 0
            };
            /************************/
            result = C_GetAttributeValue(*phSession, phObjects[0], &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, phObjects[0], &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pValue);
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.ulValueLen = 0;
            result = C_GetAttributeValue(*phSession, phObjects[1], &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, phObjects[1], &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pValue);
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.ulValueLen = 0;
            result = C_GetAttributeValue(*phSession, phObjects[2], &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, phObjects[2], &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pValue);
            //** C_FindObject **//
            //**** Template *****//
            byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Tuple<uint, byte[], int>[] pTupleF =
            {
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)
            };
            pTemplate = PKCS11Definitions.InsertAttributes(pTupleF);
            /**************/
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTupleF.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects2 = stackalloc uint[5];
            uint* pulcObjectCount2 = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects2[i], 1, pulcObjectCount2);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount2 == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            CKA_ID = Encoding.ASCII.GetBytes("testCert2");
            CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Tuple<uint, byte[], int>[] pTupleTestCert2 =
            {
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)
            };
            pTemplate = PKCS11Definitions.InsertAttributes(pTupleTestCert2);
            /**************/
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects3 = stackalloc uint[5];
            uint* pulcObjectCount3 = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects3[i], 1, pulcObjectCount3);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount3 == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            CKA_ID = Encoding.ASCII.GetBytes("testCert3");
            CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Tuple<uint, byte[], int>[] pTuplerTestCert3 =
            {
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)
            };
            pTemplate = PKCS11Definitions.InsertAttributes(pTuplerTestCert3);
            /**************/
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects4 = stackalloc uint[5];
            uint* pulcObjectCount4 = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects4[i], 1, pulcObjectCount4);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount4 == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_DestroyObject_Incorrect_Session_Handler()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject(1, 1);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_CLOSED, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_DestroyObject_Incorrect_Object_Handler()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject(*phSession, 1);
            Assert.AreEqual(PKCS11Definitions.CKR_OBJECT_HANDLE_INVALID, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_DestroyObject_After_Key_Creation()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            byte[] CKA_ENCRYPT = new byte[1];
            CKA_ENCRYPT[0] = 1;
            byte[] CKA_VERIFY = new byte[1];
            CKA_VERIFY[0] = 1;
            byte[] modulusbits = BitConverter.GetBytes(2048);
            Tuple<uint, byte[], int>[] pTuplePublic =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, Marshal.SizeOf(modulusbits[0]) * modulusbits.Length)
            };
            CK_ATTRIBUTE[] pPublicKeyTemplate = PKCS11Definitions.InsertAttributes(pTuplePublic);
            // ****** Private template ****** //
            byte[] CKA_DECRYPT = new byte[1];
            CKA_DECRYPT[0] = 1;
            byte[] CKA_SIGN = new byte[1];
            CKA_SIGN[0] = 1;
            byte[] CKA_ID = Encoding.ASCII.GetBytes("deleteKey");
            Tuple<uint, byte[], int>[] pTuplePrivate =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pPrivateKeyTemplate = PKCS11Definitions.InsertAttributes(pTuplePrivate);
            // **************************** //
            uint* phPublicKey = stackalloc uint[1];
            uint* phPrivateKey = stackalloc uint[1];
            result = C_GenerateKeyPair(*phSession, ref pMechanism, pPublicKeyTemplate, (uint)pPublicKeyTemplate.Length, pPrivateKeyTemplate, (uint)pPrivateKeyTemplate.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)2, *phPublicKey);
            Assert.AreEqual((uint)1, *phPrivateKey);
            PKCS11Definitions.FreeAttributes(pPublicKeyTemplate);
            PKCS11Definitions.FreeAttributes(pPrivateKeyTemplate);
            result = C_DestroyObject(*phSession, *phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_SignInit_correct()
        {
            string[] certificates = { "testCert1" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<uint, byte[], int>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if (phObjects[0] != 0)
            {
                result = C_SignInit(*phSession, ref pMechanism, phObjects[0]);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_Sign_Correct_Sha256()
        {
            string[] certificates = { "testCert1" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<uint, byte[], int>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if (phObjects[0] != 0)
            {
                result = C_SignInit(*phSession, ref pMechanism, phObjects[0]);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                string oidString = CryptoConfig.MapNameToOID("sha256");
                byte[] encodedOid = CryptoConfig.EncodeOID(oidString);
                string hexOIDSting = ByteArrayToString(encodedOid);
                string hash = "ebac6efe864bcb9a448d2cd234232685771e8852c89b245aa745efd94b029274";
                string asn1hash = ("30" + 49.ToString("X2") + "30" + 13.ToString("X2") + hexOIDSting + "050004" + 32.ToString("X2") + hash).ToLower();
                byte[] asn1Bytes = Enumerable.Range(0, asn1hash.Length / 2).Select(x => Convert.ToByte(asn1hash.Substring(x * 2, 2), 16)).ToArray();
                IntPtr pData = Marshal.AllocHGlobal(asn1Bytes.Length);
                Marshal.Copy(asn1Bytes, 0, pData, asn1Bytes.Length);
                IntPtr pSignature = IntPtr.Zero;
                int* pSignatureLen = stackalloc int[1];
                result = C_Sign(*phSession, pData, (uint)asn1Bytes.Length, pSignature, (uint*)pSignatureLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                pSignature = Marshal.AllocHGlobal(*pSignatureLen);
                result = C_Sign(*phSession, pData, (uint)asn1Bytes.Length, pSignature, (uint*)pSignatureLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Marshal.FreeHGlobal(pData);
                Marshal.FreeHGlobal(pSignature);
            }
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_VerifyInit_correct()
        {
            string[] certificates = { "testCert1" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
            byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<uint, byte[], int>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if (phObjects[0] != 0)
            {
                result = C_VerifyInit(*phSession, ref pMechanism, phObjects[0]);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }


        [TestMethod]
        public unsafe void Test_C_Verify_Correct_Sha256()
        {
            string[] certificates = { "testCert1" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template Private Key *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<uint, byte[], int>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if (phObjects[0] != 0)
            {
                result = C_SignInit(*phSession, ref pMechanism, phObjects[0]);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                string oidString = CryptoConfig.MapNameToOID("sha256"); // f.x. "MD5"
                byte[] encodedOid = CryptoConfig.EncodeOID(oidString);
                string hexOIDSting = ByteArrayToString(encodedOid);
                string hash = "ebac6efe864bcb9a448d2cd234232685771e8852c89b245aa745efd94b029274";
                string asn1hash = ("30" + 49.ToString("X2") + "30" + 13.ToString("X2") + hexOIDSting + "050004" + 32.ToString("X2") + hash).ToLower();
                byte[] asn1Bytes = Enumerable.Range(0, asn1hash.Length / 2).Select(x => Convert.ToByte(asn1hash.Substring(x * 2, 2), 16)).ToArray();
                IntPtr pData = Marshal.AllocHGlobal(asn1Bytes.Length);
                Marshal.Copy(asn1Bytes, 0, pData, asn1Bytes.Length);
                IntPtr pSignature = IntPtr.Zero;
                int* pSignatureLen = stackalloc int[1];
                result = C_Sign(*phSession, pData, (uint)asn1Bytes.Length, pSignature, (uint*)pSignatureLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                pSignature = Marshal.AllocHGlobal(*pSignatureLen);
                result = C_Sign(*phSession, pData, (uint)asn1Bytes.Length, pSignature, (uint*)pSignatureLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                //**** Template Public Key *****//
                CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
                CKA_ID = Encoding.ASCII.GetBytes("testCert1");
                Tuple<uint, byte[], int>[] pPublicTuple =
                {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
                };
                pTemplate = PKCS11Definitions.InsertAttributes(pPublicTuple);
                //*******************//
                //** C_FindObject **//
                result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                PKCS11Definitions.FreeAttributes(pTemplate);
                uint* phObjectsPublic = stackalloc uint[5];
                uint* pulcObjectCountPublic = stackalloc uint[1];
                for (int i = 0; i < 5; i++)
                {
                    result = C_FindObjects(*phSession, &phObjectsPublic[i], 1, pulcObjectCountPublic);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    if (*pulcObjectCountPublic == 0) break;
                }
                result = C_FindObjectsFinal(*phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (phObjects[0] != 0)
                {

                    result = C_VerifyInit(*phSession, ref pMechanism, phObjectsPublic[0]);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    result = C_Verify(*phSession, pData, (uint)asn1Bytes.Length, pSignature, *(uint*)pSignatureLen);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

                }
                Marshal.FreeHGlobal(pData);
                Marshal.FreeHGlobal(pSignature);
            }
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }
        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        [TestMethod]
        public unsafe void Test_C_EncryptInit_correct()
        {
            string[] certificates = { "testCert1" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
            byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<uint, byte[], int>[] pPublicTuple =
            {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if (phObjects[0] != 0)
            {
                result = C_EncryptInit(*phSession, ref pMechanism, phObjects[0]);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_Encrypt_correct()
        {
            string[] certificates = { "testCert1" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
            byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<uint, byte[], int>[] pPublicTuple =
            {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
                };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if (phObjects[0] != 0)
            {
                result = C_EncryptInit(*phSession, ref pMechanism, phObjects[0]);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Byte[] pDataBytes = Encoding.ASCII.GetBytes("Hola mundo");
                IntPtr pData = Marshal.AllocHGlobal(pDataBytes.Length);
                Marshal.Copy(pDataBytes, 0, pData, pDataBytes.Length);
                IntPtr pEncryptedData = IntPtr.Zero;
                uint* pEncryptedDataLen = stackalloc uint[1];
                result = C_Encrypt(*phSession, pData, (uint)pDataBytes.Length, pEncryptedData, pEncryptedDataLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                pEncryptedData = Marshal.AllocHGlobal(*(int*)pEncryptedDataLen);
                result = C_Encrypt(*phSession, pData, (uint)pDataBytes.Length, pEncryptedData, pEncryptedDataLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Marshal.FreeHGlobal(pData);
                Marshal.FreeHGlobal(pEncryptedData);
            }
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_DecryptInit_correct()
        {
            string[] certificates = { "testCert1" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);


            //**** Template *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<uint, byte[], int>[] pPublicTuple =
            {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
                };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if (phObjects[0] != 0)
            {
                result = C_DecryptInit(*phSession, ref pMechanism, phObjects[0]);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_Decrypt_correct()
        {
            string[] certificates = { "testCert1" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
            byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<uint, byte[], int>[] pPublicTuple =
            {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
                };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if (phObjects[0] != 0)
            {

                result = C_EncryptInit(*phSession, ref pMechanism, phObjects[0]);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                String plainText = "Hola mundo";
                Byte[] pDataBytes = Encoding.ASCII.GetBytes(plainText);
                IntPtr pData = Marshal.AllocHGlobal(pDataBytes.Length);
                Marshal.Copy(pDataBytes, 0, pData, pDataBytes.Length);
                IntPtr pEncryptedData = IntPtr.Zero;
                uint* pEncryptedDataLen = stackalloc uint[1];
                result = C_Encrypt(*phSession, pData, (uint)pDataBytes.Length, pEncryptedData, pEncryptedDataLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                pEncryptedData = Marshal.AllocHGlobal(*(int*)pEncryptedDataLen);
                result = C_Encrypt(*phSession, pData, (uint)pDataBytes.Length, pEncryptedData, pEncryptedDataLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                //**** Template  Private key *****//
                CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
                CKA_ID = Encoding.ASCII.GetBytes("testCert1");
                Tuple<uint, byte[], int>[] pPrivateTuple =
                {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
                };
                pTemplate = PKCS11Definitions.InsertAttributes(pPrivateTuple);
                //*******************//
                //** C_FindObject **//
                result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                PKCS11Definitions.FreeAttributes(pTemplate);
                uint* phObjectsPriv = stackalloc uint[5];
                uint* pulcObjectCountPriv = stackalloc uint[1];
                for (int i = 0; i < 5; i++)
                {
                    result = C_FindObjects(*phSession, &phObjectsPriv[i], 1, pulcObjectCountPriv);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    if (*pulcObjectCountPriv == 0) break;
                }
                result = C_FindObjectsFinal(*phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (phObjectsPriv[0] != 0)
                {
                    result = C_DecryptInit(*phSession, ref pMechanism, phObjectsPriv[0]);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    uint* pDecryptedDataLen = stackalloc uint[1];
                    IntPtr pDecryptedData = IntPtr.Zero;
                    result = C_Decrypt(*phSession, pEncryptedData, *(uint*)pEncryptedDataLen, pDecryptedData, (uint*)pDecryptedDataLen);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    pDecryptedData = Marshal.AllocHGlobal(*(int*)pDecryptedDataLen);
                    result = C_Decrypt(*phSession, pEncryptedData, *(uint*)pEncryptedDataLen, pDecryptedData, (uint*)pDecryptedDataLen);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    string DecryptedData = Marshal.PtrToStringAnsi(pDecryptedData, *(int*)pDecryptedDataLen);
                    Assert.AreEqual(DecryptedData, plainText);
                    Marshal.FreeHGlobal(pDecryptedData);
                }
                Marshal.FreeHGlobal(pData);
                Marshal.FreeHGlobal(pEncryptedData);
            }
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_SetAttributeValue_basic()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            byte[] CKA_ENCRYPT = new byte[1];
            CKA_ENCRYPT[0] = 1;
            byte[] CKA_VERIFY = new byte[1];
            CKA_VERIFY[0] = 1;
            byte[] modulusbits = BitConverter.GetBytes(2048);
            Tuple<uint, byte[], int>[] pTuplePublic =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, Marshal.SizeOf(modulusbits[0]) * modulusbits.Length)
            };
            CK_ATTRIBUTE[] pPublicKeyTemplate = PKCS11Definitions.InsertAttributes(pTuplePublic);
            // ****** Private template ****** //
            byte[] CKA_DECRYPT = new byte[1];
            CKA_DECRYPT[0] = 1;
            byte[] CKA_SIGN = new byte[1];
            CKA_SIGN[0] = 1;
            byte[] CKA_ID = Encoding.ASCII.GetBytes("SetAttKey");
            Tuple<uint, byte[], int>[] pTuplePrivate =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pPrivateKeyTemplate = PKCS11Definitions.InsertAttributes(pTuplePrivate);
            // **************************** //
            uint* phPublicKey = stackalloc uint[1];
            uint* phPrivateKey = stackalloc uint[1];
            result = C_GenerateKeyPair(*phSession, ref pMechanism, pPublicKeyTemplate, (uint)pPublicKeyTemplate.Length, pPrivateKeyTemplate, (uint)pPrivateKeyTemplate.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((uint)2, *phPublicKey);
            Assert.AreEqual((uint)1, *phPrivateKey);
            PKCS11Definitions.FreeAttributes(pPublicKeyTemplate);
            PKCS11Definitions.FreeAttributes(pPrivateKeyTemplate);
            //**** Template SetAttribute *****//
            CKA_SIGN = new byte[1];
            CKA_SIGN[0] = 0;
            Tuple<uint, byte[], int>[] pTupleSign =
            {
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length)
            };
            CK_ATTRIBUTE[] pTemplateSet = PKCS11Definitions.InsertAttributes(pTupleSign);
            result = C_SetAttributeValue(*phSession, *phPrivateKey, pTemplateSet, (uint)pTemplateSet.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplateSet);
            result = C_DestroyObject(*phSession, *phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_Wrap_basic()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags;
            flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            byte[] CKA_ENCRYPT = new byte[1];
            CKA_ENCRYPT[0] = 1;
            byte[] CKA_VERIFY = new byte[1];
            CKA_VERIFY[0] = 1;
            byte[] modulusbits = BitConverter.GetBytes(2048);
            Tuple<uint, byte[], int>[] pTuplePublic =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, Marshal.SizeOf(modulusbits[0]) * modulusbits.Length)
            };
            CK_ATTRIBUTE[] pPublicKeyTemplate = PKCS11Definitions.InsertAttributes(pTuplePublic);
            // ****** Private template ****** //
            byte[] CKA_DECRYPT = new byte[1];
            CKA_DECRYPT[0] = 1;
            byte[] CKA_SIGN = new byte[1];
            CKA_SIGN[0] = 1;
            byte[] CKA_ID = Encoding.ASCII.GetBytes("backupKey");
            Tuple<uint, byte[], int>[] pTuplePrivate =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pPrivateKeyTemplate = PKCS11Definitions.InsertAttributes(pTuplePrivate);
            // **************************** //
            uint* phPublicKey = stackalloc uint[1];
            uint* phPrivateKey = stackalloc uint[1];
            result = C_GenerateKeyPair(*phSession, ref pMechanism, pPublicKeyTemplate, (uint)pPublicKeyTemplate.Length, pPrivateKeyTemplate, (uint)pPrivateKeyTemplate.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pPublicKeyTemplate);
            PKCS11Definitions.FreeAttributes(pPrivateKeyTemplate);
            Assert.AreEqual((uint)2, *phPublicKey);
            Assert.AreEqual((uint)1, *phPrivateKey);
            uint* pulWrappedKeyLen = stackalloc uint[1];
            *pulWrappedKeyLen = 0;
            IntPtr pWrappedKey = IntPtr.Zero;
            pMechanism.mechanism = PKCS11Definitions.CKM_VENDOR_DEFINED;
            result = C_WrapKey(*phSession, ref pMechanism, 0, *phPrivateKey, pWrappedKey, pulWrappedKeyLen);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pWrappedKey = Marshal.AllocHGlobal(*(int*)pulWrappedKeyLen);
            result = C_WrapKey(*phSession, ref pMechanism, 0, *phPrivateKey, pWrappedKey, pulWrappedKeyLen);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pWrappedKey);
            result = C_DestroyObject(*phSession, *phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_UnWrap_basic()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags;
            flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            byte[] CKA_ENCRYPT = new byte[1];
            CKA_ENCRYPT[0] = 1;
            byte[] CKA_VERIFY = new byte[1];
            CKA_VERIFY[0] = 1;
            byte[] modulusbits = BitConverter.GetBytes(2048);
            Tuple<uint, byte[], int>[] pTuplePublic =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, Marshal.SizeOf(modulusbits[0]) * modulusbits.Length)
            };
            CK_ATTRIBUTE[] pPublicKeyTemplate = PKCS11Definitions.InsertAttributes(pTuplePublic);
            // ****** Private template ****** //
            byte[] CKA_DECRYPT = new byte[1];
            CKA_DECRYPT[0] = 1;
            byte[] CKA_SIGN = new byte[1];
            CKA_SIGN[0] = 1;
            byte[] CKA_ID = Encoding.ASCII.GetBytes("backupKey");
            Tuple<uint, byte[], int>[] pTuplePrivate =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
            };
            CK_ATTRIBUTE[] pPrivateKeyTemplate = PKCS11Definitions.InsertAttributes(pTuplePrivate);
            // **************************** //
            uint* phPublicKey = stackalloc uint[1];
            uint* phPrivateKey = stackalloc uint[1];
            result = C_GenerateKeyPair(*phSession, ref pMechanism, pPublicKeyTemplate, (uint)pPublicKeyTemplate.Length, pPrivateKeyTemplate, (uint)pPrivateKeyTemplate.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pPublicKeyTemplate);
            PKCS11Definitions.FreeAttributes(pPrivateKeyTemplate);
            Assert.AreEqual((uint)2, *phPublicKey);
            Assert.AreEqual((uint)1, *phPrivateKey);
            uint* pulWrappedKeyLen = stackalloc uint[1];
            *pulWrappedKeyLen = 0;
            IntPtr pWrappedKey = IntPtr.Zero;
            pMechanism.mechanism = PKCS11Definitions.CKM_VENDOR_DEFINED;
            result = C_WrapKey(*phSession, ref pMechanism, 0, *phPrivateKey, pWrappedKey, pulWrappedKeyLen);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pWrappedKey = Marshal.AllocHGlobal(*(int*)pulWrappedKeyLen);
            result = C_WrapKey(*phSession, ref pMechanism, 0, *phPrivateKey, pWrappedKey, pulWrappedKeyLen);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject(*phSession, *phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint* hKey2 = stackalloc uint[1];
            result = C_UnwrapKey(*phSession, ref pMechanism, 0, pWrappedKey, *pulWrappedKeyLen, IntPtr.Zero, 0, hKey2);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject(*phSession, *hKey2);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pWrappedKey);
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_FindObject_By_Subject()
        {
            string[] certificates = { "akv-jjimenez" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_TOKEN = new byte[1];
            CKA_TOKEN[0] = 1;
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_CERTIFICATE);
            string subject = "308197310b30090603550406130245533110300e06035504080c0747616c696369613111300f060355040a0c084772616469616e7431153013060355040b0c0c4772642053656375726974793126302406035504030c1d496e7465726d656469617465204341206a6a696d656e657a20746573743124302206092a864886f70d01090116156a6a696d656e657a406772616469616e742e6f7267";
            byte[] CKA_SUBJECT = Enumerable.Range(0, subject.Length / 2).Select(x => Convert.ToByte(subject.Substring(x * 2, 2), 16)).ToArray();
            Tuple<uint, byte[], int>[] pPublicTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_TOKEN, CKA_TOKEN, Marshal.SizeOf(CKA_TOKEN[0]) * CKA_TOKEN.Length),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                Tuple.Create(PKCS11Definitions.CKA_SUBJECT, CKA_SUBJECT, Marshal.SizeOf(CKA_SUBJECT[0]) * CKA_SUBJECT.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[5];
            uint* pulcObjectCount = stackalloc uint[1];
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects(*phSession, &phObjects[i], 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (*pulcObjectCount == 0) break;
            }
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_FindObject_By_PublicExponet()
        {
            string[] certificates = { "testCert1" };
            certificates = RestClient.ExistCertificates(certificates);
            if (certificates.Length > 0)
            {
                RestClient.CreateCertificates(certificates);
            }
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            byte[] CKA_PUBLIC_EXPOENENT = BitConverter.GetBytes(65537);
            Tuple<uint, byte[], int>[] pPublicTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                Tuple.Create(PKCS11Definitions.CKA_PUBLIC_EXPONENT, CKA_PUBLIC_EXPOENENT, Marshal.SizeOf(CKA_PUBLIC_EXPOENENT[0]) * CKA_PUBLIC_EXPOENENT.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObjects = stackalloc uint[1];
            uint* pulcObjectCount = stackalloc uint[1];
            result = C_FindObjects(*phSession, phObjects, 1, pulcObjectCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreNotEqual(*pulcObjectCount, (uint)0);
            result = C_FindObjectsFinal(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Logout(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        //[TestMethod]
        //public unsafe void Test_C_FindObject_C_GetattributeValue_Template_Exploration_SSH()
        //{
        //    string[] certificates = { "akv-darguez" };
        //    certificates = RestClient.ExistCertificates(certificates);
        //    if (certificates.Length > 0)
        //    {
        //        RestClient.CreateCertificates(certificates);
        //    }
        //    uint result = C_Initialize(null);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    CK_Info pInfo = new CK_Info();
        //    result = C_GetInfo(ref pInfo);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    bool tokenPresent = true;
        //    uint* pulCount = stackalloc uint[1];
        //    result = C_GetSlotList(tokenPresent, null, pulCount);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    uint* pSlotList = stackalloc uint[Convert.ToInt32(*pulCount)];
        //    result = C_GetSlotList(tokenPresent, pSlotList, pulCount);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    CK_TOKEN_INFO pTokenInfo = new CK_TOKEN_INFO();
        //    uint slotID = 1;
        //    result = C_GetTokenInfo(slotID, ref pTokenInfo);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
        //    void* pApplication = null;
        //    void* Notify = null;
        //    uint* phSession = stackalloc uint[1];
        //    result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    result = C_Login(*phSession, PKCS11Definitions.CKU_USER, "1234", 4);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    result = C_FindObjectsInit(*phSession, null, 0);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    uint* phObjects = stackalloc uint[5];
        //    uint* pulcObjectCount = stackalloc uint[1];
        //    result = C_FindObjects(*phSession, &phObjects[1], 1, pulcObjectCount);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    result = C_FindObjectsFinal(*phSession);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

        //    //**** Template *****//
        //    byte[] CKA_SIGN = new byte[1];
        //    CKA_SIGN[0] = 1;
        //    byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
        //    byte[] CKA_ID = Encoding.ASCII.GetBytes("akv-darguez");
        //    Tuple<uint, byte[], int>[] pTuple =
        //    {
        //         Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
        //         Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length),
        //         Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length)

        //    };
        //    CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(pTuple);
        //    //*******************//
        //    //** C_FindObject **//
        //    result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
        //    result = C_FindObjectsFinal(*phSession);
        //    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        //    PKCS11Definitions.FreeAttributes(pTemplate);
        //    Tuple<uint, byte[], int>[] pTuple2 =
        //    {
        //         Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
        //         Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)

        //    };
        //    pTemplate = PKCS11Definitions.InsertAttributes(pTuple2);
        //    result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);

        //    PKCS11Definitions.FreeAttributes(pTemplate);
        //    uint* phObjects2 = stackalloc uint[5];
        //    uint* pulcObjectCount2 = stackalloc uint[1];

        //    result = C_FindObjectsFinal(*phSession);
        //    if (phObjects2[0] != 0)
        //    {
        //        //CK_MECHANISM pMechanism = new CK_MECHANISM
        //        //{
        //        //    mechanism = PKCS11Definitions.CKM_RSA_PKCS,
        //        //    pParameter = IntPtr.Zero,
        //        //    ulParameterLen = 0
        //        //};
        //        //result = C_SignInit(*phSession, ref pMechanism, phObjects2[0]);
        //        Tuple<uint, byte[], int>[] pTuple3 = {
        //         Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
        //         Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length),
        //         Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length)
        //        };
        //        pTemplate = PKCS11Definitions.InsertAttributes(pTuple3);
        //        //*******************//
        //        //** C_FindObject **//
        //        result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
        //        result = C_FindObjectsFinal(*phSession);

        //        PKCS11Definitions.FreeAttributes(pTemplate);
        //        Tuple<uint, byte[], int>[] pTuple4 = {
        //         Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
        //         Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)
        //        };
        //        pTemplate = PKCS11Definitions.InsertAttributes(pTuple4);
        //        result = C_FindObjectsInit(*phSession, pTemplate, (uint)pTemplate.Length);
        //        PKCS11Definitions.FreeAttributes(pTemplate);
        //        result = C_FindObjectsFinal(*phSession);
        //    }
        //}

        [TestMethod]
        public unsafe void Test_C_CreateObject_Secret_Basic_And_Destroy()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_DATA);
            byte[] CKA_VALUE = Encoding.ASCII.GetBytes("Secret muy secreto");
            byte[] CKA_OBJECT_ID = Encoding.ASCII.GetBytes("secretoTest1");
            Tuple<uint, byte[], int>[] tuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                Tuple.Create(PKCS11Definitions.CKA_VALUE, CKA_VALUE, Marshal.SizeOf(CKA_VALUE[0]) * CKA_VALUE.Length),
                Tuple.Create(PKCS11Definitions.CKA_OBJECT_ID, CKA_OBJECT_ID, Marshal.SizeOf(CKA_OBJECT_ID[0]) * CKA_OBJECT_ID.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(tuple);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObject = stackalloc uint[1];
            result = C_CreateObject(*phSession, pTemplate, (uint)pTemplate.Length, phObject);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject(*phSession, *phObject);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_CreateObject_Secret_Complete_And_Destroy()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_DATA);
            byte[] CKA_VALUE = Encoding.ASCII.GetBytes("Secret muy secreto");
            byte[] CKA_OBJECT_ID = Encoding.ASCII.GetBytes("secretoTest1");
            byte[] CKA_APPLICATION = Encoding.ASCII.GetBytes("Esto es un secreto de prueba");
            Tuple<uint, byte[], int>[] tuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                Tuple.Create(PKCS11Definitions.CKA_VALUE, CKA_VALUE, Marshal.SizeOf(CKA_VALUE[0]) * CKA_VALUE.Length),
                Tuple.Create(PKCS11Definitions.CKA_OBJECT_ID, CKA_OBJECT_ID, Marshal.SizeOf(CKA_OBJECT_ID[0]) * CKA_OBJECT_ID.Length),
                Tuple.Create(PKCS11Definitions.CKA_APPLICATION, CKA_APPLICATION, Marshal.SizeOf(CKA_APPLICATION[0]) * CKA_APPLICATION.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(tuple);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObject = stackalloc uint[1];
            result = C_CreateObject(*phSession, pTemplate, (uint)pTemplate.Length, phObject);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            uint ulCount = 1;
            CK_ATTRIBUTE pTemplateG = new CK_ATTRIBUTE
            {
                type = PKCS11Definitions.CKA_OBJECT_ID,
                pValue = IntPtr.Zero,
                ulValueLen = 0
            };
            /************************/
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            byte[] managedArray = new byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_OBJECT_ID.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue);
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_VALUE;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_VALUE.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue);
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_APPLICATION;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_APPLICATION.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue);
            result = C_DestroyObject(*phSession, *phObject);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_Create_Update_Secret_Complete_And_Destroy()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            uint slotID = 1;
            uint flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            void* pApplication = null;
            void* Notify = null;
            uint* phSession = stackalloc uint[1];
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_DATA);
            byte[] CKA_VALUE = Encoding.ASCII.GetBytes("Secret muy secreto");
            byte[] CKA_OBJECT_ID = Encoding.ASCII.GetBytes("secretoTest1");
            byte[] CKA_APPLICATION = Encoding.ASCII.GetBytes("Esto es un secreto de prueba");
            Tuple<uint, byte[], int>[] tuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length),
                Tuple.Create(PKCS11Definitions.CKA_VALUE, CKA_VALUE, Marshal.SizeOf(CKA_VALUE[0]) * CKA_VALUE.Length),
                Tuple.Create(PKCS11Definitions.CKA_OBJECT_ID, CKA_OBJECT_ID, Marshal.SizeOf(CKA_OBJECT_ID[0]) * CKA_OBJECT_ID.Length),
                Tuple.Create(PKCS11Definitions.CKA_APPLICATION, CKA_APPLICATION, Marshal.SizeOf(CKA_APPLICATION[0]) * CKA_APPLICATION.Length)
            };
            CK_ATTRIBUTE[] pTemplate = PKCS11Definitions.InsertAttributes(tuple);
            PKCS11Definitions.FreeAttributes(pTemplate);
            uint* phObject = stackalloc uint[1];
            result = C_CreateObject(*phSession, pTemplate, (uint)pTemplate.Length, phObject);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            uint ulCount = 1;
            CK_ATTRIBUTE pTemplateG = new CK_ATTRIBUTE
            {
                type = PKCS11Definitions.CKA_OBJECT_ID,
                pValue = IntPtr.Zero,
                ulValueLen = 0
            };
            /************************/
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            byte[] managedArray = new byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_OBJECT_ID.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue);
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_VALUE;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_VALUE.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue);
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_APPLICATION;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_APPLICATION.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue);
            //**** Template SetAttribute *****//
            byte[] NEW_CKA_APPLICATION = Encoding.ASCII.GetBytes("Sigue siendo un Secreto...");
            Tuple<uint, byte[], int>[] pTupleSet =
            {
                Tuple.Create(PKCS11Definitions.CKA_APPLICATION, NEW_CKA_APPLICATION, Marshal.SizeOf(NEW_CKA_APPLICATION[0]) * NEW_CKA_APPLICATION.Length)
            };
            CK_ATTRIBUTE[] pTemplateSet = PKCS11Definitions.InsertAttributes(pTupleSet);
            result = C_SetAttributeValue(*phSession, *phObject, pTemplateSet, (uint)pTemplateSet.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Definitions.FreeAttributes(pTemplateSet);
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_APPLICATION;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal(pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue(*phSession, *phObject, &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, pTemplateG.ulValueLen);
            Assert.AreEqual(true, NEW_CKA_APPLICATION.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue);
            result = C_DestroyObject(*phSession, *phObject);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession(*phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_SetPIN_Test()
        {
            uint result = C_Initialize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            C_SetPIN((uint)1, "1234", 4, "1234", 4);
            result = C_Finalize(null);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }
    }
}