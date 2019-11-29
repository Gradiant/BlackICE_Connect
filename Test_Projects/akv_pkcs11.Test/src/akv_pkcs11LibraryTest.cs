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
 
using System;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;

/* DO NOT MODIFY this without tweaking compilation.sh */
using c_ulong = System.UInt32;
using c_long = System.Int32;
using c_uint = System.UInt32;
using c_int = System.Int32;

namespace akv_pkcs11.Test
{
    [TestClass]
    public unsafe class Akv_pkcs11LibraryTest
    {
        #region DLLImports
        const string LIB_NAME = "BlackICEConnect_x64.dll";

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_Initialize(IntPtr inVar);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_Finalize(IntPtr invar);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern c_ulong C_GetInfo(ref CK_INFO pInfo);
        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern c_ulong C_GetInfo(IntPtr pInfo);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetSlotList(Boolean tokenPresent, IntPtr pSlotList, IntPtr pulCount);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetSlotInfo(c_ulong slotID, ref CK_SLOT_INFO pInfo);
        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetSlotInfo(c_ulong slotID, IntPtr pInfo);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetTokenInfo(c_ulong slotID, ref CK_TOKEN_INFO pInfo);
        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetTokenInfo(c_ulong slotID, IntPtr pInfo);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetMechanismList(c_ulong slotID, IntPtr pMechanismList, IntPtr pulCount);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetMechanismInfo(c_ulong slotID, c_ulong type, ref CK_MECHANISM_INFO pInfo);
        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetMechanismInfo(c_ulong slotID, c_ulong type, IntPtr pInfo);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_OpenSession(c_ulong slotID, c_ulong flags, IntPtr pApplication, IntPtr Notify, IntPtr phSession);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_CloseSession(c_ulong hSession);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_CloseAllSessions(c_ulong slotID);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_Login(c_ulong hSession, c_ulong userType, [MarshalAs(UnmanagedType.LPStr)]string pPin, c_ulong ulPinLen);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_Logout(c_ulong hSession);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetSessionInfo(c_ulong hSession, ref CK_SESSION_INFO pInfo);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GenerateKeyPair(c_ulong hSession, ref CK_MECHANISM pMechanism,
            [In] IntPtr pPublicKeyTemplate, c_ulong ulPublicKeyAttributeCount, [In] IntPtr pPrivateKeyTemplate,
            c_ulong ulPrivateKeyAttributeCount, IntPtr phPublicKey, IntPtr phPrivateKey);
        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GenerateKeyPair(c_ulong hSession, ref CK_MECHANISM pMechanism,
            ref CK_ATTRIBUTE pPublicKeyTemplate, c_ulong ulPublicKeyAttributeCount, ref CK_ATTRIBUTE pPrivateKeyTemplate,
            c_ulong ulPrivateKeyAttributeCount, IntPtr phPublicKey, IntPtr phPrivateKey);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_FindObjectsInit(c_ulong hSession, IntPtr pTemplate, c_ulong ulCount);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_FindObjects(c_ulong hSession, IntPtr phObject, c_ulong ulMaxObjectCount, IntPtr pulObjectCount);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_FindObjectsFinal(c_ulong hSession);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_GetAttributeValue(c_ulong hSession, c_ulong hObject, [In] CK_ATTRIBUTE* pTemplate, c_ulong ulCount);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_DestroyObject(c_ulong hSession, c_ulong phObject);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_EncryptInit(c_ulong hSession, ref CK_MECHANISM pMechanism, c_ulong hKey);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_Encrypt(c_ulong hSession, IntPtr pData, c_ulong ulDataLen, IntPtr pEncryptedData, IntPtr pulEncryptedDataLen);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_DecryptInit(c_ulong hSession, ref CK_MECHANISM pMechanism, c_ulong hKey);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_Decrypt(c_ulong hSession, IntPtr pEncryptedData, c_ulong ulEncryptedDataLen, IntPtr pData, IntPtr pulDataLen);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_SignInit(c_ulong hSession, ref CK_MECHANISM pMechanism, c_ulong hKey);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_Sign(c_ulong hSession, IntPtr pData, c_ulong ulDataLen, IntPtr pSignature, IntPtr pulSignatureLen);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_VerifyInit(c_ulong hSession, ref CK_MECHANISM pMechanism, c_ulong hKey);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern c_ulong C_Verify(c_ulong hSession, IntPtr pData, c_ulong ulDataLen, IntPtr pSignature, c_ulong ulSignatureLen);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_SetAttributeValue(c_ulong hSession, c_ulong hObject, IntPtr pTemplate, c_ulong ulCount);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_WrapKey(c_ulong hSession, ref CK_MECHANISM pMechanism, c_ulong hWrappingKey,
            c_ulong hKey, IntPtr pWrappedKey, IntPtr pulWrappedKeyLen);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_UnwrapKey(c_ulong hSession, ref CK_MECHANISM pMechanism, c_ulong hUnwrappingKey,
            IntPtr pWrappedKey, c_ulong pulWrappedKeyLen, IntPtr pTemplate, c_ulong ulAttributeCount, IntPtr hKey);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_CreateObject(c_ulong hSession, IntPtr pTemplate, c_ulong ulCount, IntPtr phObject);

        [DllImport(LIB_NAME, SetLastError = true, CallingConvention = CallingConvention.Cdecl)]
        public static extern uint C_SetPIN(c_ulong hSession, [MarshalAs(UnmanagedType.LPStr)]string pOldPin, uint ulOldLen, [MarshalAs(UnmanagedType.LPStr)]string pNewPin, uint ulNewLen);

        #endregion DLLImports

        [ClassInitialize()]
        public static void Akv_pkcs11LibraryTest_Initialize(TestContext testContext) {
            string[] certificates = { "testCert1", "testCert2", "testCert3" };
            string[] nonExistingCertificates = RestClient.NonExistingCertificates(certificates);
            if (nonExistingCertificates.Length > 0)
            {
                RestClient.CreateCertificates(nonExistingCertificates);
            }
        }

        [TestMethod]
        public void Test_C_Initialize_C_Finalize_correct_config_file()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Initialize_is_already_initialized()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_ALREADY_INITIALIZED, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Finalize_without_call_C_Initialize()
        {
            c_ulong result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_Finalize_with_pReserved_not_NULL_PTR()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pReserved = Marshal.AllocHGlobal(sizeof(c_ulong));
            c_ulong resultFin = C_Finalize(pReserved);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, resultFin);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(pReserved);
        }

        [TestMethod]
        public void Test_C_GetInfo_without_call_C_Initialize()
        {
            CK_INFO pInfo = new CK_INFO();
            c_ulong result = C_GetInfo(ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_GetInfo_correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            CK_INFO pInfo = new CK_INFO();

            result = C_GetInfo(ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Assert.AreEqual(PKCS11Definitions.cryptokiVersion_major, pInfo.cryptokiVersion.major);
            Assert.AreEqual(PKCS11Definitions.cryptokiVersion_minor, pInfo.cryptokiVersion.minor);
            Assert.AreEqual(PKCS11Definitions.libraryVersion_major, pInfo.libraryVersion.major);
            Assert.AreEqual(PKCS11Definitions.libraryVersion_minor, pInfo.libraryVersion.minor);
            Assert.AreEqual((c_ulong)0, pInfo.flags);
            Assert.AreEqual(PKCS11Definitions.LIBRARY_DESCRIPTION, pInfo.libraryDescription.Trim());
            Assert.AreEqual(PKCS11Definitions.MANUFACTURER_ID, pInfo.manufacturerID.Trim());
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetInfo_Bad_Arguments()
        {
            c_ulong resultFin = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, resultFin);
            c_ulong result = C_GetInfo(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            resultFin = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, resultFin);
        }

        [TestMethod]
        public void Test_C_GetSlotList_correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Boolean tokenPresent = true;
            IntPtr pulCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_GetSlotList(tokenPresent, IntPtr.Zero, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pSlotList;
            pSlotList = Marshal.AllocHGlobal((c_int)PKCS11Utils.ReadLongFromBuffer(pulCount, 0));
            result = C_GetSlotList(tokenPresent, pSlotList, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(pulCount);
            Marshal.FreeHGlobal(pSlotList);
        }

        [TestMethod]
        public void Test_C_GetSlotList_Bad_Arguments()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Boolean tokenPresent = true;
            result = C_GetSlotList(tokenPresent, IntPtr.Zero, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        //Changed name from Test_C_GetSlotList_Buffer_To_Small
        public void Test_C_GetSlotList_Buffer_Too_Small()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Boolean tokenPresent = true;
            IntPtr pulCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            Marshal.WriteInt64(pulCount, (Int64)0);
            IntPtr pSlotList = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_GetSlotList(tokenPresent, pSlotList, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_BUFFER_TOO_SMALL, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(pulCount);
            Marshal.FreeHGlobal(pSlotList);
        }

        [TestMethod]
        public void Test_C_GetSlotList_Cryptoki_Not_Initialized()
        {
            Boolean tokenPresent = true;
            IntPtr pulCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            c_ulong result = C_GetSlotList(tokenPresent, IntPtr.Zero, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);

            Marshal.FreeHGlobal(pulCount);
        }

        [TestMethod]
        public void Test_C_GetSlotInfo_Cryptoki_Not_Initialized()
        {
            c_ulong slotID = 1;
            CK_SLOT_INFO pInfo = new CK_SLOT_INFO();
            c_ulong result = C_GetSlotInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_GetSlotInfo_Correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            CK_SLOT_INFO pInfo = new CK_SLOT_INFO();
            result = C_GetSlotInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual(PKCS11Definitions.firmwareVersion_major, pInfo.firmwareVersion.major);
            Assert.AreEqual(PKCS11Definitions.firmwareVersion_minor, pInfo.firmwareVersion.minor);
            Assert.AreEqual(PKCS11Definitions.hardwareVersion_major, pInfo.hardwareVersion.major);
            Assert.AreEqual(PKCS11Definitions.hardwareVersion_minor, pInfo.hardwareVersion.minor);
            Assert.AreEqual(PKCS11Definitions.SLOT_DESCRIPTION, pInfo.slotDescription.Trim());
            Assert.AreEqual(PKCS11Definitions.SLOT_MANUFACTURER_ID, pInfo.manufacturerID.Trim());
            Assert.AreEqual((c_ulong)5, pInfo.flags);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetSlotInfo_Bad_Arguments()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            result = C_GetSlotInfo(slotID, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetTokenInfo_Cryptoki_Not_Initialized()
        {
            c_ulong slotID = 1;
            c_ulong result = C_GetTokenInfo(slotID, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_GetTokenInfo_Bad_Arguments()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            result = C_GetTokenInfo(slotID, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetTokenInfo_Correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_LABEL, pInfo.label.Trim());
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_MANUFACTURER_ID, pInfo.manufacturerID.Trim());
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_MODEL, pInfo.model.Trim());
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_SERIAL_NUMBER, pInfo.serialNumber.Trim());
            Assert.AreEqual(PKCS11Definitions.CKF_LOGIN_REQUIRED | PKCS11Definitions.CKF_USER_PIN_INITIALIZED | PKCS11Definitions.CKF_TOKEN_INITIALIZED, pInfo.flags);
            Assert.AreEqual(PKCS11Definitions.CK_EFFECTIVELY_INFINITE, pInfo.ulMaxSessionCount);
            Assert.AreEqual((c_ulong)0, pInfo.ulSessionCount);
            Assert.AreEqual(PKCS11Definitions.CK_EFFECTIVELY_INFINITE, pInfo.ulMaxRwSessionCount);
            Assert.AreEqual((c_ulong)0, pInfo.ulRwSessionCount);
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_MAX_PIN_LEN, pInfo.ulMaxPinLen);
            Assert.AreEqual(PKCS11Definitions.TOKEN_INFO_MIN_PIN_LEN, pInfo.ulMinPinLen);
            Assert.AreEqual(PKCS11Definitions.CK_UNAVAILABLE_INFORMATION, pInfo.ulTotalPublicMemory);
            Assert.AreEqual(PKCS11Definitions.CK_UNAVAILABLE_INFORMATION, pInfo.ulTotalPrivateMemory);
            Assert.AreEqual(PKCS11Definitions.CK_UNAVAILABLE_INFORMATION, pInfo.ulFreePrivateMemory);
            Assert.AreEqual(PKCS11Definitions.hardwareVersion_major, pInfo.hardwareVersion.major);
            Assert.AreEqual(PKCS11Definitions.hardwareVersion_minor, pInfo.hardwareVersion.minor);
            Assert.AreEqual(PKCS11Definitions.firmwareVersion_major, pInfo.firmwareVersion.major);
            Assert.AreEqual(PKCS11Definitions.firmwareVersion_minor, pInfo.firmwareVersion.minor);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismList_Correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            IntPtr pulCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            PKCS11Utils.WriteIntInBuffer(pulCount, 0, 0);
            result = C_GetMechanismList(slotID, IntPtr.Zero, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)7, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pulCount, 0));
            IntPtr pMechanismList = Marshal.AllocHGlobal(Convert.ToInt32(PKCS11Utils.ReadLongFromBuffer(pulCount, 0)) * sizeof(c_ulong));
            result = C_GetMechanismList(slotID, pMechanismList, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)7, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pulCount, 0));
            c_int offset = 0;
            Assert.AreEqual(PKCS11Definitions.CKM_RSA_PKCS_KEY_PAIR_GEN, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pMechanismList, sizeof(c_ulong) * offset++));
            Assert.AreEqual(PKCS11Definitions.CKM_RSA_PKCS, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pMechanismList, sizeof(c_ulong) * offset++));
            Assert.AreEqual(PKCS11Definitions.CKM_RSA_PKCS_OAEP, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pMechanismList, sizeof(c_ulong) * offset++));
            Assert.AreEqual(PKCS11Definitions.CKM_SHA256_RSA_PKCS, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pMechanismList, sizeof(c_ulong) * offset++));
            Assert.AreEqual(PKCS11Definitions.CKM_SHA384_RSA_PKCS, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pMechanismList, sizeof(c_ulong) * offset++));
            Assert.AreEqual(PKCS11Definitions.CKM_SHA512_RSA_PKCS, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pMechanismList, sizeof(c_ulong) * offset++));
            Assert.AreEqual(PKCS11Definitions.CKM_VENDOR_DEFINED, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pMechanismList, sizeof(c_ulong) * offset++));
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(pulCount);
            Marshal.FreeHGlobal(pMechanismList);
        }

        [TestMethod]
        public void Test_C_GetMechanismList_Bad_Arguments()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            IntPtr pulCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            PKCS11Utils.WriteIntInBuffer(pulCount, 0, 0);
            result = C_GetMechanismList(slotID, IntPtr.Zero, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(pulCount);
        }

        [TestMethod]
        public void Test_C_GetMechanismList_Buffer_Too_Small()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            IntPtr pulCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            PKCS11Utils.WriteIntInBuffer(pulCount, 0, 0);
            result = C_GetMechanismList(slotID, IntPtr.Zero, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.WriteIntInBuffer(pulCount, 3, 0);
            IntPtr pMechanismList = Marshal.AllocHGlobal(Convert.ToInt32(PKCS11Utils.ReadLongFromBuffer(pulCount, 0)));
            result = C_GetMechanismList(slotID, pMechanismList, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_BUFFER_TOO_SMALL, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(pulCount);
            Marshal.FreeHGlobal(pMechanismList);
        }

        [TestMethod]
        public void Test_C_GetMechanismList_Cryptoki_Not_Initialized()
        {
            c_ulong slotID = 1;
            IntPtr pulCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            PKCS11Utils.WriteIntInBuffer(pulCount, 0, 0);
            c_ulong result = C_GetMechanismList(slotID, IntPtr.Zero, pulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismInfo_Correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            CK_MECHANISM_INFO pInfo = new CK_MECHANISM_INFO();
            result = C_GetMechanismInfo(slotID, PKCS11Definitions.CKM_RSA_PKCS, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)2048, pInfo.ulMinKeySize);
            Assert.AreEqual((c_ulong)2048, pInfo.ulMaxKeySize);
            Assert.AreEqual(PKCS11Definitions.CKF_ENCRYPT | PKCS11Definitions.CKF_DECRYPT | PKCS11Definitions.CKF_HW, pInfo.flags);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismInfot_Bad_Arguments()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            result = C_GetMechanismInfo(slotID, PKCS11Definitions.CKM_RSA_PKCS, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismInfo_MECHANISM_INVALID()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            CK_MECHANISM_INFO pInfo = new CK_MECHANISM_INFO();
            result = C_GetMechanismInfo(slotID, PKCS11Definitions.CKM_RSA_9796, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_MECHANISM_INVALID, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetMechanismInfo_Cryptoki_Not_Initialized()
        {
            c_ulong slotID = 1;
            CK_MECHANISM_INFO pInfo = new CK_MECHANISM_INFO();
            c_ulong result = C_GetMechanismInfo(slotID, PKCS11Definitions.CKM_RSA_PKCS, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_OpenSession_Cryptoki_Not_Initialized()
        {
            c_ulong slotID = 1;
            c_ulong flags = PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION;
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            c_ulong result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_OpenSession_Correct_1_Serial_Session()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)1, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_OpenSession_Correct_10_Serial_Session()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual(i + 1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            }
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)10, pInfo.ulSessionCount);
            Assert.AreEqual((c_ulong)10, pInfo.ulRwSessionCount);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_OpenSession_Correct_100_Serial_Session()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 100; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual(i + 1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            }
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)100, pInfo.ulSessionCount);
            Assert.AreEqual((c_ulong)100, pInfo.ulRwSessionCount);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_OpenSession_Arguments_Bad()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_OpenSession_Session_Paralell_Not_Suported()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_PARALLEL_NOT_SUPPORTED, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_CloseSession_Cryptoki_Not_Initialized()
        {
            c_ulong result = C_CloseSession(1);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_CloseSession_Not_Opened()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            PKCS11Utils.WriteIntInBuffer(phSession, 0, 0);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_CLOSED, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_CloseSession_Not_Exist()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_long)1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            result = C_CloseSession(2);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_HANDLE_INVALID, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_CloseSession_Session_1()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_long)1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_CloseSession_10_Sessions_Close_Number_3()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual(i + 1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            }
            result = C_CloseSession((c_ulong)3);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)9, pInfo.ulSessionCount);
            Assert.AreEqual((c_ulong)9, pInfo.ulRwSessionCount);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_CloseSession_10_Sessions_Close_all_disorderly()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual(i + 1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            }
            c_ulong j;
            for (c_ulong i = 1; i <= 5; i++)
            {
                j = (2 * i);
                result = C_CloseSession(j);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            for (c_ulong i = 0; i <= 4; i++)
            {
                j = (2 * i) + 1;
                result = C_CloseSession(j);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)0, pInfo.ulSessionCount);
            Assert.AreEqual((c_ulong)0, pInfo.ulRwSessionCount);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_CloseSession_10_Sessions_Back_To_Front()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual(i + 1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            }
            for (c_ulong i = 10; i > 0; i--)
            {
                result = C_CloseSession(i);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)0, pInfo.ulSessionCount);
            Assert.AreEqual((c_ulong)0, pInfo.ulRwSessionCount);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }


        [TestMethod]
        public void Test_C_CloseAllSession_10_Sessions_open()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual(i + 1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            }
            result = C_CloseAllSessions(slotID);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_TOKEN_INFO pInfo = new CK_TOKEN_INFO();
            result = C_GetTokenInfo(slotID, ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)0, pInfo.ulSessionCount);
            Assert.AreEqual((c_ulong)0, pInfo.ulRwSessionCount);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_CloseAllSession_Cryptoki_Not_Initialized()
        {
            c_ulong result = C_CloseAllSessions(1);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_CloseAllSession_SLOT_ID_INVALID()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual(i + 1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            }
            result = C_CloseAllSessions(2);
            Assert.AreEqual(PKCS11Definitions.CKR_SLOT_ID_INVALID, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
        }

        [TestMethod]
        public void Test_C_CloseAllSession_Bad_Arguments()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 10; i++)
            {
                result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Assert.AreEqual(i + 1, PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            }
            result = C_CloseAllSessions(0);
            Assert.AreEqual(PKCS11Definitions.CKR_ARGUMENTS_BAD, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Login_Cryptoki_Not_Initialized()
        {
            c_ulong result = C_Login(1, PKCS11Definitions.CKS_RO_USER_FUNCTIONS, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_CRYPTOKI_NOT_INITIALIZED, result);
        }

        [TestMethod]
        public void Test_C_Login_Not_Session_Initialized()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKS_RO_USER_FUNCTIONS, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_CLOSED, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Login_Invalid_User_Type()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, 3, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_USER_TYPE_INVALID, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Login_SO()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_SO, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Login_User()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Login_Invalid_Session_Handler()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(0, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_HANDLE_INVALID, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Logout_Not_Session_Initialized()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Logout(1);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_CLOSED, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_Logout_User_Not_Logged_In()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            result = C_Logout(1);
            Assert.AreEqual(PKCS11Definitions.CKR_USER_NOT_LOGGED_IN, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public void Test_C_GetSessionInfo()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_SESSION_INFO pInfo = new CK_SESSION_INFO();
            result = C_GetSessionInfo((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pInfo);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)1, pInfo.slotID);
            Assert.AreEqual(PKCS11Definitions.CKS_RW_PUBLIC_SESSION, pInfo.state);
            Assert.AreEqual((c_ulong)0, pInfo.ulDeviceError);
            Assert.AreEqual((c_ulong)0x6, pInfo.flags); //0x00000004 This flag is provided for backward compatibility, and should always be set to true. 0x00000001 True if the session is read/write
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_GenerateKeyPair()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags;
            flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
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
            Byte[] CKA_ENCRYPT = new Byte[1];
            CKA_ENCRYPT[0] = 1;
            Byte[] CKA_VERIFY = new Byte[1];
            CKA_VERIFY[0] = 1;
            Byte[] modulusbits = BitConverter.GetBytes(2048);
            Tuple<c_ulong, Byte[], c_ulong>[] publicTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, (c_ulong)(Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, (c_ulong)(Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length)),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, (c_ulong)(Marshal.SizeOf(modulusbits[0]) * modulusbits.Length))
            };

            c_int publicArraySize = PKCS11Utils.GetSizeOfTupleArray(publicTuple);
            IntPtr pPublicKeyTemplate = Marshal.AllocHGlobal(publicArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPublicKeyTemplate, publicTuple);
            // ****** Private template ****** //
            Byte[] CKA_DECRYPT = new Byte[1];
            CKA_DECRYPT[0] = 1;
            Byte[] CKA_SIGN = new Byte[1];
            CKA_SIGN[0] = 1;
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("GENKEYHSM");
            Tuple<c_ulong, Byte[], c_ulong>[] privateTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, (c_ulong)(Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, (c_ulong)(Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int privateArraySize = PKCS11Utils.GetSizeOfTupleArray(privateTuple);
            IntPtr pPrivateKeyTemplate = Marshal.AllocHGlobal(privateArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPrivateKeyTemplate, privateTuple);
            // **************************** //
            IntPtr phPublicKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            IntPtr phPrivateKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_GenerateKeyPair((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, pPublicKeyTemplate, (c_ulong)publicTuple.Length, pPrivateKeyTemplate, (c_ulong)privateTuple.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_ulong)2, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPublicKey,0));
            Assert.AreEqual((c_ulong)1, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0));
            PKCS11Utils.FreeTemplateAttributesIntPtr(pPublicKeyTemplate, publicTuple.Length);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pPrivateKeyTemplate, privateTuple.Length);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(pPublicKeyTemplate);
            Marshal.FreeHGlobal(pPrivateKeyTemplate);
            Marshal.FreeHGlobal(phPublicKey);
            Marshal.FreeHGlobal(phPrivateKey);
        }

        [TestMethod]
        public unsafe void Test_C_FindObjectsInit_Alone_NULL_Template()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Zero, 0);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_FindObject_C_GetattributeValue_Template_Exploration_Adobe()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Tuple<c_ulong, Byte[], c_ulong>[] tuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
            };
            c_int tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(tuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(tupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, tuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)tuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, tuple.Length);
            Marshal.FreeHGlobal(pTemplate);

            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)Marshal.PtrToStructure(phSession, typeof(c_ulong)), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //** C_GetAttributeValues **//
            //**** Template *****//
            c_ulong ulCount = 1;
            CK_ATTRIBUTE pTemplateG = new CK_ATTRIBUTE
            {
                type = PKCS11Definitions.CKA_ID,
                pValue = IntPtr.Zero,
                ulValueLen = 0
            };
            /************************/
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pValue = Marshal.AllocHGlobal(Convert.ToInt32(pTemplateG.ulValueLen) * sizeof(c_ulong));
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //** C_FindObject **//
            //**** Template *****//
            Byte[] CKA_SERIAL_NUMBER = Encoding.ASCII.GetBytes("0123456789asddddddddddddddddmlmlñmdlqwemdlmqlñmwqqmddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddqlñqmwdlñqmwdlñqmdlñqwmldñmqñlwqmdñlqmwñdlmqwñlmdqñlwmdñlqmlñqwmdlqmwdlqñwdmqwlqwd");
            Tuple<c_ulong, Byte[], c_ulong>[] pTemplateTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_SERIAL_NUMBER, CKA_SERIAL_NUMBER, (c_ulong)(Marshal.SizeOf(CKA_SERIAL_NUMBER[0]) * CKA_SERIAL_NUMBER.Length))
            };
            tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pTemplateTuple);
            pTemplate = Marshal.AllocHGlobal(tupleArraySize); //already freed previous template

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pTemplateTuple);
            /**************/
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pTemplateTuple.Length);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(pTemplate);
        }

        [TestMethod]
        public unsafe void Test_C_FindObject_C_GetattributeValue_Template_Exploration_Firefox()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_TOKEN = new Byte[1];
            CKA_TOKEN[0] = 1;
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_CERTIFICATE);
            Tuple<c_ulong, Byte[], c_ulong>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_TOKEN, CKA_TOKEN, (c_ulong)(Marshal.SizeOf(CKA_TOKEN[0]) * CKA_TOKEN.Length)),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length))
            };
            c_int tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(tupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (uint)pTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pTuple.Length);
            Marshal.FreeHGlobal(pTemplate);
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)Marshal.PtrToStructure(phSession, typeof(c_ulong)), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //** C_GetAttributeValues **//
            //**** Template *****//
            c_ulong ulCount = 1;
            CK_ATTRIBUTE pTemplateG = new CK_ATTRIBUTE
            {
                type = PKCS11Definitions.CKA_ID,
                pValue = IntPtr.Zero,
                ulValueLen = 0
            };
            /************************/
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0 * sizeof(c_ulong)), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0 * sizeof(c_ulong)), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pValue);
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.ulValueLen = 0;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 1 * sizeof(c_ulong)), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 1 * sizeof(c_ulong)), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pValue);
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.ulValueLen = 0;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 2 * sizeof(c_ulong)), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 2 * sizeof(c_ulong)), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pValue);
            //** C_FindObject **//
            //**** Template *****//
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Tuple<c_ulong, Byte[], c_ulong>[] pTupleF =
            {
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length))
            };
            tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pTupleF);
            pTemplate = Marshal.AllocHGlobal(tupleArraySize); //previous template already freed

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pTupleF);
            /**************/
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pTupleF.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pTupleF.Length);
            Marshal.FreeHGlobal(pTemplate);
            IntPtr phObjects2 = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount2 = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)Marshal.PtrToStructure(phSession, typeof(c_ulong)), IntPtr.Add(phObjects2, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount2);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (PKCS11Utils.ReadLongFromBuffer(pulcObjectCount2, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            CKA_ID = Encoding.ASCII.GetBytes("testCert2");
            CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Tuple<c_ulong, Byte[], c_ulong>[] pTupleTestCert2 =
            {
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length))
            };
            tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pTupleTestCert2);
            pTemplate = Marshal.AllocHGlobal(tupleArraySize); //previous template already freed

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pTupleTestCert2);
            /**************/
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pTupleTestCert2.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pTupleTestCert2.Length);
            Marshal.FreeHGlobal(pTemplate);
            IntPtr phObjects3 = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount3 = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)Marshal.PtrToStructure(phSession, typeof(c_ulong)), IntPtr.Add(phObjects3, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount3);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (PKCS11Utils.ReadLongFromBuffer(pulcObjectCount3, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            CKA_ID = Encoding.ASCII.GetBytes("testCert3");
            CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Tuple<c_ulong, Byte[], c_ulong>[] pTupleTestCert3 =
            {
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length)),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length))
            };
            tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pTupleTestCert3);
            pTemplate = Marshal.AllocHGlobal(tupleArraySize); //previous template already freed

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pTupleTestCert3);
            /**************/
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pTupleTestCert3.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pTupleTestCert3.Length);
            Marshal.FreeHGlobal(pTemplate);
            IntPtr phObjects4 = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount4 = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)Marshal.PtrToStructure(phSession, typeof(c_ulong)), IntPtr.Add(phObjects4, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount4);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (PKCS11Utils.ReadLongFromBuffer(phSession, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(phObjects2);
            Marshal.FreeHGlobal(phObjects3);
            Marshal.FreeHGlobal(phObjects4);
            Marshal.FreeHGlobal(pulcObjectCount);
            Marshal.FreeHGlobal(pulcObjectCount2);
            Marshal.FreeHGlobal(pulcObjectCount3);
            Marshal.FreeHGlobal(pulcObjectCount4);
        }

        [TestMethod]
        public unsafe void Test_C_DestroyObject_Incorrect_Session_Handler()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject(1, 1);
            Assert.AreEqual(PKCS11Definitions.CKR_SESSION_CLOSED, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_DestroyObject_Incorrect_Object_Handler()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), 1);
            Assert.AreEqual(PKCS11Definitions.CKR_OBJECT_HANDLE_INVALID, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }

        [TestMethod]
        public unsafe void Test_C_DestroyObject_After_Key_Creation()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS_KEY_PAIR_GEN,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login((c_ulong)(PKCS11Utils.ReadLongFromBuffer(phSession, 0)), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            Byte[] CKA_ENCRYPT = new Byte[1];
            CKA_ENCRYPT[0] = 1;
            Byte[] CKA_VERIFY = new Byte[1];
            CKA_VERIFY[0] = 1;
            Byte[] modulusbits = BitConverter.GetBytes(2048);
            Tuple<c_ulong, Byte[], c_ulong>[] pTuplePublic =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, (c_ulong)(Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, (c_ulong)(Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length)),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, (c_ulong)(Marshal.SizeOf(modulusbits[0]) * modulusbits.Length))
            };
            c_int publicArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuplePublic);
            IntPtr pPublicKeyTemplate = Marshal.AllocHGlobal(publicArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPublicKeyTemplate, pTuplePublic);
            // ****** Private template ****** //
            Byte[] CKA_DECRYPT = new Byte[1];
            CKA_DECRYPT[0] = 1;
            Byte[] CKA_SIGN = new Byte[1];
            CKA_SIGN[0] = 1;
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("deleteKey");
            Tuple<c_ulong, Byte[], c_ulong>[] pTuplePrivate =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, (c_ulong)(Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, (c_ulong)(Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int privateArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuplePrivate);
            IntPtr pPrivateKeyTemplate = Marshal.AllocHGlobal(privateArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPrivateKeyTemplate, pTuplePrivate);
            // **************************** //
            IntPtr phPublicKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            IntPtr phPrivateKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_GenerateKeyPair((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, pPublicKeyTemplate, (c_ulong)pTuplePublic.Length, pPrivateKeyTemplate, (c_ulong)pTuplePrivate.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_long)2, PKCS11Utils.ReadLongFromBuffer(phPublicKey, 0));
            Assert.AreEqual((c_long)1, PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0));
            PKCS11Utils.FreeTemplateAttributesIntPtr(pPublicKeyTemplate, pTuplePublic.Length);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pPrivateKeyTemplate, pTuplePrivate.Length);
            result = C_DestroyObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)(PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0)));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)(PKCS11Utils.ReadLongFromBuffer(phSession, 0)));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pPublicKeyTemplate);
            Marshal.FreeHGlobal(pPrivateKeyTemplate);
            Marshal.FreeHGlobal(phPublicKey);
            Marshal.FreeHGlobal(phPrivateKey);
        }

        [TestMethod]
        public unsafe void Test_C_SignInit_correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<c_ulong, Byte[], c_ulong>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(tupleArraySize); //previous template already freed

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pTuple.Length);
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_int i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if (PKCS11Utils.ReadLongFromBuffer(phObjects, 0) != 0)
            {
                result = C_SignInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }

        [TestMethod]
        public unsafe void Test_C_Sign_Correct_Sha256()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<c_ulong, Byte[], c_ulong>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(tupleArraySize); //previous template already freed

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pTuple.Length);
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if (PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0) != 0)
            {
                result = C_SignInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                string oidString = CryptoConfig.MapNameToOID("sha256");
                Byte[] encodedOid = CryptoConfig.EncodeOID(oidString);
                string hexOIDSting = PKCS11Utils.ByteArrayToString(encodedOid);
                string hash = "ebac6efe864bcb9a448d2cd234232685771e8852c89b245aa745efd94b029274";
                string asn1hash = ("30" + 49.ToString("X2") + "30" + 13.ToString("X2") + hexOIDSting + "050004" + 32.ToString("X2") + hash).ToLower();
                Byte[] asn1Bytes = Enumerable.Range(0, asn1hash.Length / 2).Select(x => Convert.ToByte(asn1hash.Substring(x * 2, 2), 16)).ToArray();
                IntPtr pData = Marshal.AllocHGlobal(asn1Bytes.Length);
                Marshal.Copy(asn1Bytes, 0, pData, asn1Bytes.Length);
                IntPtr pSignature = IntPtr.Zero;
                IntPtr pSignatureLen = Marshal.AllocHGlobal(sizeof(c_ulong));
                result = C_Sign((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pData, (c_ulong)asn1Bytes.Length, pSignature, pSignatureLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                pSignature = Marshal.AllocHGlobal((c_int)PKCS11Utils.ReadLongFromBuffer(pSignatureLen, 0));
                result = C_Sign((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pData, (c_ulong)asn1Bytes.Length, pSignature, pSignatureLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Marshal.FreeHGlobal(pData);
                Marshal.FreeHGlobal(pSignatureLen);
                Marshal.FreeHGlobal(pSignature);
            }
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }

        [TestMethod]
        public unsafe void Test_C_VerifyInit_correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<c_ulong, Byte[], c_ulong>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(tupleArraySize); //previous template already freed

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pTuple.Length);
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0) != 0)
            {
                result = C_VerifyInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }

        [TestMethod]
        public unsafe void Test_C_Verify_Correct_Sha256()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template Private Key *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<c_ulong, Byte[], c_ulong>[] pTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(tupleArraySize); //previous template already freed

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pTuple.Length);
            Marshal.FreeHGlobal(pTemplate); //Will be reused
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0) != 0)
            {
                result = C_SignInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                string oidString = CryptoConfig.MapNameToOID("sha256"); // f.x. "MD5"
                Byte[] encodedOid = CryptoConfig.EncodeOID(oidString);
                string hexOIDSting = PKCS11Utils.ByteArrayToString(encodedOid);
                string hash = "ebac6efe864bcb9a448d2cd234232685771e8852c89b245aa745efd94b029274";
                string asn1hash = ("30" + 49.ToString("X2") + "30" + 13.ToString("X2") + hexOIDSting + "050004" + 32.ToString("X2") + hash).ToLower();
                Byte[] asn1Bytes = Enumerable.Range(0, asn1hash.Length / 2).Select(x => Convert.ToByte(asn1hash.Substring(x * 2, 2), 16)).ToArray();
                IntPtr pData = Marshal.AllocHGlobal(asn1Bytes.Length);
                Marshal.Copy(asn1Bytes, 0, pData, asn1Bytes.Length);
                IntPtr pSignature = IntPtr.Zero;
                IntPtr pSignatureLen = Marshal.AllocHGlobal(sizeof(c_ulong));
                result = C_Sign((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pData, (c_ulong)asn1Bytes.Length, pSignature, pSignatureLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                pSignature = Marshal.AllocHGlobal((c_int)PKCS11Utils.ReadLongFromBuffer(pSignatureLen, 0));
                result = C_Sign((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pData, (c_ulong)asn1Bytes.Length, pSignature, pSignatureLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                //**** Template Public Key *****//
                CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
                CKA_ID = Encoding.ASCII.GetBytes("testCert1");
                Tuple<c_ulong, Byte[], c_ulong>[] pPublicTuple =
                {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
                };
                c_int publicTupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pPublicTuple);
                pTemplate = Marshal.AllocHGlobal(publicTupleArraySize); //previous template already freed

                PKCS11Utils.InsertAttributesIntPtr(pTemplate, pPublicTuple);
                //*******************//
                //** C_FindObject **//
                result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pPublicTuple.Length);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pPublicTuple.Length);
                IntPtr phObjectsPublic = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
                IntPtr pulcObjectCountPublic = Marshal.AllocHGlobal(sizeof(c_ulong));
                for (c_long i = 0; i < 5; i++)
                {
                    result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjectsPublic, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCountPublic);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjectsPublic, 0) == 0) break;
                }
                result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjectsPublic, 0) != 0)
                {

                    result = C_VerifyInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjectsPublic, 0));
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    result = C_Verify((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pData, (c_ulong)asn1Bytes.Length, pSignature, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pSignatureLen, 0));
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                }
                Marshal.FreeHGlobal(pData);
                Marshal.FreeHGlobal(pSignature);
                Marshal.FreeHGlobal(phObjectsPublic);
                Marshal.FreeHGlobal(pulcObjectCountPublic);
            }
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }

        [TestMethod]
        public unsafe void Test_C_EncryptInit_correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<c_ulong, Byte[], c_ulong>[] pPublicTuple =
            {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int publicTupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pPublicTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(publicTupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pPublicTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pPublicTuple.Length);
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0) != 0)
            {
                result = C_EncryptInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }

        [TestMethod]
        public unsafe void Test_C_Encrypt_correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<c_ulong, Byte[], c_ulong>[] pPublicTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int publicTupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pPublicTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(publicTupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pPublicTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pPublicTuple.Length);
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0) != 0)
            {
                result = C_EncryptInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Byte[] pDataBytes = Encoding.ASCII.GetBytes("Hola mundo");
                IntPtr pData = Marshal.AllocHGlobal(pDataBytes.Length);
                Marshal.Copy(pDataBytes, 0, pData, pDataBytes.Length);
                IntPtr pEncryptedData = IntPtr.Zero;
                IntPtr pEncryptedDataLen = Marshal.AllocHGlobal(sizeof(c_ulong));
                result = C_Encrypt((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pData, (c_ulong)pDataBytes.Length, pEncryptedData, pEncryptedDataLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                pEncryptedData = Marshal.AllocHGlobal(*(int*)pEncryptedDataLen);
                result = C_Encrypt((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pData, (c_ulong)pDataBytes.Length, pEncryptedData, pEncryptedDataLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                Marshal.FreeHGlobal(pData);
                Marshal.FreeHGlobal(pEncryptedDataLen);
                Marshal.FreeHGlobal(pEncryptedData);
            }
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }

        [TestMethod]
        public unsafe void Test_C_DecryptInit_correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            //**** Template *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<c_ulong, Byte[], c_ulong>[] pPublicTuple =
            {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
                };
            c_int publicTupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pPublicTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(publicTupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pPublicTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pPublicTuple.Length);
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (int i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0) != 0)
            {
                result = C_DecryptInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            }
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }

        [TestMethod]
        public unsafe void Test_C_Decrypt_correct()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            CK_MECHANISM pMechanism = new CK_MECHANISM
            {
                mechanism = PKCS11Definitions.CKM_RSA_PKCS,
                pParameter = IntPtr.Zero,
                ulParameterLen = 0
            };
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PUBLIC_KEY);
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("testCert1");
            Tuple<c_ulong, Byte[], c_ulong>[] pPublicTuple =
            {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
                };
            c_int publicTupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pPublicTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(publicTupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pPublicTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pPublicTuple.Length);
            Marshal.FreeHGlobal(pTemplate); //Will be reused
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0) != 0)
            {
                result = C_EncryptInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjects, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                String plainText = "Hola mundo";
                Byte[] pDataBytes = Encoding.ASCII.GetBytes(plainText);
                IntPtr pData = Marshal.AllocHGlobal(pDataBytes.Length);
                Marshal.Copy(pDataBytes, 0, pData, pDataBytes.Length);
                IntPtr pEncryptedData = IntPtr.Zero;
                IntPtr pEncryptedDataLen = Marshal.AllocHGlobal(sizeof(c_ulong));
                result = C_Encrypt((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pData, (c_ulong)pDataBytes.Length, pEncryptedData, pEncryptedDataLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                pEncryptedData = Marshal.AllocHGlobal((c_int)PKCS11Utils.ReadLongFromBuffer(pEncryptedDataLen, 0));
                result = C_Encrypt((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pData, (c_ulong)pDataBytes.Length, pEncryptedData, pEncryptedDataLen);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                //**** Template  Private key *****//
                CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
                CKA_ID = Encoding.ASCII.GetBytes("testCert1");
                Tuple<c_ulong, Byte[], c_ulong>[] pPrivateTuple =
                {
                    Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                    Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
                };
                c_int privateTupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pPrivateTuple);
                pTemplate = Marshal.AllocHGlobal(privateTupleArraySize); //template previously freed

                PKCS11Utils.InsertAttributesIntPtr(pTemplate, pPrivateTuple);
                //*******************//
                //** C_FindObject **//
                result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pPrivateTuple.Length);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pPrivateTuple.Length);
                IntPtr phObjectsPriv = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
                IntPtr pulcObjectCountPriv = Marshal.AllocHGlobal(sizeof(c_ulong));
                for (c_long i = 0; i < 5; i++)
                {
                    result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjectsPriv, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCountPriv);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCountPriv, 0) == 0) break;
                }
                result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjectsPriv, 0) != 0)
                {
                    result = C_DecryptInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObjectsPriv, 0));
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    IntPtr pDecryptedDataLen = Marshal.AllocHGlobal(sizeof(c_ulong));
                    IntPtr pDecryptedData = IntPtr.Zero;
                    result = C_Decrypt((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pEncryptedData, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pEncryptedDataLen, 0), pDecryptedData, pDecryptedDataLen);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    pDecryptedData = Marshal.AllocHGlobal((c_int)PKCS11Utils.ReadLongFromBuffer(pEncryptedDataLen, 0));
                    result = C_Decrypt((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pEncryptedData, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pEncryptedDataLen, 0), pDecryptedData, pDecryptedDataLen);
                    Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                    string DecryptedData = Marshal.PtrToStringAnsi(pDecryptedData, *(int*)pDecryptedDataLen);
                    Assert.AreEqual(DecryptedData, plainText);
                    Marshal.FreeHGlobal(pDecryptedData);
                }
                Marshal.FreeHGlobal(pData);
                Marshal.FreeHGlobal(pEncryptedData);
                Marshal.FreeHGlobal(pEncryptedDataLen);
            }
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }

        [TestMethod]
        public unsafe void Test_C_SetAttributeValue_basic()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
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
            Byte[] CKA_ENCRYPT = new Byte[1];
            CKA_ENCRYPT[0] = 1;
            Byte[] CKA_VERIFY = new Byte[1];
            CKA_VERIFY[0] = 1;
            Byte[] modulusbits = BitConverter.GetBytes(2048);
            Tuple<c_ulong, Byte[], c_ulong>[] pTuplePublic =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, (c_ulong)(Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, (c_ulong)(Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length)),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, (c_ulong)(Marshal.SizeOf(modulusbits[0]) * modulusbits.Length))
            };
            c_int publicArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuplePublic);
            IntPtr pPublicKeyTemplate = Marshal.AllocHGlobal(publicArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPublicKeyTemplate, pTuplePublic);
            // ****** Private template ****** //
            Byte[] CKA_DECRYPT = new Byte[1];
            CKA_DECRYPT[0] = 1;
            Byte[] CKA_SIGN = new Byte[1];
            CKA_SIGN[0] = 1;
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("SetAttKey");
            Tuple<c_ulong, Byte[], c_ulong>[] pTuplePrivate =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, (c_ulong)(Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, (c_ulong)(Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int privateArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuplePrivate);
            IntPtr pPrivateKeyTemplate = Marshal.AllocHGlobal(privateArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPrivateKeyTemplate, pTuplePrivate);
            // **************************** //
            IntPtr phPublicKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            IntPtr phPrivateKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_GenerateKeyPair((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, pPublicKeyTemplate, (c_ulong)pTuplePublic.Length, pPrivateKeyTemplate, (c_ulong)pTuplePrivate.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreEqual((c_long)2, PKCS11Utils.ReadLongFromBuffer(phPublicKey, 0));
            Assert.AreEqual((c_long)1, PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0));

            PKCS11Utils.FreeTemplateAttributesIntPtr(pPublicKeyTemplate, pTuplePublic.Length);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pPrivateKeyTemplate, pTuplePrivate.Length);
            //**** Template SetAttribute *****//
            CKA_SIGN = new Byte[1];
            CKA_SIGN[0] = 0;
            Tuple<c_ulong, Byte[], c_ulong>[] pTupleSign =
            {
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, (c_ulong)(Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length))
            };
            c_int signArraySize = PKCS11Utils.GetSizeOfTupleArray(pTupleSign);
            IntPtr pSignKeyTemplate = Marshal.AllocHGlobal(signArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pSignKeyTemplate, pTupleSign);

            result = C_SetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0), pSignKeyTemplate, (c_ulong)pTupleSign.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pSignKeyTemplate, pTupleSign.Length);
            result = C_DestroyObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(phPublicKey);
            Marshal.FreeHGlobal(phPrivateKey);
            Marshal.FreeHGlobal(pPublicKeyTemplate);
            Marshal.FreeHGlobal(pPrivateKeyTemplate);
            Marshal.FreeHGlobal(pSignKeyTemplate);
        }

       [TestMethod]
        public unsafe void Test_C_Wrap_basic()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags;
            flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
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
            Byte[] CKA_ENCRYPT = new Byte[1];
            CKA_ENCRYPT[0] = 1;
            Byte[] CKA_VERIFY = new Byte[1];
            CKA_VERIFY[0] = 1;
            Byte[] modulusbits = BitConverter.GetBytes(2048);
            Tuple<c_ulong, Byte[], c_ulong>[] pTuplePublic =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, (c_ulong)(Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, (c_ulong)(Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length)),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, (c_ulong)(Marshal.SizeOf(modulusbits[0]) * modulusbits.Length))
            };
            c_int publicArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuplePublic);
            IntPtr pPublicKeyTemplate = Marshal.AllocHGlobal(publicArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPublicKeyTemplate, pTuplePublic);
            // ****** Private template ****** //
            Byte[] CKA_DECRYPT = new Byte[1];
            CKA_DECRYPT[0] = 1;
            Byte[] CKA_SIGN = new Byte[1];
            CKA_SIGN[0] = 1;
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("backupKey");
            Tuple<c_ulong, Byte[], c_ulong>[] pTuplePrivate =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, (c_ulong)(Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, (c_ulong)(Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int privateArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuplePrivate);
            IntPtr pPrivateKeyTemplate = Marshal.AllocHGlobal(privateArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPrivateKeyTemplate, pTuplePrivate);
            // **************************** //
            IntPtr phPublicKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            IntPtr phPrivateKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_GenerateKeyPair((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, pPublicKeyTemplate, (c_ulong)pTuplePrivate.Length, pPrivateKeyTemplate, (c_ulong)pTuplePrivate.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pPublicKeyTemplate, pTuplePublic.Length);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pPrivateKeyTemplate, pTuplePrivate.Length);
            Assert.AreEqual(2, PKCS11Utils.ReadLongFromBuffer(phPublicKey, 0));
            Assert.AreEqual(1, PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0));
            IntPtr pulWrappedKeyLen = Marshal.AllocHGlobal(sizeof(c_ulong));
            IntPtr pWrappedKey = IntPtr.Zero;
            pMechanism.mechanism = PKCS11Definitions.CKM_VENDOR_DEFINED;
            result = C_WrapKey((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, 0, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0), pWrappedKey, pulWrappedKeyLen);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pWrappedKey = Marshal.AllocHGlobal((c_int)PKCS11Utils.ReadLongFromBuffer(pulWrappedKeyLen, 0));
            result = C_WrapKey((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, 0, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0), pWrappedKey, pulWrappedKeyLen);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pWrappedKey);
            result = C_DestroyObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pPublicKeyTemplate);
            Marshal.FreeHGlobal(phPublicKey);
            Marshal.FreeHGlobal(phPrivateKey);
            Marshal.FreeHGlobal(pulWrappedKeyLen);
        }

       [TestMethod]
        public unsafe void Test_C_UnWrap_basic()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags;
            flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
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
            Byte[] CKA_ENCRYPT = new Byte[1];
            CKA_ENCRYPT[0] = 1;
            Byte[] CKA_VERIFY = new Byte[1];
            CKA_VERIFY[0] = 1;
            Byte[] modulusbits = BitConverter.GetBytes(2048);
            Tuple<c_ulong, Byte[], c_ulong>[] pTuplePublic =
            {
                Tuple.Create(PKCS11Definitions.CKA_ENCRYPT, CKA_ENCRYPT, (c_ulong)(Marshal.SizeOf(CKA_ENCRYPT[0]) * CKA_ENCRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_VERIFY, CKA_VERIFY, (c_ulong)(Marshal.SizeOf(CKA_VERIFY[0]) * CKA_VERIFY.Length)),
                Tuple.Create(PKCS11Definitions.CKA_MODULUS_BITS, modulusbits, (c_ulong)(Marshal.SizeOf(modulusbits[0]) * modulusbits.Length))
            };
            c_int publicArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuplePublic);
            IntPtr pPublicKeyTemplate = Marshal.AllocHGlobal(publicArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPublicKeyTemplate, pTuplePublic);
            // ****** Private template ****** //
            Byte[] CKA_DECRYPT = new Byte[1];
            CKA_DECRYPT[0] = 1;
            Byte[] CKA_SIGN = new Byte[1];
            CKA_SIGN[0] = 1;
            Byte[] CKA_ID = Encoding.ASCII.GetBytes("backupKey");
            Tuple<c_ulong, Byte[], c_ulong>[] pTuplePrivate =
            {
                Tuple.Create(PKCS11Definitions.CKA_DECRYPT, CKA_DECRYPT, (c_ulong)(Marshal.SizeOf(CKA_DECRYPT[0]) * CKA_DECRYPT.Length)),
                Tuple.Create(PKCS11Definitions.CKA_SIGN, CKA_SIGN, (c_ulong)(Marshal.SizeOf(CKA_SIGN[0]) * CKA_SIGN.Length)),
                Tuple.Create(PKCS11Definitions.CKA_ID, CKA_ID, (c_ulong)(Marshal.SizeOf(CKA_ID[0]) * CKA_ID.Length))
            };
            c_int privateArraySize = PKCS11Utils.GetSizeOfTupleArray(pTuplePrivate);
            IntPtr pPrivateKeyTemplate = Marshal.AllocHGlobal(privateArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pPrivateKeyTemplate, pTuplePrivate);
            // **************************** //
            IntPtr phPublicKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            IntPtr phPrivateKey = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_GenerateKeyPair((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, pPublicKeyTemplate, (c_ulong)pTuplePublic.Length, pPrivateKeyTemplate, (c_ulong)pTuplePrivate.Length, phPublicKey, phPrivateKey);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pPublicKeyTemplate, pTuplePublic.Length);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pPrivateKeyTemplate, pTuplePublic.Length);
            Assert.AreEqual(2, PKCS11Utils.ReadLongFromBuffer(phPublicKey, 0));
            Assert.AreEqual(1, PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0));
            IntPtr pulWrappedKeyLen = Marshal.AllocHGlobal(sizeof(c_ulong));
            PKCS11Utils.WriteIntInBuffer(pulWrappedKeyLen, 1, 0);
            IntPtr pWrappedKey = IntPtr.Zero;
            pMechanism.mechanism = PKCS11Definitions.CKM_VENDOR_DEFINED;
            result = C_WrapKey((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, 0, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0), pWrappedKey, pulWrappedKeyLen);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pWrappedKey = Marshal.AllocHGlobal(*(int*)pulWrappedKeyLen);
            result = C_WrapKey((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, 0, (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0), pWrappedKey, pulWrappedKeyLen);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phPrivateKey, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr hKey2 = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_UnwrapKey((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), ref pMechanism, 0, pWrappedKey, (c_ulong)PKCS11Utils.ReadLongFromBuffer(pulWrappedKeyLen, 0), IntPtr.Zero, 0, hKey2);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(hKey2, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Marshal.FreeHGlobal(pWrappedKey);
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pPublicKeyTemplate);
            Marshal.FreeHGlobal(pPrivateKeyTemplate );
            Marshal.FreeHGlobal(phPublicKey);
            Marshal.FreeHGlobal(phPrivateKey);
            Marshal.FreeHGlobal(pulWrappedKeyLen);
            Marshal.FreeHGlobal(hKey2);
        }

       [TestMethod]
        public unsafe void Test_C_FindObject_By_Subject()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_TOKEN = new Byte[1];
            CKA_TOKEN[0] = 1;
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_CERTIFICATE);
            string subject = "308197310b30090603550406130245533110300e06035504080c0747616c696369613111300f060355040a0c084772616469616e7431153013060355040b0c0c4772642053656375726974793126302406035504030c1d496e7465726d656469617465204341206a6a696d656e657a20746573743124302206092a864886f70d01090116156a6a696d656e657a406772616469616e742e6f7267";
            Byte[] CKA_SUBJECT = Enumerable.Range(0, subject.Length / 2).Select(x => Convert.ToByte(subject.Substring(x * 2, 2), 16)).ToArray();
            Tuple<c_ulong, Byte[], c_ulong>[] pPublicTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_TOKEN, CKA_TOKEN, (c_ulong)(Marshal.SizeOf(CKA_TOKEN[0]) * CKA_TOKEN.Length)),
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_SUBJECT, CKA_SUBJECT, (c_ulong)(Marshal.SizeOf(CKA_SUBJECT[0]) * CKA_SUBJECT.Length))
            };
            c_int publicTupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pPublicTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(publicTupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pPublicTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pPublicTuple.Length);
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong) * 5);
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            for (c_long i = 0; i < 5; i++)
            {
                result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), IntPtr.Add(phObjects, (c_int)(sizeof(c_ulong) * i)), 1, pulcObjectCount);
                Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
                if ((c_ulong)PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0) == 0) break;
            }
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }

        [TestMethod]
        public unsafe void Test_C_FindObject_By_PublicExponet()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_PRIVATE_KEY);
            Byte[] CKA_PUBLIC_EXPONENT = BitConverter.GetBytes(65537);
            Tuple<c_ulong, Byte[], c_ulong>[] pPublicTuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_PUBLIC_EXPONENT, CKA_PUBLIC_EXPONENT, (c_ulong)(Marshal.SizeOf(CKA_PUBLIC_EXPONENT[0]) * CKA_PUBLIC_EXPONENT.Length))
            };
            c_int publicTupleArraySize = PKCS11Utils.GetSizeOfTupleArray(pPublicTuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(publicTupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, pPublicTuple);
            //*******************//
            //** C_FindObject **//
            result = C_FindObjectsInit((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)pPublicTuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, pPublicTuple.Length);
            IntPtr phObjects = Marshal.AllocHGlobal(sizeof(c_ulong));
            IntPtr pulcObjectCount = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_FindObjects((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), phObjects, 1, pulcObjectCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Assert.AreNotEqual((c_long)0, PKCS11Utils.ReadLongFromBuffer(pulcObjectCount, 0));
            result = C_FindObjectsFinal((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Logout((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObjects);
            Marshal.FreeHGlobal(pulcObjectCount);
        }


        [TestMethod]
        public unsafe void Test_C_CreateObject_Secret_Basic_And_Destroy()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_DATA);
            Byte[] CKA_VALUE = Encoding.ASCII.GetBytes("Secret muy secreto");
            Byte[] CKA_OBJECT_ID = Encoding.ASCII.GetBytes("secretoTest1");
            Tuple<c_ulong, Byte[], c_ulong>[] tuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_VALUE, CKA_VALUE, (c_ulong)(Marshal.SizeOf(CKA_VALUE[0]) * CKA_VALUE.Length)),
                Tuple.Create(PKCS11Definitions.CKA_OBJECT_ID, CKA_OBJECT_ID, (c_ulong)(Marshal.SizeOf(CKA_OBJECT_ID[0]) * CKA_OBJECT_ID.Length))
            };
            c_int tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(tuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(tupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, tuple);
            //*******************//
            IntPtr phObject = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_CreateObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)tuple.Length, phObject);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, tuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_DestroyObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObject);
        }

        [TestMethod]
        public unsafe void Test_C_CreateObject_Secret_Complete_And_Destroy()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_DATA);
            Byte[] CKA_VALUE = Encoding.ASCII.GetBytes("Secret muy secreto");
            Byte[] CKA_OBJECT_ID = Encoding.ASCII.GetBytes("secretoTest1");
            Byte[] CKA_APPLICATION = Encoding.ASCII.GetBytes("Esto es un secreto de prueba");
            Tuple<c_ulong, Byte[], c_ulong>[] tuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_VALUE, CKA_VALUE, (c_ulong)(Marshal.SizeOf(CKA_VALUE[0]) * CKA_VALUE.Length)),
                Tuple.Create(PKCS11Definitions.CKA_OBJECT_ID, CKA_OBJECT_ID, (c_ulong)(Marshal.SizeOf(CKA_OBJECT_ID[0]) * CKA_OBJECT_ID.Length)),
                Tuple.Create(PKCS11Definitions.CKA_APPLICATION, CKA_APPLICATION, (c_ulong)(Marshal.SizeOf(CKA_APPLICATION[0]) * CKA_APPLICATION.Length))
            };
            c_int tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(tuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(tupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, tuple);
            //*******************//
            IntPtr phObject = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_CreateObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)tuple.Length, phObject);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, tuple.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            //**** Template *****//
            c_ulong ulCount = 1;
            CK_ATTRIBUTE pTemplateG = new CK_ATTRIBUTE
            {
                type = PKCS11Definitions.CKA_OBJECT_ID,
                pValue = IntPtr.Zero,
                ulValueLen = 0
            };
            /************************/
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Byte[] managedArray = new Byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, (c_int)pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_OBJECT_ID.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue); //free before reallocating
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_VALUE;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new Byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, (c_int)pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_VALUE.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue); //free before reallocating
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_APPLICATION;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new Byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, (c_int)pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_APPLICATION.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue);
            result = C_DestroyObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(pTemplate);
            Marshal.FreeHGlobal(phObject);
        }

        [TestMethod]
        public unsafe void Test_C_Create_Update_Secret_Complete_And_Destroy()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            // ****** Public template ****** //
            Byte[] CKA_CLASS = BitConverter.GetBytes(PKCS11Definitions.CKO_DATA);
            Byte[] CKA_VALUE = Encoding.ASCII.GetBytes("Secret muy secreto");
            Byte[] CKA_OBJECT_ID = Encoding.ASCII.GetBytes("secretoTest1");
            Byte[] CKA_APPLICATION = Encoding.ASCII.GetBytes("Esto es un secreto de prueba");
            Tuple<c_ulong, Byte[], c_ulong>[] tuple =
            {
                Tuple.Create(PKCS11Definitions.CKA_CLASS, CKA_CLASS, (c_ulong)(Marshal.SizeOf(CKA_CLASS[0]) * CKA_CLASS.Length)),
                Tuple.Create(PKCS11Definitions.CKA_VALUE, CKA_VALUE, (c_ulong)(Marshal.SizeOf(CKA_VALUE[0]) * CKA_VALUE.Length)),
                Tuple.Create(PKCS11Definitions.CKA_OBJECT_ID, CKA_OBJECT_ID, (c_ulong)(Marshal.SizeOf(CKA_OBJECT_ID[0]) * CKA_OBJECT_ID.Length)),
                Tuple.Create(PKCS11Definitions.CKA_APPLICATION, CKA_APPLICATION, (c_ulong)(Marshal.SizeOf(CKA_APPLICATION[0]) * CKA_APPLICATION.Length))
            };
            c_int tupleArraySize = PKCS11Utils.GetSizeOfTupleArray(tuple);
            IntPtr pTemplate = Marshal.AllocHGlobal(tupleArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pTemplate, tuple);
            //*******************//
            IntPtr phObject = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_CreateObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), pTemplate, (c_ulong)tuple.Length, phObject);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pTemplate, tuple.Length);
            Marshal.FreeHGlobal(pTemplate);
            //**** Template *****//
            c_ulong ulCount = 1;
            CK_ATTRIBUTE pTemplateG = new CK_ATTRIBUTE
            {
                type = PKCS11Definitions.CKA_OBJECT_ID,
                pValue = IntPtr.Zero,
                ulValueLen = 0
            };
            /************************/
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            IntPtr pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            Byte[] managedArray = new Byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, (c_int)pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_OBJECT_ID.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue); //free before reallocating
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_VALUE;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new Byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, (c_int)pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_VALUE.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue); //free before reallocating
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_APPLICATION;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new Byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, (c_int)pTemplateG.ulValueLen);
            Assert.AreEqual(true, CKA_APPLICATION.SequenceEqual(managedArray));
            //**** Template SetAttribute *****//
            Byte[] NEW_CKA_APPLICATION = Encoding.ASCII.GetBytes("Sigue siendo un Secreto...");
            Tuple<c_ulong, Byte[], c_ulong>[] pTupleSet =
            {
                Tuple.Create(PKCS11Definitions.CKA_APPLICATION, NEW_CKA_APPLICATION, (c_ulong)(Marshal.SizeOf(NEW_CKA_APPLICATION[0]) * NEW_CKA_APPLICATION.Length))
            };
            c_int setArraySize = PKCS11Utils.GetSizeOfTupleArray(pTupleSet);
            IntPtr pSetTemplate = Marshal.AllocHGlobal(setArraySize);

            PKCS11Utils.InsertAttributesIntPtr(pSetTemplate, pTupleSet);

            result = C_SetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), pSetTemplate, (c_ulong)pTupleSet.Length);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            PKCS11Utils.FreeTemplateAttributesIntPtr(pSetTemplate, pTupleSet.Length);
            Marshal.FreeHGlobal(pValue); //free before reallocating
            pTemplateG.ulValueLen = 0;
            pTemplateG.pValue = IntPtr.Zero;
            pTemplateG.type = PKCS11Definitions.CKA_APPLICATION;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            pValue = Marshal.AllocHGlobal((c_int)pTemplateG.ulValueLen);
            pTemplateG.pValue = pValue;
            result = C_GetAttributeValue((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0), &pTemplateG, ulCount);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            managedArray = new Byte[pTemplateG.ulValueLen];
            Marshal.Copy(pTemplateG.pValue, managedArray, 0, (c_int)pTemplateG.ulValueLen);
            Assert.AreEqual(true, NEW_CKA_APPLICATION.SequenceEqual(managedArray));
            Marshal.FreeHGlobal(pValue);
            result = C_DestroyObject((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0), (c_ulong)PKCS11Utils.ReadLongFromBuffer(phObject, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_CloseSession((c_ulong)PKCS11Utils.ReadLongFromBuffer(phSession, 0));
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);

            Marshal.FreeHGlobal(phSession);
            Marshal.FreeHGlobal(phObject);
            Marshal.FreeHGlobal(pSetTemplate);
        }

        [TestMethod]
        public void Test_C_SetPIN_Test()
        {
            c_ulong result = C_Initialize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            c_ulong slotID = 1;
            c_ulong flags = (PKCS11Definitions.CKF_RW_SESSION | PKCS11Definitions.CKF_SERIAL_SESSION);
            IntPtr pApplication = IntPtr.Zero;
            IntPtr Notify = IntPtr.Zero;
            IntPtr phSession = Marshal.AllocHGlobal(sizeof(c_ulong));
            result = C_OpenSession(slotID, flags, pApplication, Notify, phSession);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Login(1, PKCS11Definitions.CKU_USER, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_SetPIN((c_ulong)1, "1234", 4, "1234", 4);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
            result = C_Finalize(IntPtr.Zero);
            Assert.AreEqual(PKCS11Definitions.CKR_OK, result);
        }
    }
}
