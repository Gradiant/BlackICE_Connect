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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

/* DO NOT MODIFY this without tweaking compilation.sh */
using c_ulong = System.UInt32;
using c_long = System.Int32;
using c_uint = System.UInt32;
using c_int = System.Int32;

namespace akv_pkcs11.Test
{
    public class PKCS11Definitions
    {
        public const c_ulong CKR_OK = 0x00000000;
        public const c_ulong CKR_CANCEL = 0x00000001;
        public const c_ulong CKR_HOST_MEMORY = 0x00000002;
        public const c_ulong CKR_SLOT_ID_INVALID = 0x00000003;

        /* CKR_FLAGS_INVALID was removed for v2.0 */

        /* CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED are new for v2.0 */
        public const c_ulong CKR_GENERAL_ERROR = 0x00000005;
        public const c_ulong CKR_FUNCTION_FAILED = 0x00000006;

        /* CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS,
         * and CKR_CANT_LOCK are new for v2.01 */
        public const c_ulong CKR_ARGUMENTS_BAD = 0x00000007;
        public const c_ulong CKR_NO_EVENT = 0x00000008;
        public const c_ulong CKR_NEED_TO_CREATE_THREADS = 0x00000009;
        public const c_ulong CKR_CANT_LOCK = 0x0000000A;

        public const c_ulong CKR_ATTRIBUTE_READ_ONLY = 0x00000010;
        public const c_ulong CKR_ATTRIBUTE_SENSITIVE = 0x00000011;
        public const c_ulong CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012;
        public const c_ulong CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013;
        public const c_ulong CKR_DATA_INVALID = 0x00000020;
        public const c_ulong CKR_DATA_LEN_RANGE = 0x00000021;
        public const c_ulong CKR_DEVICE_ERROR = 0x00000030;
        public const c_ulong CKR_DEVICE_MEMORY = 0x00000031;
        public const c_ulong CKR_DEVICE_REMOVED = 0x00000032;
        public const c_ulong CKR_ENCRYPTED_DATA_INVALID = 0x00000040;
        public const c_ulong CKR_ENCRYPTED_DATA_LEN_RANGE = 0x00000041;
        public const c_ulong CKR_FUNCTION_CANCELED = 0x00000050;
        public const c_ulong CKR_FUNCTION_NOT_PARALLEL = 0x00000051;

        /* CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
        public const c_ulong CKR_FUNCTION_NOT_SUPPORTED = 0x00000054;

        public const c_ulong CKR_KEY_HANDLE_INVALID = 0x00000060;

        /* CKR_KEY_SENSITIVE was removed for v2.0 */

        public const c_ulong CKR_KEY_SIZE_RANGE = 0x00000062;
        public const c_ulong CKR_KEY_TYPE_INCONSISTENT = 0x00000063;

        /* CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED, CKR_KEY_NEEDED,
         * CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED,
         * CKR_KEY_NOT_WRAPPABLE, and CKR_KEY_UNEXTRACTABLE are new for
         * v2.0 */
        public const c_ulong CKR_KEY_NOT_NEEDED = 0x00000064;
        public const c_ulong CKR_KEY_CHANGED = 0x00000065;
        public const c_ulong CKR_KEY_NEEDED = 0x00000066;
        public const c_ulong CKR_KEY_INDIGESTIBLE = 0x00000067;
        public const c_ulong CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068;
        public const c_ulong CKR_KEY_NOT_WRAPPABLE = 0x00000069;
        public const c_ulong CKR_KEY_UNEXTRACTABLE = 0x0000006A;

        public const c_ulong CKR_MECHANISM_INVALID = 0x00000070;
        public const c_ulong CKR_MECHANISM_PARAM_INVALID = 0x00000071;

        /* CKR_OBJECT_CLASS_INCONSISTENT and CKR_OBJECT_CLASS_INVALID
         * were removed for v2.0 */
        public const c_ulong CKR_OBJECT_HANDLE_INVALID = 0x00000082;
        public const c_ulong CKR_OPERATION_ACTIVE = 0x00000090;
        public const c_ulong CKR_OPERATION_NOT_INITIALIZED = 0x00000091;
        public const c_ulong CKR_PIN_INCORRECT = 0x000000A0;
        public const c_ulong CKR_PIN_INVALID = 0x000000A1;
        public const c_ulong CKR_PIN_LEN_RANGE = 0x000000A2;

        /* CKR_PIN_EXPIRED and CKR_PIN_LOCKED are new for v2.0 */
        public const c_ulong CKR_PIN_EXPIRED = 0x000000A3;
        public const c_ulong CKR_PIN_LOCKED = 0x000000A4;

        public const c_ulong CKR_SESSION_CLOSED = 0x000000B0;
        public const c_ulong CKR_SESSION_COUNT = 0x000000B1;
        public const c_ulong CKR_SESSION_HANDLE_INVALID = 0x000000B3;
        public const c_ulong CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4;
        public const c_ulong CKR_SESSION_READ_ONLY = 0x000000B5;
        public const c_ulong CKR_SESSION_EXISTS = 0x000000B6;

        /* CKR_SESSION_READ_ONLY_EXISTS and
         * CKR_SESSION_READ_WRITE_SO_EXISTS are new for v2.0 */
        public const c_ulong CKR_SESSION_READ_ONLY_EXISTS = 0x000000B7;
        public const c_ulong CKR_SESSION_READ_WRITE_SO_EXISTS = 0x000000B8;

        public const c_ulong CKR_SIGNATURE_INVALID = 0x000000C0;
        public const c_ulong CKR_SIGNATURE_LEN_RANGE = 0x000000C1;
        public const c_ulong CKR_TEMPLATE_INCOMPLETE = 0x000000D0;
        public const c_ulong CKR_TEMPLATE_INCONSISTENT = 0x000000D1;
        public const c_ulong CKR_TOKEN_NOT_PRESENT = 0x000000E0;
        public const c_ulong CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1;
        public const c_ulong CKR_TOKEN_WRITE_PROTECTED = 0x000000E2;
        public const c_ulong CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0x000000F0;
        public const c_ulong CKR_UNWRAPPING_KEY_SIZE_RANGE = 0x000000F1;
        public const c_ulong CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2;
        public const c_ulong CKR_USER_ALREADY_LOGGED_IN = 0x00000100;
        public const c_ulong CKR_USER_NOT_LOGGED_IN = 0x00000101;
        public const c_ulong CKR_USER_PIN_NOT_INITIALIZED = 0x00000102;
        public const c_ulong CKR_USER_TYPE_INVALID = 0x00000103;

        /* CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES
         * are new to v2.01 */
        public const c_ulong CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104;
        public const c_ulong CKR_USER_TOO_MANY_TYPES = 0x00000105;

        public const c_ulong CKR_WRAPPED_KEY_INVALID = 0x00000110;
        public const c_ulong CKR_WRAPPED_KEY_LEN_RANGE = 0x00000112;
        public const c_ulong CKR_WRAPPING_KEY_HANDLE_INVALID = 0x00000113;
        public const c_ulong CKR_WRAPPING_KEY_SIZE_RANGE = 0x00000114;
        public const c_ulong CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115;
        public const c_ulong CKR_RANDOM_SEED_NOT_SUPPORTED = 0x00000120;

        /* These are new to v2.0 */
        public const c_ulong CKR_RANDOM_NO_RNG = 0x00000121;

        /* These are new to v2.11 */
        public const c_ulong CKR_DOMAIN_PARAMS_INVALID = 0x00000130;

        /* These are new to v2.0 */
        public const c_ulong CKR_BUFFER_TOO_SMALL = 0x00000150;
        public const c_ulong CKR_SAVED_STATE_INVALID = 0x00000160;
        public const c_ulong CKR_INFORMATION_SENSITIVE = 0x00000170;
        public const c_ulong CKR_STATE_UNSAVEABLE = 0x00000180;

        /* These are new to v2.01 */
        public const c_ulong CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190;
        public const c_ulong CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191;
        public const c_ulong CKR_MUTEX_BAD = 0x000001A0;
        public const c_ulong CKR_MUTEX_NOT_LOCKED = 0x000001A1;

        /* The following return values are new for PKCS #11 v2.20 amendment 3 */
        public const c_ulong CKR_NEW_PIN_MODE = 0x000001B0;
        public const c_ulong CKR_NEXT_OTP = 0x000001B1;

        /* This is new to v2.20 */
        public const c_ulong CKR_FUNCTION_REJECTED = 0x00000200;

        public const c_ulong CKR_VENDOR_DEFINED = 0x80000000;


        /* The flags are defined as follows:
 *      Bit Flag               Mask        Meaning */
        public const c_ulong CKF_HW = 0x00000001;  /* performed by HW */

        /* The flags parameter is defined as follows:
 *      Bit Flag                    Mask        Meaning
 */
        public const c_ulong CKF_RNG = 0x00000001;  /* has random #
                                                 * generator*/
        public const c_ulong CKF_WRITE_PROTECTED = 0x00000002;  /* token is
                                                 * write-
                                                 * protected */
        public const c_ulong CKF_LOGIN_REQUIRED = 0x00000004;  /* user must
                                                 * login*/
        public const c_ulong CKF_USER_PIN_INITIALIZED = 0x00000008;  /* normal user's
                                                 * PIN is set*/
        /* CKF_RESTORE_KEY_NOT_NEEDED is new for v2.0.  If it is set,
         * that means that *every* time the state of cryptographic
         * operations of a session is successfully saved, all keys
         * needed to continue those operations are stored in the state */
        public const c_ulong CKF_RESTORE_KEY_NOT_NEEDED = 0x00000020;

        /* CKF_CLOCK_ON_TOKEN is new for v2.0.  If it is set, that means
         * that the token has some sort of clock.  The time on that
         * clock is returned in the token info structure */
        public const c_ulong CKF_CLOCK_ON_TOKEN = 0x00000040;

        /* CKF_PROTECTED_AUTHENTICATION_PATH is new for v2.0.  If it is
         * set, that means that there is some way for the user to login
         * without sending a PIN through the Cryptoki library itself */
        public const c_ulong CKF_PROTECTED_AUTHENTICATION_PATH = 0x00000100;

        /* CKF_DUAL_CRYPTO_OPERATIONS is new for v2.0.  If it is true,
         * that means that a single session with the token can perform
         * dual simultaneous cryptographic operations (digest and
         * encrypt; decrypt and digest; sign and encrypt; and decrypt
         * and sign) */
        public const c_ulong CKF_DUAL_CRYPTO_OPERATIONS = 0x00000200;

        /* CKF_TOKEN_INITIALIZED if new for v2.10. If it is true, the
         * token has been initialized using C_InitializeToken or an
         * equivalent mechanism outside the scope of PKCS #11.
         * Calling C_InitializeToken when this flag is set will cause
         * the token to be reinitialized. */
        public const c_ulong CKF_TOKEN_INITIALIZED = 0x00000400;

        /* CKF_SECONDARY_AUTHENTICATION if new for v2.10. If it is
         * true, the token supports secondary authentication for
         * private key objects. This flag is deprecated in v2.11 and
           onwards. */
        public const c_ulong CKF_SECONDARY_AUTHENTICATION = 0x00000800;

        /* CKF_USER_PIN_COUNT_LOW if new for v2.10. If it is true, an
         * incorrect user login PIN has been entered at least once
         * since the last successful authentication. */
        public const c_ulong CKF_USER_PIN_COUNT_LOW = 0x00010000;

        /* CKF_USER_PIN_FINAL_TRY if new for v2.10. If it is true,
         * supplying an incorrect user PIN will it to become locked. */
        public const c_ulong CKF_USER_PIN_FINAL_TRY = 0x00020000;

        /* CKF_USER_PIN_LOCKED if new for v2.10. If it is true, the
         * user PIN has been locked. User login to the token is not
         * possible. */
        public const c_ulong CKF_USER_PIN_LOCKED = 0x00040000;

        /* CKF_USER_PIN_TO_BE_CHANGED if new for v2.10. If it is true,
         * the user PIN value is the default value set by token
         * initialization or manufacturing, or the PIN has been
         * expired by the card. */
        public const c_ulong CKF_USER_PIN_TO_BE_CHANGED = 0x00080000;

        /* CKF_SO_PIN_COUNT_LOW if new for v2.10. If it is true, an
         * incorrect SO login PIN has been entered at least once since
         * the last successful authentication. */
        public const c_ulong CKF_SO_PIN_COUNT_LOW = 0x00100000;

        /* CKF_SO_PIN_FINAL_TRY if new for v2.10. If it is true,
         * supplying an incorrect SO PIN will it to become locked. */
        public const c_ulong CKF_SO_PIN_FINAL_TRY = 0x00200000;

        /* CKF_SO_PIN_LOCKED if new for v2.10. If it is true, the SO
         * PIN has been locked. SO login to the token is not possible.
         */
        public const c_ulong CKF_SO_PIN_LOCKED = 0x00400000;

        /* CKF_SO_PIN_TO_BE_CHANGED if new for v2.10. If it is true,
         * the SO PIN value is the default value set by token
         * initialization or manufacturing, or the PIN has been
         * expired by the card. */
        public const c_ulong CKF_SO_PIN_TO_BE_CHANGED = 0x00800000;

        /* some special values for certain CK_ULONG variables */
        public const c_ulong CK_UNAVAILABLE_INFORMATION = ~(c_ulong)0;
        public const c_ulong CK_EFFECTIVELY_INFINITE = 0;

        /* CK_MECHANISM_TYPE is a value that identifies a mechanism
 * type */

        /* the following mechanism types are defined: */
        public const c_ulong CKM_RSA_PKCS_KEY_PAIR_GEN = 0x00000000;
        public const c_ulong CKM_RSA_PKCS = 0x00000001;
        public const c_ulong CKM_RSA_9796 = 0x00000002;
        public const c_ulong CKM_RSA_X_509 = 0x00000003;

        /* CKM_MD2_RSA_PKCS, CKM_MD5_RSA_PKCS, and CKM_SHA1_RSA_PKCS
         * are new for v2.0.  They are mechanisms which hash and sign */
        public const c_ulong CKM_MD2_RSA_PKCS = 0x00000004;
        public const c_ulong CKM_MD5_RSA_PKCS = 0x00000005;
        public const c_ulong CKM_SHA1_RSA_PKCS = 0x00000006;

        /* CKM_RIPEMD128_RSA_PKCS, CKM_RIPEMD160_RSA_PKCS, and
         * CKM_RSA_PKCS_OAEP are new for v2.10 */
        public const c_ulong CKM_RIPEMD128_RSA_PKCS = 0x00000007;
        public const c_ulong CKM_RIPEMD160_RSA_PKCS = 0x00000008;
        public const c_ulong CKM_RSA_PKCS_OAEP = 0x00000009;

        /* CKM_RSA_X9_31_KEY_PAIR_GEN, CKM_RSA_X9_31, CKM_SHA1_RSA_X9_31,
         * CKM_RSA_PKCS_PSS, and CKM_SHA1_RSA_PKCS_PSS are new for v2.11 */
        public const c_ulong CKM_RSA_X9_31_KEY_PAIR_GEN = 0x0000000A;
        public const c_ulong CKM_RSA_X9_31 = 0x0000000B;
        public const c_ulong CKM_SHA1_RSA_X9_31 = 0x0000000C;
        public const c_ulong CKM_RSA_PKCS_PSS = 0x0000000D;
        public const c_ulong CKM_SHA1_RSA_PKCS_PSS = 0x0000000E;

        public const c_ulong CKM_DSA_KEY_PAIR_GEN = 0x00000010;
        public const c_ulong CKM_DSA = 0x00000011;
        public const c_ulong CKM_DSA_SHA1 = 0x00000012;
        public const c_ulong CKM_DH_PKCS_KEY_PAIR_GEN = 0x00000020;
        public const c_ulong CKM_DH_PKCS_DERIVE = 0x00000021;

        /* CKM_X9_42_DH_KEY_PAIR_GEN, CKM_X9_42_DH_DERIVE,
         * CKM_X9_42_DH_HYBRID_DERIVE, and CKM_X9_42_MQV_DERIVE are new for
         * v2.11 */
        public const c_ulong CKM_X9_42_DH_KEY_PAIR_GEN = 0x00000030;
        public const c_ulong CKM_X9_42_DH_DERIVE = 0x00000031;
        public const c_ulong CKM_X9_42_DH_HYBRID_DERIVE = 0x00000032;
        public const c_ulong CKM_X9_42_MQV_DERIVE = 0x00000033;

        /* CKM_SHA256/384/512 are new for v2.20 */
        public const c_ulong CKM_SHA256_RSA_PKCS = 0x00000040;
        public const c_ulong CKM_SHA384_RSA_PKCS = 0x00000041;
        public const c_ulong CKM_SHA512_RSA_PKCS = 0x00000042;
        public const c_ulong CKM_SHA256_RSA_PKCS_PSS = 0x00000043;
        public const c_ulong CKM_SHA384_RSA_PKCS_PSS = 0x00000044;
        public const c_ulong CKM_SHA512_RSA_PKCS_PSS = 0x00000045;

        /* SHA-224 RSA mechanisms are new for PKCS #11 v2.20 amendment 3 */
        public const c_ulong CKM_SHA224_RSA_PKCS = 0x00000046;
        public const c_ulong CKM_SHA224_RSA_PKCS_PSS = 0x00000047;

        public const c_ulong CKM_RC2_KEY_GEN = 0x00000100;
        public const c_ulong CKM_RC2_ECB = 0x00000101;
        public const c_ulong CKM_RC2_CBC = 0x00000102;
        public const c_ulong CKM_RC2_MAC = 0x00000103;

        /* CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0 */
        public const c_ulong CKM_RC2_MAC_GENERAL = 0x00000104;
        public const c_ulong CKM_RC2_CBC_PAD = 0x00000105;

        public const c_ulong CKM_RC4_KEY_GEN = 0x00000110;
        public const c_ulong CKM_RC4 = 0x00000111;
        public const c_ulong CKM_DES_KEY_GEN = 0x00000120;
        public const c_ulong CKM_DES_ECB = 0x00000121;
        public const c_ulong CKM_DES_CBC = 0x00000122;
        public const c_ulong CKM_DES_MAC = 0x00000123;

        /* CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0 */
        public const c_ulong CKM_DES_MAC_GENERAL = 0x00000124;
        public const c_ulong CKM_DES_CBC_PAD = 0x00000125;

        public const c_ulong CKM_DES2_KEY_GEN = 0x00000130;
        public const c_ulong CKM_DES3_KEY_GEN = 0x00000131;
        public const c_ulong CKM_DES3_ECB = 0x00000132;
        public const c_ulong CKM_DES3_CBC = 0x00000133;
        public const c_ulong CKM_DES3_MAC = 0x00000134;

        /* CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN,
         * CKM_CDMF_ECB, CKM_CDMF_CBC, CKM_CDMF_MAC,
         * CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0 */
        public const c_ulong CKM_DES3_MAC_GENERAL = 0x00000135;
        public const c_ulong CKM_DES3_CBC_PAD = 0x00000136;
        public const c_ulong CKM_CDMF_KEY_GEN = 0x00000140;
        public const c_ulong CKM_CDMF_ECB = 0x00000141;
        public const c_ulong CKM_CDMF_CBC = 0x00000142;
        public const c_ulong CKM_CDMF_MAC = 0x00000143;
        public const c_ulong CKM_CDMF_MAC_GENERAL = 0x00000144;
        public const c_ulong CKM_CDMF_CBC_PAD = 0x00000145;

        /* the following four DES mechanisms are new for v2.20 */
        public const c_ulong CKM_DES_OFB64 = 0x00000150;
        public const c_ulong CKM_DES_OFB8 = 0x00000151;
        public const c_ulong CKM_DES_CFB64 = 0x00000152;
        public const c_ulong CKM_DES_CFB8 = 0x00000153;

        public const c_ulong CKM_MD2 = 0x00000200;

        /* CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0 */
        public const c_ulong CKM_MD2_HMAC = 0x00000201;
        public const c_ulong CKM_MD2_HMAC_GENERAL = 0x00000202;

        public const c_ulong CKM_MD5 = 0x00000210;

        /* CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0 */
        public const c_ulong CKM_MD5_HMAC = 0x00000211;
        public const c_ulong CKM_MD5_HMAC_GENERAL = 0x00000212;

        public const c_ulong CKM_SHA_1 = 0x00000220;

        /* CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0 */
        public const c_ulong CKM_SHA_1_HMAC = 0x00000221;
        public const c_ulong CKM_SHA_1_HMAC_GENERAL = 0x00000222;

        /* CKM_RIPEMD128, CKM_RIPEMD128_HMAC,
         * CKM_RIPEMD128_HMAC_GENERAL, CKM_RIPEMD160, CKM_RIPEMD160_HMAC,
         * and CKM_RIPEMD160_HMAC_GENERAL are new for v2.10 */
        public const c_ulong CKM_RIPEMD128 = 0x00000230;
        public const c_ulong CKM_RIPEMD128_HMAC = 0x00000231;
        public const c_ulong CKM_RIPEMD128_HMAC_GENERAL = 0x00000232;
        public const c_ulong CKM_RIPEMD160 = 0x00000240;
        public const c_ulong CKM_RIPEMD160_HMAC = 0x00000241;
        public const c_ulong CKM_RIPEMD160_HMAC_GENERAL = 0x00000242;

        /* CKM_SHA256/384/512 are new for v2.20 */
        public const c_ulong CKM_SHA256 = 0x00000250;
        public const c_ulong CKM_SHA256_HMAC = 0x00000251;
        public const c_ulong CKM_SHA256_HMAC_GENERAL = 0x00000252;

        /* SHA-224 is new for PKCS #11 v2.20 amendment 3 */
        public const c_ulong CKM_SHA224 = 0x00000255;
        public const c_ulong CKM_SHA224_HMAC = 0x00000256;
        public const c_ulong CKM_SHA224_HMAC_GENERAL = 0x00000257;

        public const c_ulong CKM_SHA384 = 0x00000260;
        public const c_ulong CKM_SHA384_HMAC = 0x00000261;
        public const c_ulong CKM_SHA384_HMAC_GENERAL = 0x00000262;
        public const c_ulong CKM_SHA512 = 0x00000270;
        public const c_ulong CKM_SHA512_HMAC = 0x00000271;
        public const c_ulong CKM_SHA512_HMAC_GENERAL = 0x00000272;

        /* SecurID is new for PKCS #11 v2.20 amendment 1 */
        public const c_ulong CKM_SECURID_KEY_GEN = 0x00000280;
        public const c_ulong CKM_SECURID = 0x00000282;

        /* HOTP is new for PKCS #11 v2.20 amendment 1 */
        public const c_ulong CKM_HOTP_KEY_GEN = 0x00000290;
        public const c_ulong CKM_HOTP = 0x00000291;

        /* ACTI is new for PKCS #11 v2.20 amendment 1 */
        public const c_ulong CKM_ACTI = 0x000002A0;
        public const c_ulong CKM_ACTI_KEY_GEN = 0x000002A1;

        /* All of the following mechanisms are new for v2.0 */
        /* Note that CAST128 and CAST5 are the same algorithm */
        public const c_ulong CKM_CAST_KEY_GEN = 0x00000300;
        public const c_ulong CKM_CAST_ECB = 0x00000301;
        public const c_ulong CKM_CAST_CBC = 0x00000302;
        public const c_ulong CKM_CAST_MAC = 0x00000303;
        public const c_ulong CKM_CAST_MAC_GENERAL = 0x00000304;
        public const c_ulong CKM_CAST_CBC_PAD = 0x00000305;
        public const c_ulong CKM_CAST3_KEY_GEN = 0x00000310;
        public const c_ulong CKM_CAST3_ECB = 0x00000311;
        public const c_ulong CKM_CAST3_CBC = 0x00000312;
        public const c_ulong CKM_CAST3_MAC = 0x00000313;
        public const c_ulong CKM_CAST3_MAC_GENERAL = 0x00000314;
        public const c_ulong CKM_CAST3_CBC_PAD = 0x00000315;
        public const c_ulong CKM_CAST5_KEY_GEN = 0x00000320;
        public const c_ulong CKM_CAST128_KEY_GEN = 0x00000320;
        public const c_ulong CKM_CAST5_ECB = 0x00000321;
        public const c_ulong CKM_CAST128_ECB = 0x00000321;
        public const c_ulong CKM_CAST5_CBC = 0x00000322;
        public const c_ulong CKM_CAST128_CBC = 0x00000322;
        public const c_ulong CKM_CAST5_MAC = 0x00000323;
        public const c_ulong CKM_CAST128_MAC = 0x00000323;
        public const c_ulong CKM_CAST5_MAC_GENERAL = 0x00000324;
        public const c_ulong CKM_CAST128_MAC_GENERAL = 0x00000324;
        public const c_ulong CKM_CAST5_CBC_PAD = 0x00000325;
        public const c_ulong CKM_CAST128_CBC_PAD = 0x00000325;
        public const c_ulong CKM_RC5_KEY_GEN = 0x00000330;
        public const c_ulong CKM_RC5_ECB = 0x00000331;
        public const c_ulong CKM_RC5_CBC = 0x00000332;
        public const c_ulong CKM_RC5_MAC = 0x00000333;
        public const c_ulong CKM_RC5_MAC_GENERAL = 0x00000334;
        public const c_ulong CKM_RC5_CBC_PAD = 0x00000335;
        public const c_ulong CKM_IDEA_KEY_GEN = 0x00000340;
        public const c_ulong CKM_IDEA_ECB = 0x00000341;
        public const c_ulong CKM_IDEA_CBC = 0x00000342;
        public const c_ulong CKM_IDEA_MAC = 0x00000343;
        public const c_ulong CKM_IDEA_MAC_GENERAL = 0x00000344;
        public const c_ulong CKM_IDEA_CBC_PAD = 0x00000345;
        public const c_ulong CKM_GENERIC_SECRET_KEY_GEN = 0x00000350;
        public const c_ulong CKM_CONCATENATE_BASE_AND_KEY = 0x00000360;
        public const c_ulong CKM_CONCATENATE_BASE_AND_DATA = 0x00000362;
        public const c_ulong CKM_CONCATENATE_DATA_AND_BASE = 0x00000363;
        public const c_ulong CKM_XOR_BASE_AND_DATA = 0x00000364;
        public const c_ulong CKM_EXTRACT_KEY_FROM_KEY = 0x00000365;
        public const c_ulong CKM_SSL3_PRE_MASTER_KEY_GEN = 0x00000370;
        public const c_ulong CKM_SSL3_MASTER_KEY_DERIVE = 0x00000371;
        public const c_ulong CKM_SSL3_KEY_AND_MAC_DERIVE = 0x00000372;

        /* CKM_SSL3_MASTER_KEY_DERIVE_DH, CKM_TLS_PRE_MASTER_KEY_GEN,
         * CKM_TLS_MASTER_KEY_DERIVE, CKM_TLS_KEY_AND_MAC_DERIVE, and
         * CKM_TLS_MASTER_KEY_DERIVE_DH are new for v2.11 */
        public const c_ulong CKM_SSL3_MASTER_KEY_DERIVE_DH = 0x00000373;
        public const c_ulong CKM_TLS_PRE_MASTER_KEY_GEN = 0x00000374;
        public const c_ulong CKM_TLS_MASTER_KEY_DERIVE = 0x00000375;
        public const c_ulong CKM_TLS_KEY_AND_MAC_DERIVE = 0x00000376;
        public const c_ulong CKM_TLS_MASTER_KEY_DERIVE_DH = 0x00000377;

        /* CKM_TLS_PRF is new for v2.20 */
        public const c_ulong CKM_TLS_PRF = 0x00000378;

        public const c_ulong CKM_SSL3_MD5_MAC = 0x00000380;
        public const c_ulong CKM_SSL3_SHA1_MAC = 0x00000381;
        public const c_ulong CKM_MD5_KEY_DERIVATION = 0x00000390;
        public const c_ulong CKM_MD2_KEY_DERIVATION = 0x00000391;
        public const c_ulong CKM_SHA1_KEY_DERIVATION = 0x00000392;

        /* CKM_SHA256/384/512 are new for v2.20 */
        public const c_ulong CKM_SHA256_KEY_DERIVATION = 0x00000393;
        public const c_ulong CKM_SHA384_KEY_DERIVATION = 0x00000394;
        public const c_ulong CKM_SHA512_KEY_DERIVATION = 0x00000395;

        /* SHA-224 key derivation is new for PKCS #11 v2.20 amendment 3 */
        public const c_ulong CKM_SHA224_KEY_DERIVATION = 0x00000396;

        public const c_ulong CKM_PBE_MD2_DES_CBC = 0x000003A0;
        public const c_ulong CKM_PBE_MD5_DES_CBC = 0x000003A1;
        public const c_ulong CKM_PBE_MD5_CAST_CBC = 0x000003A2;
        public const c_ulong CKM_PBE_MD5_CAST3_CBC = 0x000003A3;
        public const c_ulong CKM_PBE_MD5_CAST5_CBC = 0x000003A4;
        public const c_ulong CKM_PBE_MD5_CAST128_CBC = 0x000003A4;
        public const c_ulong CKM_PBE_SHA1_CAST5_CBC = 0x000003A5;
        public const c_ulong CKM_PBE_SHA1_CAST128_CBC = 0x000003A5;
        public const c_ulong CKM_PBE_SHA1_RC4_128 = 0x000003A6;
        public const c_ulong CKM_PBE_SHA1_RC4_40 = 0x000003A7;
        public const c_ulong CKM_PBE_SHA1_DES3_EDE_CBC = 0x000003A8;
        public const c_ulong CKM_PBE_SHA1_DES2_EDE_CBC = 0x000003A9;
        public const c_ulong CKM_PBE_SHA1_RC2_128_CBC = 0x000003AA;
        public const c_ulong CKM_PBE_SHA1_RC2_40_CBC = 0x000003AB;

        /* CKM_PKCS5_PBKD2 is new for v2.10 */
        public const c_ulong CKM_PKCS5_PBKD2 = 0x000003B0;

        public const c_ulong CKM_PBA_SHA1_WITH_SHA1_HMAC = 0x000003C0;

        /* WTLS mechanisms are new for v2.20 */
        public const c_ulong CKM_WTLS_PRE_MASTER_KEY_GEN = 0x000003D0;
        public const c_ulong CKM_WTLS_MASTER_KEY_DERIVE = 0x000003D1;
        public const c_ulong CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC = 0x000003D2;
        public const c_ulong CKM_WTLS_PRF = 0x000003D3;
        public const c_ulong CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE = 0x000003D4;
        public const c_ulong CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE = 0x000003D5;

        public const c_ulong CKM_KEY_WRAP_LYNKS = 0x00000400;
        public const c_ulong CKM_KEY_WRAP_SET_OAEP = 0x00000401;

        /* CKM_CMS_SIG is new for v2.20 */
        public const c_ulong CKM_CMS_SIG = 0x00000500;

        /* CKM_KIP mechanisms are new for PKCS #11 v2.20 amendment 2 */
        public const c_ulong CKM_KIP_DERIVE = 0x00000510;
        public const c_ulong CKM_KIP_WRAP = 0x00000511;
        public const c_ulong CKM_KIP_MAC = 0x00000512;

        /* Camellia is new for PKCS #11 v2.20 amendment 3 */
        public const c_ulong CKM_CAMELLIA_KEY_GEN = 0x00000550;
        public const c_ulong CKM_CAMELLIA_ECB = 0x00000551;
        public const c_ulong CKM_CAMELLIA_CBC = 0x00000552;
        public const c_ulong CKM_CAMELLIA_MAC = 0x00000553;
        public const c_ulong CKM_CAMELLIA_MAC_GENERAL = 0x00000554;
        public const c_ulong CKM_CAMELLIA_CBC_PAD = 0x00000555;
        public const c_ulong CKM_CAMELLIA_ECB_ENCRYPT_DATA = 0x00000556;
        public const c_ulong CKM_CAMELLIA_CBC_ENCRYPT_DATA = 0x00000557;
        public const c_ulong CKM_CAMELLIA_CTR = 0x00000558;

        /* ARIA is new for PKCS #11 v2.20 amendment 3 */
        public const c_ulong CKM_ARIA_KEY_GEN = 0x00000560;
        public const c_ulong CKM_ARIA_ECB = 0x00000561;
        public const c_ulong CKM_ARIA_CBC = 0x00000562;
        public const c_ulong CKM_ARIA_MAC = 0x00000563;
        public const c_ulong CKM_ARIA_MAC_GENERAL = 0x00000564;
        public const c_ulong CKM_ARIA_CBC_PAD = 0x00000565;
        public const c_ulong CKM_ARIA_ECB_ENCRYPT_DATA = 0x00000566;
        public const c_ulong CKM_ARIA_CBC_ENCRYPT_DATA = 0x00000567;

        /* Fortezza mechanisms */
        public const c_ulong CKM_SKIPJACK_KEY_GEN = 0x00001000;
        public const c_ulong CKM_SKIPJACK_ECB64 = 0x00001001;
        public const c_ulong CKM_SKIPJACK_CBC64 = 0x00001002;
        public const c_ulong CKM_SKIPJACK_OFB64 = 0x00001003;
        public const c_ulong CKM_SKIPJACK_CFB64 = 0x00001004;
        public const c_ulong CKM_SKIPJACK_CFB32 = 0x00001005;
        public const c_ulong CKM_SKIPJACK_CFB16 = 0x00001006;
        public const c_ulong CKM_SKIPJACK_CFB8 = 0x00001007;
        public const c_ulong CKM_SKIPJACK_WRAP = 0x00001008;
        public const c_ulong CKM_SKIPJACK_PRIVATE_WRAP = 0x00001009;
        public const c_ulong CKM_SKIPJACK_RELAYX = 0x0000100a;
        public const c_ulong CKM_KEA_KEY_PAIR_GEN = 0x00001010;
        public const c_ulong CKM_KEA_KEY_DERIVE = 0x00001011;
        public const c_ulong CKM_FORTEZZA_TIMESTAMP = 0x00001020;
        public const c_ulong CKM_BATON_KEY_GEN = 0x00001030;
        public const c_ulong CKM_BATON_ECB128 = 0x00001031;
        public const c_ulong CKM_BATON_ECB96 = 0x00001032;
        public const c_ulong CKM_BATON_CBC128 = 0x00001033;
        public const c_ulong CKM_BATON_COUNTER = 0x00001034;
        public const c_ulong CKM_BATON_SHUFFLE = 0x00001035;
        public const c_ulong CKM_BATON_WRAP = 0x00001036;

        /* CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
         * CKM_EC_KEY_PAIR_GEN is preferred */
        public const c_ulong CKM_ECDSA_KEY_PAIR_GEN = 0x00001040;
        public const c_ulong CKM_EC_KEY_PAIR_GEN = 0x00001040;

        public const c_ulong CKM_ECDSA = 0x00001041;
        public const c_ulong CKM_ECDSA_SHA1 = 0x00001042;

        /* CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE, and CKM_ECMQV_DERIVE
         * are new for v2.11 */
        public const c_ulong CKM_ECDH1_DERIVE = 0x00001050;
        public const c_ulong CKM_ECDH1_COFACTOR_DERIVE = 0x00001051;
        public const c_ulong CKM_ECMQV_DERIVE = 0x00001052;

        public const c_ulong CKM_JUNIPER_KEY_GEN = 0x00001060;
        public const c_ulong CKM_JUNIPER_ECB128 = 0x00001061;
        public const c_ulong CKM_JUNIPER_CBC128 = 0x00001062;
        public const c_ulong CKM_JUNIPER_COUNTER = 0x00001063;
        public const c_ulong CKM_JUNIPER_SHUFFLE = 0x00001064;
        public const c_ulong CKM_JUNIPER_WRAP = 0x00001065;
        public const c_ulong CKM_FASTHASH = 0x00001070;

        /* CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_MAC,
         * CKM_AES_MAC_GENERAL, CKM_AES_CBC_PAD, CKM_DSA_PARAMETER_GEN,
         * CKM_DH_PKCS_PARAMETER_GEN, and CKM_X9_42_DH_PARAMETER_GEN are
         * new for v2.11 */
        public const c_ulong CKM_AES_KEY_GEN = 0x00001080;
        public const c_ulong CKM_AES_ECB = 0x00001081;
        public const c_ulong CKM_AES_CBC = 0x00001082;
        public const c_ulong CKM_AES_MAC = 0x00001083;
        public const c_ulong CKM_AES_MAC_GENERAL = 0x00001084;
        public const c_ulong CKM_AES_CBC_PAD = 0x00001085;

        /* AES counter mode is new for PKCS #11 v2.20 amendment 3 */
        public const c_ulong CKM_AES_CTR = 0x00001086;

        /* BlowFish and TwoFish are new for v2.20 */
        public const c_ulong CKM_BLOWFISH_KEY_GEN = 0x00001090;
        public const c_ulong CKM_BLOWFISH_CBC = 0x00001091;
        public const c_ulong CKM_TWOFISH_KEY_GEN = 0x00001092;
        public const c_ulong CKM_TWOFISH_CBC = 0x00001093;


        /* CKM_xxx_ENCRYPT_DATA mechanisms are new for v2.20 */
        public const c_ulong CKM_DES_ECB_ENCRYPT_DATA = 0x00001100;
        public const c_ulong CKM_DES_CBC_ENCRYPT_DATA = 0x00001101;
        public const c_ulong CKM_DES3_ECB_ENCRYPT_DATA = 0x00001102;
        public const c_ulong CKM_DES3_CBC_ENCRYPT_DATA = 0x00001103;
        public const c_ulong CKM_AES_ECB_ENCRYPT_DATA = 0x00001104;
        public const c_ulong CKM_AES_CBC_ENCRYPT_DATA = 0x00001105;

        public const c_ulong CKM_DSA_PARAMETER_GEN = 0x00002000;
        public const c_ulong CKM_DH_PKCS_PARAMETER_GEN = 0x00002001;
        public const c_ulong CKM_X9_42_DH_PARAMETER_GEN = 0x00002002;

        public const c_ulong CKM_VENDOR_DEFINED = 0x80000000;

        /* The flags CKF_ENCRYPT, CKF_DECRYPT, CKF_DIGEST, CKF_SIGN,
 * CKG_SIGN_RECOVER, CKF_VERIFY, CKF_VERIFY_RECOVER,
 * CKF_GENERATE, CKF_GENERATE_KEY_PAIR, CKF_WRAP, CKF_UNWRAP,
 * and CKF_DERIVE are new for v2.0.  They specify whether or not
 * a mechanism can be used for a particular task */
        public const c_ulong CKF_ENCRYPT = 0x00000100;
        public const c_ulong CKF_DECRYPT = 0x00000200;
        public const c_ulong CKF_DIGEST = 0x00000400;
        public const c_ulong CKF_SIGN = 0x00000800;
        public const c_ulong CKF_SIGN_RECOVER = 0x00001000;
        public const c_ulong CKF_VERIFY = 0x00002000;
        public const c_ulong CKF_VERIFY_RECOVER = 0x00004000;
        public const c_ulong CKF_GENERATE = 0x00008000;
        public const c_ulong CKF_GENERATE_KEY_PAIR = 0x00010000;
        public const c_ulong CKF_WRAP = 0x00020000;
        public const c_ulong CKF_UNWRAP = 0x00040000;
        public const c_ulong CKF_DERIVE = 0x00080000;

        /* CK_STATE enumerates the session states */
        /* CK_STATE has been changed from an enum to a CK_ULONG for
         * v2.0 */
        public const c_ulong CKS_RO_PUBLIC_SESSION = 0;
        public const c_ulong CKS_RO_USER_FUNCTIONS = 1;
        public const c_ulong CKS_RW_PUBLIC_SESSION = 2;
        public const c_ulong CKS_RW_USER_FUNCTIONS = 3;
        public const c_ulong CKS_RW_SO_FUNCTIONS = 4;

        /* Security Officer */
        public const c_ulong CKU_SO = 0;
        /* Normal user */
        public const c_ulong CKU_USER = 1;
        /* Context specific (added in v2.20) */
        public const c_ulong CKU_CONTEXT_SPECIFIC = 2;

        /* The flags are defined in the following table:
         *      Bit Flag                Mask        Meaning
         */
        public const c_ulong CKF_RW_SESSION = 0x00000002;  /* session is r/w */
        public const c_ulong CKF_SERIAL_SESSION = 0x00000004;  /* no parallel */

        /* The following attribute types are defined: */
        public const c_ulong CKA_CLASS = 0x00000000;
        public const c_ulong CKA_TOKEN = 0x00000001;
        public const c_ulong CKA_PRIVATE = 0x00000002;
        public const c_ulong CKA_LABEL = 0x00000003;
        public const c_ulong CKA_APPLICATION = 0x00000010;
        public const c_ulong CKA_VALUE = 0x00000011;

        /* CKA_OBJECT_ID is new for v2.10 */
        public const c_ulong CKA_OBJECT_ID = 0x00000012;

        public const c_ulong CKA_CERTIFICATE_TYPE = 0x00000080;
        public const c_ulong CKA_ISSUER = 0x00000081;
        public const c_ulong CKA_SERIAL_NUMBER = 0x00000082;

        /* CKA_AC_ISSUER, CKA_OWNER, and CKA_ATTR_TYPES are new
         * for v2.10 */
        public const c_ulong CKA_AC_ISSUER = 0x00000083;
        public const c_ulong CKA_OWNER = 0x00000084;
        public const c_ulong CKA_ATTR_TYPES = 0x00000085;

        /* CKA_TRUSTED is new for v2.11 */
        public const c_ulong CKA_TRUSTED = 0x00000086;

        /* CKA_CERTIFICATE_CATEGORY ...
         * CKA_CHECK_VALUE are new for v2.20 */
        public const c_ulong CKA_CERTIFICATE_CATEGORY = 0x00000087;
        public const c_ulong CKA_JAVA_MIDP_SECURITY_DOMAIN = 0x00000088;
        public const c_ulong CKA_URL = 0x00000089;
        public const c_ulong CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008A;
        public const c_ulong CKA_HASH_OF_ISSUER_PUBLIC_KEY = 0x0000008B;
        public const c_ulong CKA_CHECK_VALUE = 0x00000090;

        public const c_ulong CKA_KEY_TYPE = 0x00000100;
        public const c_ulong CKA_SUBJECT = 0x00000101;
        public const c_ulong CKA_ID = 0x00000102;
        public const c_ulong CKA_SENSITIVE = 0x00000103;
        public const c_ulong CKA_ENCRYPT = 0x00000104;
        public const c_ulong CKA_DECRYPT = 0x00000105;
        public const c_ulong CKA_WRAP = 0x00000106;
        public const c_ulong CKA_UNWRAP = 0x00000107;
        public const c_ulong CKA_SIGN = 0x00000108;
        public const c_ulong CKA_SIGN_RECOVER = 0x00000109;
        public const c_ulong CKA_VERIFY = 0x0000010A;
        public const c_ulong CKA_VERIFY_RECOVER = 0x0000010B;
public const c_ulong CKA_DERIVE             =0x0000010C;
        public const c_ulong CKA_START_DATE         =0x00000110;
        public const c_ulong CKA_END_DATE           =0x00000111;
        public const c_ulong CKA_MODULUS            =0x00000120;
        public const c_ulong CKA_MODULUS_BITS       =0x00000121;
        public const c_ulong CKA_PUBLIC_EXPONENT    =0x00000122;
        public const c_ulong CKA_PRIVATE_EXPONENT   =0x00000123;
        public const c_ulong CKA_PRIME_1            =0x00000124;
        public const c_ulong CKA_PRIME_2            =0x00000125;
        public const c_ulong CKA_EXPONENT_1         =0x00000126;
        public const c_ulong CKA_EXPONENT_2         =0x00000127;
        public const c_ulong CKA_COEFFICIENT        =0x00000128;
        public const c_ulong CKA_PRIME              =0x00000130;
        public const c_ulong CKA_SUBPRIME           =0x00000131;
        public const c_ulong CKA_BASE               =0x00000132;

        /* CKA_PRIME_BITS and CKA_SUB_PRIME_BITS are new for v2.11 */
        public const c_ulong CKA_PRIME_BITS         =0x00000133;
        public const c_ulong CKA_SUBPRIME_BITS      =0x00000134;
        public const c_ulong CKA_SUB_PRIME_BITS    =  CKA_SUBPRIME_BITS;
        /* (To retain backwards-compatibility) */

public const c_ulong CKA_VALUE_BITS         =0x00000160;
        public const c_ulong CKA_VALUE_LEN          =0x00000161;

        /* CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
         * CKA_ALWAYS_SENSITIVE, CKA_MODIFIABLE, CKA_ECDSA_PARAMS,
         * and CKA_EC_POINT are new for v2.0 */
        public const c_ulong CKA_EXTRACTABLE        =0x00000162;
        public const c_ulong CKA_LOCAL              =0x00000163;
        public const c_ulong CKA_NEVER_EXTRACTABLE  =0x00000164;
        public const c_ulong CKA_ALWAYS_SENSITIVE   =0x00000165;

        /* CKA_KEY_GEN_MECHANISM is new for v2.11 */
        public const c_ulong CKA_KEY_GEN_MECHANISM  =0x00000166;

        public const c_ulong CKA_MODIFIABLE         =0x00000170;

        /* CKA_ECDSA_PARAMS is deprecated in v2.11,
         * CKA_EC_PARAMS is preferred. */
        public const c_ulong CKA_ECDSA_PARAMS       =0x00000180;
        public const c_ulong CKA_EC_PARAMS          =0x00000180;

        public const c_ulong CKA_EC_POINT           =0x00000181;

        /* CKA_SECONDARY_AUTH, CKA_AUTH_PIN_FLAGS,
         * are new for v2.10. Deprecated in v2.11 and onwards. */
        public const c_ulong CKA_SECONDARY_AUTH     =0x00000200;
        public const c_ulong CKA_AUTH_PIN_FLAGS     =0x00000201;

        /* CKA_ALWAYS_AUTHENTICATE ...
         * CKA_UNWRAP_TEMPLATE are new for v2.20 */
        public const c_ulong CKA_ALWAYS_AUTHENTICATE  =0x00000202;

        public const c_ulong CKA_WRAP_WITH_TRUSTED    =0x00000210;
        public const c_ulong CKA_WRAP_TEMPLATE  =      (CKF_ARRAY_ATTRIBUTE|0x00000211);
        public const c_ulong CKA_UNWRAP_TEMPLATE    =  (CKF_ARRAY_ATTRIBUTE|0x00000212);

        /* CKA_OTP... atttributes are new for PKCS #11 v2.20 amendment 3. */
        public const c_ulong CKA_OTP_FORMAT                =0x00000220;
        public const c_ulong CKA_OTP_LENGTH                =0x00000221;
        public const c_ulong CKA_OTP_TIME_INTERVAL         =0x00000222;
        public const c_ulong CKA_OTP_USER_FRIENDLY_MODE    =0x00000223;
        public const c_ulong CKA_OTP_CHALLENGE_REQUIREMENT =0x00000224;
        public const c_ulong CKA_OTP_TIME_REQUIREMENT      =0x00000225;
        public const c_ulong CKA_OTP_COUNTER_REQUIREMENT   =0x00000226;
        public const c_ulong CKA_OTP_PIN_REQUIREMENT       =0x00000227;
        public const c_ulong CKA_OTP_COUNTER               =0x0000022E;
        public const c_ulong CKA_OTP_TIME                  =0x0000022F;
        public const c_ulong CKA_OTP_USER_IDENTIFIER       =0x0000022A;
        public const c_ulong CKA_OTP_SERVICE_IDENTIFIER    =0x0000022B;
        public const c_ulong CKA_OTP_SERVICE_LOGO          =0x0000022C;
        public const c_ulong CKA_OTP_SERVICE_LOGO_TYPE     =0x0000022D;


        /* CKA_HW_FEATURE_TYPE, CKA_RESET_ON_INIT, and CKA_HAS_RESET
         * are new for v2.10 */
        public const c_ulong CKA_HW_FEATURE_TYPE    =0x00000300;
        public const c_ulong CKA_RESET_ON_INIT      =0x00000301;
        public const c_ulong CKA_HAS_RESET          =0x00000302;

        /* The following attributes are new for v2.20 */
        public const c_ulong CKA_PIXEL_X                     =0x00000400;
        public const c_ulong CKA_PIXEL_Y                     =0x00000401;
        public const c_ulong CKA_RESOLUTION                  =0x00000402;
        public const c_ulong CKA_CHAR_ROWS                   =0x00000403;
        public const c_ulong CKA_CHAR_COLUMNS                =0x00000404;
        public const c_ulong CKA_COLOR                       =0x00000405;
        public const c_ulong CKA_BITS_PER_PIXEL              =0x00000406;
        public const c_ulong CKA_CHAR_SETS                   =0x00000480;
        public const c_ulong CKA_ENCODING_METHODS            =0x00000481;
        public const c_ulong CKA_MIME_TYPES                  =0x00000482;
        public const c_ulong CKA_MECHANISM_TYPE              =0x00000500;
        public const c_ulong CKA_REQUIRED_CMS_ATTRIBUTES     =0x00000501;
        public const c_ulong CKA_DEFAULT_CMS_ATTRIBUTES      =0x00000502;
        public const c_ulong CKA_SUPPORTED_CMS_ATTRIBUTES    =0x00000503;
        public const c_ulong CKA_ALLOWED_MECHANISMS          = (CKF_ARRAY_ATTRIBUTE|0x00000600);

        public const c_ulong CKA_VENDOR_DEFINED     =0x80000000;


        public const c_ulong CKF_ARRAY_ATTRIBUTE = 0x40000000;

        public const c_ulong CKO_DATA = 0x00000000;
        public const c_ulong CKO_CERTIFICATE = 0x00000001;
        public const c_ulong CKO_PUBLIC_KEY = 0x00000002;
        public const c_ulong CKO_PRIVATE_KEY = 0x00000003;
        public const c_ulong CKO_SECRET_KEY = 0x00000004;
        public const c_ulong CKO_HW_FEATURE = 0x00000005;
        public const c_ulong CKO_DOMAIN_PARAMETERS = 0x00000006;
        public const c_ulong CKO_MECHANISM = 0x00000007;


        public const c_ulong TOKEN_INFO_MAX_PIN_LEN = 256;
        public const c_ulong TOKEN_INFO_MIN_PIN_LEN = 4;
        public const string MANUFACTURER_ID = "Gradiant";
        public const string LIBRARY_DESCRIPTION = "Wrapper pkcs11 Azure Key Vault";
        public const c_ulong SLOT_ID = 1;
        public const string SLOT_DESCRIPTION = "Virtual slot";
        public const string SLOT_MANUFACTURER_ID = "Gradiant";
        public const string TOKEN_INFO_LABEL = "BlackICEConnect";
        public const string TOKEN_INFO_MANUFACTURER_ID = "www.gradiant.org";
        public const string TOKEN_INFO_MODEL = "API 1.0";
        public const string TOKEN_INFO_SERIAL_NUMBER = "SN00000001";
        public const Byte cryptokiVersion_major = 0x02;
        public const Byte cryptokiVersion_minor = 0x20;
        public const Byte libraryVersion_major = 0x01;
        public const Byte libraryVersion_minor = 0x00;
        public const Byte hardwareVersion_major = 0x01;
        public const Byte hardwareVersion_minor = 0x00;
        public const Byte firmwareVersion_major = 0x01;
        public const Byte firmwareVersion_minor = 0x00;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct CK_VERSION
    {
        public Byte major;  /* integer portion of version number */
        public Byte minor;  /* 1/100ths portion of version number */
    }

#if (LINUX)
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Ansi)]
#else
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Ansi, Pack = 1)]
#endif
    public struct CK_INFO
    {
        public CK_VERSION cryptokiVersion;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string manufacturerID;

        public c_ulong flags; // Unsigned long.

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string libraryDescription;

        public CK_VERSION libraryVersion;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct CK_SLOT_INFO
    {
        /* slotDescription and manufacturerID have been changed from
         * CK_CHAR to CK_UTF8CHAR for v2.10 */
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string slotDescription;  /* blank padded */
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string manufacturerID;   /* blank padded */
        public c_ulong flags;

        /* hardwareVersion and firmwareVersion are new for v2.0 */
        public CK_VERSION hardwareVersion;  /* version of hardware */
        public CK_VERSION firmwareVersion;  /* version of firmware */
    }
    /* CK_TOKEN_INFO provides information about a token */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct CK_TOKEN_INFO
    {
        /* label, manufacturerID, and model have been changed from
         * CK_CHAR to CK_UTF8CHAR for v2.10 */
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string label;           /* blank padded */
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string manufacturerID;  /* blank padded */
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string model;           /* blank padded */
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string serialNumber;    /* blank padded */
        public c_ulong flags;               /* see below */

        /* ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount,
         * ulRwSessionCount, ulMaxPinLen, and ulMinPinLen have all been
         * changed from CK_USHORT to CK_ULONG for v2.0 */
        public c_ulong ulMaxSessionCount;     /* max open sessions */
        public c_ulong ulSessionCount;        /* sess. now open */
        public c_ulong ulMaxRwSessionCount;   /* max R/W sessions */
        public c_ulong ulRwSessionCount;      /* R/W sess. now open */
        public c_ulong ulMaxPinLen;           /* in bytes */
        public c_ulong ulMinPinLen;           /* in bytes */
        public c_ulong ulTotalPublicMemory;   /* in bytes */
        public c_ulong ulFreePublicMemory;    /* in bytes */
        public c_ulong ulTotalPrivateMemory;  /* in bytes */
        public c_ulong ulFreePrivateMemory;   /* in bytes */

        /* hardwareVersion, firmwareVersion, and time are new for
         * v2.0 */
        public CK_VERSION hardwareVersion;       /* version of hardware */
        public CK_VERSION firmwareVersion;       /* version of firmware */
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public char[] utcTime;           /* time */
    }
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct CK_MECHANISM_INFO
    {
        public c_ulong ulMinKeySize;
        public c_ulong ulMaxKeySize;
        public c_ulong flags;
    }
    /* CK_ATTRIBUTE is a structure that includes the type, length
 * and value of an attribute */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct CK_ATTRIBUTE
    {
        public c_ulong type;
        public IntPtr pValue;
        public c_ulong ulValueLen;  /* in bytes */
                                 /* ulValueLen went from CK_USHORT to CK_ULONG for v2.0 */
    }
    /* CK_SESSION_INFO provides information about a session */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct CK_SESSION_INFO
    {
        public c_ulong slotID;
        public c_ulong state;
        public c_ulong flags;          /* see below */

        /* ulDeviceError was changed from CK_USHORT to CK_ULONG for
         * v2.0 */
        public c_ulong ulDeviceError;  /* device-dependent error code */
    }

    /* CK_MECHANISM is a structure that specifies a particular
     * mechanism  */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct CK_MECHANISM
    {
        public c_ulong mechanism;
        public IntPtr pParameter;

        /* ulParameterLen was changed from CK_USHORT to CK_ULONG for
         * v2.0 */
        public c_ulong ulParameterLen;  /* in bytes */
    }

}
