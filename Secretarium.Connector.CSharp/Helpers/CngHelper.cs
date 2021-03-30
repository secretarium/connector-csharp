using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Secretarium.Helpers
{
    public static class CngHelper
    {
        public static byte[] P256_KEY_LENGTH = new byte[] { 32, 0, 0, 0 };

        public static int BCRYPT_DSA_PUBLIC_MAGIC = 0x42505344;
        public static int BCRYPT_DSA_PRIVATE_MAGIC = 0x56505344;
        public static int BCRYPT_DSA_PUBLIC_MAGIC_V2 = 0x32425044;
        public static int BCRYPT_DSA_PRIVATE_MAGIC_V2 = 0x32565044;

        public static int BCRYPT_ECDH_PUBLIC_P256_MAGIC = 0x314B4345;
        public static int BCRYPT_ECDH_PRIVATE_P256_MAGIC = 0x324B4345;
        public static int BCRYPT_ECDH_PUBLIC_P384_MAGIC = 0x334B4345;
        public static int BCRYPT_ECDH_PRIVATE_P384_MAGIC = 0x344B4345;
        public static int BCRYPT_ECDH_PUBLIC_P521_MAGIC = 0x354B4345;
        public static int BCRYPT_ECDH_PRIVATE_P521_MAGIC = 0x364B4345;
        public static int BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC = 0x504B4345;
        public static int BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC = 0x564B4345;

        public static int BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345;
        public static int BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345;
        public static int BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345;
        public static int BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 0x34534345;
        public static int BCRYPT_ECDSA_PUBLIC_P521_MAGIC = 0x35534345;
        public static int BCRYPT_ECDSA_PRIVATE_P521_MAGIC = 0x36534345;
        public static int BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC = 0x50444345;
        public static int BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC = 0x56444345;
                      
        public static int BCRYPT_RSAPUBLIC_MAGIC = 0x31415352;
        public static int BCRYPT_RSAPRIVATE_MAGIC = 0x32415352;
        public static int BCRYPT_RSAFULLPRIVATE_MAGIC = 0x33415352;
        public static int BCRYPT_KEY_DATA_BLOB_MAGIC = 0x4d42444b;

        public static byte[] ExportPublicKeyRaw(this CngKey key)
        {
            return key.Export(CngKeyBlobFormat.EccPublicBlob).Extract(8 /* remove prolog */);
        }
        
        public static byte[] ExportPrivateKeyRaw(this CngKey key)
        {
            return key.ForceExport(CngKeyBlobFormat.EccPrivateBlob).Extract(8 + 64 /* remove prolog and public key */);
        }

        public static unsafe byte[] ForceExport(this CngKey key, CngKeyBlobFormat format)
        {
            if ((key.ExportPolicy & CngExportPolicies.AllowPlaintextExport) != 0)
                return key.Export(format);

            // The key is not exportable, lets hack. Thanks @bartonjs
            // https://stackoverflow.com/questions/57269726/x509certificate2-import-with-ncrypt-allow-plaintext-export-flag
            // https://stackoverflow.com/questions/55236230/export-private-key-pkcs8-of-cng-rsa-certificate-with-oldschool-net

            string blobType = "PKCS8_PRIVATEKEY";

            try
            {
                byte[] exported;

                fixed (byte* oidPtr = CryptNativeHelpers.PKCS12_3DES_OID)
                {
                    var salt = ByteHelper.GetRandom(CryptNativeHelpers.NCrypt.PbeParams.RgbSaltSize);
                    var pbeParams = new CryptNativeHelpers.NCrypt.PbeParams();
                    pbeParams.Params.iIterations = 1;
                    pbeParams.Params.cbSalt = salt.Length;
                    Marshal.Copy(salt, 0, (IntPtr)pbeParams.rgbSalt, salt.Length);

                    var buffers = stackalloc CryptNativeHelpers.NCrypt.NCryptBuffer[3];
                    buffers[0] = new CryptNativeHelpers.NCrypt.NCryptBuffer
                    {
                        BufferType = CryptNativeHelpers.NCrypt.BufferType.PkcsSecret,
                        cbBuffer = 0,
                        pvBuffer = IntPtr.Zero,
                    };
                    buffers[1] = new CryptNativeHelpers.NCrypt.NCryptBuffer
                    {
                        BufferType = CryptNativeHelpers.NCrypt.BufferType.PkcsAlgOid,
                        cbBuffer = CryptNativeHelpers.PKCS12_3DES_OID.Length,
                        pvBuffer = (IntPtr)oidPtr,
                    };
                    buffers[2] = new CryptNativeHelpers.NCrypt.NCryptBuffer
                    {
                        BufferType = CryptNativeHelpers.NCrypt.BufferType.PkcsAlgParam,
                        cbBuffer = sizeof(CryptNativeHelpers.NCrypt.PbeParams),
                        pvBuffer = (IntPtr)(&pbeParams),
                    };
                    var desc = new CryptNativeHelpers.NCrypt.NCryptBufferDesc
                    {
                        cBuffers = 3,
                        pBuffers = (IntPtr)buffers,
                        ulVersion = 0,
                    };

                    if (CryptNativeHelpers.NCrypt.NCryptExportKey(key.Handle, IntPtr.Zero, blobType, ref desc, null, 0, out int bytesNeeded, 0) != 0)
                        return null;

                    exported = new byte[bytesNeeded];
                    if (CryptNativeHelpers.NCrypt.NCryptExportKey(key.Handle, IntPtr.Zero, blobType, ref desc, exported, exported.Length, out bytesNeeded, 0) != 0)
                        return null;
                }

                fixed (char* keyNamePtr = key.KeyName)
                fixed (byte* blobPtr = exported)
                {
                    var buffers = stackalloc CryptNativeHelpers.NCrypt.NCryptBuffer[2];
                    buffers[0] = new CryptNativeHelpers.NCrypt.NCryptBuffer
                    {
                        BufferType = CryptNativeHelpers.NCrypt.BufferType.PkcsSecret,
                        cbBuffer = 0,
                        pvBuffer = IntPtr.Zero,
                    };
                    buffers[1] = new CryptNativeHelpers.NCrypt.NCryptBuffer
                    {
                        BufferType = CryptNativeHelpers.NCrypt.BufferType.PkcsName,
                        cbBuffer = checked(2 * (key.KeyName.Length + 1)),
                        pvBuffer = new IntPtr(keyNamePtr),
                    };
                    var desc = new CryptNativeHelpers.NCrypt.NCryptBufferDesc
                    {
                        cBuffers = 2,
                        pBuffers = (IntPtr)buffers,
                        ulVersion = 0,
                    };

                    SafeNCryptKeyHandle keyHandle;
                    if (CryptNativeHelpers.NCrypt.NCryptImportKey(key.ProviderHandle, IntPtr.Zero, blobType, ref desc, out keyHandle, new IntPtr(blobPtr), exported.Length,
                        CryptNativeHelpers.NCrypt.NCryptImportFlags.NCRYPT_OVERWRITE_KEY_FLAG | CryptNativeHelpers.NCrypt.NCryptImportFlags.NCRYPT_DO_NOT_FINALIZE_FLAG) != 0)
                    {
                        keyHandle.Dispose();
                        return null;
                    }

                    using (keyHandle)
                    using (CngKey cngKey = CngKey.Open(keyHandle, CngKeyHandleOpenOptions.None))
                    {
                        cngKey.SetProperty(new CngProperty("Export Policy", BitConverter.GetBytes((int)CngExportPolicies.AllowPlaintextExport), CngPropertyOptions.Persist));

                        if (CryptNativeHelpers.NCrypt.NCryptFinalizeKey(keyHandle, 0) != 0)
                            return null;

                        return cngKey.Export(format);
                    }
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static CngKey CreateCngKey(CngAlgorithm algorithm, string name = null, bool allowExport = false)
        {
            if (!allowExport)
                return CngKey.Create(algorithm, name);

            return CngKey.Create(algorithm, name, new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport });
        }
    }
}
