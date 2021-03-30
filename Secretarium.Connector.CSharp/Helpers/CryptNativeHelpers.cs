using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Secretarium.Helpers
{
    // Thanks @bartonjs
    // https://stackoverflow.com/questions/57269726/x509certificate2-import-with-ncrypt-allow-plaintext-export-flag
    // https://stackoverflow.com/questions/55236230/export-private-key-pkcs8-of-cng-rsa-certificate-with-oldschool-net
    public static class CryptNativeHelpers
    {
        public const string NCRYPT_PKCS8_PRIVATE_KEY_BLOB = "PKCS8_PRIVATEKEY";
        public static readonly byte[] PKCS12_3DES_OID = Encoding.ASCII.GetBytes("1.2.840.113549.1.12.1.3\0");

        public static class Crypt32
        {
            public enum AcquireCertificateKeyOptions
            {
                None = 0x00000000,
                CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG = 0x00040000,
            }

            [DllImport("crypt32.dll", SetLastError = true)]
            public static extern bool CryptAcquireCertificatePrivateKey(
                IntPtr pCert,
                AcquireCertificateKeyOptions dwFlags,
                IntPtr pvReserved,
                out SafeNCryptKeyHandle phCryptProvOrNCryptKey,
                out int dwKeySpec,
                out bool pfCallerFreeProvOrNCryptKey);

            [DllImport("crypt32.dll", SetLastError = true)]
            public static extern unsafe bool CertSetCertificateContextProperty(IntPtr pCertContext, CertContextPropId dwPropId, CertSetPropertyFlags dwFlags, SafeNCryptKeyHandle pvData);

            public enum CertContextPropId : int
            {
                CERT_NCRYPT_KEY_HANDLE_PROP_ID = 78,
            }

            [Flags]
            public enum CertSetPropertyFlags : int
            {
                None = 0,
            }
        }

        public static class NCrypt
        {
            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            public static extern int NCryptExportKey(
                SafeNCryptKeyHandle hKey,
                IntPtr hExportKey,
                string pszBlobType,
                ref NCryptBufferDesc pParameterList,
                byte[] pbOutput,
                int cbOutput,
                [Out] out int pcbResult,
                int dwFlags);

            [StructLayout(LayoutKind.Sequential)]
            public unsafe struct PbeParams
            {
                public const int RgbSaltSize = 8;

                public CryptPkcs12PbeParams Params;
                public fixed byte rgbSalt[RgbSaltSize];
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct CryptPkcs12PbeParams
            {
                public int iIterations;
                public int cbSalt;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct NCryptBufferDesc
            {
                public int ulVersion;
                public int cBuffers;
                public IntPtr pBuffers;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct NCryptBuffer
            {
                public int cbBuffer;
                public BufferType BufferType;
                public IntPtr pvBuffer;
            }

            public enum BufferType
            {
                PkcsAlgOid = 41,
                PkcsAlgParam = 42,
                PkcsName = 45,
                PkcsSecret = 46,
            }

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            public static extern int NCryptOpenStorageProvider(
                out SafeNCryptProviderHandle phProvider,
                string pszProviderName,
                int dwFlags);

            public enum NCryptImportFlags
            {
                None = 0,
                NCRYPT_MACHINE_KEY_FLAG = 0x00000020,
                NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080,
                NCRYPT_DO_NOT_FINALIZE_FLAG = 0x00000400,
            }

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            public static extern int NCryptImportKey(
                SafeNCryptProviderHandle hProvider,
                IntPtr hImportKey,
                string pszBlobType,
                ref NCryptBufferDesc pParameterList,
                out SafeNCryptKeyHandle phKey,
                IntPtr pbData,
                int cbData,
                NCryptImportFlags dwFlags);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            public static extern int NCryptFinalizeKey(SafeNCryptKeyHandle hKey, int dwFlags);
        }
    }
}
