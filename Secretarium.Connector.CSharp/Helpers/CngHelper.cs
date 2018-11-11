using System;
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

        public static byte[] PublicKey(this CngKey key, bool includeProlog = false)
        {
            var publicKeyWithProlog = key.Export(CngKeyBlobFormat.EccPublicBlob);
            
            if (includeProlog)
                return publicKeyWithProlog;

            var publicKey = new byte[64];
            Array.Copy(publicKeyWithProlog, 8, publicKey, 0, publicKey.Length);

            return publicKey;
        }
        
        public static CngKey CreateCngKey(CngAlgorithm algorithm, string name = null, bool allowExport = false)
        {
            if(!allowExport)
                return CngKey.Create(algorithm, name);

            return CngKey.Create(algorithm, name, new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.AllowPlaintextExport });
        }
    }
}
