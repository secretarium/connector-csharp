using System;
using System.Security.Cryptography;

namespace Secretarium.Helpers
{
    public static class ECDsaHelper
    {
        public static byte[] P256PublicMagic = ByteHelper.Combine(BitConverter.GetBytes(CngHelper.BCRYPT_ECDSA_PUBLIC_P256_MAGIC), CngHelper.P256_KEY_LENGTH);
        public static byte[] P256PrivateMagic = ByteHelper.Combine(BitConverter.GetBytes(CngHelper.BCRYPT_ECDSA_PRIVATE_P256_MAGIC), CngHelper.P256_KEY_LENGTH);

        public static byte[] ExportPublicKeyRaw(this ECDsaCng cng)
        {
            return cng.Key.ExportPublicKeyRaw();
        }

        public static byte[] ExportPrivateKeyRaw(this ECDsaCng cng)
        {
            return cng.Key.ExportPrivateKeyRaw();
        }

        public static byte[] ExportPrivateKey(this ECDsaCng cng)
        {
            return cng.Key.ExportPrivateKeyRaw();
        }

        public static CngKey CreateCngKey(string name = null)
        {
            return CngHelper.CreateCngKey(CngAlgorithm.ECDsaP256, name);
        }

        public static ECDsaCng CreateECDsaCng256(CngKey key = null)
        {
            return key == null
                ? new ECDsaCng
                {
                    HashAlgorithm = CngAlgorithm.Sha256,
                    KeySize = 256                    
                }
                : new ECDsaCng(key)
                {
                    HashAlgorithm = CngAlgorithm.Sha256,
                    KeySize = 256
                };
        }

        public static ECDsaCng ImportPublicKey(byte[] publicKey)
        {
            var key = publicKey.Length == 64 ? ByteHelper.Combine(P256PublicMagic, publicKey) : publicKey;
            var cng = CngKey.Import(key, CngKeyBlobFormat.EccPublicBlob);
            return new ECDsaCng(cng) { HashAlgorithm = CngAlgorithm.Sha256, KeySize = 256 };
        }

        public static ECDsaCng ImportPrivateKey(byte[] pubKey, byte[] priKey)
        {
            var blob = ByteHelper.Combine(P256PrivateMagic, pubKey, priKey);
            var cng = CngKey.Import(blob, CngKeyBlobFormat.EccPrivateBlob);
            return new ECDsaCng(cng) { HashAlgorithm = CngAlgorithm.Sha256, KeySize = 256 };
        }
    }
}
