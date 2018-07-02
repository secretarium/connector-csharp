using System;
using System.Security.Cryptography;

namespace Secretarium.Client.Helpers
{
    public static class ECDHHelper
    {
        public static byte[] P256PublicMagic = ByteHelper.Combine(BitConverter.GetBytes(CngHelper.BCRYPT_ECDH_PUBLIC_P256_MAGIC), CngHelper.P256_KEY_LENGTH);
        public static byte[] P256PrivateMagic = ByteHelper.Combine(BitConverter.GetBytes(CngHelper.BCRYPT_ECDH_PRIVATE_P256_MAGIC), CngHelper.P256_KEY_LENGTH);

        public static byte[] PublicKey(this ECDiffieHellmanCng cng, bool includeProlog = false)
        {
            return cng.Key.PublicKey(includeProlog);
        }
        
        public static CngKey CreateCngKey(string name = null, bool allowExport = false)
        {
            return CngHelper.CreateCngKey(CngAlgorithm.ECDiffieHellmanP256, name, allowExport);
        }

        public static CngKey ToECDHCngKey(this byte[] publicKey)
        {
            var key = publicKey.Length == 64 ? ByteHelper.Combine(P256PublicMagic, publicKey) : publicKey;
            return CngKey.Import(key, CngKeyBlobFormat.EccPublicBlob);
        }

        public static ECDiffieHellmanCng ToECDHCng(this byte[] publicKey)
        {
            var cng = publicKey.ToECDHCngKey();

            return new ECDiffieHellmanCng(cng)
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256,
                KeySize = 256
            };
        }

        public static ECDiffieHellmanCng CreateECDiffieHellmanCngSha256(CngKey key = null)
        {
            return key == null
                ? new ECDiffieHellmanCng
                {
                    KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                    HashAlgorithm = CngAlgorithm.Sha256,
                    KeySize = 256
                }
                : new ECDiffieHellmanCng(key)
                {
                    KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                    HashAlgorithm = CngAlgorithm.Sha256,
                    KeySize = 256
                };
        }
        
        public static ECDiffieHellmanCng Import(byte[] pubKey, byte[] priKey)
        {
            var blob = ByteHelper.Combine(P256PrivateMagic, pubKey, priKey);
            var cng = CngKey.Import(blob, CngKeyBlobFormat.EccPrivateBlob);
            return new ECDiffieHellmanCng(cng)
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256,
                KeySize = 256
            };
        }

        public static ECDiffieHellmanCng ImportFromEccPrivateBlob(byte[] blob, out byte[] publicKey, out byte[] privateKey)
        {
            publicKey = blob.Extract(8, 64);
            privateKey = blob.Extract(72);

            var cng = CngKey.Import(blob, CngKeyBlobFormat.EccPrivateBlob);
            return new ECDiffieHellmanCng(cng)
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256,
                KeySize = 256
            };
        }
    }
}
