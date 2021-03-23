using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Secretarium.Helpers
{
    public static class AESGCMHelper
    {
        private static void ExtractKeyAndIv(this byte[] key256, out byte[] key128, out byte[] iv128)
        {
            key128 = new byte[16];
            iv128 = new byte[16];

            Array.Copy(key256, 0, key128, 0, key128.Length);
            Array.Copy(key256, key128.Length, iv128, 0, iv128.Length);
        }

        public static byte[] AesGcm(this byte[] data, bool encrypt, byte[] key, byte[] iv)
        {
            var cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
            cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
            return cipher.DoFinal(data);
        }

        public static byte[] AesGcmEncrypt(this byte[] data, byte[] key, byte[] iv)
        {
            return data.AesGcm(true, key, iv);
        }

        public static byte[] AesGcmDecrypt(this byte[] encryptedData, byte[] key, byte[] iv)
        {
            return encryptedData.AesGcm(false, key, iv);
        }

        public static byte[] AesGcmEncryptWithOffset(this byte[] data, byte[] key256, byte[] ivOffset)
        {
            ExtractKeyAndIv(key256, out byte[] key128, out byte[] iv128);

            return data.AesGcm(true, key128, iv128.IncrementBy(ivOffset).Extract(0, 12));
        }

        public static byte[] AesGcmDecryptWithOffset(this byte[] encryptedData, byte[] key256, byte[] ivOffset)
        {
            ExtractKeyAndIv(key256, out byte[] key128, out byte[] iv128);

            return encryptedData.AesGcm(false, key128, iv128.IncrementBy(ivOffset).Extract(0, 12));
        }
    }
}
