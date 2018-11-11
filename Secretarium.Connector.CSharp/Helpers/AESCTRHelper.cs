using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Secretarium.Helpers
{
    public static class AESCTRHelper
    {
        private static void ExtractKeyAndIv(this byte[] key256, out byte[] key128, out byte[] iv128)
        {
            key128 = new byte[16];
            iv128 = new byte[16];

            Array.Copy(key256, 0, key128, 0, key128.Length);
            Array.Copy(key256, key128.Length, iv128, 0, iv128.Length);
        }

        public static byte[] AesCtr(this byte[] data, bool encrypt, byte[] key, byte[] iv)
        {
            var cipher = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
            return cipher.DoFinal(data);
        }

        public static byte[] AesCtrEncrypt(this byte[] data, byte[] key256, byte[] ivOffset)
        {
            ExtractKeyAndIv(key256, out byte[] key128, out byte[] iv128);

            return data.AesCtr(true, key128, iv128.IncrementBy(ivOffset));
        }

        public static byte[] AesCtrDecrypt(this byte[] encryptedData, byte[] key256, byte[] ivOffset)
        {
            ExtractKeyAndIv(key256, out byte[] key128, out byte[] iv128);

            return encryptedData.AesCtr(false, key128, iv128.IncrementBy(ivOffset));
        }
    }
}
