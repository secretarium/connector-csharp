using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Secretarium.Helpers
{
    public static class AESGCMHelper
    {
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
    }
}
