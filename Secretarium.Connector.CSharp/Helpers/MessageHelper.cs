using System;

namespace Secretarium.Helpers
{
    public static class MessageHelper
    {
        public static Message ParseMessage(this byte[] data)
        {
            return data.GetUtf8String().DeserializeJsonAs<Message>();
        }

        public static Result<T> ParseMessage<T>(this byte[] data, Func<byte[], Result<T>> convertor = null)
        {
            return convertor == null ? data.GetUtf8String().DeserializeJsonAs<Result<T>>() : convertor(data);
        }

        public static Result<T> ParseMessage<T>(this byte[] data, byte[] symmetricKey, ScpConfig.EncryptionMode encryptionMode, Func<byte[], T> convertor = null)
        {
            var ivOffset = data.Extract(0, 16);
            var decrypted = encryptionMode == ScpConfig.EncryptionMode.AESCTR
                ? data.Extract(16).AesCtrDecrypt(symmetricKey, ivOffset)
                : data.Extract(16).AesGcmDecryptWithOffset(symmetricKey, ivOffset);
            return ParseMessage<T>(decrypted);
        }
    }
}
