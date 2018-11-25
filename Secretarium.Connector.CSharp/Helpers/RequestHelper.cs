namespace Secretarium.Helpers
{
    public static class RequestHelper
    {
        public static byte[] ToBytes<T>(this Request<T> command) where T : class
        {
            return command.ToJson().ToBytes();
        }

        public static byte[] Encrypt<T>(this Request<T> command, byte[] symmetricKey) where T : class
        {
            var ivOffset = ByteHelper.GetRandom(16);
            var encryptedCmd = command.ToBytes().AesCtrEncrypt(symmetricKey, ivOffset);
            return ByteHelper.Combine(ivOffset, encryptedCmd);
        }
    }
}
