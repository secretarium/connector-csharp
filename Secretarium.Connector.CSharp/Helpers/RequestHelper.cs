namespace Secretarium.Client.Helpers
{
    public static class RequestHelper
    {
        public static byte[] ToBytes(this Request command)
        {
            return command.ToJson().ToBytes();
        }

        public static byte[] Encrypt(this Request command, byte[] symmetricKey)
        {
            var ivOffset = ByteHelper.GetRandom(16);
            var encryptedCmd = command.ToBytes().AesCtrEncrypt(symmetricKey, ivOffset);
            return ByteHelper.Combine(ivOffset, encryptedCmd);
        }
    }
}
