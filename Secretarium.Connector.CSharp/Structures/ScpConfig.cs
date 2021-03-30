namespace Secretarium
{
    public class ScpConfig
    {
        public EncryptionMode encryptionMode { get; set; }
        public ClientConfig client { get; set; }
        public SecretariumConfig secretarium { get; set; }

        // client auth
        public SecretariumKeyConfig secretariumKey { get; set; }
        public Certificate certificate { get; set; }
        public RawKeyConfig rawKeys { get; set; }

        public enum EncryptionMode
        {
            AESCTR = 0,
            AESGCM = 1
        }

        public class ClientConfig
        {
            public int proofOfWorkMaxDifficulty { get; set; }
        }

        public class SecretariumConfig
        {
            public string endPoint { get; set; }
            public string knownPubKey { get; set; }
        }

        public class SecretariumKeyConfig
        {
            public string name { get; set; }
            public string version { get; set; }
            public string iv { get; set; }
            public string salt { get; set; }
            public string keys { get; set; }
        }

        public class Certificate
        {
            public string pfxFile { get; set; }
        }

        public class RawKeyConfig
        {
            public string publicKey { get; set; }
            public string privateKey { get; set; }
        }
    }
}