namespace Secretarium
{
    public class ScpConfig
    {
        public EncryptionMode encryptionMode { get; set; }
        public ClientConfig client { get; set; }
        public SecretariumConfig secretarium { get; set; }
        public KeyConfig keys { get; set; }

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

        public class KeyConfig
        {
            // Secretarium key
            public string iv { get; set; }
            public string salt { get; set; }
            public string keys { get; set; }
            public string password { get; set; }

            // Pfx file
            public string pfxFile { get; set; }

            // ECDSA key
            public string publicKey { get; set; }
            public string privateKey { get; set; }
        }
    }
}