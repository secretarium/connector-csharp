namespace Secretarium.Client
{
    public class SwssConfig
    {
        public ClientConfig client { get; set; }
        public SecretariumConfig secretarium { get; set; }
        
        public class ClientConfig
        {
            public KeyConfig keys { get; set; }
            public CertificateConfig certificate { get; set; }
            public int proofOfWorkMaxDifficulty { get; set; }
        }

        public class SecretariumConfig
        {
            public string endPoint { get; set; }
            public string knownPubKey { get; set; }
        }

        public class KeyConfig
        {
            public string publicKey { get; set; }
            public string privateKey { get; set; }
        }

        public class CertificateConfig
        {
            public string pfxFile { get; set; }
            public string password { get; set; }
        }
    }
}