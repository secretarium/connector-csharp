using Secretarium.Helpers;

namespace Secretarium
{
    public class ClientHello
    {
        public byte[] ephDHKey { get; set; }

        public static bool Parse(byte[] data, out ClientHello p)
        {
            if (data.Length != 64)
            {
                p = null;
                return false;
            }

            p = new ClientHello { ephDHKey = data.Extract(0, 64) };

            return true;
        }
    }

    public class ProofOfWorkDetails
    {
        public byte difficulty { get; set; }
        public byte[] challenge { get; set; }
    }

    public class ServerHello
    {
        public ProofOfWorkDetails proofOfWorkDetails { get; set; }

        public static bool Parse(byte[] data, byte maxAllowedDifficilty, out ServerHello p)
        {
            if (data.Length != 64) // 32 bytes of nonce ignored
            {
                p = null;
                return false;
            }

            var difficulty = data[32];
            if (difficulty > maxAllowedDifficilty)
            {
                p = null;
                return false;
            }

            p = new ServerHello
            {
                proofOfWorkDetails = new ProofOfWorkDetails
                {
                    difficulty = difficulty,
                    challenge = data.Extract(33)
                }
            };

            return true;
        }
    }

    public class ClientProofOfWork
    {
        public byte[] proofOfWork { get; set; }
        public byte[] knownSecretariumPubKey { get; set; }

        public static bool Parse(byte[] data, out ClientProofOfWork p)
        {
            if (data.Length != 96) {
                p = null;
                return false;
            }

            p = new ClientProofOfWork
            {
                proofOfWork = data.Extract(0, 32),
                knownSecretariumPubKey = data.Extract(32, 64)
            };

            return true;
        }
    }

    public class ServerIdentity
    {
        public byte[] preMasterSecret { get; set; }
        public byte[] ephDHKey { get; set; }
        public byte[] publicKeyPath { get; set; }
        public byte[] publicKey { get; set; }

        public static bool Parse(byte[] data, out ServerIdentity p)
        {
            if (data.Length < 160 || (data.Length - 96) % 128 != 64)
            {
                p = null;
                return false;
            }

            p = new ServerIdentity
            {
                preMasterSecret = data.Extract(0, 32),
                ephDHKey = data.Extract(32, 64),
                publicKeyPath = data.Extract(96),
                publicKey = data.Extract(data.Length - 64, 64)
            };

            return true;
        }
    }

    public class ClientProofOfIdentity
    {
        public byte[] nonce { get; set; }
        public byte[] ephDHKey { get; set; }
        public byte[] publicKey { get; set; }
        public byte[] nonceSigned { get; set; }

        public static bool Parse(byte[] data, out ClientProofOfIdentity p)
        {
            if (data.Length != 224)
            {
                p = null;
                return false;
            }

            p = new ClientProofOfIdentity
            {
                nonce = data.Extract(0, 32),
                ephDHKey = data.Extract(32, 64),
                publicKey = data.Extract(96, 64),
                nonceSigned = data.Extract(160, 64)
            };

            return true;
        }
    }

    public class ServerProofOfIdentityEncrypted
    {
        public byte[] ivOffset { get; set; }
        public byte[] encryptedPayload { get; set; }

        public static bool Parse(byte[] data, out ServerProofOfIdentityEncrypted p)
        {
            if (data.Length != 112)
            {
                p = null;
                return false;
            }

            p = new ServerProofOfIdentityEncrypted
            {
                ivOffset = data.Extract(0, 16),
                encryptedPayload = data.Extract(16)
            };

            return true;
        }
    }

    public class ServerProofOfIdentity
    {
        public byte[] nonce { get; set; }
        public byte[] welcomeSigned { get; set; }

        public static bool Parse(byte[] data, out ServerProofOfIdentity p)
        {
            if (data.Length != 96)
            {
                p = null;
                return false;
            }

            p = new ServerProofOfIdentity
            {
                nonce = data.Extract(0, 32),
                welcomeSigned = data.Extract(32, 64)
            };

            return true;
        }
    }
}