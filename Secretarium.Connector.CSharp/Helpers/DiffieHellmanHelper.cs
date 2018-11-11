using System.Linq;
using System.Security.Cryptography;

namespace Secretarium.Helpers
{
    public static class DiffieHellmanHelper
    {
        public static bool ComputeProofOfWork(this ProofOfWorkDetails details, out byte[] proof)
        {
            var computer = new ProofOfWork<SHA256Cng>(details.difficulty, details.challenge);

            return computer.Compute(out proof);
        }

        public static bool CheckKnownPubKeyPath(byte[] knownPubKey, byte[] publicKeyPath)
        {
            if (publicKeyPath.Length == 64)
                return knownPubKey.SequenceEqual(publicKeyPath);

            for (var i = 0; i < publicKeyPath.Length - 64; i = i + 128) {
                var key = publicKeyPath.Extract(i, 64);
                var proof = publicKeyPath.Extract(i + 64, 64);
                var keyChild = publicKeyPath.Extract(i + 128, 64);
                if (!key.ToECDsaCngKey().VerifyData(keyChild, proof))
                    return false;
            }
            return true;
        }

        public static byte[] GetSymmetricKey(ECDiffieHellmanCng client, byte[] serverPublicKey, byte[] preMasterSecret)
        {
            var serverPublicKeyCng = serverPublicKey.ToECDHCngKey();
            var commonKey = client.DeriveKeyMaterial(serverPublicKeyCng);

            return commonKey.Xor(preMasterSecret);
        }
    }
}
