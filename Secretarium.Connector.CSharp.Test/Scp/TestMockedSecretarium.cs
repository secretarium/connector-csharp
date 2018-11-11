using System.Linq;
using Secretarium.Helpers;
using NUnit.Framework;
using System.Security.Cryptography;

namespace Secretarium.Test
{
    [TestFixture]
    public class TestMockedSecretarium
    {
        #region Test Diffiehellman

        [Test]
        public void TestKeyExchange()
        {
            // Client side
            var clientEph = ECDHHelper.CreateCngKey();
            var clientEphCng = ECDHHelper.CreateECDiffieHellmanCngSha256(clientEph);
            var clientEphPubKey = clientEphCng.PublicKey();

            // Server side
            var secretarium = new MockedSecretarium();
            Assert.IsTrue(secretarium.GetServerHello(clientEphPubKey, out byte[] serverHello));
            Assert.IsTrue(ServerHello.Parse(serverHello, 18, out ServerHello serverHelloObj));

            // Client side
            Assert.IsTrue(DiffieHellmanHelper.ComputeProofOfWork(serverHelloObj.proofOfWorkDetails, out byte[] proofOfWork));
            var clientProofOfWork = ByteHelper.Combine(proofOfWork.ExtendTo(32), MockedSecretarium.GenesisPubKey);

            // Server side
            Assert.IsTrue(secretarium.GetServerIdentity(clientProofOfWork, out byte[] serverIdentity));
            Assert.IsTrue(ServerIdentity.Parse(serverIdentity, out ServerIdentity serverIdentityObj));

            // Client side
            var symmetricKey = DiffieHellmanHelper.GetSymmetricKey(
                clientEphCng, serverIdentityObj.ephDHKey, serverIdentityObj.preMasterSecret);

            // Check keys are the same both sides
            Assert.IsTrue(symmetricKey.SequenceEqual(secretarium.Session.SymmetricKey));
        }
        
        private bool FullProtocolFromX509(out byte[] symmetricKey, out MockedSecretarium secretarium)
        {
            // Client keys
            Assert.IsTrue(ScpConfigHelper.TryLoad("test.x509.json", out ScpConfig config));
            Assert.IsTrue(config.keys.TryGetECDsaKey(out ECDsaCng clientECDsaCng));
            var clientPub = clientECDsaCng.Key.PublicKey();

            // Client Hello
            var clientEph = ECDHHelper.CreateCngKey();
            var clientEphCng = ECDHHelper.CreateECDiffieHellmanCngSha256(clientEph);
            var clientEphPub = clientEphCng.PublicKey();
            var clientHello = clientEphPub;
            Assert.IsTrue(ClientHello.Parse(clientHello, out ClientHello clientHelloObj));

            // Server Hello
            secretarium = new MockedSecretarium();
            secretarium.GetServerHello(clientHello, out byte[] serverHello);
            Assert.IsTrue(ServerHello.Parse(serverHello, 18, out ServerHello serverHelloObj));

            // Client ClientProofOfWork
            Assert.IsTrue(DiffieHellmanHelper.ComputeProofOfWork(serverHelloObj.proofOfWorkDetails, out byte[] proofOfWork));
            var clientProofOfWork = ByteHelper.Combine(proofOfWork.ExtendTo(32), MockedSecretarium.GenesisPubKey);
            Assert.IsTrue(ClientProofOfWork.Parse(clientProofOfWork, out ClientProofOfWork clientProofOfWorkObj));

            // Server Identity
            secretarium.GetServerIdentity(clientProofOfWork, out byte[] serverIdentity);
            Assert.IsTrue(ServerIdentity.Parse(serverIdentity, out ServerIdentity serverIdentityObj));

            // Client computes symmetric key
            symmetricKey = DiffieHellmanHelper.GetSymmetricKey(
                clientEphCng, serverIdentityObj.ephDHKey, serverIdentityObj.preMasterSecret);

            // Client Proof Of Identity
            var nonce = ByteHelper.GetRandom(32);
            var nonceSigned = clientECDsaCng.SignData(nonce);
            var clientProofOfIdentity = ByteHelper.Combine(nonce, clientEphPub, clientPub, nonceSigned);
            Assert.IsTrue(ClientProofOfIdentity.Parse(clientProofOfIdentity, out ClientProofOfIdentity clientProofOfIdentityObj));

            // Client Encrypts Client Proof Of Identity
            var ivOffset = ByteHelper.GetRandom(16);
            var encryptedClientProofOfIdentity = clientProofOfIdentity.AesCtrEncrypt(symmetricKey, ivOffset);
            var encryptedClientProofOfIdentityWithIvOffset = ByteHelper.Combine(ivOffset, encryptedClientProofOfIdentity);

            // Server Checks And Sends Proof Of Identity
            Assert.IsTrue(secretarium.GetServerProofOfIdentity(
                encryptedClientProofOfIdentityWithIvOffset, out byte[] encryptedServerProofOfIdentity));

            // Client Decrypts Server Proof Of Identity
            ivOffset = encryptedServerProofOfIdentity.Extract(0, 16);
            var serverProofOfIdentity = encryptedServerProofOfIdentity.Extract(16).AesCtrDecrypt(symmetricKey, ivOffset);
            Assert.IsTrue(ServerProofOfIdentity.Parse(serverProofOfIdentity, out ServerProofOfIdentity serverProofOfIdentityObj));

            // Client Checks Server Proof Of Idendity
            var msg = "Hey you! Welcome to Secretarium!".ToBytes();
            var secretariumECDsaCng = serverIdentityObj.publicKey.ToECDsaCngKey();
            Assert.IsTrue(secretariumECDsaCng.VerifyData(
                ByteHelper.Combine(serverProofOfIdentityObj.nonce, msg), serverProofOfIdentityObj.welcomeSigned));

            return true;
        }
        
        [Test]
        public void TestFullProtocolFromX509()
        {
            var session = FullProtocolFromX509(out byte[] symmetricKey, out MockedSecretarium secretarium);
            Assert.IsNotNull(session);
        }

        #endregion

        #region Test Commands

        [Test]
        public void TestSumCommand()
        {
            var session = FullProtocolFromX509(out byte[] symmetricKey, out MockedSecretarium secretarium);
            var command = new Request<double[]>("Secretarium.Test.DCAppForTesting", "Sum", new double[] { 1, 2, 3, 4, 5 });
            var data = secretarium.RunCommand(command.Encrypt(symmetricKey));
            var sum = data.ParseMessage<double>(symmetricKey);
            Assert.AreEqual(15d, sum.result);
        }

        [Test]
        public void TestAvgCommand()
        {
            var session = FullProtocolFromX509(out byte[] symmetricKey, out MockedSecretarium secretarium);
            var command = new Request<double[]>("Secretarium.Test.DCAppForTesting", "Avg", new double[] { 1, 2, 3, 4, 5 });
            var data = secretarium.RunCommand(command.Encrypt(symmetricKey));
            var avg = data.ParseMessage<double>(symmetricKey);
            Assert.AreEqual(3d, avg.result);
        }

        [Test]
        public void TestTextReplaceCommand()
        {
            var session = FullProtocolFromX509(out byte[] symmetricKey, out MockedSecretarium secretarium);
            var args = new DCAppForTesting.TextReplaceArgs { FindValue = "def", ReplaceWith = "xyz", Value = "abcdefghi" };
            var command = new Request<DCAppForTesting.TextReplaceArgs>("Secretarium.Test.DCAppForTesting", "TextReplace", args);
            var data = secretarium.RunCommand(command.Encrypt(symmetricKey));
            var avg = data.ParseMessage<string>(symmetricKey);
            Assert.AreEqual("abcxyzghi", avg.result);
        }

        #endregion
    }
}
