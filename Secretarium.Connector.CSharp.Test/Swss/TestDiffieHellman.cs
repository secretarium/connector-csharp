using System;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Secretarium.Client.Helpers;
using NUnit.Framework;

namespace Secretarium.Client.Test.Dev
{
    [TestFixture]
    public class TestECDiffieHellmanCng
    {
        [Test]
        public void TestDiffieHellmanP256()
        {
            var clientKey = ECDHHelper.CreateCngKey();
            var serverKey = ECDHHelper.CreateCngKey();

            var clientECDHCng = ECDHHelper.CreateECDiffieHellmanCngSha256(clientKey);
            var serverECDHCng = ECDHHelper.CreateECDiffieHellmanCngSha256(serverKey);

            var commonSecretServer = serverECDHCng.DeriveKeyMaterial(clientECDHCng.PublicKey);
            var commonSecretClient = clientECDHCng.DeriveKeyMaterial(serverECDHCng.PublicKey);

            Assert.IsTrue(commonSecretClient.SequenceEqual(commonSecretServer));
        }

        [Test]
        public void TestDiffieHellmanP256IsReplayable()
        {
            var clientKey = ECDHHelper.CreateCngKey();
            var serverKey = ECDHHelper.CreateCngKey();

            var clientECDH1 = ECDHHelper.CreateECDiffieHellmanCngSha256(clientKey);
            var serverECDH1 = ECDHHelper.CreateECDiffieHellmanCngSha256(serverKey);

            var commonSecretBytesClient1 = clientECDH1.DeriveKeyMaterial(serverECDH1.PublicKey);
            var commonSecretBytesServer1 = serverECDH1.DeriveKeyMaterial(clientECDH1.PublicKey);

            Assert.IsTrue(commonSecretBytesClient1.SequenceEqual(commonSecretBytesServer1));
            
            var clientECDH2 = ECDHHelper.CreateECDiffieHellmanCngSha256(clientKey);
            var serverECDH2 = ECDHHelper.CreateECDiffieHellmanCngSha256(serverKey);

            var commonSecretBytesClient2 = clientECDH2.DeriveKeyMaterial(serverECDH2.PublicKey);
            var commonSecretBytesServer2 = serverECDH2.DeriveKeyMaterial(clientECDH2.PublicKey);

            Assert.IsTrue(commonSecretBytesClient2.SequenceEqual(commonSecretBytesServer2));

            Assert.IsTrue(commonSecretBytesClient1.SequenceEqual(commonSecretBytesClient2));
        }
        
        [Test]
        public void TestDiffieHellmanSha256()
        {
            var client = ECDHHelper.CreateECDiffieHellmanCngSha256();
            var server = ECDHHelper.CreateECDiffieHellmanCngSha256();

            var commonSecretBytesClient = client.DeriveKeyMaterial(server.PublicKey);
            var commonSecretBytesServer = server.DeriveKeyMaterial(client.PublicKey);

            Assert.IsTrue(commonSecretBytesClient.SequenceEqual(commonSecretBytesServer));
        }

        [Test]
        public void TestDiffieHellmanSha256IsReplayable()
        {
            var clientFullKey = ECDHHelper.CreateECDiffieHellmanCngSha256().Key;
            var serverFullKey = ECDHHelper.CreateECDiffieHellmanCngSha256().Key;

            var clientECDH1 = ECDHHelper.CreateECDiffieHellmanCngSha256(clientFullKey);
            var serverECDH1 = ECDHHelper.CreateECDiffieHellmanCngSha256(serverFullKey);
            var commonSecretBytesClient1 = clientECDH1.DeriveKeyMaterial(serverECDH1.PublicKey);
            var commonSecretBytesServer1 = serverECDH1.DeriveKeyMaterial(clientECDH1.PublicKey);
            Assert.IsTrue(commonSecretBytesClient1.SequenceEqual(commonSecretBytesServer1));

            var clientECDH2 = ECDHHelper.CreateECDiffieHellmanCngSha256(clientFullKey);
            var serverECDH2 = ECDHHelper.CreateECDiffieHellmanCngSha256(serverFullKey);
            var commonSecretBytesClient2 = clientECDH2.DeriveKeyMaterial(serverECDH2.PublicKey);
            var commonSecretBytesServer2 = serverECDH2.DeriveKeyMaterial(clientECDH2.PublicKey);
            Assert.IsTrue(commonSecretBytesClient2.SequenceEqual(commonSecretBytesServer2));

            Assert.IsTrue(commonSecretBytesClient1.SequenceEqual(commonSecretBytesClient2));
        }
        
        [Test, Description("control group test that verifies that NIST point G is pqert of NIST P256 curve")]
        public void TestNISTKeyBelongsToP256()
        {
            var gx = BigInteger.Parse("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", NumberStyles.AllowHexSpecifier);
            var gy = BigInteger.Parse("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", NumberStyles.AllowHexSpecifier);
            EllipticCurveHelper.TestKeyBelongsToP256(gx, gy);
        }

        [Test]
        public void TestCngKeyOnP256()
        {
            CngKey key = ECDHHelper.CreateCngKey();
            EllipticCurveHelper.TestKeyBelongsToP256(key);
        }

        [Test, Description("test that clears up endianness of encoding etc")]
        public void TestECDHCngKeyEncoding()
        {
            ECDiffieHellmanCng aliceCng = new ECDiffieHellmanCng(256)
            {
                HashAlgorithm = CngAlgorithm.Sha256,
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash
            };

            byte[] alicePubKeyBlob = aliceCng.Key.Export(CngKeyBlobFormat.EccPublicBlob);
            byte[] aliceCoordinateX = new byte[33];//byte0 = 0 to ensure that the biginteger is positive
            byte[] aliceCoordinateY = new byte[33];//byte0 = 0 to ensure that the biginteger is positive
            aliceCoordinateX[0] = 0x00;
            aliceCoordinateX[0] = 0x00;

            Array.Copy(alicePubKeyBlob, 8, aliceCoordinateX, 1, 32);
            Array.Copy(alicePubKeyBlob, 8 + 32, aliceCoordinateY, 1, 32);

            BigInteger x = new BigInteger(aliceCoordinateX.Reverse().ToArray());
            BigInteger y = new BigInteger(aliceCoordinateY.Reverse().ToArray());
            EllipticCurveHelper.TestKeyBelongsToP256(x, y);
        }

        [Test, Description("simple variant of TestCngKeyEncoding")]
        public void TestCngGeneratP256PublicKeysWithBigEndianEncoding()
        {
            ECDiffieHellmanCng aliceCng = new ECDiffieHellmanCng(256)
            {
                HashAlgorithm = CngAlgorithm.Sha256,
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash
            };

            byte[] alicePubKeyBlob = aliceCng.Key.Export(CngKeyBlobFormat.EccPublicBlob);
            Assert.AreEqual(2 * 32 + 8, alicePubKeyBlob.Length);

            var keyType = new byte[] { 0x45, 0x43, 0x4b, 0x31 };
            var keyLength = new byte[] { 0x20, 0x00, 0x00, 0x00 };
            var keyTypeAndLength = new[] { keyType, keyLength }.SelectMany(l => l).ToArray();
            var startOfKey = alicePubKeyBlob.Where((b, i) => i < 8).ToArray();
            Assert.IsTrue(keyTypeAndLength.SequenceEqual(startOfKey));

            byte[] aliceElipticCoordinates = new byte[64];
            Array.Copy(alicePubKeyBlob, 8, aliceElipticCoordinates, 0, aliceElipticCoordinates.Length);

            EllipticCurveHelper.TestKeyBelongsToP256(aliceElipticCoordinates);
        }

        [Test]
        public void TestDiffieHellmanSha256FromBase64()
        {
            var serverEphPubKeyBase64BE = "5+K+/aahgA7QLksySOV43r+iwM0F/RPDfgCM344Mf+pqKlLMPKzGJhkhhKriE6UJ95JmfiGngIoKegQ+plHz2w==";
            var serverEphPriKeyBase64BE = "sxJNyEO7i6YfA1p9CTglH13Uy/yW9UU7Ew2JChzbrjI=";
            
            var clientEphEccPrivateBlobBase64 = "RUNLMiAAAADgzTD0gIgNIjSEoCVMZnIvGerxx6FTZHheMPzI44s1mBAjjtZw5R2YVC1zubdetTpRHnGXBoje56G97htrY7WGpUWP1xM8GhdWN31HjIgR68JNuW4XIlTgO0qOE0ezNjI=";
            var clientEphEccPrivateBlob = clientEphEccPrivateBlobBase64.FromBase64String();
            var clientEphCng = ECDHHelper.ImportFromEccPrivateBlob(
                clientEphEccPrivateBlob, out byte[] clientEphPubKey, out byte[] clientEphPriKey);
            
            byte[] commonSecretClient;
            {
                var serverEphPub = serverEphPubKeyBase64BE.FromBase64String().ReverseEndianness();
                var serverEphCngKey = serverEphPub.ToECDHCngKey();

                commonSecretClient = clientEphCng.DeriveKeyMaterial(serverEphCngKey);
            }

            byte[] commonSecretServer;
            {
                var serverEphPubKey = serverEphPubKeyBase64BE.FromBase64String().ReverseEndianness();
                var serverEphPriKey = serverEphPriKeyBase64BE.FromBase64String().ReverseEndianness();
                var serverEphCng = ECDHHelper.Import(serverEphPubKey, serverEphPriKey);

                commonSecretServer = serverEphCng.DeriveKeyMaterial(clientEphCng.PublicKey);
            }

            Assert.IsTrue(commonSecretClient.SequenceEqual(commonSecretServer));
        }
    }
}
