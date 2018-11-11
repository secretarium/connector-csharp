using Secretarium.Helpers;
using NUnit.Framework;
using System.Security.Cryptography;
using System.Diagnostics;

namespace Secretarium.Test
{
    [TestFixture]
    public class TestProofOfWork
    {
        private void VerifyPow(ProofOfWorkDetails details, byte[] proof)
        {
            var res = new ProofOfWork<SHA256Cng>(details.difficulty, details.challenge).Verify(proof);
            Assert.IsTrue(res);
        }

        [Test]
        public void TestComputeProofOfWork()
        {
            var d = new ProofOfWorkDetails
            {
                difficulty = 15,
                challenge = ByteHelper.GetRandom(31)
            };

            var res = DiffieHellmanHelper.ComputeProofOfWork(d, out byte[] proof);
            Assert.IsTrue(res);

            VerifyPow(d, proof);
        }

        /* With 50 loops
           Difficulty 15, proof 73ms, verification 0ms
           Difficulty 16, proof 153ms, verification 0ms
           Difficulty 17, proof 285ms, verification 0ms
           Difficulty 18, proof 555ms, verification 0ms
           Difficulty 19, proof 1121ms, verification 0ms
           Difficulty 20, proof 2646ms, verification 0ms
           Difficulty 21, proof 6063ms, verification 0ms
           Difficulty 22, proof 11010ms, verification 0ms */
        [Test, Explicit]
        public void TestPerformances()
        {
            var difficulties = new int[] { 15, 16, 17, 18, 19, 20, 21, 22 };
            var results = new long[difficulties.Length * 2];
            var loops = 50L;

            for (var k = 0; k < loops; k++)
            {
                var d = new ProofOfWorkDetails
                {
                    challenge = ByteHelper.GetRandom(31)
                };

                for (var i = 0; i <difficulties.Length; i++)
                {
                    var sw1 = Stopwatch.StartNew();

                    d.difficulty = (byte)difficulties[i];

                    var res = DiffieHellmanHelper.ComputeProofOfWork(d, out byte[] proof);
                    Assert.IsTrue(res);

                    sw1.Stop();

                    var sw2 = Stopwatch.StartNew();

                    VerifyPow(d, proof);

                    sw2.Stop();

                    results[i * 2] += sw1.ElapsedMilliseconds;
                    results[i * 2 + 1] += sw2.ElapsedMilliseconds;
                }
            }

            for (var i = 0; i < difficulties.Length; i++)
            {
                var msg = string.Format("Difficulty {0}, proof {1}ms, verification {2}ms", difficulties[i], results[i * 2] / loops, results[i * 2 + 1] / loops);
                TestContext.WriteLine(msg);
            }
        }
    }
}
