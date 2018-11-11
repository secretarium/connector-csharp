using System.Linq;
using Secretarium.Helpers;
using NUnit.Framework;

namespace Secretarium.Test
{
    [TestFixture]
    public class TestAesCtr
    {
        [Test]
        public void TestReverseEndianness()
        {
            byte[] arr = ByteHelper.GetRandom(32);
            byte[] rra = arr.ReverseEndianness();
            for (var i = 0; i < 32; i++)
            {
                Assert.AreEqual(arr[i], rra[31 - i]);
            }

            arr = ByteHelper.GetRandom(64);
            rra = arr.ReverseEndianness();
            for (var i = 0; i < 32; i++)
            {
                Assert.AreEqual(arr[i], rra[31 - i]);
                Assert.AreEqual(arr[i + 32], rra[63 - i]);
            }
        }

        [Test]
        public void TestIncrementIV()
        {
            // -0- IncrementBy does not change inputs
            var iv = new byte[] { 1 };
            var offset = new byte[] { 2 };
            var inc = iv.IncrementBy(offset);
            Assert.AreNotSame(iv, inc);
            Assert.AreNotSame(offset, inc);
            Assert.IsTrue(iv.SequenceEqual(new byte[] { 1 }));
            Assert.IsTrue(offset.SequenceEqual(new byte[] { 2 }));
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 3 }));


            // -1a- Offset zeros does nothing on zeros
            iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            offset = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));

            // -1b- Offset zeros does nothing on non zeros
            iv = new byte[] { 10, 0, 10, 0, 10, 0, 10, 0, 10, 0, 255 };
            offset = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 10, 0, 10, 0, 10, 0, 10, 0, 10, 0, 255 }));


            // -2a- Offset on zeros
            iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            offset = new byte[] {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 }));

            // -2b- Offset on non zeros
            iv = new byte[] { 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10 };
            offset = new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11 }));

            // -2c- Offset on 255
            iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255 };
            offset = new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0 }));

            // -2d- Offset on complex 255
            iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255 };
            offset = new byte[] { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 0 }));

            // -2e- Offset on full 255
            iv = new byte[] { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };
            offset = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }));

            // -2f- Offset on full 255
            iv = new byte[] { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };
            offset = new byte[] { 1, 1, 1, 1, 1, 1, 5, 1, 1, 1, 1 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 1, 1, 1, 1, 1, 1, 5, 1, 1, 1, 0 }));

            // -2g- Offset on 255 by 255
            iv = new byte[] { 0, 0, 255 };
            offset = new byte[] { 0, 0, 255 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 0, 1, 254 }));

            // -2h- Offset on 255 by 255
            iv = new byte[] { 255, 255, 255 };
            offset = new byte[] { 255, 1, 1 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 255, 1, 0 }));

            // -2i- Offset with different sizes
            iv = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            inc = iv.IncrementBy(512L.ToBytes());
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0 }));


            // -3a- Full no loop
            iv = new byte[] { 0, 85, 138, 48, 253, 0, 8, 150, 254, 10, 255 };
            offset = new byte[] { 85, 214, 231, 37, 2, 148, 255, 10, 0, 255, 255 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 86, 44, 113, 85, 255, 149, 7, 160, 255, 10, 254 }));

            // -3b- Full with loop
            iv = new byte[] { 255, 85, 138, 48, 253, 0, 8, 150, 254, 10, 255 };
            offset = new byte[] { 125, 214, 231, 37, 2, 148, 255, 10, 0, 255, 255 };
            inc = iv.IncrementBy(offset);
            Assert.IsTrue(inc.SequenceEqual(new byte[] { 125, 44, 113, 85, 255, 149, 7, 160, 255, 10, 254 }));
        }

        [Test]
        public void TestEncryptDecrypt()
        {
            byte[] plaintextMessage = "Secretarium is the ultimate shared trusted information system !".ToBytes();
            byte[] key = ByteHelper.GetRandom(32);
            byte[] ivOffset = new byte[16];

            byte[] encrypted = plaintextMessage.AesCtrEncrypt(key, ivOffset);
            byte[] decrypted = encrypted.AesCtrDecrypt(key, ivOffset);

            Assert.IsTrue(plaintextMessage.SequenceEqual(decrypted));
        }
    }
}
