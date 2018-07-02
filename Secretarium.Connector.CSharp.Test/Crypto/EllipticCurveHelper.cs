using System;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using NUnit.Framework;

namespace Secretarium.Client.Test
{
    public class ECPoint
    {
        public BigInteger CharK { get; set; }
        public BigInteger P { get; set; }
        public BigInteger X { get; set; }
        public BigInteger Y { get; set; }

        public ECPoint(BigInteger charK, BigInteger p, BigInteger x, BigInteger y)
        {
            CharK = charK;
            P = p;
            X = x;
            Y = y;
        }
    }

    public class EllipticCurve
    {
        //This application tests an elliptic curve class with methods for calculating the discriminant of a general Weierstrass elliptic curve 
        //y^2 +a1*x*y + a3*y = x^3 + a2*x^2 + a4*x + a6 mod p, 
        //point addition, point doubling, and point multiplication.

        public static BigInteger P256_P = BigInteger.Parse("115792089210356248762697446949407573530086143415290314195533631308867097853951");
        private static BigInteger P256_B = BigInteger.Parse("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", NumberStyles.AllowHexSpecifier);
        public static EllipticCurve P256 = new EllipticCurve(BigInteger.Zero, BigInteger.Zero, BigInteger.Zero, new BigInteger(-3), P256_B, BigInteger.One, P256_P);

        // see Chapter 3 of Guide to Elliptic Curve Cryptography
        // by Darrel Hankerson, Alfred Menezes, and Scott Vanstone

        private BigInteger a1, a2, a3, a4, a6, charK, p;

        public EllipticCurve(
            BigInteger a1,
            BigInteger a2,
            BigInteger a3,
            BigInteger a4,
            BigInteger a6,
            BigInteger charK,
            BigInteger p)
        {
            this.a1 = a1;
            this.a2 = a2;
            this.a3 = a3;
            this.a4 = a4;
            this.a6 = a6;
            this.charK = charK;
            this.p = p;
        }

        public ECPoint Point(BigInteger x, BigInteger y)
        {
            return new ECPoint(charK, p, x, y);
        }

        public bool IsOnCurve(ECPoint point)
        {
            var x = point.X;
            var y = point.Y;
            BigInteger weierstrassD = ((y * ((y + a1 * x + a3) % p)) % p - (x * ((a4 + x * ((a2 + x) % p)) % p) + a6) % p) % p;
            if (weierstrassD < BigInteger.Zero)
                weierstrassD += p;
            weierstrassD %= p;//overkill
            return weierstrassD == BigInteger.Zero;
        }
    }
    
    class EllipticCurveHelper
    {
        public static bool IsKeyOnP256(BigInteger x, BigInteger y)
        {
            var point = EllipticCurve.P256.Point(x, y);
            return EllipticCurve.P256.IsOnCurve(point);
        }
        
        public static bool IsKeyOnP256(byte[] cx, byte[] cy)
        {
            if (cx.Length == 32)
            {
                var cx2 = new byte[33];
                Array.Copy(cx, cx2, 32);
                cx2[32] = 0x00;
                cx = cx2;
            }
            if (cy.Length == 32)
            {
                var cy2 = new byte[33];
                Array.Copy(cy, cy2, 32);
                cy2[32] = 0x00;
                cy = cy2;
            }
            BigInteger x = new BigInteger(cx);
            BigInteger y = new BigInteger(cy);
            return IsKeyOnP256(x, y);
        }
        
        public static bool IsKeyOnP256(byte[] dhPubKey, bool reverseEndianness = true)
        {
            var cx = dhPubKey.Where((b, i) => i < 32).ToArray();
            var cy = dhPubKey.Where((b, i) => i >= 32).ToArray();
            if (reverseEndianness)
            {
                cx = cx.Reverse().ToArray();
                cy = cy.Reverse().ToArray();
            }
            return IsKeyOnP256(cx, cy);
        }
        
        public static void TestKeyBelongsToP256(BigInteger x, BigInteger y)
        {
            var point = EllipticCurve.P256.Point(x, y);
            Assert.IsTrue(EllipticCurve.P256.IsOnCurve(point));
        }
        
        public static bool IsKeyOnP256(CngKey key)
        {
            byte[] pubKeyBlob = key.Export(CngKeyBlobFormat.EccPublicBlob);
            byte[] pubKeyBytes = new byte[64];
            Array.Copy(pubKeyBlob, 8, pubKeyBytes, 0, pubKeyBytes.Length);
            return IsKeyOnP256(pubKeyBytes);
        }
        
        public static void TestKeyBelongsToP256(byte[] dhPubKey, bool reverseEndianness = true)
        {
            Assert.IsTrue(IsKeyOnP256(dhPubKey, reverseEndianness));
        }
        
        public static void TestKeyBelongsToP256(CngKey key)
        {
            Assert.IsTrue(IsKeyOnP256(key));
        }
    }
}
