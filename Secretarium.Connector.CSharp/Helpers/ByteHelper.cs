using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Secretarium.Helpers
{
    public static class ByteHelper
    {
        public static readonly RandomNumberGenerator RandomNumberGenerator = new RNGCryptoServiceProvider();

        public static string ToBase64String(this byte[] bytes, bool urlMode = true)
        {
            var b64 = Convert.ToBase64String(bytes);
            if (!urlMode)
                return b64;

            return b64.Replace("+", "-").Replace("/", "_");
        }

        public static byte[] FromBase64String(this string b64)
        {
            return Convert.FromBase64String(b64.Replace("-", "+").Replace("_", "/"));
        }

        public static string GetUtf8String(this byte[] a)
        {
            return Encoding.UTF8.GetString(a);
        }

        public static byte[] ToBytes(this string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }

        public static byte[] ToBytes(this long l)
        {
            return BitConverter.GetBytes(l).ReverseEndianness();
        }

        public static byte[] ToBytes(this int i)
        {
            return BitConverter.GetBytes(i).ReverseEndianness();
        }

        public static IEnumerable<T> ReverseChunkWise<T>(this IEnumerable<T> collection, int chunkSz)
        {
            T[] buff = new T[chunkSz];
            int acc = 0;
            foreach (var itemPush in collection)
            {
                if (acc == chunkSz)
                {
                    while (acc > 0)
                        yield return buff[--acc];
                }
                buff[acc++] = itemPush;
            }
            while (acc > 0)
                yield return buff[--acc];
        }

        public static byte[] ReverseEndianness(this byte[] byteArray, int chunkSz = 32)
        {
            return byteArray.ReverseChunkWise(32).ToArray();
        }

        public static byte[] Xor(this byte[] a1, byte[] a2)
        {
            return a1.Select((b, i) => (byte)(b ^ a2[i])).ToArray();
        }

        public static byte[] Combine(params byte[][] arrays)
        {
            var c = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (var array in arrays)
            {
                Buffer.BlockCopy(array, 0, c, offset, array.Length);
                offset += array.Length;
            }
            return c;
        }

        public static byte[] GetRandom(int length)
        {
            var a = new byte[length];
            RandomNumberGenerator.GetBytes(a);

            return a;
        }

        public static byte[] ExtendTo(this byte[] a, int length)
        {
            if (a.Length >= length)
                return a;

            var b = new byte[length - a.Length];

            return Combine(a, b);
        }

        public static byte[] Extract(this byte[] src, int srcIndex)
        {
            return src.Extract(srcIndex, src.Length - srcIndex);
        }

        public static byte[] Extract(this byte[] src, int srcIndex, long length)
        {
            var dest = new byte[length];
            Array.Copy(src, srcIndex, dest, 0, length);

            return dest;
        }

        public static byte[] IncrementBy(this byte[] iv, byte[] offset)
        {
            var szDiff = iv.Length - offset.Length;
            if (szDiff < 0)
                throw new ArgumentException();

            var inc = new byte[iv.Length];
            Array.Copy(iv, inc, iv.Length);

            for (var j = offset.Length - 1; j >= 0; j--)
            {
                for (int i = j + szDiff, o = offset[j]; i >= 0; i--)
                {
                    if (inc[i] + o > 255)
                    {
                        // Not enough room, will have to carry
                        inc[i] = (byte)(inc[i] + o - 256);
                        o = 1;
                    }
                    else
                    {
                        inc[i] = (byte)(inc[i] + o);
                        break;
                    }
                }
            }

            return inc;
        }
    }
}
