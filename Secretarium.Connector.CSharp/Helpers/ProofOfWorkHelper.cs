using System;
using System.Security.Cryptography;

namespace Secretarium.Helpers
{
    public class ProofOfWork<T> where T : HashAlgorithm
    {
        private const int _proofLength = 8;

        private readonly T _hasher;

        public byte Difficulty { get; private set; }
        public byte[] Challenge { get; private set; }

        public ProofOfWork(byte difficulty, byte[] challenge)
        {
            _hasher = (T)Activator.CreateInstance(typeof(T));

            Difficulty = difficulty;
            Challenge = challenge;
        }

        public bool Compute(out byte[] proof)
        {
            byte[] hash = null;
            byte[] buffer = new byte[_proofLength + Challenge.Length];
            Buffer.BlockCopy(Challenge, 0, buffer, _proofLength, Challenge.Length);

            var maxCounter = (uint)Math.Pow(2, Difficulty) * 10; // proba not finding ~ 1/22000

            for (uint i = 0; i < maxCounter; i++)
            {
                unsafe
                {
                    fixed (byte* ptr = &buffer[0])
                    {
                        *((uint*)ptr) = i;
                    }
                }

                hash = _hasher.ComputeHash(buffer);

                if (CountLeadingZero(hash, Difficulty) >= Difficulty)
                {
                    proof = new byte[_proofLength];
                    Buffer.BlockCopy(buffer, 0, proof, 0, proof.Length);

                    return true;
                }
            }

            proof = null;
            return false;
        }

        public bool Verify(byte[] proof)
        {
            if (proof == null || proof.Length != _proofLength)
                return false;

            var buffer = new byte[proof.Length + Challenge.Length];

            Buffer.BlockCopy(proof, 0, buffer, 0, proof.Length);
            Buffer.BlockCopy(Challenge, 0, buffer, proof.Length, Challenge.Length);

            byte[] hash = _hasher.ComputeHash(buffer);

            return CountLeadingZero(hash, Difficulty) >= Difficulty;
        }
        
        private static int CountLeadingZero(byte[] data, int limit)
        {
            if (data == null) return 0;

            int zeros = 0;
            byte value = 0;

            for (int i = 0; i < data.Length; i++)
            {
                value = data[i];

                if (value == 0)
                {
                    zeros += 8;
                }
                else
                {
                    int count = 1;

                    if (value >> 4 == 0) { count += 4; value <<= 4; }
                    if (value >> 6 == 0) { count += 2; value <<= 2; }

                    zeros += count - (value >> 7);

                    break;
                }

                if (zeros >= limit)
                {
                    break;
                }
            }

            return zeros;
        }
    }
}