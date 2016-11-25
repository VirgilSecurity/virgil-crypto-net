using System;
using Chaos.NaCl;

namespace ManagedCrypto
{
    public static class Signatures
    {
        public static byte[] Sign(byte[] message, byte[] privateKey)
        {
            return Ed25519.Sign(message, privateKey);
        }

        public static bool Verify(byte[] signature, byte[] message, byte[] publicKey)
        {
            return Ed25519.Verify(signature, message, publicKey);
        }
    }
}