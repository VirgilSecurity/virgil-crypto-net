#region Copyright (C) Virgil Security Inc.
// Copyright (C) 2015-2016 Virgil Security Inc.
// 
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions 
// are met:
// 
//   (1) Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//   
//   (2) Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in
//   the documentation and/or other materials provided with the
//   distribution.
//   
//   (3) Neither the name of the copyright holder nor the names of its
//   contributors may be used to endorse or promote products derived 
//   from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
#endregion

using System;
using System.IO;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

namespace Virgil.SDK.Cryptography
{
    public static class ChunkCipher
    {
        
        public const int DEFAULT_CHUNK_SIZE = 1024*1024;

        public static void Encrypt(Stream inStream, Stream outStream, byte[] key, byte[] nonce, byte[] ad, int chunkSize)
        {
            var counter = new byte[nonce.Length];
            var chunkNonce = new byte[nonce.Length];
            var buf = new byte[chunkSize + AesUtils.GCM_TAG_SIZE];

            int read;
            var engine = new AesFastEngine();
            var gcmCipher = new GcmBlockCipher(engine);
            while ((read = inStream.Read(buf, 0, buf.Length- AesUtils.GCM_TAG_SIZE)) > 0)
            {
                XorArrays(chunkNonce, nonce, counter);
                AesUtils.EncryptWithAesGcm(buf, 0, read, buf, 0, read+ AesUtils.GCM_TAG_SIZE, key, chunkNonce, ad, gcmCipher);
                outStream.Write(buf, 0, read + AesUtils.GCM_TAG_SIZE);
                IncrementCounter(counter);
            }
        }


        public static void Decrypt(Stream inStream, Stream outStream, byte[] key, byte[] nonce, byte[] ad, int chunkSize)
        {
            var counter = new byte[nonce.Length];
            var chunkNonce = new byte[nonce.Length];
            var buf = new byte[chunkSize+ AesUtils.GCM_TAG_SIZE];

            int read;
            while ((read = inStream.Read(buf, 0, buf.Length)) > 0)
            {
                if (read < AesUtils.GCM_TAG_SIZE + 1)
                {
                    throw new Exception("Chunk is too small");
                }
                XorArrays(chunkNonce, nonce, counter);
                AesUtils.DecryptAesGcm(buf, 0, read, buf, 0, read- AesUtils.GCM_TAG_SIZE, key, chunkNonce, ad);
                outStream.Write(buf, 0, read - AesUtils.GCM_TAG_SIZE);
                IncrementCounter(counter);
            }
        }

        private static void XorArrays(byte[] res, byte[] a, byte[] b)
        {
            for (var i = 0; i < res.Length; i++)
            {
                res[i] = (byte) (a[i] ^ b[i]);
            }
        }

        private static void IncrementCounter(byte[] counter)
        {
            for (var i = counter.Length - 1; i >= 0; i--)
            {
                counter[i]++;

                if (counter[i] != 0)
                {
                    break;

                }
            }
        }
    }
}
