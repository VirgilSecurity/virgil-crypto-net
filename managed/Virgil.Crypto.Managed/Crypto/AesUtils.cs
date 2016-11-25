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
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Virgil.SDK.Cryptography
{
    public class AesUtils
    {
        public const int GCM_TAG_SIZE = 16;

        public static byte[] DecryptKeyWithPassword(string password, byte[] encryptedKey, byte[] kdfIV, byte[] keyIV, int iterations)
        {
            var keyEncryptionKey = PBKdf2.GetHash(password, kdfIV, iterations, 32);

            var decryptedKey = DecryptWithAesCBC(encryptedKey, keyEncryptionKey, keyIV);
            return decryptedKey;
        }

        public static byte[] DecryptWithAesCBC(byte[] ciphertext, byte[] key, byte[] IV)
        {
            using (var aes = new AesCryptoServiceProvider())
            using (var decyptor = aes.CreateDecryptor(key, IV))
            using (var msi = new MemoryStream(ciphertext))
            using (var cs = new CryptoStream(msi, decyptor, CryptoStreamMode.Read))
            using (var mso = new MemoryStream())
            {
                int read;
                byte[] buffer = new byte[64];
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    mso.Write(buffer, 0, read);
                }
                return mso.ToArray();
            }

        }

        public static byte[] EncryptKeyWithPassword(string password, byte[] plainKey, out byte[] keyIV, out byte[] kdfIV,
            out int iterations)
        {
            var rnd = new SecureRandom();
            kdfIV = new byte[16];
            iterations = rnd.Next(3072, 8192);
            rnd.NextBytes(kdfIV);

            var keyEncryptionKey = PBKdf2.GetHash(password, kdfIV, iterations, 32);
            var encryptedKey = EncryptWithAesCbc(plainKey, keyEncryptionKey, out keyIV);

            return encryptedKey;

        }

        public static byte[] EncryptWithAesCbc(byte[] plaintext, byte[] key, out byte[] IV)
        {
            var rnd = new SecureRandom();
            IV = new byte[16];
            rnd.NextBytes(IV);

            using (var aes = new AesCryptoServiceProvider())
            using (var encryptor = aes.CreateEncryptor(key, IV))
            using (var ms = new MemoryStream())
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                cs.Write(plaintext, 0, plaintext.Length);
                cs.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        public static void EncryptWithAesGcm(byte[] data, int inOff, int inLen, byte[] outBuf, int outOff, int outLen, byte[] randomKey, byte[] nonce, byte[] ad = null, IAeadBlockCipher cipher = null)
        {
            IAeadBlockCipher gcmCipher;
            if (cipher != null)
            {
                gcmCipher = cipher;
            }
            else
            {
                var engine = new AesFastEngine();
                gcmCipher = new GcmBlockCipher(engine);
            }
            
            var keyParam = new KeyParameter(randomKey);
            var cipherParams = new AeadParameters(keyParam, 128, nonce, ad);

            gcmCipher.Init(true, cipherParams);
            if (outBuf == null || outLen < gcmCipher.GetOutputSize(inLen))
            {
                throw new Exception("Output buffer must be the size of input buffer + GCM tag size");
            }
            var resultLength = gcmCipher.ProcessBytes(data, inOff, inLen, outBuf, outOff);
            resultLength += gcmCipher.DoFinal(outBuf, resultLength+outOff);
            if (resultLength != outLen)
            {
                throw new Exception("AES GCM buffers size mismatch");
            }
        }

        public static void DecryptAesGcm(byte[] data, int inOff, int inLen, byte[] outBuff, int outOff, int outLen, byte[] key, byte[] nonce, byte[] ad = null, IAeadBlockCipher cipher = null)
        {
            IAeadBlockCipher gcmCipher;
            if (cipher != null)
            {
                gcmCipher = cipher;
            }
            else
            {
                var engine = new AesFastEngine();
                gcmCipher = new GcmBlockCipher(engine);
            }

            var keyParam = new KeyParameter(key);
            var cipherParams = new AeadParameters(keyParam, 128, nonce, ad);

            gcmCipher.Init(false, cipherParams);
            if (outBuff == null || outLen < gcmCipher.GetOutputSize(outLen))
            {
                throw new Exception("Output buffer must be the size of input buffer - GCM tag size");
            }
            var length = gcmCipher.ProcessBytes(data, inOff, inLen, outBuff, outOff);
            length += gcmCipher.DoFinal(outBuff, length+outOff);

            if (length != outLen)
            {
                throw new Exception("AES GCM buffers size mismatch");
            }

        }
    }
}