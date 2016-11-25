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
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Virgil.SDK.Cryptography.ASN1.Models;

namespace Virgil.SDK.Cryptography
{
    public static class ECIES
    {

        public static PublicKeyRecipient EncryptSymmetricKey(byte[] id, byte[] publicKey, byte[] symmetricKey)
        {
            if (publicKey == null)
                throw new ArgumentNullException("publicKey");
            if (symmetricKey == null)
                throw new ArgumentNullException("symmetricKey");
            if (publicKey.Length != Ed25519.Ed25519.PublicKeySizeInBytes)
                throw new ArgumentException("publicKey");
            var random = new SecureRandom();
            var seed = random.GenerateSeed(Ed25519.Ed25519.PrivateKeySeedSizeInBytes);
            byte[] ephPub, ephPriv;
            Ed25519.Ed25519.KeyPairFromSeed(out ephPub, out ephPriv, seed);

            var shared = Ed25519.Ed25519.KeyExchange(publicKey, ephPriv);

            var kdf = new Kdf2BytesGenerator(new Sha384Digest());
            kdf.Init(new KdfParameters(shared, null));
            var derivedKeys = new byte[80];
            kdf.GenerateBytes(derivedKeys, 0, 80); // 32 bytes - AES key + 48 bytes HMAC key

            var keyEncryptionKey = derivedKeys.Take(32).ToArray();
            byte[] keyIv;

            var encryptedKey = AesUtils.EncryptWithAesCbc(symmetricKey, keyEncryptionKey, out keyIv);

            byte[] tag;
            using (var macFunc = new HMACSHA384(derivedKeys.Skip(32).ToArray()))
            {
                macFunc.Initialize();
                tag = macFunc.ComputeHash(encryptedKey);
            }
            
            return new PublicKeyRecipient(id, ephPub,tag,keyIv,encryptedKey);
        }

        public static byte[] DecryptSymmetricKey(PublicKeyRecipient model, byte[] privateKey)
        {
            if (privateKey?.Length !=Ed25519.Ed25519.ExpandedPrivateKeySizeInBytes)
                throw new ArgumentException("privateKey");
            if (model == null)
                throw new ArgumentNullException("model");
            if (model.EphemeralPublicKey?.Length != Ed25519.Ed25519.PublicKeySizeInBytes)
                throw new ArgumentException("EphemeralPublicKey");
            if (model.EncryptedSymmetricKey == null || model.EncryptedSymmetricKey.Length == 0)
                throw new ArgumentException("EncryptedSymmetricKey");
            if (model.IV?.Length != 16)
                throw new ArgumentException("IV");
            if (model.Tag.Length != 48)
                throw new ArgumentException("Tag");

            var shared = Ed25519.Ed25519.KeyExchange(model.EphemeralPublicKey, privateKey);

            var kdf = new Kdf2BytesGenerator(new Sha384Digest());
            kdf.Init(new KdfParameters(shared, null));
            var derivedKeys = new byte[80];
            kdf.GenerateBytes(derivedKeys, 0, 80); // 32 bytes - AES key + 48 bytes HMAC key

            byte[] tag;
            using (var macFunc = new HMACSHA384(derivedKeys.Skip(32).ToArray()))
            {
                macFunc.Initialize();
                tag = macFunc.ComputeHash(model.EncryptedSymmetricKey);
            }
            if (!Arrays.AreEqual(tag, model.Tag))
            {
                throw new ArgumentException("Tag");
            }

            return AesUtils.DecryptWithAesCBC(model.EncryptedSymmetricKey, derivedKeys.Take(32).ToArray(), model.IV);
        }
    }
}
