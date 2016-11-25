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
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;
using Virgil.SDK.Cryptography.ASN1.Models;
using Virgil.SDK.Cryptography.Ed25519;
using Virgil.SDK.Cryptography.Models;

namespace Virgil.SDK.Cryptography
{
    public class ManagedCrypto : Crypto
    {

        private const string SIGN = "VIRGIL-DATA-SIGNATURE";
        private const string CHUNK_SIZE = "chunkSize";

        public override KeyPair GenerateKeys()
        {
            var rnd = new SecureRandom();
            byte[] publicKeyBytes, privateKeyBytes;
            Ed25519.Ed25519.KeyPairFromSeed(out publicKeyBytes, out privateKeyBytes,
                rnd.GenerateSeed(Ed25519.Ed25519.PrivateKeySeedSizeInBytes));

            var pubEncoded = new PublicKey(publicKeyBytes).GetDerEncoded();
            var RecieverId = CalculateFingerprint(pubEncoded).GetValue();

            var pub = new EdPublicKey (publicKeyBytes, RecieverId);
            var priv = new EdPrivateKey (privateKeyBytes, RecieverId);
            return new KeyPair(pub, priv);
        }

        public override IPrivateKey ImportPrivateKey(byte[] keyData, string password = null)
        {
            var tmp = keyData;
            if (password != null)
            {
                var parsed = EncryptedPrivateKey.GetInstance(tmp);

                tmp = AesUtils.DecryptKeyWithPassword(password, parsed.EncryptedKey, parsed.KdfIV,
                    parsed.KeyIV, parsed.Iterations);
            }

            var privateKeyParsed = PrivateKey.GetInstance(tmp);
            var privatekeyExpanded = Ed25519.Ed25519.ExpandedPrivateKeyFromSeed(privateKeyParsed.Key);

            var publicKey = Ed25519.Ed25519.PublicKeyFromSeed(privateKeyParsed.Key);
            var encoded = new PublicKey(publicKey).GetDerEncoded();
            var fp = CalculateFingerprint(encoded).GetValue();
            var privateKey = new EdPrivateKey (privatekeyExpanded, fp);
            return privateKey;
        }


        public override IPublicKey ImportPublicKey(byte[] keyData)
        {
            var parsedKey = PublicKey.GetInstance(keyData);
            var encoded = new PublicKey(parsedKey.Key).GetDerEncoded();

            return new EdPublicKey (parsedKey.Key, CalculateFingerprint(encoded).GetValue());
        }

        public override byte[] ExportPrivateKey(IPrivateKey privateKey, string password = null)
        {
            var pk = CheckPrivateKey(privateKey);
            var encodedKey = new PrivateKey(pk.Value.Take(Ed25519.Ed25519.PrivateKeySeedSizeInBytes).ToArray()).GetDerEncoded();
            if (password != null)
            {
                byte[] keyIV;
                byte[] kdfIV;
                int iterations;
                var encryptedKey = AesUtils.EncryptKeyWithPassword(password, encodedKey, out keyIV, out kdfIV,
                    out iterations);
                encodedKey = new EncryptedPrivateKey(kdfIV, keyIV, iterations,encryptedKey).GetDerEncoded();
            }
            return encodedKey;
        }

        public override byte[] ExportPublicKey(IPublicKey publicKey)
        {
            var pub = CheckPublicKey(publicKey);
            return new PublicKey(pub.Value).GetDerEncoded();
        }

        public override IPublicKey ExtractPublicKey(IPrivateKey privateKey)
        {
            var pk = CheckPrivateKey(privateKey);
            var publicKey = Ed25519.Ed25519.PublicKeyFromSeed(pk.Value.Take(Ed25519.Ed25519.PrivateKeySeedSizeInBytes).ToArray());
            var encoded = new PublicKey(publicKey).GetDerEncoded();
            return new EdPublicKey (publicKey, CalculateFingerprint(encoded).GetValue());
           
        }

        public override byte[] Encrypt(byte[] data, params IPublicKey[] recipients)
        {
            return InternalSignThenEncrypt(data, null, recipients);
        }

        public override void Encrypt(Stream inputStream, Stream outputStream, params IPublicKey[] recipients)
        {
            byte[] randomKey;
            byte[] nonce;
            var customParams = new Dictionary<string, object>();
            customParams[CHUNK_SIZE] = ChunkCipher.DEFAULT_CHUNK_SIZE;
            var envelope = MakeEnvelope(out randomKey, recipients, customParams, out nonce);

            outputStream.Write(envelope,0, envelope.Length);
            ChunkCipher.Encrypt(inputStream, outputStream, randomKey, nonce, null, ChunkCipher.DEFAULT_CHUNK_SIZE);
        }

        public override byte[] Decrypt(byte[] cipherData, IPrivateKey privateKey)
        {
            return InternalDecryptThenVerify(cipherData, privateKey);
        }

        public override void Decrypt(Stream inputStream, Stream outputStream, IPrivateKey privateKey)
        {
            var envelope = ExtractEnvelope(inputStream);
            var decryptedKey = DecryptSymmetricKey(envelope, privateKey);
            ChunkCipher.Decrypt(inputStream,outputStream,decryptedKey, envelope.Nonce.Content, null, (int)envelope.CustomParams[CHUNK_SIZE]);
        }

        public override byte[] SignThenEncrypt(byte[] data, IPrivateKey privateKey, params IPublicKey[] recipients)
        {
            return InternalSignThenEncrypt(data, privateKey, recipients);
        }

        public override byte[] DecryptThenVerify(byte[] cipherData, IPrivateKey privateKey, IPublicKey publicKey)
        {
            return InternalDecryptThenVerify(cipherData, privateKey, publicKey);
        }

        public override bool Verify(byte[] data, byte[] signature, IPublicKey signerKey)
        {
            var pub = CheckPublicKey(signerKey);
            var hash = ComputeHash(data, Virgil.SDK.Cryptography.HashAlgorithm.SHA384);
            var decodedSignature = VirgilSign.GetInstance(signature);
            var res = Ed25519.Ed25519.Verify(decodedSignature.Sign, hash, pub.Value);
            return res;
        }

        public override bool Verify(Stream inputStream, byte[] signature, IPublicKey signerKey)
        {
            var pub = CheckPublicKey(signerKey);
            var sha384 = new SHA384Managed();
            var hash = sha384.ComputeHash(inputStream);
            var decodedSignature = VirgilSign.GetInstance(signature);
            var res = Ed25519.Ed25519.Verify(decodedSignature.Sign, hash, pub.Value);
            return res;
        }

        public override byte[] Sign(byte[] data, IPrivateKey privateKey)
        {
            var pk = CheckPrivateKey(privateKey);
            var hash = ComputeHash(data, Virgil.SDK.Cryptography.HashAlgorithm.SHA384);
            var signatureBytes = Ed25519.Ed25519.Sign(hash, pk.Value);
            return new VirgilSign(signatureBytes).GetDerEncoded();
        }

        public override byte[] Sign(Stream inputStream, IPrivateKey privateKey)
        {
            var pk = CheckPrivateKey(privateKey);
            var sha384 = new SHA384Managed();
            var hash = sha384.ComputeHash(inputStream);
            var signatureBytes = Ed25519.Ed25519.Sign(hash, pk.Value);
            return new VirgilSign(signatureBytes).GetDerEncoded();
        }

        public override Fingerprint CalculateFingerprint(byte[] data)
        {
            return new Fingerprint(ComputeHash(data, Virgil.SDK.Cryptography.HashAlgorithm.SHA256));

        }

        public override byte[] ComputeHash(byte[] data, Virgil.SDK.Cryptography.HashAlgorithm algorithm)
        {
            if (!Hash.SupportedHashes.ContainsKey(algorithm))
            {
                throw new NotImplementedException();
            }

            using (var hash = Hash.SupportedHashes[algorithm]())
            {
                return hash.ComputeHash(data);
            }
                
        }

        private byte[] InternalSignThenEncrypt(byte[] data, IPrivateKey privateKey, params IPublicKey[] recipients)
        {
            var customParams = new Dictionary<string,object>();
            if (privateKey != null) //first, sign the plaintext if we have a private key
            {
                customParams.Add(SIGN,Sign(data, privateKey));
            }

            byte[] randomKey;
            byte[] nonce;
            var envelope = MakeEnvelope(out randomKey, recipients, customParams, out nonce);
            var ciphertext = new byte[data.Length + AesUtils.GCM_TAG_SIZE];

            AesUtils.EncryptWithAesGcm(data, 0, data.Length, ciphertext, 0, ciphertext.Length, randomKey, nonce);


            var message = new byte[envelope.Length + ciphertext.Length];
            Buffer.BlockCopy(envelope, 0, message, 0, envelope.Length);
            Buffer.BlockCopy(ciphertext, 0, message, envelope.Length, ciphertext.Length);
            return message;
        }

        private byte[] MakeEnvelope(out byte[] randomKey, IPublicKey[] recipients, Dictionary<string,object> customParam , out byte[] nonce)
        {
            var rnd = new SecureRandom();
            randomKey = new byte[32];
            nonce = new byte[12];

            rnd.NextBytes(randomKey);
            rnd.NextBytes(nonce);

            var key = randomKey;
            var recs = recipients.Select(r =>
            {
                var pub = CheckPublicKey(r);

                var rec = ECIES.EncryptSymmetricKey(pub.RecieverId, pub.Value, key);
                var model = new PublicKeyRecipient(rec.Id, rec.EphemeralPublicKey, rec.Tag, rec.IV,
                    rec.EncryptedSymmetricKey);
                return model;
            });
            var nonceModel = new Nonce(nonce);
            var envelope = new Envelope(recs, nonceModel, customParam).GetDerEncoded();
            return envelope;
        }


        private byte[] InternalDecryptThenVerify(byte[] data, IPrivateKey privateKey, IPublicKey publicKey = null)
        {

            var stream = new MemoryStream(data);
            var envelope = ExtractEnvelope(stream);

            var decryptedSymmetricKey = DecryptSymmetricKey(envelope, privateKey);

            var ciphertext = new byte[stream.Length - stream.Position];
            stream.Read(ciphertext, 0, ciphertext.Length);
            var plaintext = new byte[ciphertext.Length - AesUtils.GCM_TAG_SIZE];
            AesUtils.DecryptAesGcm(ciphertext, 0, ciphertext.Length, plaintext,0, plaintext.Length, decryptedSymmetricKey, envelope.Nonce.Content);

            if (publicKey != null)
            {
	            if (!envelope.CustomParams.ContainsKey(SIGN))
		            throw new ArgumentException("signature");
	            var res = Verify(plaintext, envelope.CustomParams[SIGN] as byte[], publicKey);
                if (!res)
                {
                    throw new ArgumentException("signature");
                }
            }
            return plaintext;

        }


        private Envelope ExtractEnvelope(Stream inStream)
        {
            var obj = Asn1Object.FromStream(inStream);
            var envelope = Envelope.GetInstance(obj);
            return envelope;
        }

        private byte[] DecryptSymmetricKey(Envelope envelope, IPrivateKey privateKey)
        {
            var pk = CheckPrivateKey(privateKey);
            foreach (var recipient in envelope.Recipients)
            {
                var rec = recipient as PublicKeyRecipient;
                if (rec != null)
                {
                    var pkRec = rec;
                    if (CryptoBytes.ConstantTimeEquals(pk.RecieverId, pkRec.Id))
                    {
                        var decryptedSymmetricKey = ECIES.DecryptSymmetricKey(pkRec, pk.Value);
                        return decryptedSymmetricKey;
                    }
                }
            }
            throw new ArgumentException("key");
        }

        private
            EdPrivateKey CheckPrivateKey(IPrivateKey privateKey)
        {
            if (privateKey == null)
            {
                throw new ArgumentNullException(nameof(privateKey));
            }
            if (!(privateKey is EdPrivateKey))
            {
                throw new ArgumentException(nameof(privateKey));
            }
            return (EdPrivateKey)privateKey;
        }

        private EdPublicKey CheckPublicKey(IPublicKey publicKey)
        {
            if (publicKey == null)
            {
                throw new ArgumentNullException(nameof(publicKey));
            }
            if (!(publicKey is EdPublicKey))
            {
                throw new ArgumentException(nameof(publicKey));
            }
            return (EdPublicKey)publicKey;
        }
    }
}
