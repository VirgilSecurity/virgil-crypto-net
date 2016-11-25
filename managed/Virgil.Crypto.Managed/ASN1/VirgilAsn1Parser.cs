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

using System.IO;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;

namespace Virgil.SDK.Cryptography.ASN1
{

    public class MessageModel
    {
        public byte[] KdfIV { get; set; }
        public int Iterations { get; set; }
        public byte[] KeyIV { get; set; }
        public byte[] EncryptedKey { get; set; }
        public byte[] Nonce { get; set; }
        public byte[] CipherText { get; set; }
    }

    public class VirgilAsn1Parser
    {
        public static MessageModel ParseMessage(byte[] message)
        {
            var stream = new MemoryStream(message);
            var obj = (Asn1Sequence)Asn1Object.FromStream(stream);
            var cipherText = new byte[stream.Length - stream.Position];
            stream.Read(cipherText, 0, cipherText.Length);

            var contentInfo = ContentInfo.GetInstance(obj[1]);
            var envelope = GetEnvelopeData(Asn1Sequence.GetInstance(contentInfo.Content));
            envelope.CipherText = cipherText;
            return envelope;
        }

        private static MessageModel GetEnvelopeData(Asn1Sequence seq)
        {
            var index = 0;
            object version = seq[index++];
            var recipientInfos = Asn1Set.GetInstance(seq[index++]);
            var result = new MessageModel();
            foreach (var info in recipientInfos)
            {
                var recepient = PasswordRecipientInfo.GetInstance((Asn1TaggedObject) info, true);
                var paramz = PbeS2Parameters.GetInstance(recepient.KeyEncryptionAlgorithm.Parameters);
                var kdfParams = (Pbkdf2Params) paramz.KeyDerivationFunc.Parameters;
                result.KdfIV = kdfParams.GetSalt();
                result.Iterations = kdfParams.IterationCount.IntValue;
                result.KeyIV = ((Asn1OctetString) paramz.EncryptionScheme.Parameters).GetOctets();
                result.EncryptedKey = recepient.EncryptedKey.GetOctets();
                break;
            }

            var nonce = GetEncryptedContentInfo((Asn1Sequence)seq[index]);
            result.Nonce = nonce;
            return result;
        }

        private static byte[] GetEncryptedContentInfo(Asn1Sequence seq)
        {
            var contentEncryptionAlgorithm = AlgorithmIdentifier.GetInstance(seq[1]);
            return ((Asn1OctetString)contentEncryptionAlgorithm.Parameters).GetOctets();
        }

        public static byte[] ComposeMessage(MessageModel model)
        {
            var info = MakeEncryptedContentInfo(model.Nonce);
            var recepient = MakeRecepient(model.KdfIV, model.Iterations, model.KeyIV, model.EncryptedKey);
            var recepients = new Asn1EncodableVector();
            recepients.Add(recepient);
            var v = new Asn1EncodableVector(new DerInteger(3)) {{new DerSet(recepients), info}};
            var contentInfo = new ContentInfo(
                CmsObjectIdentifiers.EnvelopedData,
                new BerSequence(v));
            var vec = new Asn1EncodableVector(new DerInteger(0)) {contentInfo};
            var envelope = new DerSequence(vec);
            return envelope.GetDerEncoded().Concat(model.CipherText).ToArray();
        }

        private static Asn1Encodable MakeRecepient(byte[] kdfIv, int iterations, byte[] keyIv, byte[] encryptedKey)
        {
            var keyDerevationParameters = new Pbkdf2Params(kdfIv, iterations, new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha384));
            var func = new KeyDerivationFunc(PkcsObjectIdentifiers.IdPbkdf2, keyDerevationParameters);
            var scheme = new EncryptionScheme(NistObjectIdentifiers.IdAes256Cbc, new DerOctetString(keyIv));
            var keyEncryptionParameters = new PbeS2Parameters(func, scheme);
            var keyEncryptionAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, keyEncryptionParameters);
            var info = new PasswordRecipientInfo(keyEncryptionAlgorithm, new DerOctetString(encryptedKey));
            return new DerTaggedObject(true, 3, info);
        }

        private static EncryptedContentInfo MakeEncryptedContentInfo(byte[] nonce)
        {
            var contentType = PkcsObjectIdentifiers.Data;
            var algo = new AlgorithmIdentifier(NistObjectIdentifiers.IdAes256Gcm,new DerOctetString(nonce));
            return new EncryptedContentInfo(contentType, algo, null);
        }
    }
}