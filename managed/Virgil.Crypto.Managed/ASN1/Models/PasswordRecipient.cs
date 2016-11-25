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

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Virgil.SDK.Cryptography.ASN1.Models
{
	public class PasswordRecipient : Asn1Encodable
	{
		public byte[] KdfIV { get; private set; }
		public byte[] KeyIV { get; private set; }
		public int Iterations { get; private set; }
		public byte[] EncryptedKey { get; private set; }

		public PasswordRecipient(byte[] kdfIv, int iterations, byte[] keyIv, byte[] encryptedKey)
		{
			KdfIV = kdfIv;
			Iterations = iterations;
			KeyIV = keyIv;
			EncryptedKey = encryptedKey;
		}

		public PasswordRecipient(Asn1TaggedObject tag)
		{
				var recepient = PasswordRecipientInfo.GetInstance(tag, true);
			if(recepient.Version.Value.IntValue!= 0)
				throw new Asn1Exception("Unsupported recipient version");
			if (recepient.KeyEncryptionAlgorithm.Algorithm.Id != PkcsObjectIdentifiers.IdPbeS2.Id)
					throw new Asn1Exception("Unsupported algorithm");

				var paramz = PbeS2Parameters.GetInstance(recepient.KeyEncryptionAlgorithm.Parameters);
				if (paramz.EncryptionScheme.Algorithm.Id != NistObjectIdentifiers.IdAes256Cbc.Id)
					throw new Asn1Exception("Unsupported algorithm");
				if (paramz.KeyDerivationFunc.Algorithm.Id != PkcsObjectIdentifiers.IdPbkdf2.Id)
					throw new Asn1Exception("Unsupported algorithm");

				var kdfParams = (Pbkdf2Params)paramz.KeyDerivationFunc.Parameters;
				if (kdfParams.Prf.Algorithm.Id != PkcsObjectIdentifiers.IdHmacWithSha384.Id)
					throw new Asn1Exception("Unsupported algorithm");


				KdfIV = kdfParams.GetSalt();
				Iterations = kdfParams.IterationCount.IntValue;
				KeyIV = ((Asn1OctetString)paramz.EncryptionScheme.Parameters).GetOctets();
				EncryptedKey = recepient.EncryptedKey.GetOctets();				
		}
		
		public override Asn1Object ToAsn1Object()
		{
			var keyDerevationParameters = new Pbkdf2Params(KdfIV, Iterations,
				new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha384));
			var func = new KeyDerivationFunc(PkcsObjectIdentifiers.IdPbkdf2, keyDerevationParameters);
			var scheme = new EncryptionScheme(NistObjectIdentifiers.IdAes256Cbc, new DerOctetString(KeyIV));
			var keyEncryptionParameters = new PbeS2Parameters(func, scheme);
			var keyEncryptionAlgorithm = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, keyEncryptionParameters);
			var info = new PasswordRecipientInfo(keyEncryptionAlgorithm, new DerOctetString(EncryptedKey));
			return new DerTaggedObject(true, 3, info);
		}

		public static PasswordRecipient GetInstance(object obj)
		{
			if (obj == null)
				return (PasswordRecipient)null;
			return obj as PasswordRecipient ?? new PasswordRecipient(Asn1TaggedObject.GetInstance(obj));
		}
	}
}