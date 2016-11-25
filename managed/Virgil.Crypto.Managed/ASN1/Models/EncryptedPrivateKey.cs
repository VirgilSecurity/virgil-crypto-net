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
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace Virgil.SDK.Cryptography.ASN1.Models
{
	
	public class EncryptedPrivateKey:Asn1Encodable
	{
		public byte[] KdfIV { get; private set; }
		public byte[] KeyIV { get; private set; }
		public int Iterations { get;private set; }
		public byte[] EncryptedKey { get; private set; }

		public EncryptedPrivateKey(byte[] kdfIV,byte[] keyIV,int iteration, byte[] encryptedKey)
		{
			KdfIV = kdfIV;
			KeyIV = keyIV;
			Iterations = iteration;
			EncryptedKey = encryptedKey;
		}

		public EncryptedPrivateKey(Asn1Encodable asn1)
		{
			var info = EncryptedPrivateKeyInfo.GetInstance(asn1);
			if(info.EncryptionAlgorithm.Algorithm.Id != PkcsObjectIdentifiers.IdPbeS2.Id)
				throw new Asn1Exception("Unsupported algorithm");
			EncryptedKey = info.GetEncryptedData();

			var pbeSParam = PbeS2Parameters.GetInstance(info.EncryptionAlgorithm.Parameters);
			var func = pbeSParam.KeyDerivationFunc;
			if(func.Algorithm.Id != PkcsObjectIdentifiers.IdPbkdf2.Id)
				throw new Asn1Exception("Unsupported algorithm");
			var pbkdf2 = Pbkdf2Params.GetInstance(func.Parameters);
			if (pbkdf2.Prf.Algorithm.Id != PkcsObjectIdentifiers.IdHmacWithSha384.Id)
				throw new Asn1Exception("Unsupported algorithm");
			KdfIV = pbkdf2.GetSalt();
			Iterations = pbkdf2.IterationCount.IntValue;

			if(KdfIV.Length!=16)
				throw new Asn1Exception("Kdf salt should be 16 bytes");
			if(3072 > Iterations || Iterations > 8192)
				throw new Asn1Exception("Kdf iteration should be between 3072 and 8192");

			var schema = EncryptionScheme.GetInstance(pbeSParam.EncryptionScheme);
			if(schema.Algorithm.Id != NistObjectIdentifiers.IdAes256Cbc.Id)
				throw new Asn1Exception("Unsupported algorithm");
			KeyIV = ((DerOctetString) schema.Parameters).GetOctets();
			if(KeyIV.Length!= 16)
				throw new Asn1Exception("Kdf salt should be 16 bytes");
		}

		public override Asn1Object ToAsn1Object()
		{
			var param1 = new Pbkdf2Params(KdfIV, Iterations, new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha384));
			var func = new KeyDerivationFunc(PkcsObjectIdentifiers.IdPbkdf2, param1);

			var schema = new EncryptionScheme(NistObjectIdentifiers.IdAes256Cbc, new DerOctetString(KeyIV));
			var param = new PbeS2Parameters(func, schema);
			var alg = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, param);

			return new EncryptedPrivateKeyInfo(alg, EncryptedKey).ToAsn1Object();
		}

		public static EncryptedPrivateKey GetInstance(object obj)
		{
			if (obj == null)
				return (EncryptedPrivateKey)null;

            if (obj is byte[])
            {
                return new EncryptedPrivateKey(Asn1Object.FromByteArray(Pem.Unwrap((byte[])obj)));
            }
            return obj as EncryptedPrivateKey ?? new EncryptedPrivateKey(Asn1Sequence.GetInstance(obj));
		}
	}
}