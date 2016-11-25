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
	public class Nonce : Asn1Encodable
	{
		public byte[] Content { get; set; }

		public Nonce( byte[] content)
		{
			Content = content;
		}

		public Nonce(Asn1Sequence asn1Sequence)
		{
			var info = EncryptedContentInfo.GetInstance(asn1Sequence);
			if(PkcsObjectIdentifiers.Data.Id!= info.ContentType.Id)
				throw new Asn1Exception("Unsupported algorithm");
			
			if(info.ContentEncryptionAlgorithm.Algorithm.Id!= NistObjectIdentifiers.IdAes256Gcm.Id)
				throw new Asn1Exception("Unsupported algorithm");
			Content = ((DerOctetString) info.ContentEncryptionAlgorithm.Parameters).GetOctets();
		}

		public override Asn1Object ToAsn1Object()
		{
			var algo = new AlgorithmIdentifier(NistObjectIdentifiers.IdAes256Gcm,
				new DerOctetString(Content));
			return new EncryptedContentInfo(PkcsObjectIdentifiers.Data, algo, null).ToAsn1Object();
		}

		public static Nonce GetInstance(object obj)
		{
			if (obj == null)
				return null;
			return obj as Nonce ?? new Nonce(Asn1Sequence.GetInstance(obj));
		}
	}
}