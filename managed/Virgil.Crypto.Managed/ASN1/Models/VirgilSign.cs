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
using Org.BouncyCastle.Asn1.X509;

namespace Virgil.SDK.Cryptography.ASN1.Models
{
	public class VirgilSign : Asn1Encodable
	{
		public byte[] Sign { get; }

		public VirgilSign( byte[] sign)
		{
			Sign = sign;
		}

		public VirgilSign(Asn1Encodable asn1)
		{
			var seqInfo = Asn1Sequence.GetInstance(asn1);

			var alg = AlgorithmIdentifier.GetInstance(seqInfo[0]);
			if(alg.Algorithm.Id != NistObjectIdentifiers.IdSha384.Id)
				throw new Asn1Exception("Unsupported algorithm");
			Sign = Asn1OctetString.GetInstance(seqInfo[1]).GetOctets();
		}

		public override Asn1Object ToAsn1Object()
		{
			return 
					new DerSequence(
						new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance),
						new DerOctetString(Sign)
					);
		}

		public static VirgilSign GetInstance(object obj)
		{
			if (obj == null)
				return null;

            if (obj is byte[])
            {
                return new VirgilSign(Asn1Object.FromByteArray((byte[])obj));
            }
            return obj as VirgilSign ?? new VirgilSign(Asn1Sequence.GetInstance(obj));
		}
	}
}