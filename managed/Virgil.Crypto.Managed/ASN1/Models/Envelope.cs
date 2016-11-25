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

using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using ContentInfo = Org.BouncyCastle.Asn1.Pkcs.ContentInfo;

namespace Virgil.SDK.Cryptography.ASN1.Models
{
	public class Envelope : Asn1Encodable
	{
		public Envelope(IEnumerable<Asn1Encodable> recipients, Nonce nonce,Dictionary<string,object> customParams = null)
		{
			Recipients = recipients;
			Nonce = nonce;
			CustomParams = customParams;
		}

		public Envelope(Asn1Sequence asn1Sequence)
		{
			CustomParams = new Dictionary<string, object>();
			var v = DerInteger.GetInstance(asn1Sequence[0]);
			if(v.Value.IntValue != 0)
				throw new Asn1ParsingException("Unsupported version");
			var info = ContentInfo.GetInstance(asn1Sequence[1]);
			if (info.ContentType.Id != PkcsObjectIdentifiers.EnvelopedData.Id)
				throw new Asn1ParsingException("Unsupported version");
			var seq = (DerSequence) info.Content;

			v = DerInteger.GetInstance(seq[0]);
			if (v.Value.IntValue != 2)
				throw new Asn1ParsingException("Unsupported version");

			var recipientsSet = (DerSet) seq[1];
			var recipients = new List<Asn1Encodable>();
			foreach (Asn1Encodable recipient in recipientsSet)
			{
				var tag = recipient as DerTaggedObject;
				if ((tag != null) && (tag.TagNo == 3))
					recipients.Add(PasswordRecipient.GetInstance(tag));
				else if (recipient is DerSequence)
					recipients.Add(PublicKeyRecipient.GetInstance(recipient));
				else
					throw new Asn1Exception("Unsupported recipient");
			}
			Recipients = recipients;
			Nonce = Nonce.GetInstance(seq[2]);
			if (asn1Sequence.Count == 3)
			{
				DecodeCustomParams(Asn1TaggedObject.GetInstance(asn1Sequence[2]));
			}

		}

		public IEnumerable<Asn1Encodable> Recipients { get; }
		public Nonce Nonce { get; }
		public Dictionary<string, object> CustomParams { get; private set; }

		public override Asn1Object ToAsn1Object()
		{
			var v = new Asn1EncodableVector(new DerInteger(0),
				new ContentInfo(PkcsObjectIdentifiers.EnvelopedData,
					new DerSequence(new DerInteger(2), new DerSet(Recipients.ToArray()),
						Nonce
					)));
			if(CustomParams!=null && CustomParams.Any())
				v.Add(EncodeCustomParam());
			return new DerSequence(v);
		}

		private Asn1Encodable EncodeCustomParam()
		{
			var v = new Asn1EncodableVector();
			foreach (var p in CustomParams)
			{
				if (p.Value is byte[])
					v.Add(new DerSequence(
						new DerUtf8String(p.Key),
						new DerTaggedObject(true, 2, new DerOctetString((byte[])p.Value)
					)));
				else if (p.Value is int)
				{
					v.Add(new DerSequence(
						new DerUtf8String(p.Key),
						new DerTaggedObject(true, 0, new DerInteger((int)p.Value))));
				}
			}
			return new DerTaggedObject(true, 0, new DerSet(v));
		}


		private void DecodeCustomParams(Asn1TaggedObject asn1)
		{
			
			if (asn1.TagNo != 0)
				throw new Asn1ParsingException("Unsupported signature formata");
			var set = Asn1Set.GetInstance(asn1.GetObject());
			foreach (Asn1Encodable item in set)
			{
				var seq = Asn1Sequence.GetInstance(item);
				var info = DerUtf8String.GetInstance(seq[0]);
				var key = info.GetString();

				var tag = Asn1TaggedObject.GetInstance(seq[1]);
				switch (tag.TagNo)
				{
					case 2:
						CustomParams.Add(key, GetByteValue(tag));
						break;
					case 0:
						CustomParams.Add(key, GetIntValue(tag));
						break;
					default:
						throw new Asn1Exception("unsupported tag parameter");

				}
				
			}
		}

		private object GetIntValue(Asn1TaggedObject tag)
		{
			return DerInteger.GetInstance(tag, true).Value.IntValue;
		}

		private object GetByteValue(Asn1TaggedObject tag)
		{
		    return Asn1OctetString.GetInstance(tag.GetObject()).GetOctets();
		}

		public static Envelope GetInstance(object obj)
		{
			if (obj == null)
				return null;
			return obj as Envelope ?? new Envelope(Asn1Sequence.GetInstance(obj));
		}
	}
}