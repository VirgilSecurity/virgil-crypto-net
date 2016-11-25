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
	public class PublicKeyRecipient : Asn1Encodable
	{
		private static readonly DerObjectIdentifier Kdf2 = new DerObjectIdentifier("1.0.18033.2.5.2");

		public PublicKeyRecipient(byte[] id, byte[] ephemeralPublicKey, byte[] tag, byte[] iv, byte[] encryptedSymmetricKey)
		{
			Id = id;
			EphemeralPublicKey = ephemeralPublicKey;
			Tag = tag;
			IV = iv;
			EncryptedSymmetricKey = encryptedSymmetricKey;
		}

		public PublicKeyRecipient(Asn1Sequence asn1Sequence)
		{
			var ktri = KeyTransRecipientInfo.GetInstance(asn1Sequence);
			if (ktri.Version.Value.IntValue != 2)
				throw new Asn1Exception("Unsupported public key recipient version");
			if (ktri.KeyEncryptionAlgorithm.Algorithm.Id != VirgilIdentifier.Ed25519.Id)
				throw new Asn1Exception("Unsupported algorithm");

			Id = ((DerOctetString) ktri.RecipientIdentifier.ID).GetOctets();

			var seq = (DerSequence) Asn1Object.FromStream(ktri.EncryptedKey.GetOctetStream());
			var v = DerInteger.GetInstance(seq[0]);
			if (v.Value.IntValue != 0)
				throw new Asn1Exception("Unsupported algrithm version");

			var seqEphemeralPublicKey = (DerSequence) seq[1];
			if (AlgorithmIdentifier.GetInstance(seqEphemeralPublicKey[0]).Algorithm.Id != VirgilIdentifier.Ed25519.Id)
				throw new Asn1Exception("Unsupported algorithm");
			EphemeralPublicKey = DerBitString.GetInstance(seqEphemeralPublicKey[1]).GetBytes();

			var algoKdf = AlgorithmIdentifier.GetInstance(seq[2]);
			if (algoKdf.Algorithm.Id != Kdf2.Id)
				throw new Asn1Exception("Unsupported algorithm");
			if (DerObjectIdentifier.GetInstance(Asn1Sequence.GetInstance(algoKdf.Parameters)[0]).Id != NistObjectIdentifiers.IdSha384.Id)
				throw new Asn1Exception("Unsupported algorithm");

			var tag = (DerSequence) Asn1Sequence.GetInstance(seq[3]);
			if (AlgorithmIdentifier.GetInstance(tag[0]).Algorithm.Id != NistObjectIdentifiers.IdSha384.Id)
				throw new Asn1Exception("Unsupported algorithm");
			Tag = ((DerOctetString) tag[1]).GetOctets();

			var symetricKey = Asn1Sequence.GetInstance(seq[4]);
			var scheme = EncryptionScheme.GetInstance(symetricKey[0]);
			if (scheme.Algorithm.Id != NistObjectIdentifiers.IdAes256Cbc.Id)
				throw new Asn1Exception("Unsupported algorithm");
			IV = ((DerOctetString) scheme.Parameters).GetOctets();

			EncryptedSymmetricKey = Asn1OctetString.GetInstance(symetricKey[1]).GetOctets();
		}

		public byte[] EncryptedSymmetricKey { get; }
		public byte[] Id { get; }
		public byte[] EphemeralPublicKey { get; }
		public byte[] IV { get; }
		public byte[] Tag { get; }


		public static PublicKeyRecipient GetInstance(object obj)
		{
			if (obj == null)
				return null;
			return obj as PublicKeyRecipient ?? new PublicKeyRecipient(Asn1Sequence.GetInstance(obj));
		}

		public override Asn1Object ToAsn1Object()
		{
			var rid = new RecipientIdentifier(new DerTaggedObject(true, 0, new DerOctetString(Id)));
			var algorithm = new AlgorithmIdentifier(VirgilIdentifier.Ed25519);

			var octetString = new DerOctetString(new DerSequence(new DerInteger(0),
				new DerSequence(
					new DerSequence(VirgilIdentifier.Ed25519), new DerBitString(EphemeralPublicKey)),
				new AlgorithmIdentifier(Kdf2,
					new DerSequence(NistObjectIdentifiers.IdSha384, DerNull.Instance)),
				new DerSequence(
					new AlgorithmIdentifier(NistObjectIdentifiers.IdSha384, DerNull.Instance),
					new DerOctetString(Tag)),
				new DerSequence(
					new EncryptionScheme(NistObjectIdentifiers.IdAes256Cbc, new DerOctetString(IV)),
					new DerOctetString(EncryptedSymmetricKey))));
			return new KeyTransRecipientInfo(rid, algorithm, octetString).ToAsn1Object();
		}
	}
}