﻿using Virgil.SDK.Cryptography.ASN1.Models;
using Xunit;

namespace Virgil.SDK.Cryptography.Tests
{
	public class EncryptedPrivateKeyTests
	{
		[Fact]
		public void Compose()
		{
			var data = "3081A1305D06092A864886F70D01050D3050302F06092A864886F70D01050C302204103EF40DC1E47AD6C100CC80BBE8AFFD9A020213AB300A06082A864886F70D020A301D060960864801650304012A0410F7FDE25F23816B4A025F0A4AB8EC165A0440A29CA63B131C6490624FAD1FB5466D444555E360520C5FA0F720455A6108C155A7844F3A8DF0960E29261498F1041800D28D6923357C395FB2733363EEC00956".ToBytes();
			var model = EncryptedPrivateKey.GetInstance(data);
			Assert.Equal("3EF40DC1E47AD6C100CC80BBE8AFFD9A".ToBytes(),model.KdfIV);
			Assert.Equal(5035,model.Iterations);
			Assert.Equal("F7FDE25F23816B4A025F0A4AB8EC165A".ToBytes(),model.KeyIV);
			Assert.Equal("A29CA63B131C6490624FAD1FB5466D444555E360520C5FA0F720455A6108C155A7844F3A8DF0960E29261498F1041800D28D6923357C395FB2733363EEC00956".ToBytes(),model.EncryptedKey);
		}

		[Fact]
		public void Parse()
		{
			var expected = "3081A1305D06092A864886F70D01050D3050302F06092A864886F70D01050C302204103EF40DC1E47AD6C100CC80BBE8AFFD9A020213AB300A06082A864886F70D020A301D060960864801650304012A0410F7FDE25F23816B4A025F0A4AB8EC165A0440A29CA63B131C6490624FAD1FB5466D444555E360520C5FA0F720455A6108C155A7844F3A8DF0960E29261498F1041800D28D6923357C395FB2733363EEC00956".ToBytes();
			var kdfIV = "3EF40DC1E47AD6C100CC80BBE8AFFD9A".ToBytes();
			var iterations = 5035;
			var keyIV = "F7FDE25F23816B4A025F0A4AB8EC165A".ToBytes();
			var encryptedKey ="A29CA63B131C6490624FAD1FB5466D444555E360520C5FA0F720455A6108C155A7844F3A8DF0960E29261498F1041800D28D6923357C395FB2733363EEC00956".ToBytes();
			var actual = new EncryptedPrivateKey(kdfIV, keyIV, iterations, encryptedKey).GetDerEncoded();
			Assert.Equal(expected,actual);
		}
	}
}