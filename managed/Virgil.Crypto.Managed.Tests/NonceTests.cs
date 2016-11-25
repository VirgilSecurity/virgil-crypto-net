using Org.BouncyCastle.Asn1;
using Virgil.SDK.Cryptography.ASN1.Models;
using Xunit;

namespace Virgil.SDK.Cryptography.Tests
{
	public class NonceTests
	{
		[Fact]
		public void Parse()
		{
			var data = "302606092A864886F70D0107013019060960864801650304012E040C125556F30B83791A795B8221".ToBytes();
			var nonce = Nonce.GetInstance(Asn1Object.FromByteArray(data));
			
			Assert.Equal("125556F30B83791A795B8221".ToBytes(), nonce.Content);
		}

		[Fact]
		public void Compose()
		{
			var expected = "302606092A864886F70D0107013019060960864801650304012E040C125556F30B83791A795B8221".ToBytes();
			var actual = new Nonce("125556F30B83791A795B8221".ToBytes())
				.GetDerEncoded();
			Assert.Equal(expected,actual);
		}
	}
}