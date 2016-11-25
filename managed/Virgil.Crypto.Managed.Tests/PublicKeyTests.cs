using Org.BouncyCastle.Asn1;
using Virgil.SDK.Cryptography.ASN1.Models;
using Xunit;

namespace Virgil.SDK.Cryptography.Tests
{
	public class PublicKeyTests
	{
		
		[Fact]
		public void GetInstance_CorrectStructur()
		{
			var expectedKey = "365D819E432741FB013187D68EE92F09D398E979E8C0EAFB4D921D88DF6CB7F3".ToBytes();
			var pubKeyData = "302A300506032B6570032100365D819E432741FB013187D68EE92F09D398E979E8C0EAFB4D921D88DF6CB7F3".ToBytes();
			var pubKey= PublicKey.GetInstance(Asn1Object.FromByteArray(pubKeyData));
			Assert.Equal(expectedKey,pubKey.Key);
		}

		[Fact]
		public void ComposePublicKeyCorrectStructur()
		{
			var expected = "302A300506032B6570032100365D819E432741FB013187D68EE92F09D398E979E8C0EAFB4D921D88DF6CB7F3".ToBytes();
			var key = "365D819E432741FB013187D68EE92F09D398E979E8C0EAFB4D921D88DF6CB7F3".ToBytes();
			var actual = new PublicKey(key).GetDerEncoded();
			Assert.Equal(expected,actual);
		}
		
	}
}
