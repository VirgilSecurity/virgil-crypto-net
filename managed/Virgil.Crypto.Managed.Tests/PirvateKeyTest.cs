using Virgil.SDK.Cryptography.ASN1.Models;
using Xunit;

namespace Virgil.SDK.Cryptography.Tests
{
	public class PirvateKeyTest
	{
		[Fact]
		public void Compose()
		{
			var privateKeyData = "302E020100300506032B6570042204201B9DD8299657F00D46F60F036727161713EE88F1F1058D9FF629FE38B172C105".ToBytes();
			var key = "1B9DD8299657F00D46F60F036727161713EE88F1F1058D9FF629FE38B172C105".ToBytes();
			var k = PrivateKey.GetInstance(privateKeyData);
			Assert.Equal(key,k.Key);
		}

		[Fact]
		public void Parse()
		{
			var expected = "302E020100300506032B6570042204201B9DD8299657F00D46F60F036727161713EE88F1F1058D9FF629FE38B172C105".ToBytes();
			var key = "1B9DD8299657F00D46F60F036727161713EE88F1F1058D9FF629FE38B172C105".ToBytes();
			var actual = new PrivateKey( key).GetDerEncoded();
			Assert.Equal(expected, actual);
		}
	}
}