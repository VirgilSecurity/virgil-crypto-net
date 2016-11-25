using System.Text;
using Org.BouncyCastle.Utilities.Encoders;
using Xunit;

namespace Virgil.SDK.Cryptography.Tests.Crypto
{
    public class SignsTest
    {
        ICrypto c = new ManagedCrypto();
        [Fact]
        public void TestVerifyValidSignature()
        {
            var publicKeyText = @"MCowBQYDK2VwAyEAeHNDpvtFBy71liNK7qoyck/asAEkRdRsc9dVxlI+/WU=";
            var text = "Hello, Bob";
            var signatureText = @"MFEwDQYJYIZIAWUDBAICBQAEQD8+kwWC21QnCm/5fu95CGFyxfBG9ZwvjpVjfTKL34uJ/f18NeN6Q/GENDpd/onLyRggxjHv0gv/0ZlFv4QA2g4=";

            var key = c.ImportPublicKey(Encoding.UTF8.GetBytes(publicKeyText));
            var signatureBytes = Base64.Decode(signatureText);
            var plainTextBytes = Encoding.UTF8.GetBytes(text);

            Assert.True(c.Verify(plainTextBytes, signatureBytes, key));

        }

        [Fact]
        public void TestVerifyInvalidSignature_fails()
        {
            var publicKeyText = @"MCowBQYDK2VwAyEAeHNDpvtFBy71liNK7qoyck/asAEkRdRsc9dVxlI+/WU=";
            var text = "Hello, Bob";
            var signatureText = @"MFEwDQYJYIZIAWUDBAICBQAEQD8+kwWC21QnCm/5fu95CGFyxfBG9ZwvjpVjfTKL34uJ/f18NeN6Q/GENDpd/onLyRggxjHv0gv/0ZlFv4QA3g4=";

            var key = c.ImportPublicKey(Encoding.UTF8.GetBytes(publicKeyText));
            var signatureBytes = Base64.Decode(signatureText);
            var plainTextBytes = Encoding.UTF8.GetBytes(text);

            Assert.False(c.Verify(plainTextBytes, signatureBytes, key));

        }

        [Fact]
        public void TestVerifyInvalidText_fails()
        {
            var publicKeyText = @"MCowBQYDK2VwAyEAeHNDpvtFBy71liNK7qoyck/asAEkRdRsc9dVxlI+/WU=";
            var text = "Hello, Bob!";
            var signatureText = @"MFEwDQYJYIZIAWUDBAICBQAEQD8+kwWC21QnCm/5fu95CGFyxfBG9ZwvjpVjfTKL34uJ/f18NeN6Q/GENDpd/onLyRggxjHv0gv/0ZlFv4QA2g4=";

            var key = c.ImportPublicKey(Encoding.UTF8.GetBytes(publicKeyText));
            var signatureBytes = Base64.Decode(signatureText);
            var plainTextBytes = Encoding.UTF8.GetBytes(text);

            Assert.False(c.Verify(plainTextBytes, signatureBytes, key));

        }
    }
}
