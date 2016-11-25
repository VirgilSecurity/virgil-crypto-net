using System.Text;
using Org.BouncyCastle.Utilities.Encoders;
using Xunit;

namespace Virgil.SDK.Cryptography.Tests.Crypto
{
    public class EncryptDecryptTests
    {
        ICrypto c = new ManagedCrypto();
        [Fact]
        public void TestDecryptAndVerify()
        {
            var privText =
                @"MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBD3cbA5ioqDMU1n3k3R2YmKAgIQYTAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEELS3ecpRh5kab/vR6tEv1v0EQF+CJncCAJKR7zyP3iTzcfXeUEwj/FKeczF4/JgkXCPwZRRbpLT0OvNByuIBrNa8XAV3NtqLPf8fgdG5KQ+W2Rs=";
            var pubText = @"MCowBQYDK2VwAyEAtyFcWSJQUmurwX8UFn+mbXjGczWo7nzT0QKzXW1ANLk=";
            var encryptedAndSignedText =
                @"MIIB1AIBADCCAVkGCSqGSIb3DQEHA6CCAUowggFGAgECMYIBFzCCARMCAQKgIgQg1xvnUzCuV4eaq8KGpv1DY3Vjao3CSFg7rL967ynuk/4wBQYDK2VwBIHiMIHfAgEAMCowBQYDK2VwAyEAESOqmPan6iATV1byh2llqk0hsz2P+VfPRB3++FU51+8wGAYHKIGMcQIFAjANBglghkgBZQMEAgIFADBBMA0GCWCGSAFlAwQCAgUABDBxUaRu3VH6QsVEKPj1ax+9LKVFPLeKPdtz5vA8PzhnOuLtz4Z4CzZKsx2z2cgiMxwwUTAdBglghkgBZQMEASoEEFsAT/5O9ymyEl1AJ78FTNwEMF8tzHts3x0Xq2XKGtFY0lkQVsN1jLbBaDvBsWaZuJy8hCocCD7im/SzczhzCGTKCTAmBgkqhkiG9w0BBwEwGQYJYIZIAWUDBAEuBAzYz6zzwXr92S4SQWCgcjFwMG4MFVZJUkdJTC1EQVRBLVNJR05BVFVSRaJVBFMwUTANBglghkgBZQMEAgIFAARAR+GQYK6SquBMxSmLfKwja+mY/OA3DBQq3uKr3f524M8VariYwlkYKzZkNBKHDP/V7kwJz60Uc83zjL+jgdyiBIkB/J+GGQcOC89KGLAWWhDgwMTYloLyeIYp56f2XSjufo7xNuTsQpem6TJMlz3jrrzLqKIeuxvJCEg=";

            var pub = c.ImportPublicKey(Base64.Decode(pubText));
            var priv = c.ImportPrivateKey(Base64.Decode(privText),"qwerty");
            var ciphertext = Base64.Decode(encryptedAndSignedText);

            var plainText = c.DecryptThenVerify(ciphertext, priv, pub);

            Assert.Equal(plainText, Encoding.UTF8.GetBytes("The quick brown fox jumped over a lazy dog"));
        }


        [Fact]
        public void TestEncryptDecrypt()
        {
            var kp1 = c.GenerateKeys();
            var kp2 = c.GenerateKeys();

            var text = Encoding.UTF8.GetBytes("Test stringы漢字");

            var ct1 = c.SignThenEncrypt(text, kp1.PrivateKey, kp2.PublicKey);
            var ct2 = c.SignThenEncrypt(text, kp2.PrivateKey, kp1.PublicKey);

            var dec1 = c.DecryptThenVerify(ct1, kp2.PrivateKey, kp1.PublicKey);
            var dec2 = c.DecryptThenVerify(ct2, kp1.PrivateKey, kp2.PublicKey);

            Assert.Equal(text, dec1);
            Assert.Equal(dec1, dec2);
        }
    }
}
