using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Virgil.SDK.Cryptography.Tests.Crypto
{
    public class KeysTests
    {
        ICrypto crypto = new ManagedCrypto();
        //password - qwerty
        const string privText = @"MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBBAmnEXkCd5wVq62RcPYSSnAgINDzAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEEAnMRNaURGYL6lwuY1TI4doEQMDUAYcJ6BA4AVeFZMCvNlRJC8TTHUZ1vWLVgxCaC1l4PoAyOVo8PSz3pckqD3yGoJG8xRx8n8Ztqfw0Xium+mQ=";

        [Fact]
        public void ImportGoodPublicKey()
        {
            var textKey = @"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAYR501kV1tUne2uOdkw4kErRRbJrc2Syaz5V1fuG+rVs=
-----END PUBLIC KEY-----";
            crypto.ImportPublicKey(Encoding.UTF8.GetBytes(textKey));
        }

        [Fact]
        public void ImportBadPublicKey_throws()
        {
            var textKey = @"-----BEGIN PUBLIC KEY-----
ZCowBQYDK2VwAyEAYR501kV1tUne2uOdkw4kErRRbJrc2Syaz5V1fuG+rVs=
-----END PUBLIC KEY-----";
            Assert.Throws(typeof(ArgumentException), () => crypto.ImportPublicKey(Encoding.UTF8.GetBytes(textKey)));
        }

        [Fact]
        public void ImportGoodPrivateKey()
        {
            var privText = @"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICM4hGSdeteNCGAmgI1rYo9lEq91bsgqIIOs4mC4h+IK
-----END PRIVATE KEY-----";

           crypto.ImportPrivateKey(Encoding.UTF8.GetBytes(privText));
        }

        [Fact]
        public void ImportGoodPrivateKey_password()
        {
            crypto.ImportPrivateKey(Encoding.UTF8.GetBytes(privText), "qwerty");
        }

        [Fact]
        public void ImportGoodPrivateKey_BadPassword()
        {
            Assert.Throws(typeof(CryptographicException), () => crypto.ImportPrivateKey(Encoding.UTF8.GetBytes(privText), "qwqerty"));
        }
    }
}