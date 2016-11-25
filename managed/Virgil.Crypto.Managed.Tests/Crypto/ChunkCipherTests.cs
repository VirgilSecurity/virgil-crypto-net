using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.Encoders;
using Xunit;

namespace Virgil.SDK.Cryptography.Tests.Crypto
{
    public class ChunkCipherTests
    {
        private readonly ICrypto c = new ManagedCrypto();
        [Fact]
        public void TestChunkDecrypt()
        {
            var encryptedStream =
                @"308201760201003082015906092a864886f70d010703a082014a308201460201023182011730820113020102a0220420350b3c115578b9cca88ee1d0a052d800ed3ad442619a5972d1171f4c68555df9300506032b65700481e23081df020100302a300506032b657003210000b04b68f32758be2ec62fe308f05cb458f28943976bdd5a4022ad372875f3823018060728818c71020502300d060960864801650304020205003041300d060960864801650304020205000430a377fe86e1cae0a7bb4ccf990a866f3cae63f13b2d1de758e3a8275a41d565da343f83c06ff219d16346965470a6f9653051301d060960864801650304012a0410b7a80ffd5c121a73ff99c699e0bd7dff0430ba8614aa7b3792a2ec788dae9c5af7e868322d8a3a1aed60682b7193ed50d9f13657e1ccfc759c6644ad1d401e07df3e302606092a864886f70d0107013019060960864801650304012e040cdc55a9217b2fcfdcb6cc9047a014311230100c096368756e6b53697a65a003020102f04b58cd9196037d4138e1762195c20d28f734565851b70bf559abbba221c4a4204e113d941294cdfa8263e2716aa2a4fd2619000392aeee883bfdb301269a43a0f91c1b5e9412ba50fc285f4ec70cce75d1ea42699fccf6a3d1c848cc054c52746a0ffdc0d22e0892e27bf6729fb6ccd1436fd88956134c3c8ed82a95";
            var privText =
                @"MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBDVO6bkaAxgPZf3qKtjH/ZBAgIdiDAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEECMLUd4cUy3hveIdrSesXFQEQDYvV+ITSLbPTZLf7siI18DLtfNWYBdNldE0LrkDaGGa3SJaYeiIN+8pfLLnLhmQNISjwIbqyKuB4LIJgs5hsYc=";

            //prepare streams
            var cipherText = Hex.Decode(encryptedStream);
            var inStream = new MemoryStream(cipherText);
            var outStream = new MemoryStream();

            //prepare keys

            var priv = c.ImportPrivateKey(Base64.Decode(privText), "qwerty");
            c.Decrypt(inStream, outStream, priv);

            Assert.Equal(outStream.ToArray(), Encoding.UTF8.GetBytes("Hello, there!"));
        }

        [Fact]
        public void TestEncryptDecryptChunk()
        {
            var buf = new byte[1024*1024*2 + 1];
            //prepare streams
            var inStream = new MemoryStream(buf);
            var outStream = new MemoryStream();

            var keys = c.GenerateKeys();

            c.Encrypt(inStream, outStream, keys.PublicKey);

            inStream = new MemoryStream(outStream.ToArray());
            outStream = new MemoryStream();
            c.Decrypt(inStream, outStream, keys.PrivateKey);

            Assert.Equal(buf, outStream.ToArray());
        }

        [Fact]
        public void TestChunkDecrypt_BadTag()
        {
            var encryptedStream =
                @"308201760201003082015906092a864886f70d010703a082014a308201460201023182011730820113020102a0220420350b3c115578b9cca88ee1d0a052d800ed3ad442619a5972d1171f4c68555df9300506032b65700481e23081df020100302a300506032b657003210000b04b68f32758be2ec62fe308f05cb458f28943976bdd5a4022ad372875f3823018060728818c71020502300d060960864801650304020205003041300d060960864801650304020205000430a377fe86e1cae0a7bb4ccf990a866f3cae63f13b2d1de758e3a8275a41d565da343f83c06ff219d16346965470a6f9653051301d060960864801650304012a0410b7a80ffd5c121a73ff99c699e0bd7dff0430ba8614aa7b3792a2ec788dae9c5af7e868322d8a3a1aed60682b7193ed50d9f13657e1ccfc759c6644ad1d401e07df3e302606092a864886f70d0107013019060960864801650304012e040cdc55a9217b2fcfdcb6cc9047a014311230100c096368756e6b53697a65a003020102f04b58cd9196037d4138e1762195c20d28f734565851b70bf559abbba221c4a4204e113d941294cdfa8263e2716aa2a4fd2619000392aeee883bfdb301269a43a0f91c1b5e9412ba50fc285f4ec70cce75d1ea42699fccf6a3d1c848cc054c52746a0ffdc0d22e0892e27bf6729fb6ccd1436fd88956134c3c8ed82a96";
            var privText =
                @"MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBDVO6bkaAxgPZf3qKtjH/ZBAgIdiDAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEECMLUd4cUy3hveIdrSesXFQEQDYvV+ITSLbPTZLf7siI18DLtfNWYBdNldE0LrkDaGGa3SJaYeiIN+8pfLLnLhmQNISjwIbqyKuB4LIJgs5hsYc=";

            //prepare streams
            var cipherText = Hex.Decode(encryptedStream);
            var inStream = new MemoryStream(cipherText);
            var outStream = new MemoryStream();

            var priv = c.ImportPrivateKey(Base64.Decode(privText), "qwerty");
            Assert.Throws(typeof(InvalidCipherTextException), () =>c.Decrypt(inStream, outStream, priv));
        }

        [Fact]
        public void TestChunkDecrypt_BadSize()
        {
            var encryptedStream =
                @"308201760201003082015906092a864886f70d010703a082014a308201460201023182011730820113020102a0220420350b3c115578b9cca88ee1d0a052d800ed3ad442619a5972d1171f4c68555df9300506032b65700481e23081df020100302a300506032b657003210000b04b68f32758be2ec62fe308f05cb458f28943976bdd5a4022ad372875f3823018060728818c71020502300d060960864801650304020205003041300d060960864801650304020205000430a377fe86e1cae0a7bb4ccf990a866f3cae63f13b2d1de758e3a8275a41d565da343f83c06ff219d16346965470a6f9653051301d060960864801650304012a0410b7a80ffd5c121a73ff99c699e0bd7dff0430ba8614aa7b3792a2ec788dae9c5af7e868322d8a3a1aed60682b7193ed50d9f13657e1ccfc759c6644ad1d401e07df3e302606092a864886f70d0107013019060960864801650304012e040cdc55a9217b2fcfdcb6cc9047a014311230100c096368756e6b53697a65a003020102f04b58cd9196037d4138e1762195c20d28f734565851b70bf559abbba221c4a4204e113d941294cdfa8263e2716aa2a4fd2619000392aeee883bfdb301269a43a0f91c1b5e9412ba50fc285f4ec70cce75d1ea42699fccf6a3d1c848cc054c52746a0ffdc0d22e0892e27bf6729fb6ccd1436fd88956134c3c8ed8";
            var privText =
                @"MIGhMF0GCSqGSIb3DQEFDTBQMC8GCSqGSIb3DQEFDDAiBBDVO6bkaAxgPZf3qKtjH/ZBAgIdiDAKBggqhkiG9w0CCjAdBglghkgBZQMEASoEECMLUd4cUy3hveIdrSesXFQEQDYvV+ITSLbPTZLf7siI18DLtfNWYBdNldE0LrkDaGGa3SJaYeiIN+8pfLLnLhmQNISjwIbqyKuB4LIJgs5hsYc=";

            //prepare streams
            var cipherText = Hex.Decode(encryptedStream);
            var inStream = new MemoryStream(cipherText);
            var outStream = new MemoryStream();

            var priv = c.ImportPrivateKey(Base64.Decode(privText), "qwerty");
            Assert.Throws(typeof(Exception), () => c.Decrypt(inStream, outStream, priv));
        }
    }
}
