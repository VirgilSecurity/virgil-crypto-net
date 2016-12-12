# Library: Virgil Crypto for managed .NET

This library implements ICrypto interface in Virgil SDK .NET using [Bouncy Castle](https://www.bouncycastle.org/csharp/index.html) library and [Chaos.NaCL](https://github.com/CodesInChaos/Chaos.NaCl) Ed25519/Curve25519 implementation

# Installation and usage 
Nuget location: www.nuget.org/packages/Virgil.SDK.ManagedCrypto
```
Install-Package Virgil.SDK -Pre
Install-Package Virgil.SDK.ManagedCrypto -Pre
```
Use this crypto with [Virgil SDK](https://github.com/VirgilSecurity/virgil-sdk-net) that will provide your to create an application using Virgil Security. 

# Usage
The `ManagedCrypto` class provides cryptographic operations in applications, such as hashing, signature generation and verification, and encryption and decryption.

```csharp
var crypto = new ManagedCrypto();
```

## Generate Keys
The following code sample illustrates key pair generation.

```charp
 var aliceKeys = crypto.GenerateKeys();
```

## Import and Export Keys
All `crypto` api methods accept and return keys in an internal format. 
To get the raw key data as `byte[]` object use `ExportPrivateKey` and `ExportPublicKey` methods of `crypto` 
passing the appropriate internal key representation. To get the internal key representation out of the raw key data 
use `ImportPrivateKey` and `ImportPublicKey` respectively:

```csharp
 var exportedPrivateKey = crypto.ExportPrivateKey(aliceKeys.PrivateKey);
 var exportedPublicKey = crypto.ExportPublicKey(aliceKeys.PublicKey);

 var privateKey = crypto.importPrivateKey(exportedPrivateKey);
 var publicKey = crypto.importPublicKey(exportedPublicKey);
```

If you want to encrypt the private key before exporting it you must provide a password to encrypt the key with 
as a second parameter to `ExportPrivateKey` function. Similarly, if you want to import a private key that has been
encrypted - provide a password as a second parameter to `ImportPrivateKey` method:

```csharp
var exportedEncryptedKey = crypto.ExportPrivateKey(aliceKeys.PrivateKey, 'pa$$w0rd');
var importedEncryptedKey = crypto.ImportPublicKey(exportedPublicKey, 'pa$$w0rd');
```

## Encryption and Decryption
Data encryption using ECIES scheme with AES-GCM.

Generate keypair

```javascript
var alice = crypto.GenerateKeys();
```

### Encrypt Data

The `crypto.Encrypt` method requires two parameters:
- **data** - The data to be encrypted as a `byte[]`
- **recipients** - Public key or an array of Public keys to encrypt the data with

```csharp
var plaintext = Encoding.UTF8.GetBytes("Nice and easy");
var cipherData = crypto.Encrypt(plaintext, alice.PublicKey);
```

### Decrypt Data

The `crypto.Decrypt` method requires two parameters:
- **cipherData** - Encrypted data as a `byte[]`
- **privateKey** - The Private key to decrypt with

```javascript
var decryptedData = crypto.Decrypt(cipherData, alice.PrivateKey);
```

## Signatures
This section walks you through the steps necessary to use the `crypto` to generate a digital signature for data and to verify that a signature is authentic. 

Generate a new Public/Private keypair and *data* to be signed.

```javascript
var alice = crypto.GenerateKeys();
var data = Encoding.UTF8.GetBytes("Hello Bob, How are you?");
```

### Generate Signature

Sign the SHA-384 fingerprint of data using your private key. To generate the signature, simply call one of the sign methods:

```javascript
var signature = crypto.Sign(data, alice.PrivateKey);
```

### Verify Signature

Verify the signature of the SHA-384 fingerprint of data using Public key. The signature can now be verified by calling the verify method:

```javascript
 var isValid = crypto.Verify(data, signature, alice.PublicKey);
 ```
 
## Authenticated Encryption
Authenticated Encryption provides both data confidentiality and data integrity assurances to the information being protected.

```javascript
 
var alice = crypto.GenerateKeys();
var bob = crypto.GenerateKeys();

// The data to be signed with alice's Private key
var data = Encoding.UTF8.GetBytes("Hello Bob, How are you?");
```

### Sign then encrypt
Generates the signature, encrypts the data and attaches the signature to the cipher data. Returns a signed cipher data. 
To encrypt for multiple recipients, pass an array of public keys as third parameter

```csharp
var cipherData = crypto.SignThenEncrypt(data, alice.PrivateKey, bob.PublicKey);
```

### Decrypt then verify
Decrypts the data and verifies attached signature. Returns decrypted data if verification succeeded or throws `CryptoException` if it failed. 

```csharp
var decryptedData = crypto.DecryptThenVerify(cipherData, bob.PrivateKey, alice.PublicKey);
```
 
## Fingerprint Generation
The default algorithm for Fingerprint generation is SHA-256.
```csharp
var content = Encoding.UTF8.GetBytes("CONTENT_TO_CALCULATE_FINGERPRINT_OF");
var fingerprint = crypto.CalculateFingerprint(content);
```


# It supports:

* Ed25519 public/private keys import/export
* ECIES encryption/decryption using Curve25519/AES-GCM/SHA384
* EDDSA signatures
