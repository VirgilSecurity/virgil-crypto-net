# Library: Virgil Crypto for managed .NET

This library implements ICrypto interface in Virgil SDK .NET using [Bouncy Castle](https://www.bouncycastle.org/csharp/index.html) library and [Chaos.NaCL](https://github.com/CodesInChaos/Chaos.NaCl) Ed25519/Curve25519 implementation

# Installation and usage 
Nuget location: www.nuget.org/packages/Virgil.SDK.ManagedCrypto
```
Install-Package Virgil.SDK -Pre
Install-Package Virgil.SDK.ManagedCrypto -Pre
```
# Usage

```csharp
VirgilConfig.Initialize("YOUR_ACCESS_TOKEN", new ManagedCrypto());
```

# It supports:

* Ed25519 public/private keys import/export
* ECIES encryption/decryption using Curve25519/AES-GCM/SHA384
* EDDSA signatures
