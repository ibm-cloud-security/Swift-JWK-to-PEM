# Swift-JWK-to-PEM

Library to convert RSA keys in JWK/JWKS format to more popular formats such as PEM.

**Right now only supports RSA and outputs PEM PKCS#8 format.**

**Tested in Sierra only**

## Usage

### TL;DR
```
import SwiftJWKtoPEM

let key = try RSAKey(jwk: token)

let publicPem = try key.getPublicKey()
let privatePem = try key.getPrivateKey()
```

### Initialization
Can use either the JWK string or the JWK RSA components as initializer input.

```
let key = try RSAKey(jwk: token)
```
where
```
init(jwk: String) throws
```
or
```
let key = try RSAKey(n: mod, e: expE, d: expD)
```
where
```
init(n: String, e: String, d: String? = nil,
p: String? = nil, q: String? = nil,
dp: String? = nil, dq: String? = nil,
qi: String? = nil) throws


- parameter n: Base64 URL encoded string representing the `modulus` of the RSA Key.
- parameter e: Base64 URL encoded string representing the `public exponent` of the RSA Key.
- parameter d: Base64 URL encoded string representing the `private exponent` of the RSA Key.
- parameter p: Base64 URL encoded string representing the `secret prime factor` of the RSA Key.
- parameter q: Base64 URL encoded string representing the `secret prime factor` of the RSA Key.
- parameter dp: Base64 URL encoded string representing the `first factor CRT exponent` of the RSA Key. `d mod (p-1)`
- parameter dq: Base64 URL encoded string representing the `second factor CRT exponent` of the RSA Key. `d mod (q-1)`
- parameter qi: Base64 URL encoded string representing the `first CRT coefficient` of the RSA Key. `q^-1 mod p`
```

### Conversion
Once initialized, can extract public and private keys as PEM format using PKCS#8 encoding.
```
let key = try RSAKey(jwk: token)

let publicPem = try key.getPublicKey()
let privatePem = try key.getPrivateKey()
```

#### Comparing with OpenSSL generated RSA keys

`public key`: This library should produce the public key that OpenSSL generates.

`private key`: RSA private key only requires `n`, `e`, `d` but RSA operations are generally much faster when the rest of the values above are provided. The OpenSSL generated RSA private key files includes these values. Therefore if not all private paramters are provided, then the produced private key might not be an exact match to the original OpenSSL generated.


## What's a JWK

JSON Web Key (JWK) defined in https://tools.ietf.org/html/rfc7517

Example JWK:

```
{
"kty": "RSA",            // key type
"alg": "RS256",         // algorithm for the key
"use": "sig",            // how the key is meant to be used. For this example, sig represents signature.
"x5c": [                // x.509 certificate chain
"MIIC+DCCAe..="
],
// n = modulus and e = exponent for a standard PEM. Both are base64url encoded
"n": "AJ+E8O4KJ...ltU=",
"e": "AQAB",
"kid": "NjVB...TM2Qg",            // unique identifier for the key
"x5t": "NjVB...TM2Qg"            // thumbprint of x.509 cert (SHA-1 thumbprint)
}
```
