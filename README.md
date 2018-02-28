# Swift-JWT-to-PEM

Library to convert keys of JWK format to more popular formats such as PEM.
**Right now only works for RSA and outputs PEM PKCS#8 format.**


## Build Instructions

** Tested in Sierra only **

Since this library uses OpenSSL under the covers, it requires explicitly passing build and linker paths to the OpenSSL library. Additionally, `swift package generate-xcodeproj` doesn't add the proper flags when they are passed in using the flags, therefore they must be added to the generated xcode project.

swift build -Xlinker -L/usr/local/opt/openssl/lib -Xcc -I/usr/local/opt/openssl/include

#### To build in Xcode:
swift package generate-xcodeproj

Go to targets -> build settings -> search for user paths add to Header Search Paths /usr/local/opt/openssl/include add to Library Search Paths /usr/local/opt/openssl/lib

✨ Build magic ✨


## Usage




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
