/*
 Copyright 2017 IBM Corp.
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 http://www.apache.org/licenses/LICENSE-2.0
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

import Foundation
import OpenSSL

public class RSAKey {

    private var key: OpaquePointer? = nil

    enum keyType {
        case privateKey
        case publicKey
    }
    
    private var type: keyType
    
    /**
     - parameter n: Base64 URL encoded string representing the `modulus` of the RSA Key.
     - parameter e: Base64 URL encoded string representing the `public exponent` of the RSA Key.
     - parameter d: Base64 URL encoded string representing the `private exponent` of the RSA Key.
     - parameter p: Base64 URL encoded string representing the `secret prime factor` of the RSA Key.
     - parameter q: Base64 URL encoded string representing the `secret prime factor` of the RSA Key.
     - parameter dp: Base64 URL encoded string representing the `first factor CRT exponent` of the RSA Key. `d mod (p-1)`
     - parameter dq: Base64 URL encoded string representing the `second factor CRT exponent` of the RSA Key. `d mod (q-1)`
     - parameter qi: Base64 URL encoded string representing the `first CRT coefficient` of the RSA Key. `q^-1 mod p`
     */
    public init(n: String, e: String, d: String? = nil,
                p: String? = nil, q: String? = nil,
                dp: String? = nil, dq: String? = nil,
                qi: String? = nil) throws {
        
        let rsakey = RSA_new()
        guard rsakey != nil  else {
            throw JWKError.opensslInternal
        }

        var new_n, new_e, new_d, new_p, new_q, new_dp, new_dq, new_qi: OpaquePointer?

        type = .publicKey

        new_n = try base64URLToBignum(n)
        new_e = try base64URLToBignum(e)

        if let d = d {
            new_d = try base64URLToBignum(d)
            type = .privateKey
        }
        
        // p, q, dmp1, dmq1 and iqmp may be NULL in private keys,
        // but the RSA operations are much faster when these values are available.
        if let p = p {
            new_p =  try base64URLToBignum(p)
        }
        if let q = q {
            new_q = try base64URLToBignum(q)
        }
        if let dq = dq {
            new_dq = try base64URLToBignum(dq)
        }
        if let dp = dp {
            new_dp = try base64URLToBignum(dp)
        }
        if let qi = qi {
            new_qi = try base64URLToBignum(qi)
        }

        RSA_set_keys(rsakey, .make(optional: new_n), .make(optional: new_e), .make(optional: new_d), .make(optional: new_p), .make(optional: new_q), .make(optional: new_dp), .make(optional: new_dq), .make(optional: new_qi))
        
        // assign RSAkey to EVP_Pkey to keep
        // EVP_PKEY_assign_RSA but complex macro
        // EVP_PKEY_assign((pkey),EVP_PKEY_RSA,(char *)(rsa))
        key = .init(EVP_PKEY_new())

        EVP_PKEY_assign_wrapper(.make(optional: key), .make(optional: rsakey))

        guard key != nil else {
            throw JWKError.createKey
        }
    }
    
    public convenience init(jwk: String) throws {
        
        if let jwkData = jwk.data(using: .utf8) {
            let jwkJSON = try? JSONDecoder().decode(JWK.self, from: jwkData)
            
            // Check presence of mandatory fields
            guard jwkJSON?.kty == "RSA", let modulus = jwkJSON?.n, let exp = jwkJSON?.e else {
                throw JWKError.input
            }
            
            try self.init(n: modulus, e: exp, d: jwkJSON?.d, p: jwkJSON?.p, q: jwkJSON?.q, dp: jwkJSON?.dp, dq: jwkJSON?.dq, qi: jwkJSON?.qi)
            
        } else {
            throw JWKError.input
        }
    }
    
    deinit {
        if let key = key {
            EVP_PKEY_free(.make(optional: key))
        }
    }
    
    public func getPublicKey(_ encoding: certEncoding? = certEncoding.pemPkcs8) throws -> String? {
        
        // currently only support PEM PKCS#8
        guard encoding == certEncoding.pemPkcs8 else {
            throw JWKError.invalidKeyType
        }
        
        // PEM PKCS#8
        return try getPublicPEM()
    }
    
    public func getPrivateKey(_ encoding: certEncoding? = certEncoding.pemPkcs8) throws -> String? {
        
        // currently only support PEM PKCS#8
        guard encoding == certEncoding.pemPkcs8 else {
            throw JWKError.invalidKeyType
        }
        
        // PEM PKCS#8
        return try getPrivatePEM()
    }
    
    private func getPublicPEM() throws -> String? {
        
        // Public key can be extracted from both public and private keys
        guard ( type == keyType.publicKey || type == keyType.privateKey )  else {
            throw JWKError.invalidKeyType
        }
        
        let bio = BIO_new(BIO_s_mem())
        
        // writes EVP key to bio
        let  retval = PEM_write_bio_PUBKEY(bio, .make(optional: key))
        
        // get length of BIO that was created
        // BIO_PENDING is complex macro
        let publicKeyLen = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        
        guard retval == 1, publicKeyLen > 0 else {
            throw JWKError.createPublicKey
        }
        
        // read the key from the buffer
        let publicKey: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(publicKeyLen))
        BIO_read(bio, publicKey, Int32(publicKeyLen));
        
        let pk = Data(bytes: publicKey!, count: Int(publicKeyLen))
        return String(data: pk, encoding: .utf8)
    }
    
    private func getPrivatePEM() throws -> String? {
        
        guard type == keyType.privateKey else {
            throw JWKError.invalidKeyType
        }
        
        let bio = BIO_new(BIO_s_mem())
        
        // writes EVP key to bio
        let  retval = PEM_write_bio_PrivateKey(bio, .make(optional: key), nil, nil, 0, nil, nil);
        
        // get length of BIO that was created
        // BIO_PENDING is complex macro
        let publicKeyLen = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        
        guard retval == 1, publicKeyLen > 0 else {
            throw JWKError.createPublicKey
        }
        
        // read the key from the buffer
        let publicKey: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(publicKeyLen))
        BIO_read(bio, publicKey, Int32(publicKeyLen));
        
        let pk = Data(bytes: publicKey!, count: Int(publicKeyLen))
        return String(data: pk, encoding: .utf8)
    }

    // Convert from base64URL to Data to BIGNUM
    private func base64URLToBignum (_ str: String) throws -> OpaquePointer {

        guard let data = str.base64URLDecode() else {
            throw JWKError.decoding
        }

        let array = [UInt8](data)
        return array.withUnsafeBufferPointer { p in

            // BN_bin2bn() converts the positive integer in big-endian form of length len
            // at s into a BIGNUM and places it in ret.
            // If ret is NULL, a new BIGNUM is created.

            let bn: OpaquePointer = OpaquePointer.make(optional: BN_bin2bn(p.baseAddress, Int32(p.count), nil))!
            //BN_print_fp(stdout, bn)
            return bn
        }
    }
}
