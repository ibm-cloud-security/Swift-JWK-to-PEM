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

import XCTest
@testable import Swift_JWT_to_PEM

class Swift_JWT_to_PEMTests: XCTestCase {
    
    func testJWKtoPEM_OpenSSLGenerated() {
        let token = """
{
    "kty": "RSA",
    "n": "ALPElc5pCLJZ8WJq9H2v4vPH00v2usB97Tc0YxNTNklB489BOyCdvtiY6sLHn7tEHGA5x_6IsJyxp_5vnrcNbaACAt9FHniorJDNaakYumfC00WSEt1mB0RRqmtyH1RAX_7I5cYzanxvMvXOHyf6UWBsacwm43l7A3n7NM30l5pUHFi9TMCCAxzdGZwHJqY0rDs6NMD0Bm_5_DCH0_q1K_dG8XIffudcDhFV0ThOZ0KY5FvZ-mghAnskgyCtJ7yC7IFzFlDVt6ACBd-bSvcmlJBsV1TY7vkRiS4qZyCA1OWqSWPJZik1ZswTIJWNn4F6TSm4EJjAZVCeC9V9OalM8Oc",
    "e":"AQAB",
    "d":"QcTVbgv9c4r2hiRNSMKVzMy54FvnXU90_zJ6YPKbtNeXahcac8disEnZ8eMo7FFx9D6Pje8idmGE7dCWh7AxAE5cEKVwDYLgh6WvV39Fi3q64wQbRMb0N6mNKPw6vA9FT6jeb9IVzmq8gTOlMHIjXZysZFWB-crorbMbUZJ_-KTaHoPf2yYMhJAmUhrtRrSICASnzL010aay5kyAx0pQmrLQRtl8jtYjLqMt1Eie1Rcm_OlZtfMm2bWmXAWkaH9K6WJlI6pAAeCeZ9FKjBumMjmTnwNgx480pPhWxojR5J5WWbVI8EGuUVJZ1LrNT47uofM3lPXWJqCc4L7VXni9MQ",
    "p":"AN3iQAHGt2PRITXNEDo0y8aHkZgvb9V-V3VQ0uNF7A5nDGL11431K2YEq0GvB5uJf25ISSTG2nMaGkGqFScg7AVOktkouId0gvEWrVHIBDNfEWVQC0gmVAQZJbyIbitxNOI1XqFp3eMvMeGrZTeSBf0OfqstP_J0ybhispMhr_HP",
    "q":"AM9ok9apT18nNjoeJweWbbneBGncD_eZiMSutMo6lma-IotkjH5DFN1BPwHexbi16EAlkDrdeTPmn8N6twvT5Faa3ZtWRB6gW-tM669DgPPPLwA77ZwdbOV7YLmujVW-TC4MeqYcEGkXY-BAn49MGF9CFDwhZky8uujYrzA0gM1p",
    "dp":"H2luYlH9mHX8258CUxsyVhLPO9pLXNAcFZGxqVc2yfswt7nSIFi7IiA7Fntu-kgG8FfvcvNr7aueV_l6MSXqA_5Rr8iiBxsphnQNaWyFm7gzwEIKttYmQsZEn2I5JpFKSVQA550TOpxt1WLsW2eizWaF7Dnlua9q912Rpl64h-U",
    "dq":"AIw5U9pJVZQrWoooYJLMrRqAc9NuKI1pjAINa8VdntmPqqM7M5EZoT2FIygMiPi8Y20a-EwT-CGSxmjOynqAo1u6ECE5TYy3Ne37b0xrAv_TDx_FZHurmTf9FgPzczKJGc_4N-OeDao_WhL_HeEvvTqJ3kxY-GThJCzQcoDQvlQh",
    "qi":"Y5o3dg_DFtdZn2hNURsm5veC_pAjFSxVmJyc5Qd0dOOv2NjOWjlcux7Q7EtaOhGa_hp0Q-dzc1oMg-WnMnIHoiJjdWYFxdGAWDN4JKPl_71k2kjWMRvL_jm_N8RUUK9EvEK8FPvJb0U5fL6L79JDIuM1CcUQWjspEtBIKCsDPqk"
}
"""
        let expectedPublicKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8SVzmkIslnxYmr0fa/i
88fTS/a6wH3tNzRjE1M2SUHjz0E7IJ2+2Jjqwsefu0QcYDnH/oiwnLGn/m+etw1t
oAIC30UeeKiskM1pqRi6Z8LTRZIS3WYHRFGqa3IfVEBf/sjlxjNqfG8y9c4fJ/pR
YGxpzCbjeXsDefs0zfSXmlQcWL1MwIIDHN0ZnAcmpjSsOzo0wPQGb/n8MIfT+rUr
90bxch9+51wOEVXROE5nQpjkW9n6aCECeySDIK0nvILsgXMWUNW3oAIF35tK9yaU
kGxXVNju+RGJLipnIIDU5apJY8lmKTVmzBMglY2fgXpNKbgQmMBlUJ4L1X05qUzw
5wIDAQAB
-----END PUBLIC KEY-----\n
"""
        let expectedPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzxJXOaQiyWfFi
avR9r+Lzx9NL9rrAfe03NGMTUzZJQePPQTsgnb7YmOrCx5+7RBxgOcf+iLCcsaf+
b563DW2gAgLfRR54qKyQzWmpGLpnwtNFkhLdZgdEUaprch9UQF/+yOXGM2p8bzL1
zh8n+lFgbGnMJuN5ewN5+zTN9JeaVBxYvUzAggMc3RmcByamNKw7OjTA9AZv+fww
h9P6tSv3RvFyH37nXA4RVdE4TmdCmORb2fpoIQJ7JIMgrSe8guyBcxZQ1begAgXf
m0r3JpSQbFdU2O75EYkuKmcggNTlqkljyWYpNWbMEyCVjZ+Bek0puBCYwGVQngvV
fTmpTPDnAgMBAAECggEAQcTVbgv9c4r2hiRNSMKVzMy54FvnXU90/zJ6YPKbtNeX
ahcac8disEnZ8eMo7FFx9D6Pje8idmGE7dCWh7AxAE5cEKVwDYLgh6WvV39Fi3q6
4wQbRMb0N6mNKPw6vA9FT6jeb9IVzmq8gTOlMHIjXZysZFWB+crorbMbUZJ/+KTa
HoPf2yYMhJAmUhrtRrSICASnzL010aay5kyAx0pQmrLQRtl8jtYjLqMt1Eie1Rcm
/OlZtfMm2bWmXAWkaH9K6WJlI6pAAeCeZ9FKjBumMjmTnwNgx480pPhWxojR5J5W
WbVI8EGuUVJZ1LrNT47uofM3lPXWJqCc4L7VXni9MQKBgQDd4kABxrdj0SE1zRA6
NMvGh5GYL2/Vfld1UNLjRewOZwxi9deN9StmBKtBrwebiX9uSEkkxtpzGhpBqhUn
IOwFTpLZKLiHdILxFq1RyAQzXxFlUAtIJlQEGSW8iG4rcTTiNV6had3jLzHhq2U3
kgX9Dn6rLT/ydMm4YrKTIa/xzwKBgQDPaJPWqU9fJzY6HicHlm253gRp3A/3mYjE
rrTKOpZmviKLZIx+QxTdQT8B3sW4tehAJZA63Xkz5p/DercL0+RWmt2bVkQeoFvr
TOuvQ4Dzzy8AO+2cHWzle2C5ro1VvkwuDHqmHBBpF2PgQJ+PTBhfQhQ8IWZMvLro
2K8wNIDNaQKBgB9pbmJR/Zh1/NufAlMbMlYSzzvaS1zQHBWRsalXNsn7MLe50iBY
uyIgOxZ7bvpIBvBX73Lza+2rnlf5ejEl6gP+Ua/IogcbKYZ0DWlshZu4M8BCCrbW
JkLGRJ9iOSaRSklUAOedEzqcbdVi7Ftnos1mhew55bmvavddkaZeuIflAoGBAIw5
U9pJVZQrWoooYJLMrRqAc9NuKI1pjAINa8VdntmPqqM7M5EZoT2FIygMiPi8Y20a
+EwT+CGSxmjOynqAo1u6ECE5TYy3Ne37b0xrAv/TDx/FZHurmTf9FgPzczKJGc/4
N+OeDao/WhL/HeEvvTqJ3kxY+GThJCzQcoDQvlQhAoGAY5o3dg/DFtdZn2hNURsm
5veC/pAjFSxVmJyc5Qd0dOOv2NjOWjlcux7Q7EtaOhGa/hp0Q+dzc1oMg+WnMnIH
oiJjdWYFxdGAWDN4JKPl/71k2kjWMRvL/jm/N8RUUK9EvEK8FPvJb0U5fL6L79JD
IuM1CcUQWjspEtBIKCsDPqk=
-----END PRIVATE KEY-----\n
"""
        
        do {
            let k = try RSAKey(jwk: token)
            XCTAssertNotNil(k)
            
            let publicPem = try k.getPublicKey()
            XCTAssertNotNil(publicPem)
            //            print("\n\npublicPemPKCS1: \n", publicPem ?? "nil")
            XCTAssertEqual(publicPem, expectedPublicKey, "Does not match expected public key")
            
            let privatePem = try k.getPrivateKey(certEncoding.pemPkcs8)
            XCTAssertNotNil(privatePem)
            //            print("\n\n*** privatePem: \n", privatePem ?? "nil")
            XCTAssertEqual(privatePem, expectedPrivateKey, "Does not match expected private key")
        } catch {
            XCTFail()
        }
        
    }
    
    
    func testJWKFieldstoPEM_opensslGenerated() {
        
        let expE = "AQAB"
        let mod = "ALPElc5pCLJZ8WJq9H2v4vPH00v2usB97Tc0YxNTNklB489BOyCdvtiY6sLHn7tEHGA5x_6IsJyxp_5vnrcNbaACAt9FHniorJDNaakYumfC00WSEt1mB0RRqmtyH1RAX_7I5cYzanxvMvXOHyf6UWBsacwm43l7A3n7NM30l5pUHFi9TMCCAxzdGZwHJqY0rDs6NMD0Bm_5_DCH0_q1K_dG8XIffudcDhFV0ThOZ0KY5FvZ-mghAnskgyCtJ7yC7IFzFlDVt6ACBd-bSvcmlJBsV1TY7vkRiS4qZyCA1OWqSWPJZik1ZswTIJWNn4F6TSm4EJjAZVCeC9V9OalM8Oc"
        let expD = "QcTVbgv9c4r2hiRNSMKVzMy54FvnXU90_zJ6YPKbtNeXahcac8disEnZ8eMo7FFx9D6Pje8idmGE7dCWh7AxAE5cEKVwDYLgh6WvV39Fi3q64wQbRMb0N6mNKPw6vA9FT6jeb9IVzmq8gTOlMHIjXZysZFWB-crorbMbUZJ_-KTaHoPf2yYMhJAmUhrtRrSICASnzL010aay5kyAx0pQmrLQRtl8jtYjLqMt1Eie1Rcm_OlZtfMm2bWmXAWkaH9K6WJlI6pAAeCeZ9FKjBumMjmTnwNgx480pPhWxojR5J5WWbVI8EGuUVJZ1LrNT47uofM3lPXWJqCc4L7VXni9MQ"
        
        let expectedPublicKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8SVzmkIslnxYmr0fa/i
88fTS/a6wH3tNzRjE1M2SUHjz0E7IJ2+2Jjqwsefu0QcYDnH/oiwnLGn/m+etw1t
oAIC30UeeKiskM1pqRi6Z8LTRZIS3WYHRFGqa3IfVEBf/sjlxjNqfG8y9c4fJ/pR
YGxpzCbjeXsDefs0zfSXmlQcWL1MwIIDHN0ZnAcmpjSsOzo0wPQGb/n8MIfT+rUr
90bxch9+51wOEVXROE5nQpjkW9n6aCECeySDIK0nvILsgXMWUNW3oAIF35tK9yaU
kGxXVNju+RGJLipnIIDU5apJY8lmKTVmzBMglY2fgXpNKbgQmMBlUJ4L1X05qUzw
5wIDAQAB
-----END PUBLIC KEY-----\n
"""
        
        do {
            let k = try RSAKey(n: mod, e: expE, d: expD)
            XCTAssertNotNil(k)
            
            let publicPem = try k.getPublicKey(certEncoding.pemPkcs8)
            XCTAssertNotNil(publicPem)
            //            print("\n\npublicPemPKCS1: \n", publicPem ?? "nil")
            XCTAssertEqual(publicPem, expectedPublicKey, "Does not match expected public key")
            
            let privatePem = try k.getPrivateKey(certEncoding.pemPkcs8)
            XCTAssertNotNil(privatePem)
            //            print("\n\nprivatePem: \n", privatePem ?? "nil")
        } catch {
            XCTFail()
        }
    }
    
    func testJWKtoPEM_appIDGenerated() {
        let token = """
{"kty":"RSA","n":"AKSd08Gubj4wkfVNcy1g2aDD2SP4rSAxqqSpq3ByTQw1A4NRlN_2obyaU_NSA0o2kBWLDX3bNO4tyBqdNHzcEhYuMWaafteurPx9_Li6Ng4HxMgk_MucCqPerDN6pf6IGxJxWXUT3R949XJGtPNVwRCey1iheFcUp5M4LGZxHfZfkg_YVHOu5Fsx6f0aL2Q_6QbUEle2ZkwHz9Gh8OLoLcVq_yBk9bHV46DYQwNk3_pQcd8tgmxpRYED6X2O7PdjEm6NU6ZE17meux0J_TKUpyZzCUeMYyoQbuC2KscHO6KbpkTJaUg-OygNIAN_Fwy7hljCXVAs05LgIVdjpHiDBrM","e":"AQAB","kid":"appId-1504675475000"}
"""
        let expectedPublicKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn4Tw7golPpKj+VSQIiRT
RApbtCMyn28btLu9nHQzf32J1niY/uJZZbo5O+MsekNPHu5qmLBFCS0M3HcYeKAk
OZtu7z9W1Lkronpt7WBWu+7qnGZm2vPw9rOUflZjGS5Qh9RinPJ9S5tnOrO5VapA
7Rb2Q6EU3scgsDFvVaxBERf6IuDXgwYZp+tCcmBccEDBIfQ44mvu/6dHPwAUICJw
3y/S4hqv2VEDslEdAJm2kj+WRIYooFBPVlp7371iVZtmV9cStBLW5igBvePe5ots
lU7tI2NCoSxFONjF+kGxO2S8mbBzADTBXaAE7clHorp6nRj8rIxHzD0V3+W8mp2W
1QIDAQAB
-----END PUBLIC KEY-----\n
"""
        
        do {
            let k = try RSAKey(jwk: token)
            XCTAssertNotNil(k)
            
            let publicPem = try k.getPublicKey(certEncoding.pemPkcs8)
            XCTAssertNotNil(publicPem)
            print("\n\npublicPemPKCS1: \n", publicPem ?? "nil")
            //            XCTAssertEqual(publicPem, expectedPublicKey, "Does not match expected public key")
            
        } catch {
            XCTFail()
        }
        
    }
    
    func testJWKFieldstoPEM_appIDGenerated() {
        
        let expE = "AQAB"
        let mod = "AJ-E8O4KJT6So_lUkCIkU0QKW7QjMp9vG7S7vZx0M399idZ4mP7iWWW6OTvjLHpDTx7uapiwRQktDNx3GHigJDmbbu8_VtS5K6J6be1gVrvu6pxmZtrz8PazlH5WYxkuUIfUYpzyfUubZzqzuVWqQO0W9kOhFN7HILAxb1WsQREX-iLg14MGGafrQnJgXHBAwSH0OOJr7v-nRz8AFCAicN8v0uIar9lRA7JRHQCZtpI_lkSGKKBQT1Zae9-9YlWbZlfXErQS1uYoAb3j3uaLbJVO7SNjQqEsRTjYxfpBsTtkvJmwcwA0wV2gBO3JR6K6ep0Y_KyMR8w9Fd_lvJqdltU"
        let expectedPublicKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn4Tw7golPpKj+VSQIiRT
RApbtCMyn28btLu9nHQzf32J1niY/uJZZbo5O+MsekNPHu5qmLBFCS0M3HcYeKAk
OZtu7z9W1Lkronpt7WBWu+7qnGZm2vPw9rOUflZjGS5Qh9RinPJ9S5tnOrO5VapA
7Rb2Q6EU3scgsDFvVaxBERf6IuDXgwYZp+tCcmBccEDBIfQ44mvu/6dHPwAUICJw
3y/S4hqv2VEDslEdAJm2kj+WRIYooFBPVlp7371iVZtmV9cStBLW5igBvePe5ots
lU7tI2NCoSxFONjF+kGxO2S8mbBzADTBXaAE7clHorp6nRj8rIxHzD0V3+W8mp2W
1QIDAQAB
-----END PUBLIC KEY-----\n
"""
        
        do {
            let k = try RSAKey(n: mod, e: expE)
            XCTAssertNotNil(k)
            
            let publicPem = try k.getPublicKey(certEncoding.pemPkcs8)
            XCTAssertNotNil(publicPem)
            //            print("\n\nPublic Key (PEM PKCS#8): \n", publicPem ?? "nil")
            XCTAssertEqual(publicPem, expectedPublicKey, "Does not match expected public key")
            
        } catch {
            XCTFail()
        }
    }
    
    static var allTests = [
        ("testJWKtoPEM_OpenSSLGenerated", testJWKtoPEM_OpenSSLGenerated),
        ("testJWKFieldstoPEM_opensslGenerated", testJWKFieldstoPEM_opensslGenerated),
        ("testJWKtoPEM_appIDGenerated", testJWKtoPEM_appIDGenerated),
        ("testJWKFieldstoPEM_appIDGenerated", testJWKFieldstoPEM_appIDGenerated),
        ]
}
