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

public extension String {
    
    public func base64URLDecode() -> Data? {
        var str = self
        
        // add padding if necessary
        str = str.padding(toLength: ((str.count+3)/4)*4, withPad: "=", startingAt: 0)
        
        // URL decode
        str = str.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let d = Data(base64Encoded: str)
        
        return d
    }
}

extension Data {
    
    func hexEncodedString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
    
    public func base64URLEncode() -> String {
        let d = self
        // base64 encoding
        var str = d.base64EncodedString()
        
        // URL encode
        str = str.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        
        return str
    }
    
}
