//
//  Key.swift
//  
//
//  Created by Ho Hien on 8/9/21.
//

import Foundation

public struct KeyInfo {
    let fingerprint, ethAddress: String
    let creationDate: Date
}

public struct SeedPublicData: Codable {
    let ethAddress: String
    let creationDate: Date
    let name: String?
    let did: String
    let preGenerateEthAddress: [Int: String]
    let tezosPublicKeys: [Int: String]
    var _encryptionPrivateKeyBase64: String? = nil
    var _accountDIDPrivateKeyBase64: String? = nil
    
    var encryptionPrivateKey: Secp256k1.Signing.PrivateKey? {
        get {
            guard let base64String = _encryptionPrivateKeyBase64,
                let data = Data(base64Encoded: base64String) else {
                            fatalError("Invalid base64 string for private key")
            }
            do {
                return try Secp256k1.Signing.PrivateKey(rawRepresentation: data)
            } catch {
                fatalError("Failed to initialize private key: \(error)")
            }
        }
        
        set {
            if let newValue = newValue {
                let privateKeyData = newValue.rawRepresentation
                _encryptionPrivateKeyBase64 = privateKeyData.base64EncodedString()
            } else {
                _encryptionPrivateKeyBase64 = nil
            }
        }
    }
    
    var accountDIDPrivateKey: Secp256k1.Signing.PrivateKey? {
        get {
            guard let base64String = _accountDIDPrivateKeyBase64,
                let data = Data(base64Encoded: base64String) else {
                            fatalError("Invalid base64 string for private key")
            }
            do {
                return try Secp256k1.Signing.PrivateKey(rawRepresentation: data)
            } catch {
                fatalError("Failed to initialize private key: \(error)")
            }
        }
        
        set {
            if let newValue = newValue {
                let privateKeyData = newValue.rawRepresentation
                _accountDIDPrivateKeyBase64 = privateKeyData.base64EncodedString()
            } else {
                _accountDIDPrivateKeyBase64 = nil
            }
        }
    }

}
