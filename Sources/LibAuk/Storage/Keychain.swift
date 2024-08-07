//
//  Keychain.swift
//  LibAuk
//
//  Created by Ho Hien on 8/6/21.
//  Copyright © 2021 Bitmark Inc. All rights reserved.
//

import Foundation

protocol KeychainProtocol {
    @discardableResult
    func set(_ data: Data, forKey: String, isSync: Bool) -> Bool
    func getData(_ key: String, isSync: Bool) -> Data?
    @discardableResult
    func remove(key: String, isSync: Bool) -> Bool
}

class Keychain: KeychainProtocol {
    
    let prefix: String?
    
    init(prefix: String? = nil) {
        self.prefix = prefix
    }
    
    @discardableResult
    func set(_ data: Data, forKey: String, isSync: Bool = true) -> Bool {
        let syncAttr = isSync ? kCFBooleanTrue : kCFBooleanFalse
        let query = [
            kSecClass as String: kSecClassGenericPassword as String,
            kSecAttrSynchronizable as String: syncAttr!,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecAttrAccessGroup as String: LibAuk.shared.keyChainGroup,
            kSecAttrAccount as String: buildKeyAttr(prefix: prefix, key: forKey),
            kSecValueData as String: data
        ] as [String: Any]

        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)

        if status == noErr {
            return true
        } else {
            return false
        }
    }

    func getData(_ key: String, isSync: Bool = true) -> Data? {
        let syncAttr = isSync ? kCFBooleanTrue : kCFBooleanFalse
        let query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrSynchronizable as String: syncAttr!,
            kSecAttrAccount as String: buildKeyAttr(prefix: prefix, key: key),
            kSecReturnData as String: kCFBooleanTrue!,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecAttrAccessGroup as String: LibAuk.shared.keyChainGroup,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as [String: Any]

        var dataTypeRef: AnyObject?

        let status: OSStatus = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)

        if status == noErr {
            return dataTypeRef as? Data
        } else {
            return nil
        }
    }

    @discardableResult
    func remove(key: String, isSync: Bool = true) -> Bool {
        let syncAttr = isSync ? kCFBooleanTrue : kCFBooleanFalse
        let query = [
            kSecClass as String: kSecClassGenericPassword as String,
            kSecAttrSynchronizable as String: syncAttr!,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecAttrAccessGroup as String: LibAuk.shared.keyChainGroup,
            kSecAttrAccount as String: buildKeyAttr(prefix: prefix, key: key)
        ] as [String: Any]

        // Delete any existing items
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess {
            return false
        } else {
            return true
        }

    }

    private func buildKeyAttr(prefix: String?, key: String) -> String {
        if let prefix = prefix {
            return "\(prefix)_\(key)"
        } else {
            return key
        }
    }
}
