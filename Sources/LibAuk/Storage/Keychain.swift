//
//  Keychain.swift
//  LibAuk
//
//  Created by Ho Hien on 8/6/21.
//  Copyright © 2021 Bitmark Inc. All rights reserved.
//

import Foundation
import LocalAuthentication

protocol KeychainProtocol {
    @discardableResult
    func set(_ data: Data, forKey: String, isSync: Bool, isPrivate: Bool) -> Bool
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
    func set(_ data: Data, forKey: String, isSync: Bool = true, isPrivate: Bool) -> Bool {
        let syncAttr = isSync ? kCFBooleanTrue : kCFBooleanFalse
        var error: Unmanaged<CFError>?
        var accessControl: SecAccessControl?
        if (isPrivate) { accessControl =  SecAccessControlCreateWithFlags(kCFAllocatorDefault,  // Use the default allocator.
                                                                   AccessControl.shared.accessible,
                                                                   [.biometryCurrentSet, .or, .devicePasscode],
                                                                   &error)
        }
    
        var query = [
            kSecClass as String: kSecClassGenericPassword as String,
//            kSecAttrSynchronizable as String: syncAttr!,
            kSecAttrAccessGroup as String: LibAuk.shared.keyChainGroup,
            kSecAttrAccount as String: buildKeyAttr(prefix: prefix, key: forKey),
            kSecValueData as String: data,
//            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
//            kSecAttrAccessControl as String: access,
//            kSecUseAuthenticationContext as String: context,
        ] as [String: Any]
        
        if let access = accessControl {
                query[kSecAttrAccessControl as String] = access
            }

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
        let context = AccessControl.shared.context
        let query = [
            kSecClass as String: kSecClassGenericPassword,
//            kSecAttrSynchronizable as String: syncAttr!,
            kSecAttrAccount as String: buildKeyAttr(prefix: prefix, key: key),
            kSecReturnData as String: kCFBooleanTrue!,
            kSecAttrAccessGroup as String: LibAuk.shared.keyChainGroup,
            kSecAttrAccessible as String: AccessControl.shared.accessible,
            kSecMatchLimit as String: kSecMatchLimitOne,
//            kSecUseAuthenticationContext as String: context,
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
            kSecAttrAccessGroup as String: LibAuk.shared.keyChainGroup,
            kSecAttrAccount as String: buildKeyAttr(prefix: prefix, key: key),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked,
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
