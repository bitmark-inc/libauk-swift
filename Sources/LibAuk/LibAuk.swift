//
//  LibAuk.swift
//
//
//  Created by Ho Hien on 8/9/21.
//

import Foundation

public class LibAuk {
    
    public static var shared: LibAuk!
    
    public static func create(keyChainGroup: String) {
        guard Self.shared == nil else {
            return
        }
        
        Self.shared = LibAuk(keyChainGroup: keyChainGroup)
    }
    
    let keyChainGroup: String

    private init(keyChainGroup: String) {
        self.keyChainGroup = keyChainGroup
    }
    
    public func storage(for uuid: UUID) -> SecureStorageProtocol {
        let keychain = Keychain(prefix: Constant.KeychainKey.personaPrefix(at: uuid))
        return SecureStorage(keychain: keychain)
    }

    public func general() -> GeneralStorageProtocol {
        return GeneralStorage()
    }
}
