//
//  LibAuk.swift
//
//
//  Created by Ho Hien on 8/9/21.
//

import Foundation
import Combine
import BCFoundation

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
    
    public func calculateEthFirstAddress(words: [String], passphrase: String) -> AnyPublisher<String, Error> {
        Future<BIP39, Error> { promise in
            guard let entropy = Keys.entropy(words),
                  let bip39 = Keys.mnemonic(entropy) else {
                promise(.failure(LibAukError.invalidMnemonicError))
                return
            }
            promise(.success(bip39))
        }.tryMap({ bip39 in
            let ethPrivateKey = try Keys.ethereumPrivateKey(bip39: bip39, passphrase: passphrase)
            return ethPrivateKey.address.hex(eip55: true)
        })
        .eraseToAnyPublisher()
    }
}
