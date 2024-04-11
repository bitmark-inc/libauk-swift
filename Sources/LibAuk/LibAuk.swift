//
//  LibAuk.swift
//
//
//  Created by Ho Hien on 8/9/21.
//

import Foundation
import Combine

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
    
    public func calculateEthFirstAddress(words: [String], passphrase: String?) -> AnyPublisher<String, Error> {
        Future<String, Error> { promise in
            guard let entropy = Keys.entropy(words) else {
                promise(.failure(LibAukError.invalidMnemonicError))
                return
            }

            guard let mnemonic = Keys.mnemonic(entropy) else {
                promise(.failure(LibAukError.invalidMnemonicError))
                return
            }

            do {
                let ethPrivateKey = try Keys.ethereumPrivateKey(mnemonic: mnemonic, passphrase: passphrase)
                let ethAddress = ethPrivateKey.address.hex(eip55: true)
                promise(.success(ethAddress))
            } catch {
                promise(.failure(error))
            }
        }
        .eraseToAnyPublisher()
    }
}
