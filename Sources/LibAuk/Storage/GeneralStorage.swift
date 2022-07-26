//
//  File.swift
//  
//
//  Created by Thuyên Trương on 26/07/2022.
//

import Foundation
import Combine

public protocol GeneralStorageProtocol {
    func hasPlatformShards() -> AnyPublisher<Bool, Error>
    func scanPersonaUUIDs(isSync: Bool) -> AnyPublisher<[String], Error>

    ///
    /// scan all SecureStorage: migrate keys from remote keychain to local keychain
    func migrateAccountsFromV0ToV1() -> AnyPublisher<Void, Error>
}

class GeneralStorage: GeneralStorageProtocol {
    private let keychain: KeychainProtocol

    init(keychain: KeychainProtocol = Keychain()) {
        self.keychain = keychain
    }

    func hasPlatformShards() -> AnyPublisher<Bool, Error> {
        Just(())
            .setFailureType(to: Error.self)
            .tryMap { _ in
                let query: NSDictionary = [
                    kSecClass: kSecClassGenericPassword,
                    kSecAttrSynchronizable: true,
                    kSecReturnAttributes as String : true,
                    kSecMatchLimit as String: kSecMatchLimitAll,
                    kSecAttrAccessGroup as String: LibAuk.shared.keyChainGroup
                ]

                var dataTypeRef: AnyObject?
                let lastResultCode = withUnsafeMutablePointer(to: &dataTypeRef) {
                    SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
                }

                if lastResultCode == noErr {
                    guard let array = dataTypeRef as? Array<Dictionary<String, Any>> else {
                        return false
                    }

                    return array.first { item in
                        if let key = item[kSecAttrAccount as String] as? String, key.contains(Constant.KeychainKey.shardKey(type: ShardType.platform)) {
                            return true
                        }
                        return false
                    } != nil
                } else if lastResultCode == errSecItemNotFound {
                    return false
                } else {
                    throw LibAukError.other(reason: "hasPlatformShards failed \(lastResultCode)")
                }
            }
            .eraseToAnyPublisher()
    }

    func scanPersonaUUIDs(isSync: Bool) -> AnyPublisher<[String], Error> {
        Just(())
            .setFailureType(to: Error.self)
            .tryMap { (_) -> [String: Seed] in
                var personaUUIDs = [String: Seed]()
                let query: NSDictionary = [
                    kSecClass: kSecClassGenericPassword,
                    kSecAttrSynchronizable: isSync,
                    kSecReturnData: true,
                    kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
                    kSecReturnAttributes as String : true,
                    kSecMatchLimit as String: kSecMatchLimitAll,
                    kSecAttrAccessGroup as String: LibAuk.shared.keyChainGroup,
                ]

                var dataTypeRef: AnyObject?
                let lastResultCode = withUnsafeMutablePointer(to: &dataTypeRef) {
                    SecItemCopyMatching(query as CFDictionary, UnsafeMutablePointer($0))
                }

                if lastResultCode == noErr {
                    guard let array = dataTypeRef as? Array<Dictionary<String, Any>> else {
                        return [:]
                    }

                    for item in array {
                        if let key = item[kSecAttrAccount as String] as? String, key.contains(Constant.KeychainKey.seed) {
                            let personaUUIDString = key.replacingOccurrences(of: "persona.", with: "")
                                .replacingOccurrences(of: "_\(Constant.KeychainKey.seed)", with: "")
                            if let seedUR = (item[kSecValueData as String] as? Data)?.utf8,
                               let seed = try? Seed(urString: seedUR) {
                                personaUUIDs[personaUUIDString] = seed
                            }
                        }
                    }

                    return personaUUIDs
                } else if lastResultCode == errSecItemNotFound {
                    return [:]
                } else {
                    throw LibAukError.other(reason: "scanPersonaUUIDs \(lastResultCode)")
                }
            }
            .map { (personaSeedUUIDs) in
                return personaSeedUUIDs
                    .sorted(by: {
                        $0.value.creationDate ?? Date() < $1.value.creationDate ?? Date()
                    })
                    .map(\.key)
            }
            .eraseToAnyPublisher()
    }

    func migrateAccountsFromV0ToV1() -> AnyPublisher<Void, Error> {
        scanPersonaUUIDs(isSync: true)
            .flatMap { personaUUIDs -> AnyPublisher<Void, Error> in
                let executionPublishers = personaUUIDs.compactMap { uuid in
                    return LibAuk.shared.storage(for: UUID(uuidString: uuid)!)
                        .migrateV0ToV1()
                        .eraseToAnyPublisher()
                }

                return Publishers.MergeMany(executionPublishers)
                    .collect()
                    .map { _ in () }
                    .eraseToAnyPublisher()
            }
            .eraseToAnyPublisher()
    }
}
