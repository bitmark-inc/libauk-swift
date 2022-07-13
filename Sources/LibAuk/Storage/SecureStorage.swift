//
//  SecureStorage.swift
//  
//
//  Created by Ho Hien on 8/9/21.
//

import Foundation
import Combine
import LibWally
import Web3
import KukaiCoreSwift
import Base58Swift
import CryptoKit
import SSKR
import BCFoundation

public protocol SecureStorageProtocol {
    func createKey(name: String) -> AnyPublisher<Void, Error>
    func importKey(words: [String], name: String, creationDate: Date?) -> AnyPublisher<Void, Error>
    func restoreByBytewordShards(shares: [String], name: String, creationDate: Date?) -> AnyPublisher<Void, Error>
    func isWalletCreated() -> AnyPublisher<Bool, Error>
    func getName() -> String?
    func updateName(name: String) -> AnyPublisher<Void, Error>
    func getAccountDID() -> AnyPublisher<String, Error>
    func getAccountDIDSignature(message: String) -> AnyPublisher<String, Error>
    func getETHAddress() -> String?
    func sign(message: Bytes) -> AnyPublisher<(v: UInt, r: Bytes, s: Bytes), Error>
    func signTransaction(transaction: EthereumTransaction, chainId: EthereumQuantity) -> AnyPublisher<EthereumSignedTransaction, Error>
    func encryptFile(inputPath: String, outputPath: String) -> AnyPublisher<String, Error>
    func decryptFile(inputPath: String, outputPath: String) -> AnyPublisher<String, Error>
    func getTezosWallet() -> AnyPublisher<Wallet, Error>
    func getBitmarkAddress() -> AnyPublisher<String, Error>
    func exportSeed() -> AnyPublisher<Seed, Error>
    func exportMnemonicWords() -> AnyPublisher<[String], Error>
    func removeKeys() -> AnyPublisher<Void, Error>
    func setupSSKR() -> AnyPublisher<Void, Error>
    func getShard(type: ShardType) -> AnyPublisher<String, Error>
    func removeShard(type: ShardType) -> AnyPublisher<Void, Error>
}

class SecureStorage: SecureStorageProtocol {
    
    private let keychain: KeychainProtocol

    private let groupThreshold: Int = 1
    private let numberOfShardsEachGroup: UInt8 = 3
    private let shardsCombinationThreshold: UInt8 = 2
    
    init(keychain: KeychainProtocol = Keychain()) {
        self.keychain = keychain
    }
    
    func createKey(name: String) -> AnyPublisher<Void, Error> {
        Future<Seed, Error> { promise in
            guard self.keychain.getData(Constant.KeychainKey.ethInfoKey, isSync: true) == nil else {
                promise(.failure(LibAukError.keyCreationExistingError(key: "createETHKey")))
                return
            }
            
            guard let entropy = KeyCreator.createEntropy() else {
                promise(.failure(LibAukError.keyCreationError))
                return
            }
            
            let seed = Seed(data: entropy, name: name, creationDate: Date())
            let seedData = seed.urString.utf8

            
            self.keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
            promise(.success(seed))
        }
        .compactMap { seed in
            Keys.mnemonic(seed.data)
        }
        .tryMap { [unowned self] in
            try self.saveKeyInfo(mnemonic: $0)
        }
        .eraseToAnyPublisher()
    }
    
    func importKey(words: [String], name: String, creationDate: Date?) -> AnyPublisher<Void, Error> {
        Future<Seed, Error> { promise in
            guard self.keychain.getData(Constant.KeychainKey.ethInfoKey, isSync: true) == nil else {
                promise(.failure(LibAukError.keyCreationExistingError(key: "createETHKey")))
                return
            }
            
            if let entropy = Keys.entropy(words) {
                let seed = Seed(data: entropy, name: name, creationDate: creationDate ?? Date())
                let seedData = seed.urString.utf8

                self.keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
                promise(.success(seed))
            } else {
                promise(.failure(LibAukError.invalidMnemonicError))
            }
        }
        .compactMap { seed in
            Keys.mnemonic(seed.data)
        }
        .tryMap { [unowned self] in
            try self.saveKeyInfo(mnemonic: $0)
        }
        .eraseToAnyPublisher()
    }
    
    func isWalletCreated() -> AnyPublisher<Bool, Error> {
        Future<Bool, Error> { promise in
            guard let infoData = self.keychain.getData(Constant.KeychainKey.ethInfoKey, isSync: true),
                  (try? JSONDecoder().decode(KeyInfo.self, from: infoData)) != nil else {
                promise(.success(false))
                return
            }
            
            promise(.success(true))
        }
        .eraseToAnyPublisher()
    }
    
    func getName() -> String? {
        guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
              let seed = try? Seed(urString: seedUR.utf8) else {
            return ""
        }
        
        return seed.name
    }
    
    func updateName(name: String) -> AnyPublisher<Void, Error> {
        Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(seed))
        }
        .map {
            Seed(data: $0.data, name: name, creationDate: $0.creationDate)
        }
        .map { seed in
            let seedData = seed.urString.utf8

            self.keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
            return ()
        }
        .eraseToAnyPublisher()
    }
    
    func getAccountDID() -> AnyPublisher<String, Error> {
        Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(seed))
        }
        .compactMap {
            Keys.mnemonic($0.data)
        }
        .tryMap { (mnemonic) in
            let privateKey = try Keys.accountDIDPrivateKey(mnemonic: mnemonic)
            // Multicodec encoded with prefix 0xe7            
            
            var bytes: [UInt8] = [231, 1]
            bytes.append(contentsOf: privateKey.publicKey.rawRepresentation.bytes)
            let did = "did:key:z\(Base58.base58Encode(bytes))"

            return did
        }
        .eraseToAnyPublisher()
    }
    
    func getAccountDIDSignature(message: String) -> AnyPublisher<String, Error> {
        Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(seed))
        }
        .compactMap {
            Keys.mnemonic($0.data)
        }
        .tryMap { (mnemonic) in
            let privateKey = try Keys.accountDIDPrivateKey(mnemonic: mnemonic)
            
            return try privateKey.signature(for: message.utf8).derRepresentation.hexString
        }
        .eraseToAnyPublisher()
    }
    
    func getETHAddress() -> String? {
        guard let infoData = self.keychain.getData(Constant.KeychainKey.ethInfoKey, isSync: true),
              let keyInfo = try? JSONDecoder().decode(KeyInfo.self, from: infoData) else {
            return nil
        }
        return keyInfo.ethAddress
    }
    
    func sign(message: Bytes) -> AnyPublisher<(v: UInt, r: Bytes, s: Bytes), Error> {
        Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(seed))
        }
        .compactMap {
            Keys.mnemonic($0.data)
        }
        .tryMap { (mnemonic) in
            let ethPrivateKey = try Keys.ethereumPrivateKey(mnemonic: mnemonic)
            return try ethPrivateKey.sign(message: message)
        }
        .eraseToAnyPublisher()
    }
    
    func signTransaction(transaction: EthereumTransaction, chainId: EthereumQuantity) -> AnyPublisher<EthereumSignedTransaction, Error> {
        Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(seed))
        }
        .compactMap {
            Keys.mnemonic($0.data)
        }
        .tryMap { mnemonic in
            let ethPrivateKey = try Keys.ethereumPrivateKey(mnemonic: mnemonic)
            
            return try transaction.sign(with: ethPrivateKey, chainId: chainId)
        }
        .eraseToAnyPublisher()
    }

    private func getEncryptKey() -> AnyPublisher<SymmetricKey, Error> {
        return Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            promise(.success(seed))
        }
        .compactMap {
            Keys.mnemonic($0.data)
        }
        .tryMap({ (mnemonic) in
            let privateKey = try Keys.encryptionPrivateKey(mnemonic: mnemonic)
            return SymmetricKey(data: privateKey.rawRepresentation)
        })
        .eraseToAnyPublisher()
    }

    func encryptFile(inputPath: String, outputPath: String) -> AnyPublisher<String, Error> {
        return getEncryptKey().tryMap({ key in
            let url = URL(fileURLWithPath: inputPath)
            let data = try Data(contentsOf: url)
            let seal = try ChaChaPoly.seal(data, using: key, nonce: ChaChaPoly.Nonce())
            try seal.combined.write(to: URL(fileURLWithPath: outputPath))
            return outputPath
        })
        .eraseToAnyPublisher()
    }

    func decryptFile(inputPath: String, outputPath: String) -> AnyPublisher<String, Error> {
        return getEncryptKey().tryMap({ key in
            let url = URL(fileURLWithPath: inputPath)
            let data = try Data(contentsOf: url)
            let box = try ChaChaPoly.SealedBox(combined: data)
            let decrypted = try ChaChaPoly.open(box, using: key)
            try decrypted.write(to: URL(fileURLWithPath: outputPath))
            return outputPath
        })
        .eraseToAnyPublisher()
    }

    func getTezosWallet() -> AnyPublisher<Wallet, Error> {
        Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(seed))
        }
        .compactMap {
            Keys.mnemonic($0.data)
        }
        .compactMap {
            Keys.tezosWallet(mnemonic: $0)
        }
        .eraseToAnyPublisher()
    }
    
    func getBitmarkAddress() -> AnyPublisher<String, Error> {
        Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(seed))
        }
        .compactMap {
            Keys.mnemonic($0.data)
        }
        .tryMap {
            try Keys.bitmarkPrivateKey(mnemonic: $0)
        }
        .eraseToAnyPublisher()
    }
    
    func exportSeed() -> AnyPublisher<Seed, Error> {
        Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(seed))
        }
        .eraseToAnyPublisher()
    }

    func exportMnemonicWords() -> AnyPublisher<[String], Error> {
        self.exportSeed()
            .compactMap { seed in
                Keys.mnemonic(seed.data)
            }
            .map { $0.words }
            .eraseToAnyPublisher()
    }
    
    func removeKeys() -> AnyPublisher<Void, Error> {
        Future<Void, Error> { promise in
            guard self.keychain.getData(Constant.KeychainKey.seed, isSync: true) != nil,
                  self.keychain.getData(Constant.KeychainKey.ethInfoKey, isSync: true) != nil else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            self.keychain.remove(key: Constant.KeychainKey.seed, isSync: true)
            self.keychain.remove(key: Constant.KeychainKey.ethInfoKey, isSync: true)

            ShardType.allCases.forEach { type in
                self.keychain.remove(key: Constant.KeychainKey.shardKey(type: type), isSync: type.isSync)
            }

            promise(.success(()))
        }
        .eraseToAnyPublisher()
    }

    func setupSSKR() -> AnyPublisher<Void, Error> {
        Future<Data, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }

            promise(.success(seed.data))
        }
        .tryMap { [unowned self]  data -> [[SSKRShare]] in
            return try SSKROperator.generate(
                data: data,
                groupThreshold: self.groupThreshold,
                numberOfShardsInGroup: self.numberOfShardsEachGroup,
                shardsCombinationThreshold: self.shardsCombinationThreshold)
        }
        .tryMap { (groupsShares) -> [ShardType: Data] in
            guard let shares = groupsShares.first, shares.count == ShardType.allCases.count else {
                throw LibAukError.shardCreationError
            }

            var result = [ShardType: Data]()

            for (index, share) in shares.enumerated() {
                if let type = ShardType(rawValue: index) {
                    result[type] = Data(share.data)
                } else {
                    throw LibAukError.shardCreationError
                }
            }

            return result
        }
        .map { [unowned self] (shardDict) in
            for (type, shardData) in shardDict {
                self.keychain.set(shardData,
                                  forKey: Constant.KeychainKey.shardKey(type: type),
                                  isSync: type.isSync)
            }
        }
        .eraseToAnyPublisher()
    }

    func getShard(type: ShardType) -> AnyPublisher<String, Error> {
        Future<String, Error> { promise in
            guard let data = self.keychain.getData(Constant.KeychainKey.shardKey(type: type), isSync: type.isSync) else {
                promise(.failure(LibAukError.other(reason: "Couldn't load shards from Keychain")))
                return
            }

            let share = SSKRShare(data: data.bytes)
            promise(.success(share.bytewords(style: .standard)))
        }
        .eraseToAnyPublisher()
    }

    func removeShard(type: ShardType) -> AnyPublisher<Void, Error> {
        Future<Void, Error> { promise in
            let result = self.keychain.remove(key: Constant.KeychainKey.shardKey(type: type), isSync: type.isSync)

            if (result) {
                promise(.success(()))
            } else {
                promise(.failure(LibAukError.other(reason: "Could remove shard")))
            }
        }
        .eraseToAnyPublisher()
    }

    func restoreByBytewordShards(shares: [String], name: String, creationDate: Date?) -> AnyPublisher<Void, Error> {
        Just(shares)
            .setFailureType(to: Error.self)
            .tryMap { byteWordShares in
                try byteWordShares.map {
                    let shard = try SSKRShare(bytewords: $0)
                    if let shard = shard {
                        return shard
                    } else {
                        throw LibAukError.shardInvalidError
                    }
                }
            }
            .tryMap {
                try SSKROperator.combine(shares: $0)
            }
            .tryMap { [unowned self] (seedData) -> Seed in
                let seed = Seed(data: seedData, name: name, creationDate: creationDate)
                self.keychain.set(seed.urString.utf8, forKey: Constant.KeychainKey.seed, isSync: true)
                return seed
            }
            .compactMap { seed in
                Keys.mnemonic(seed.data)
            }
            .tryMap { [unowned self] in
                try self.saveKeyInfo(mnemonic: $0)
            }
            .eraseToAnyPublisher()
    }

    func saveKeyInfo(mnemonic: BIP39Mnemonic) throws {
        let ethPrivateKey = try Keys.ethereumPrivateKey(mnemonic: mnemonic)
        
        let keyInfo = KeyInfo(fingerprint: Keys.fingerprint(mnemonic: mnemonic) ?? "",
                              ethAddress: ethPrivateKey.address.hex(eip55: true),
                              creationDate: Date())

        let keyInfoData = try JSONEncoder().encode(keyInfo)
        keychain.set(keyInfoData, forKey: Constant.KeychainKey.ethInfoKey, isSync: true)
    }
}
