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
import Sodium

public protocol SecureStorageProtocol {
    func createKey(name: String) -> AnyPublisher<Void, Error>
    func importKey(words: [String], name: String, creationDate: Date?) -> AnyPublisher<Void, Error>
    func isWalletCreated() -> AnyPublisher<Bool, Error>
    func getName() -> String?
    func updateName(name: String) -> AnyPublisher<Void, Error>
    func getAccountDID() -> AnyPublisher<String, Error>
    func getAccountDIDSignature(message: String) -> AnyPublisher<String, Error>
    func getETHAddress() -> String?
    func ethSign(message: Bytes) -> AnyPublisher<(v: UInt, r: Bytes, s: Bytes), Error>
    func ethSignTransaction(transaction: EthereumTransaction, chainId: EthereumQuantity) -> AnyPublisher<EthereumSignedTransaction, Error>
    func getETHAddressWithIndex(index: Int) -> AnyPublisher<String, Error>
    func ethSignWithIndex(message: Bytes, index: Int) -> AnyPublisher<(v: UInt, r: Bytes, s: Bytes), Error>
    func ethSignTransactionWithIndex(transaction: EthereumTransaction, chainId: EthereumQuantity, index: Int) -> AnyPublisher<EthereumSignedTransaction, Error>
    func encryptFile(inputPath: String, outputPath: String) -> AnyPublisher<String, Error>
    func decryptFile(inputPath: String, outputPath: String, usingLegacy: Bool) -> AnyPublisher<String, Error>
    func getTezosPublicKey() -> AnyPublisher<String, Error>
    func tezosSign(message: Data) -> AnyPublisher<[UInt8], Error>
    func tezosSignTransaction(forgedHex: String) -> AnyPublisher<[UInt8], Error>
    func getTezosPublicKeyWithIndex(index: Int) -> AnyPublisher<String, Error>
    func tezosSignWithIndex(message: Data, index: Int) -> AnyPublisher<[UInt8], Error>
    func tezosSignTransactionWithIndex(forgedHex: String, index: Int) -> AnyPublisher<[UInt8], Error>
    func exportSeed() -> AnyPublisher<Seed, Error>
    func exportMnemonicWords() -> AnyPublisher<[String], Error>
    func removeKeys() -> AnyPublisher<Void, Error>
}

class SecureStorage: SecureStorageProtocol {
    
    private let keychain: KeychainProtocol
    
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
    
    func getETHAddressWithIndex(index: Int) -> AnyPublisher<String, Error> {
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
            let ethPrivateKey = try Keys.ethereumPrivateKeyWithIndex(mnemonic: mnemonic, index: index)
            return ethPrivateKey.address.hex(eip55: true)
        }
        .eraseToAnyPublisher()
    }
    
    func ethSign(message: Bytes) -> AnyPublisher<(v: UInt, r: Bytes, s: Bytes), Error> {
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
    
    func ethSignWithIndex(message: Bytes, index: Int) -> AnyPublisher<(v: UInt, r: Bytes, s: Bytes), Error> {
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
            let ethPrivateKey = try Keys.ethereumPrivateKeyWithIndex(mnemonic: mnemonic, index: index)
            return try ethPrivateKey.sign(message: message)
        }
        .eraseToAnyPublisher()
    }
       
    func ethSignTransaction(transaction: EthereumTransaction, chainId: EthereumQuantity) -> AnyPublisher<EthereumSignedTransaction, Error> {
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
    
    func ethSignTransactionWithIndex(transaction: EthereumTransaction, chainId: EthereumQuantity, index: Int) -> AnyPublisher<EthereumSignedTransaction, Error> {
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
            let ethPrivateKey = try Keys.ethereumPrivateKeyWithIndex(mnemonic: mnemonic, index: index)
            
            return try transaction.sign(with: ethPrivateKey, chainId: chainId)
        }
        .eraseToAnyPublisher()
    }

    private func getEncryptKey(usingLegacy: Bool = false) -> AnyPublisher<SymmetricKey, Error> {
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
            if (usingLegacy) {
                return SymmetricKey(data: privateKey.rawRepresentation)
            } else {
                let encryptionKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: privateKey.rawRepresentation), salt: Data(), outputByteCount: 32)
                return encryptionKey
            }
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

    func decryptFile(inputPath: String, outputPath: String, usingLegacy: Bool) -> AnyPublisher<String, Error> {
        return getEncryptKey(usingLegacy: usingLegacy).tryMap({ key in
            let url = URL(fileURLWithPath: inputPath)
            let data = try Data(contentsOf: url)
            let box = try ChaChaPoly.SealedBox(combined: data)
            let decrypted = try ChaChaPoly.open(box, using: key)
            try decrypted.write(to: URL(fileURLWithPath: outputPath))
            return outputPath
        })
        .eraseToAnyPublisher()
    }
    
    func getTezosPublicKey() -> AnyPublisher<String, Error> {
        getTezosWallet()
            .compactMap {
                $0.publicKeyBase58encoded()
            }
            .eraseToAnyPublisher()
    }
    
    func getTezosPublicKeyWithIndex(index: Int) -> AnyPublisher<String, Error> {
        getTezosWalletWithIndex(index: index)
            .compactMap {
                $0.publicKeyBase58encoded()
            }
            .eraseToAnyPublisher()
    }
    
    func tezosSign(message: Data) -> AnyPublisher<[UInt8], Error> {
        getTezosWallet()
            .compactMap { wallet in
                let messageHash = Sodium.shared.genericHash.hash(message: message.bytes, outputLength: 32) ?? []
                let messageHashData = Data(bytes: messageHash, count: messageHash.count)

                let signedData = wallet.privateKey.sign(digest: messageHashData, curve: .ed25519)
                
                return signedData?.bytes
            }
            .eraseToAnyPublisher()
    }
    
    func tezosSignWithIndex(message: Data, index: Int) -> AnyPublisher<[UInt8], Error> {
        getTezosWalletWithIndex(index: index)
            .compactMap { wallet in
                let messageHash = Sodium.shared.genericHash.hash(message: message.bytes, outputLength: 32) ?? []
                let messageHashData = Data(bytes: messageHash, count: messageHash.count)

                let signedData = wallet.privateKey.sign(digest: messageHashData, curve: .ed25519)
                
                return signedData?.bytes
            }
            .eraseToAnyPublisher()
    }
    
    func tezosSignTransaction(forgedHex: String) -> AnyPublisher<[UInt8], Error> {
        getTezosWallet()
            .compactMap {
                $0.sign(forgedHex)
            }
            .eraseToAnyPublisher()
    }
    
    func tezosSignTransactionWithIndex(forgedHex: String, index: Int) -> AnyPublisher<[UInt8], Error> {
        getTezosWalletWithIndex(index: index)
            .compactMap {
                $0.sign(forgedHex)
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

            promise(.success(()))
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
    
    internal func getTezosWallet() -> AnyPublisher<HDWallet, Error> {
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
    
    internal func getTezosWalletWithIndex(index: Int) -> AnyPublisher<HDWallet, Error> {
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
            Keys.tezosWalletWithIndex(mnemonic: $0, index: index)
        }
        .eraseToAnyPublisher()
    }
}
