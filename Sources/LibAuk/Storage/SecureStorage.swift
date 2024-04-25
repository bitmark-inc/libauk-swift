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
    func createKey(passphrase: String?, name: String, isPrivate: Bool) -> AnyPublisher<Void, Error>
    func importKey(words: [String], passphrase: String?, name: String, creationDate: Date?, isPrivate: Bool) -> AnyPublisher<Void, Error>
    func isWalletCreated() -> AnyPublisher<Bool, Error>
    func getName() -> String?
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
    func tezosSign(message: Data) -> AnyPublisher<[UInt8], Error>
    func tezosSignTransaction(forgedHex: String) -> AnyPublisher<[UInt8], Error>
    func getTezosPublicKeyWithIndex(index: Int) -> AnyPublisher<String, Error>
    func tezosSignWithIndex(message: Data, index: Int) -> AnyPublisher<[UInt8], Error>
    func tezosSignTransactionWithIndex(forgedHex: String, index: Int) -> AnyPublisher<[UInt8], Error>
    func exportMnemonicPassphrase() -> AnyPublisher<String, Error>
    func exportSeed() -> AnyPublisher<Seed, Error>
    func exportMnemonicWords() -> AnyPublisher<[String], Error>
    func removeKeys() -> AnyPublisher<Void, Error>
    func setSeed(seed: Seed, isPrivate: Bool) -> AnyPublisher<Bool, Error>
    func removeSeed() -> AnyPublisher<Bool, Error>
    func generateSeedPublicData(seed: Seed) throws -> AnyPublisher<SeedPublicData, Error>
    func setData(_ data: Data, forKey: String, isSync: Bool, isPrivate: Bool) -> Bool
}

class SecureStorage: SecureStorageProtocol {

    private let keychain: KeychainProtocol
    
    private let preGenerateAddressLimit: Int = 100

    init(keychain: KeychainProtocol = Keychain()) {
        self.keychain = keychain
    }
    
    private func generateEthAddresses(mnemonic: BIP39Mnemonic, passphrase: String?, start: Int = 0, end: Int = 100) -> [Int: String] {
        var ethAddresses: [Int: String] = [:]

        for index in start...end {
            do {
                // Generate Ethereum private key for the current index
                let privateKey = try Keys.ethereumPrivateKeyWithIndex(mnemonic: mnemonic, passphrase: passphrase, index: index)

                // Derive Ethereum address from the private key
                let address = privateKey.address.hex(eip55: true)

                // Store the address in the dictionary
                ethAddresses[index] = address
            } catch {
                // Handle errors if private key generation fails
                print("Error generating private key for index \(index): \(error)")
            }
        }

        return ethAddresses
    }

    private func generateTezosPublicKeys(mnemonic: BIP39Mnemonic, passphrase: String?, start: Int, end: Int) -> [Int: String] {
        var tezosPublicKeys: [Int: String] = [:]

        for index in start...end {
                // Generate Tezos wallet for the current index
                let tezosWallet = Keys.tezosWalletWithIndex(mnemonic: mnemonic, passphrase: passphrase, index: index)

                // Get the public key for the Tezos wallet
                let publicKey = tezosWallet?.publicKeyBase58encoded()

                // Store the public key in the dictionary
                tezosPublicKeys[index] = publicKey
        }

        return tezosPublicKeys
    }

    private func generateEthAddress(mnemonic: BIP39Mnemonic, passphrase: String?) throws -> String {
        let ethPrivateKey = try Keys.ethereumPrivateKey(mnemonic: mnemonic, passphrase: passphrase)
        let ethAddress = ethPrivateKey.address.hex(eip55: true)
        return ethAddress
    }

    func generateSeedPublicData(seed: Seed) -> AnyPublisher<SeedPublicData, Error> {
        Future<SeedPublicData, Error> { promise in
            do {
                /* seedName */
                let name = seed.name
                
                /*  accountDidKey */
                let mnemonic = Keys.mnemonic(seed.data)!
                let passphrase = seed.passphrase
                let privateKey = try Keys.accountDIDPrivateKey(mnemonic: mnemonic)
                
                // Multicodec encoded with prefix 0xe7
                var bytes: [UInt8] = [231, 1]
                bytes.append(contentsOf: privateKey.publicKey.rawRepresentation.bytes)
                let did = "did:key:z\(Base58.base58Encode(bytes))"
                
                /* pre-generate 100 eth addresses */
                let ethAddresses = self.generateEthAddresses(mnemonic: mnemonic, passphrase: passphrase, start: 0, end: self.preGenerateAddressLimit)
                
                /* encryptionPrivateKey */
                let encryptionPrivateKey = try Keys.encryptionPrivateKey(mnemonic: mnemonic, passphrase: passphrase)
                
                /* accountDIDPrivateKey */
                let accountDIDPrivateKey = try Keys.accountDIDPrivateKey(mnemonic: mnemonic, passphrase: passphrase)
                
                /* tezos public key */
                let tezosPublicKeys = self.generateTezosPublicKeys(mnemonic: mnemonic, passphrase: passphrase, start: 0, end: self.preGenerateAddressLimit)
                
                let ethAddress = try self.generateEthAddress(mnemonic: mnemonic, passphrase: passphrase)
                
                var seedPublicData = SeedPublicData(ethAddress: ethAddress,
                                                    creationDate: Date(),
                                                    name: name,
                                                    did: did,
                                                    preGenerateEthAddress: ethAddresses,
                                                    tezosPublicKeys: tezosPublicKeys)
                
                seedPublicData.encryptionPrivateKey = encryptionPrivateKey
                seedPublicData.accountDIDPrivateKey = accountDIDPrivateKey
                promise(.success(seedPublicData))
            }
            catch {
                promise(.failure(LibAukError.generateSeedPublicDataError))
            }
        }.eraseToAnyPublisher()
    }

    internal func getSeedPublicData() -> SeedPublicData? {
        guard let seedPublicDataRaw = self.keychain.getData(Constant.KeychainKey.seedPublicData, isSync: true),
              let seedPublicData = try? JSONDecoder().decode(SeedPublicData.self, from: seedPublicDataRaw)
        else {
            return nil
        }
        return seedPublicData
    }

    func createKey(passphrase: String? = "", name: String, isPrivate: Bool) -> AnyPublisher<Void, Error> {
        Future<Seed, Error> { promise in
            guard self.getSeedPublicData() == nil else {
                promise(.failure(LibAukError.keyCreationExistingError(key: "createETHKey")))
                return
            }
            
            guard let entropy = KeyCreator.createEntropy() else {
                promise(.failure(LibAukError.keyCreationError))
                return
            }
            
            let seed = Seed(data: entropy, name: name, creationDate: Date(), passphrase: passphrase)
            let seedData = seed.urString.utf8
            
            self.keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true, isPrivate: isPrivate)
            promise(.success(seed))
        }
        .flatMap { seed in
            do {
                return try self.saveSeedPublicData(seed: seed)
                    .map { _ in () } // Map the output to Void
                    .eraseToAnyPublisher()
            } catch {
                return Fail(error: error).eraseToAnyPublisher()
            }
        }.eraseToAnyPublisher()
    }
    
    func importKey(words: [String], passphrase: String? = "", name: String, creationDate: Date?, isPrivate: Bool) -> AnyPublisher<Void, Error> {
        Future<Seed, Error> { promise in
            guard self.getSeedPublicData() == nil else {
                promise(.failure(LibAukError.keyCreationExistingError(key: "createETHKey")))
                return
            }
            
            if let entropy = Keys.entropy(words) {
                let seed = Seed(data: entropy, name: name, creationDate: creationDate ?? Date(), passphrase: passphrase)
                let seedData = seed.urString.utf8

                self.keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true, isPrivate: isPrivate)
                promise(.success(seed))
            } else {
                promise(.failure(LibAukError.invalidMnemonicError))
            }
        }
        .tryMap { [unowned self] in
            try self.saveSeedPublicData(seed: $0)
        }
        .eraseToAnyPublisher()
    }
    
    func setSeed(seed: Seed, isPrivate: Bool) -> AnyPublisher<Bool, Error> {
        Future<Bool, Error> { promise in
            guard self.keychain.set(seed.urString.utf8, forKey: Constant.KeychainKey.seed, isSync: true, isPrivate: isPrivate) else {
                promise(.success(false))
                return
            }
            promise(.success(true))
        }.eraseToAnyPublisher()
    }
    
    func setData(_ data: Data, forKey: String, isSync: Bool = true, isPrivate: Bool) -> Bool {
        return self.keychain.set(data, forKey: forKey, isSync: isSync, isPrivate: isPrivate)
    }

    func removeSeed() -> AnyPublisher<Bool, Error> {
        Future<Bool, Error> { promise in
            guard self.keychain.remove(key: Constant.KeychainKey.seed, isSync: true) else {
                promise(.success(false))
                return
            }
            promise(.success(true))
        }.eraseToAnyPublisher()
    }

    func isWalletCreated() -> AnyPublisher<Bool, Error> {
        Future<Bool, Error> { promise in
            guard let seedPublicDataRaw = self.keychain.getData(Constant.KeychainKey.seedPublicData, isSync: true),
                  (try? JSONDecoder().decode(SeedPublicData.self, from: seedPublicDataRaw)) != nil else {
                promise(.success(false))
                return
            }
            
            promise(.success(true))
        }
        .eraseToAnyPublisher()
    }
    
    func getName() -> String? {
        guard let seedPublicData = self.getSeedPublicData() else {
            return ""
        }
        
        return seedPublicData.name
    }
    
    func getAccountDID() -> AnyPublisher<String, Error> {
        Future<SeedPublicData, Error> { promise in
            guard let seedPublicData = self.getSeedPublicData() else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(seedPublicData))
        }
        .tryMap { (seedPublicData) in
            return seedPublicData.did
        }
        .eraseToAnyPublisher()
    }
    
    func getAccountDIDSignature(message: String) -> AnyPublisher<String, Error> {
        Future<Secp256k1.Signing.PrivateKey, Error> { promise in
            guard let seedPublicData = self.getSeedPublicData(),
                  let privateKey = seedPublicData.accountDIDPrivateKey
            else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            promise(.success(privateKey))
        }
        .tryMap { (privateKey) in
            return try privateKey.signature(for: message.utf8).derRepresentation.hexString
        }
        .eraseToAnyPublisher()
    }
    
    func getETHAddress() -> String? {
        guard let seedPublicData = self.getSeedPublicData(),
              let ethAddress = seedPublicData.ethAddress as String? else {
            return nil
        }
        return ethAddress
    }
    
    func getETHAddressWithIndex(index: Int) -> AnyPublisher<String, Error> {
        Future<String, Error> { promise in
            guard let seedPublicData = self.getSeedPublicData(),
                  let address = seedPublicData.preGenerateEthAddress[index] else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            promise(.success(address))
        }
        .catch({ error in
            Future<Seed, Error> { promise in
                guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                      let seed = try? Seed(urString: seedUR.utf8) else {
                    promise(.failure(LibAukError.emptyKey))
                    return
                }

                promise(.success(seed))
            }
            .compactMap { seed in
                guard let mnemonic = Keys.mnemonic(seed.data) else {
                    return nil
                }
                return (mnemonic, seed.passphrase)
            }
            .tryMap { (mnemonic: BIP39Mnemonic, passphrase: String?) in
                let ethPrivateKey = try Keys.ethereumPrivateKeyWithIndex(mnemonic: mnemonic, passphrase: passphrase, index: index)
                return ethPrivateKey.address.hex(eip55: true)
            }
            .eraseToAnyPublisher()
        })
        .eraseToAnyPublisher()
    }
    
    private func getSeed() -> AnyPublisher<Seed, Error> {
        Future<Seed, Error> { promise in
            guard let seedUR = self.keychain.getData(Constant.KeychainKey.seed, isSync: true),
                  let seed = try? Seed(urString: seedUR.utf8) else {
                promise(.failure(LibAukError.emptyKey))
                return
            }

            promise(.success(seed))
        }.eraseToAnyPublisher()
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
        .compactMap { seed in
            guard let mnemonic = Keys.mnemonic(seed.data) else {
                return nil
            }
            return (mnemonic, seed.passphrase)
        }
        .tryMap { (mnemonic: BIP39Mnemonic, passphrase: String?) in
            let ethPrivateKey = try Keys.ethereumPrivateKey(mnemonic: mnemonic, passphrase: passphrase)
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
        .compactMap { seed in
            guard let mnemonic = Keys.mnemonic(seed.data) else {
                return nil
            }
            return (mnemonic, seed.passphrase)
        }
        .tryMap { (mnemonic: BIP39Mnemonic, passphrase: String?) in
            let ethPrivateKey = try Keys.ethereumPrivateKeyWithIndex(mnemonic: mnemonic, passphrase: passphrase, index: index)
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
        .compactMap { seed in
            guard let mnemonic = Keys.mnemonic(seed.data) else {
                return nil
            }
            return (mnemonic, seed.passphrase)
        }
        .tryMap { (mnemonic: BIP39Mnemonic, passphrase: String?) in
            let ethPrivateKey = try Keys.ethereumPrivateKey(mnemonic: mnemonic, passphrase: passphrase)
            
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
        .compactMap { seed in
            guard let mnemonic = Keys.mnemonic(seed.data) else {
                return nil
            }
            return (mnemonic, seed.passphrase)
        }
        .tryMap { (mnemonic: BIP39Mnemonic, passphrase: String?) in
            let ethPrivateKey = try Keys.ethereumPrivateKeyWithIndex(mnemonic: mnemonic, passphrase: passphrase, index: index)
            
            return try transaction.sign(with: ethPrivateKey, chainId: chainId)
        }
        .eraseToAnyPublisher()
    }

    private func getEncryptKey(usingLegacy: Bool = false) -> AnyPublisher<SymmetricKey, Error> {
        return Future<SeedPublicData, Error> { promise in
            guard let seedPublicData = self.getSeedPublicData() else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            promise(.success(seedPublicData))
        }
        .tryMap({ (seedPublicData) in
            let privateKey = seedPublicData.encryptionPrivateKey!
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

    func getTezosPublicKeyWithIndex(index: Int) -> AnyPublisher<String, Error> {
        return Future<String, Error> { promise in
            guard let seedPublicData = self.getSeedPublicData(),
                  let address = seedPublicData.tezosPublicKeys[index] else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            promise(.success(address))

        }
        .catch({ error in
            return self.getTezosWalletWithIndex(index: index)
                .compactMap {
                    $0.publicKeyBase58encoded()
                }
                .eraseToAnyPublisher()
        })
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

    func exportMnemonicPassphrase() -> AnyPublisher<String, Error> {
        self.exportSeed()
            .map { $0.passphrase ?? "" }
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
            guard self.keychain.getData(Constant.KeychainKey.seedPublicData, isSync: true) != nil else {
                promise(.failure(LibAukError.emptyKey))
                return
            }
            
            self.keychain.remove(key: Constant.KeychainKey.seed, isSync: true)
            self.keychain.remove(key: Constant.KeychainKey.seedPublicData, isSync: true)

            promise(.success(()))
        }
        .eraseToAnyPublisher()
    }

    
    func saveSeedPublicData(seed: Seed) -> AnyPublisher<Void, Error> {
        return self.generateSeedPublicData(seed: seed).tryMap { seedPublicData in
            let seedPublicDataRaw = try JSONEncoder().encode(seedPublicData)
            self.keychain.set(seedPublicDataRaw, forKey: Constant.KeychainKey.seedPublicData, isSync: true, isPrivate: false)
        }.eraseToAnyPublisher()
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
        .compactMap { seed in
            guard let mnemonic = Keys.mnemonic(seed.data) else {
                return nil
            }
            return (mnemonic, seed.passphrase)
        }
        .compactMap { (mnemonic: BIP39Mnemonic, passphrase: String?) in
            Keys.tezosWallet(mnemonic: mnemonic, passphrase: passphrase)
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
        .compactMap { seed in
            guard let mnemonic = Keys.mnemonic(seed.data) else {
                return nil
            }
            return (mnemonic, seed.passphrase)
        }
        .compactMap { (mnemonic: BIP39Mnemonic, passphrase: String?) in
            Keys.tezosWalletWithIndex(mnemonic: mnemonic, passphrase: passphrase, index: index)
        }
        .eraseToAnyPublisher()
    }
}
