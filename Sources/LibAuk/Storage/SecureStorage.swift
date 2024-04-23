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
    func migrateFromKeyInfo2SeedPublicData() -> AnyPublisher<Bool, Error>
    func migrateSeed(isPrivate: Bool) -> AnyPublisher<Bool, Error>
}

class SecureStorage: SecureStorageProtocol {
    func migrateFromKeyInfo2SeedPublicData() -> AnyPublisher<Bool, Error> {
        Future<Bool, Error> { promise in
            let isPasscodeEnable = UserDefaults.standard.bool(forKey: "flutter.device_passcode")
            promise(.success(true))
        }.eraseToAnyPublisher()
    }

    func migrateSeed(isPrivate: Bool) -> AnyPublisher<Bool, Error> {
        Future<Bool, Error> { promise in
            guard self.getSeedPublicData() == nil else {
                promise(.failure(LibAukError.keyCreationExistingError(key: "seedPublicData")))
                return
            }
            promise(.success(true))

        }.eraseToAnyPublisher()
    }

    private let keychain: KeychainProtocol
    
    private let preGenerateAddressLimit: Int = 100

    init(keychain: KeychainProtocol = Keychain()) {
        self.keychain = keychain
    }
    
    internal func generateEthAddresses(mnemonic: BIP39Mnemonic, start: Int = 0, end: Int = 100) -> [Int: String] {
        var ethAddresses: [Int: String] = [:]

        for index in start...end {
            do {
                // Generate Ethereum private key for the current index
                let privateKey = try Keys.ethereumPrivateKeyWithIndex(mnemonic: mnemonic, index: index)

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

    internal func generateTezosAddresses(mnemonic: BIP39Mnemonic, start: Int = 0, end: Int = 100) -> [Int: String] {
        var tezosAddresses: [Int: String] = [:]

        for index in start...end {
            do {
                let privateKey = try Keys.ethereumPrivateKeyWithIndex(mnemonic: mnemonic, index: index)
                let address = privateKey.address.hex(eip55: true)
                // Store the address in the dictionary
                tezosAddresses[index] = address
            } catch {
                print("Error generating private key for index \(index): \(error)")
            }
        }

        return tezosAddresses
    }

    internal func generateTezosPublicKeys(mnemonic: BIP39Mnemonic, start: Int, end: Int) -> [Int: String] {
        var tezosPublicKeys: [Int: String] = [:]

        for index in start...end {
            do {
                // Generate Tezos wallet for the current index
                let tezosWallet = Keys.tezosWalletWithIndex(mnemonic: mnemonic, index: index)

                // Get the public key for the Tezos wallet
                let publicKey = tezosWallet?.publicKeyBase58encoded()

                // Store the public key in the dictionary
                tezosPublicKeys[index] = publicKey
            } catch {
                // Handle errors if Tezos wallet generation fails
                print("Error generating Tezos public key for index \(index): \(error)")
            }
        }

        return tezosPublicKeys
    }

    internal func generateEthAddress(mnemonic: BIP39Mnemonic) throws -> String {
        let ethPrivateKey = try Keys.ethereumPrivateKey(mnemonic: mnemonic)
        let ethAddress = ethPrivateKey.address.hex(eip55: true)
        return ethAddress
    }

    internal func generateSeedPublicData(seed: Seed) throws -> SeedPublicData? {
        do {
            /* seedName */
            let name = seed.name

            /*  accountDidKey */
            let mnemonic = Keys.mnemonic(seed.data)!
            let privateKey = try Keys.accountDIDPrivateKey(mnemonic: mnemonic)

            // Multicodec encoded with prefix 0xe7
            var bytes: [UInt8] = [231, 1]
            bytes.append(contentsOf: privateKey.publicKey.rawRepresentation.bytes)
            let did = "did:key:z\(Base58.base58Encode(bytes))"

            /* pre-generate 100 eth addresses */
            let ethAddresses = generateEthAddresses(mnemonic: mnemonic, start: 0, end: self.preGenerateAddressLimit)

            /* pre-generate 100 tezos addresses */
            let tezosAddresses = generateTezosAddresses(mnemonic: mnemonic, start: 0, end: self.preGenerateAddressLimit)

            /* encryptionPrivateKey */
            let encryptionPrivateKey = try Keys.encryptionPrivateKey(mnemonic: mnemonic)

            /* accountDIDPrivateKey */
            let accountDIDPrivateKey = try Keys.accountDIDPrivateKey(mnemonic: mnemonic)

            /* tezos public key */
            let tezosPublicKeys = generateTezosPublicKeys(mnemonic: mnemonic, start: 0, end: self.preGenerateAddressLimit)

            let ethAddress = try generateEthAddress(mnemonic: mnemonic)



            var seedPublicData = SeedPublicData(ethAddress: ethAddress,
                creationDate: Date(),
                                  name: name,
                                  did: did,
                                  preGenerateEthAddress: ethAddresses,
                                  preGenerateTezosAddress: tezosAddresses,
                                  tezosPublicKeys: tezosPublicKeys)

            seedPublicData.encryptionPrivateKey = encryptionPrivateKey
            seedPublicData.accountDIDPrivateKey = accountDIDPrivateKey
            return seedPublicData
        }
        catch {
            print("Error generating public info")
        }
        return nil


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
            guard self.keychain.getData(Constant.KeychainKey.seedPublicData, isSync: true) == nil else {
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
        .tryMap { [unowned self] in
            try self.saveSeedPublicData(seed: $0)
        }

        .eraseToAnyPublisher()
    }
    
    func importKey(words: [String], passphrase: String? = "", name: String, creationDate: Date?, isPrivate: Bool) -> AnyPublisher<Void, Error> {
        Future<Seed, Error> { promise in
            guard self.keychain.getData(Constant.KeychainKey.seedPublicData, isSync: true) == nil else {
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

    
    func saveSeedPublicData(seed: Seed) throws {
        let seedPublicData = try self.generateSeedPublicData(seed: seed)

        let seedPublicDataRaw = try JSONEncoder().encode(seedPublicData)
        keychain.set(seedPublicDataRaw, forKey: Constant.KeychainKey.seedPublicData, isSync: true, isPrivate: false)
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
