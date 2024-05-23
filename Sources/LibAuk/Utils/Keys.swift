//
//  File.swift
//  
//
//  Created by Ho Hien on 08/10/2021.
//

import Foundation
import Web3
import BCFoundation
import KukaiCoreSwift
import CryptoKit
import TweetNacl

class Keys {
    
    static func fingerprint(bip39: BIP39, passphrase: String? = "") -> String? {
        
        guard let hdMasterKey = try? HDKey(bip39Seed: BIP39.Seed(bip39: bip39, passphrase: passphrase ?? "")) else { return nil }
        
        return hdMasterKey.keyFingerprint.hex
    }
    
    static func validMnemonicArray(_ words: [String]) -> Bool {
        return BIP39(words: words)?.data != nil
    }
    
    static func validMnemonicString(_ words: String) -> Bool {
        return BIP39(mnemonic: words)?.data != nil
    }
    
    static func entropy(_ words: [String]) -> Data? {
        return BIP39(words: words)?.data
    }
    
    static func entropy(_ words: String) -> Data? {
        return BIP39(mnemonic: words)?.data
    }
    
    static func mnemonic(_ entropy: Data) -> BIP39? {
        let bip39entropy = BIP39(data: entropy)

        return bip39entropy
    }
    
    static func accountDIDPrivateKey(bip39: BIP39, passphrase: String? = "") throws -> Secp256k1.Signing.PrivateKey {
        guard let masterKey = try? HDKey(bip39Seed: BIP39.Seed(bip39: bip39, passphrase: passphrase ?? "")) else {
            throw LibAukError.keyCreationError
        }
        guard let derivationPath = DerivationPath(string: Constant.accountDerivationPath) else {
            throw LibAukError.keyDerivationError
        }
        guard let account = try? HDKey(parent: masterKey, childDerivationPath: derivationPath) else {
            throw LibAukError.keyCreationError
        }
        
        guard let privateKey = account.base58PrivateKey?.bytes else {
            throw LibAukError.keyCreationError
        }
        
        return try Secp256k1.Signing.PrivateKey(rawRepresentation: privateKey)
    }

    static func encryptionPrivateKey(bip39: BIP39, passphrase: String? = "") throws -> Secp256k1.Signing.PrivateKey {
        guard let masterKey = try? HDKey(bip39Seed: BIP39.Seed(bip39: bip39, passphrase: passphrase ?? "")) else {
            throw LibAukError.keyCreationError
        }
        guard let derivationPath = DerivationPath(string: Constant.encryptionKeyDerivationPath) else {
            throw LibAukError.keyDerivationError
        }
        guard let keyPair = try? HDKey(parent: masterKey, childDerivationPath: derivationPath) else {
            throw LibAukError.keyCreationError
        }

        guard let privateKey = keyPair.base58PrivateKey?.bytes else {
            throw LibAukError.keyCreationError
        }
        return try Secp256k1.Signing.PrivateKey(rawRepresentation: privateKey)
    }

    static func ethereumPrivateKey(bip39: BIP39, passphrase: String? = "") throws -> EthereumPrivateKey {
        guard let masterKey = try? HDKey(bip39Seed: BIP39.Seed(bip39: bip39, passphrase: passphrase ?? "")) else {
            throw LibAukError.keyCreationError
        }
        guard let derivationPath = DerivationPath(string: Constant.ethDerivationPath) else {
            throw LibAukError.keyDerivationError
        }
        guard let account = try? HDKey(parent: masterKey, childDerivationPath: derivationPath) else {
            throw LibAukError.keyCreationError
        }
        
        guard let privateKey = account.base58PrivateKey?.bytes else {
            throw LibAukError.keyCreationError
        }
        
        return try EthereumPrivateKey(privateKey)
    }
    
    static func ethereumPrivateKeyWithIndex(bip39: BIP39, passphrase: String? = "", index: Int) throws -> EthereumPrivateKey {
        guard let masterKey = try? HDKey(bip39Seed: BIP39.Seed(bip39: bip39, passphrase: passphrase ?? "")) else {
            throw LibAukError.keyCreationError
        }
        let path = "m/44'/60'/0'/0/\(index)"
        guard let derivationPath = DerivationPath(string: path) else {
            throw LibAukError.keyDerivationError
        }
        guard let account = try? HDKey(parent: masterKey, childDerivationPath: derivationPath) else {
            throw LibAukError.keyCreationError
        }
        
        guard let privateKey = account.base58PublicKey?.bytes else {
            throw LibAukError.keyCreationError
        }
        
        return try EthereumPrivateKey(privateKey)
    }
    
    static func tezosWallet(bip39: BIP39, passphrase: String? = "") -> HDWallet? {
        HDWallet.create(withMnemonic: bip39.mnemonic, passphrase: passphrase ?? "")
    }
    
    static func tezosWalletWithIndex(bip39: BIP39, passphrase: String? = "", index: Int) -> HDWallet? {
        let path = "m/44'/1729'/\(index)'/0'"
        return HDWallet.create(withMnemonic: bip39.mnemonic, passphrase: passphrase ?? "", derivationPath: path)
    }
}
