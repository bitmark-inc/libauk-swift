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
        guard let hdMasterKey = try? HDKey(seed: BIP39(bip39: bip39, passphrase: passphrase ?? "")) else { return nil }
        
        return hdMasterKey.fingerprint.hexString
    }
    
    static func validMnemonicArray(_ words: [String]) -> Bool {
        guard (try? BIP39(words: words).data) != nil else { return false }
        
        return true
    }
    
    static func validMnemonicString(_ words: String) -> Bool {
        guard (try? BIP39(words: words).data) != nil else { return false }
        
        return true
    }
    
    static func entropy(_ words: [String]) -> Data? {
        guard let mnemonic = try? BIP39(words: words).data else { return nil }
        
        return mnemonic.entropy.data
    }
    
    static func entropy(_ words: String) -> Data? {
        guard let mnemonic = try? BIP39(words: words)?.data else { return nil }
        
        return mnemonic.entropy.data
    }
    
    static func mnemonic(_ entropy: Data) -> BIP39? {
        let bip39entropy = BIP39(data: entropy)

        return bip39entropy
    }
    
    static func accountDIDPrivateKey(bip39: BIP39, passphrase: String? = "") throws -> Secp256k1.Signing.PrivateKey {
        let masterKey = try HDKey(seed: BIP39(bip39: bip39, passphrase: passphrase ?? ""))
        let derivationPath = try DerivationPath(string: Constant.accountDerivationPath)
        let account = try masterKey.derive(using: derivationPath)
        
        guard let privateKey = account.privateKey?.data.bytes else {
            throw LibAukError.keyDerivationError
        }
        
        return try Secp256k1.Signing.PrivateKey(rawRepresentation: privateKey)
    }

    static func encryptionPrivateKey(bip39: BIP39, passphrase: String? = "") throws -> Secp256k1.Signing.PrivateKey {
        let masterKey = try HDKey(seed: BIP39(bip39: bip39, passphrase: passphrase ?? ""))
        let derivationPath = try DerivationPath(string: Constant.encryptionKeyDerivationPath)
        let keyPair = try masterKey.derive(using: derivationPath)

        guard let privateKey = keyPair.privKey?.data.bytes else {
            throw LibAukError.keyDerivationError
        }

        return try Secp256k1.Signing.PrivateKey(rawRepresentation: privateKey)
    }

    static func ethereumPrivateKey(bip39: BIP39, passphrase: String? = "") throws -> EthereumPrivateKey {
        let masterKey = try HDKey(seed: BIP39(bip39: bip39, passphrase: passphrase ?? ""))
        let derivationPath = try DerivationPath(string: Constant.ethDerivationPath)
        let account = try HDKey(parent: masterKey, childDerivationPath: derivationPath)
        
        guard let privateKey = account.privateKey?.data.bytes else {
            throw LibAukError.keyDerivationError
        }
        
        return try EthereumPrivateKey(privateKey)
    }
    
    static func ethereumPrivateKeyWithIndex(bip39: BIP39, passphrase: String? = "", index: Int) throws -> EthereumPrivateKey {
        let masterKey = try HDKey(seed: BIP39(bip39: bip39, passphrase: passphrase ?? ""))
        let path = "m/44'/60'/0'/0/\(index)"
        let derivationPath = try DerivationPath(string: path)
        let account = try HDKey(parent: masterKey, childDerivationPath: derivationPath)
        
        guard let privateKey = account.privateKey?.data.bytes else {
            throw LibAukError.keyDerivationError
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
