//
//  File.swift
//  
//
//  Created by Ho Hien on 08/10/2021.
//

import Foundation
import LibWally
import Web3
import KukaiCoreSwift
import CryptoKit
import TweetNacl
import BitmarkSDK

class Keys {
    
    static func fingerprint(mnemonic: BIP39Mnemonic, passphrase: String = "") -> String? {
        guard let hdMasterKey = try? HDKey(seed: mnemonic.seedHex(passphrase: passphrase)) else { return nil }
        
        return hdMasterKey.fingerprint.hexString
    }
    
    static func validMnemonicArray(_ words: [String]) -> Bool {
        guard (try? BIP39Mnemonic(words: words)) != nil else { return false }
        
        return true
    }
    
    static func validMnemonicString(_ words: String) -> Bool {
        guard (try? BIP39Mnemonic(words: words)) != nil else { return false }
        
        return true
    }
    
    static func entropy(_ words: [String]) -> Data? {
        guard let mnemonic = try? BIP39Mnemonic(words: words) else { return nil }
        
        return mnemonic.entropy.data
    }
    
    static func entropy(_ words: String) -> Data? {
        guard let mnemonic = try? BIP39Mnemonic(words: words) else { return nil }
        
        return mnemonic.entropy.data
    }
    
    static func mnemonic(_ entropy: Data) -> BIP39Mnemonic? {
        let bip39entropy = BIP39Mnemonic.Entropy(entropy)

        return try? BIP39Mnemonic(entropy: bip39entropy)
    }
    
    static func accountDIDPrivateKey(mnemonic: BIP39Mnemonic, passphrase: String = "") throws -> Secp256k1.Signing.PrivateKey {
        let masterKey = try HDKey(seed: mnemonic.seedHex(passphrase: ""))
        let derivationPath = try BIP32Path(string: Constant.accountDerivationPath)
        let account = try masterKey.derive(using: derivationPath)
        
        guard let privateKey = account.privKey?.data.bytes else {
            throw LibAukError.keyDerivationError
        }
        
        return try Secp256k1.Signing.PrivateKey(rawRepresentation: privateKey)
    }
    
    static func ethereumPrivateKey(mnemonic: BIP39Mnemonic, passphrase: String = "") throws -> EthereumPrivateKey {
        let masterKey = try HDKey(seed: mnemonic.seedHex(passphrase: ""))
        let derivationPath = try BIP32Path(string: Constant.ethDerivationPath)
        let account = try masterKey.derive(using: derivationPath)
        
        guard let privateKey = account.privKey?.data.bytes else {
            throw LibAukError.keyDerivationError
        }
        
        return try EthereumPrivateKey(privateKey)
    }
    
    static func tezosWallet(mnemonic: BIP39Mnemonic, passphrase: String = "") -> HDWallet? {
        HDWallet.create(withMnemonic: mnemonic.words.joined(separator: " "), passphrase: passphrase)
    }
    
    static func bitmarkPrivateKey(mnemonic: BIP39Mnemonic, passphrase: String = "") throws -> String {
        let masterKey = try HDKey(seed: mnemonic.seedHex(passphrase: ""))
        let derivationPath = try BIP32Path(string: Constant.bitmarkDerivationPath)
        let account = try masterKey.derive(using: derivationPath)
        
        guard let privateKey = account.privKey?.data.bytes else {
            throw LibAukError.keyDerivationError
        }

        let seed = Data(privateKey)

        let keyPair = try NaclSign.KeyPair.keyPair(fromSeed: seed)
        
        return try Account(withSeedOrphanedPrivateKey: keyPair.secretKey).address
    }
}
