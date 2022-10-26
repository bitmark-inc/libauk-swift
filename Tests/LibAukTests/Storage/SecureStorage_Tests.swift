//
//  SecureStorage_Tests.swift
//  
//
//  Created by Ho Hien on 8/10/21.
//

import Foundation
import XCTest
import LibWally
import Combine
import Web3
import URKit
@testable import LibAuk

class SecureStorage_Tests: XCTestCase {
    
    private var cancelBag: Set<AnyCancellable>!
    private var storage: SecureStorage!
    private var keychain: KeychainMock!

    override func setUpWithError() throws {
        cancelBag = []
        keychain = KeychainMock()
        storage = SecureStorage(keychain: keychain)
        LibAuk.create(keyChainGroup: "com.bitmark.autonomy")
    }

    override func tearDownWithError() throws {
        storage = nil
        keychain = nil
        cancelBag.removeAll()
    }
    
    func testCreateKeySuccessfully() throws {
        let receivedExpectation = expectation(description: "all values received")

        storage.createKey(name: "account1")
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    XCTAssertNotNil(self.keychain.getData(Constant.KeychainKey.seed))
                    XCTAssertTrue(self.keychain.getSync(Constant.KeychainKey.seed)!)
                    XCTAssertNotNil(self.keychain.getData(Constant.KeychainKey.ethInfoKey))
                    XCTAssertTrue(self.keychain.getSync(Constant.KeychainKey.ethInfoKey)!)

                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("create key failed \(error)")
                }

            }, receiveValue: { _ in })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testImportKeySuccessfully() throws {
        let words: [String] = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak".components(separatedBy: " ")
        let receivedExpectation = expectation(description: "all values received")

        storage.importKey(words: words, name: "account1", creationDate: Date(timeIntervalSince1970: 1628656699))
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    XCTAssertNotNil(self.keychain.getData(Constant.KeychainKey.seed))
                    XCTAssertTrue(self.keychain.getSync(Constant.KeychainKey.seed)!)
                    XCTAssertNotNil(self.keychain.getData(Constant.KeychainKey.ethInfoKey))
                    XCTAssertTrue(self.keychain.getSync(Constant.KeychainKey.ethInfoKey)!)

                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("import key failed \(error)")
                }

            }, receiveValue: { _ in })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testIsWalletCreatedSuccessfully() throws {
        let mnemomic = try BIP39Mnemonic(words: "daring mix cradle palm crowd sea observe whisper rubber either uncle oak")
        try storage.saveKeyInfo(mnemonic: mnemomic)
        
        let receivedExpectation = expectation(description: "all values received")

        storage.isWalletCreated()
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("IsWalletCreated failed \(error)")
                }

            }, receiveValue: { isCreated in
                XCTAssertTrue(isCreated)
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testUpdateNameSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date())
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")

        storage.updateName(name: "account2")
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    let seed = try! Seed(urString: self.keychain.getData(Constant.KeychainKey.seed)!.utf8)
                    XCTAssertEqual(seed.name, "account2")
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("update name failed \(error)")
                }

            }, receiveValue: { _ in })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testGetNameSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date())
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        XCTAssertEqual(storage.getName(), "account1")
    }
    
    func testGetNameWithOptionalCreationDateSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: nil)
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        XCTAssertEqual(storage.getName(), "account1")
    }
    
    func testGetNameWithEmptySuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "", creationDate: Date())
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        XCTAssertEqual(storage.getName(), "")
    }
    
    func testGetETHAddressSuccessfully() throws {
        let mnemomic = try BIP39Mnemonic(words: "daring mix cradle palm crowd sea observe whisper rubber either uncle oak")
        try storage.saveKeyInfo(mnemonic: mnemomic)
        
        XCTAssertEqual(storage.getETHAddress(), "0xA00cbE6a45102135A210F231901faA6c05D51465")
    }
    
    func testGetAccountDIDSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date())
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")
        
        storage.getAccountDID()
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("get account DID failed \(error)")
                }

            }, receiveValue: { (did) in
                XCTAssertEqual(did, "did:key:zQ3shUnBWE7Dkskaozsnzsb78kVcgQFbtXf7zdCCDN3qepBGL")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testGetAccountDIDSignatureSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date())
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")
        
        storage.getAccountDIDSignature(message: "hello")
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("get account DID failed \(error)")
                }

            }, receiveValue: { (signature) in
                XCTAssertEqual(signature, "3045022100bcab09830ca590e641db881d9642ea2372cecedc1a37647e9d6ab8365521b7c0022041cba853b76596a64baf909aa311a18ae4d79c88aec15a080a897e3266e44aa2")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testSignMessageSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date())
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let message = "hello"
        let receivedExpectation = expectation(description: "all values received")
        
        storage.ethSign(message: message.bytes)
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("sign messge failed \(error)")
                }

            }, receiveValue: { (v, r, s) in
                XCTAssertEqual(v, 1)
                XCTAssertEqual(Data(r).hexString, "87996ffe97e732c1e20463a5858a03c9ca4084117dfbc95c5f7dd79c766ef7f9")
                XCTAssertEqual(Data(s).hexString, "3cbc5e6025e1c5a1b49406c59c6e64c81af18d0b9b122bf5b227bab7af3e0aa8")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testSignTransactionSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date())
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let tx = EthereumTransaction(
            nonce: 1,
            gasPrice: EthereumQuantity(quantity: 21.gwei),
            gas: 21000,
            to: try EthereumAddress(hex: "0xCeb523d2cE54b34af420cab27e10eD56ebcc93DE", eip55: true),
            value: EthereumQuantity(quantity: 1.eth)
        )
        let receivedExpectation = expectation(description: "all values received")
        
        storage.ethSignTransaction(transaction: tx, chainId: 0)
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("signTx failed \(error)")
                }

            }, receiveValue: { signedTx in
                XCTAssertTrue(signedTx.verifySignature())
                XCTAssertEqual(signedTx.chainId, 0)
                XCTAssertEqual(signedTx.nonce, 1)
                XCTAssertEqual(signedTx.gasPrice, EthereumQuantity(quantity: 21.gwei))
                XCTAssertEqual(signedTx.to?.hex(eip55: true), "0xCeb523d2cE54b34af420cab27e10eD56ebcc93DE")
                XCTAssertEqual(signedTx.value, EthereumQuantity(quantity: 1.eth))
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testGetTezosWalletSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date(timeIntervalSince1970: 1628656699))
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")
        
        storage.getTezosWallet()
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("exportSeed failed \(error)")
                }

            }, receiveValue: { wallet in
                XCTAssertEqual(wallet.address, "tz1TK8o3WKrPLKGwMgsdn3duPtT9tJcdh3FQ")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testGetTezosPublickeySuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date(timeIntervalSince1970: 1628656699))
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")
        
        storage.getTezosPublicKey()
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("exportSeed failed \(error)")
                }

            }, receiveValue: { publickKey in
                XCTAssertEqual(publickKey, "edpkuJKSkDoBpDs1aDtQWfBothZxpu6KxWG8gkB77TLxjJ344adoaP")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testTezosSignMessageSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date(timeIntervalSince1970: 1628656699))
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")
        
        storage.tezosSign(message: "hello".data(using: .utf8)!)
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("exportSeed failed \(error)")
                }

            }, receiveValue: { data in
                XCTAssertEqual(data.toHexString(), "fd778e710e90b554c7e6e74d34adc00f8804d3fe667b47de96f8c8a9ef1b5af7ffa80808a460ff8411558d1180f8aa6e905299a983c251c2d5a29750540a7f0e")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testTezosSignTransactionSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date(timeIntervalSince1970: 1628656699))
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")
        
        storage.tezosSignTransaction(forgedHex: "0xad059fe0310b029f")
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("exportSeed failed \(error)")
                }

            }, receiveValue: { data in
                XCTAssertEqual(data.toHexString(), "923fbff6073c4be53f2af62ff5dc35a9063a4272f70a306f1a3c2226ea9589997c41842c2b16945f86c7213d77c0d6e3a7605e03f90a28abe5e2b10a7a65e40e")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testGetBitmarkAddressSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date(timeIntervalSince1970: 1628656699))
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let keyInfo = KeyInfo(fingerprint: "0a3df912", ethAddress: "0xA00cbE6a45102135A210F231901faA6c05D51465", creationDate: Date(timeIntervalSince1970: 1628656699))
        let keyInfoData = try JSONEncoder().encode(keyInfo)
        keychain.set(keyInfoData, forKey: Constant.KeychainKey.ethInfoKey, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")
        
        storage.getBitmarkAddress()
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("exportSeed failed \(error)")
                }

            }, receiveValue: { adress in
                XCTAssertEqual(adress, "a8CEoztw62ockgt8TcXjt1Davw8HTEkJ2k1247qagDVp1RqLyT")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testExportSeedSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date(timeIntervalSince1970: 1628656699))
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let keyInfo = KeyInfo(fingerprint: "0a3df912", ethAddress: "0xA00cbE6a45102135A210F231901faA6c05D51465", creationDate: Date(timeIntervalSince1970: 1628656699))
        let keyInfoData = try JSONEncoder().encode(keyInfo)
        keychain.set(keyInfoData, forKey: Constant.KeychainKey.ethInfoKey, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")
        
        storage.exportSeed()
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("exportSeed failed \(error)")
                }

            }, receiveValue: { seed in
                XCTAssertEqual(seed.data.hexString, "3791c0c7cfa34583e61fd4bcc8e3b24b")
                XCTAssertEqual(seed.creationDate, Date(timeIntervalSince1970: 1628656699))
                XCTAssertEqual(seed.ur.string, "ur:crypto-seed/otadgdemmertsttkotfelsvacttyrfspvlprgraosecyhsbwghfraxishsiaiajlkpjtjyehwscsfejs")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }

    func testExportMnemonicWordsSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date())
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")

        storage.exportMnemonicWords()
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("exportMnemonicWords failed \(error)")
                }

            }, receiveValue: { mnemonicWords in
                XCTAssertEqual(mnemonicWords.joined(separator: " "), "daring mix cradle palm crowd sea observe whisper rubber either uncle oak")
            })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
    
    func testRemoveKeysSuccessfully() throws {
        let words = "daring mix cradle palm crowd sea observe whisper rubber either uncle oak"
        let seed = Seed(data: Keys.entropy(words)!, name: "account1", creationDate: Date(timeIntervalSince1970: 1628656699))
        let seedData = seed.urString.utf8
        keychain.set(seedData, forKey: Constant.KeychainKey.seed, isSync: true)
        
        let keyInfo = KeyInfo(fingerprint: "0a3df912", ethAddress: "0xA00cbE6a45102135A210F231901faA6c05D51465", creationDate: Date(timeIntervalSince1970: 1628656699))
        let keyInfoData = try JSONEncoder().encode(keyInfo)
        keychain.set(keyInfoData, forKey: Constant.KeychainKey.ethInfoKey, isSync: true)
        
        let receivedExpectation = expectation(description: "all values received")

        storage.removeKeys()
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    XCTAssertNil(self.keychain.getData(Constant.KeychainKey.seed))
                    XCTAssertNil(self.keychain.getData(Constant.KeychainKey.ethInfoKey))

                    receivedExpectation.fulfill()
                case .failure(let error):
                    XCTFail("remove keys failed \(error)")
                }

            }, receiveValue: { _ in })
            .store(in: &cancelBag)

        waitForExpectations(timeout: 1, handler: nil)
    }
}
