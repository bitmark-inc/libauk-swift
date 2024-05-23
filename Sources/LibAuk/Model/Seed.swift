//
//  Seed.swift
//  
//
//  Created by Ho Hien on 8/11/21.
//

import Foundation
import URKit
import OrderedCollections

public class Seed: Codable {
    public let data: Data
    public let name: String
    public let creationDate: Date?
    public let passphrase: String?
    
    init(data: Data, name: String, creationDate: Date? = nil, passphrase: String? = "") {
        self.data = data
        self.name = name
        self.creationDate = creationDate
        self.passphrase = passphrase
    }
    /*
    
    func cbor(nameLimit: Int? = nil, noteLimit: Int? = nil) -> CBOR {
        var a: [OrderedMap.Entry] = [
            .init(key: 1, value: CBOR.data(data))
        ]
        
        if let creationDate = creationDate {
            a.append(.init(key: 2, value: CBOR.date(creationDate)))
        }
        
        if !name.isEmpty {
            a.append(.init(key: 3, value: CBOR.utf8String(name)))
        }
        
        if let passphrase = passphrase, !passphrase.isEmpty {
            a.append(.init(key: 4, value: CBOR.utf8String(passphrase)))
        }
        
        return CBOR.orderedMap(OrderedMap(a))
    }
    
    public var ur: UR {
        try! UR(type: "crypto-seed", cbor: cbor())
    }
    
    public var urString: String {
        UREncoder.encode(ur)
    }
    
    public convenience init(urString: String) throws {
        let ur = try URDecoder.decode(urString)
        try self.init(ur: ur)
    }
    
    public convenience init(ur: UR) throws {
        guard ur.type == "crypto-seed" else {
            throw LibAukError.other(reason: "Unexpected UR type.")
        }
        try self.init(cborData: ur.cbor)
    }

    public convenience init(cborData: Data) throws {
        guard let cbor = try? CBOR(cborData) else {
            throw LibAukError.other(reason: "ur:crypto-seed: Invalid CBOR.")
        }
        try self.init(cbor: cbor)
    }
    
    public convenience init(cbor: CBOR) throws {
        guard case let CBOR.orderedMap(orderedMap) = cbor else {
            throw LibAukError.other(reason: "ur:crypto-seed: CBOR doesn't contain a map.")
        }

        let iterator = orderedMap.makeIterator()
        var seedData: Data?
        var creationDate: Date? = nil
        var name: String = ""
        var passphrase: String = ""

        while let element = iterator.next() {
            let (indexElement, valueElement) = element

            guard case let CBOR.unsigned(index) = indexElement else {
                throw LibAukError.other(reason: "ur:crypto-seed: CBOR contains invalid keys.")
            }

            switch index {
            case 1:
                guard case let CBOR.bytes(data) = valueElement else {
                    throw LibAukError.other(reason: "ur:crypto-seed: CBOR doesn't contain data field.")
                }
                seedData = data
            case 2:
                guard case let CBOR.date(d) = valueElement else {
                    throw LibAukError.other(reason: "ur:crypto-seed: CreationDate field doesn't contain a date.")
                }
                creationDate = d
            case 3:
                guard case let CBOR.text(s) = valueElement else {
                    throw LibAukError.other(reason: "ur:crypto-seed: Name field doesn't contain a string.")
                }
                name = s
            case 4:
                guard case let CBOR.text(s) = valueElement else {
                    throw LibAukError.other(reason: "ur:crypto-seed: Passphrase field doesn't contain a string.")
                }
                passphrase = s
            default:
                throw LibAukError.other(reason: "ur:crypto-seed: CBOR contains invalid keys.")
            }
        }
        
        
        self.init(data: seedData!, name: name, creationDate: creationDate, passphrase: passphrase)
    }
     */
}
