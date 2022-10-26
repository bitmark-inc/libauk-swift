//
//  Seed.swift
//  
//
//  Created by Ho Hien on 8/11/21.
//

import Foundation
import URKit

public class Seed: Codable {
    public let data: Data
    public let name: String
    public let creationDate: Date?
    
    init(data: Data, name: String, creationDate: Date? = nil) {
        self.data = data
        self.name = name
        self.creationDate = creationDate
    }
    
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
        
        return CBOR.orderedMap(OrderedMap(a))
    }
    
    public var ur: UR {
        try! UR(type: "crypto-seed", cbor: cbor())
    }
    
    public var urString: String {
        UREncoder.encode(ur)
    }
    
    convenience init(urString: String) throws {
        let ur = try URDecoder.decode(urString)
        try self.init(ur: ur)
    }
    
    convenience init(ur: UR) throws {
        guard ur.type == "crypto-seed" else {
            throw LibAukError.other(reason: "Unexpected UR type.")
        }
        try self.init(cborData: ur.cbor)
    }

    convenience init(cborData: Data) throws {
        guard let cbor = try? CBOR(cborData) else {
            throw LibAukError.other(reason: "ur:crypto-seed: Invalid CBOR.")
        }
        try self.init(cbor: cbor)
    }
    
    convenience init(cbor: CBOR) throws {
        guard case let CBOR.orderedMap(orderedMap) = cbor else {
            throw LibAukError.other(reason: "ur:crypto-seed: CBOR doesn't contain a map.")
        }
        let iterator = orderedMap.makeIterator()
        guard let seedData = iterator.next(), case let CBOR.unsignedInt(index) = seedData.0, index == 1, case let CBOR.data(data) = seedData.1 else {
            throw LibAukError.other(reason: "ur:crypto-seed: CBOR doesn't contain data field.")
        }
        
        var creationDate: Date? = nil
        var name: String = ""
        
        if let secondElement = iterator.next() {
            guard case let CBOR.unsignedInt(index) = secondElement.0 else {
                throw LibAukError.other(reason: "ur:crypto-seed: CBOR contains invalid keys.")
            }
            
            if index == 2 {
                guard case let CBOR.date(d) = secondElement.1 else {
                    throw LibAukError.other(reason: "ur:crypto-seed: CreationDate field doesn't contain a date.")
                }
                creationDate = d
                
                if let nameData = iterator.next(), case let CBOR.unsignedInt(index) = nameData.0, index == 3, case let CBOR.utf8String(s) = nameData.1 {
                    name = s
                }
                
            } else if index == 3 {
                guard case let CBOR.utf8String(s) = secondElement.1 else {
                    throw LibAukError.other(reason: "ur:crypto-seed: Name field doesn't contain a string.")
                }
                name = s
            } else {
                throw LibAukError.other(reason: "ur:crypto-seed: CBOR contains invalid keys.")
            }
        }
        
        self.init(data: data, name: name, creationDate: creationDate)
    }
}
