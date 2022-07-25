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
        var a: [OrderedMapEntry] = [
            .init(key: 1, value: CBOR.data(data))
        ]
        
        if let creationDate = creationDate {
            a.append(.init(key: 2, value: CBOR.date(creationDate)))
        }
        
        if !name.isEmpty {
            a.append(.init(key: 3, value: CBOR.utf8String(name)))
        }
        
        return CBOR.orderedMap(a)
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
        guard case let CBOR.map(pairs) = cbor else {
            throw LibAukError.other(reason: "ur:crypto-seed: CBOR doesn't contain a map.")
        }
        guard let dataItem = pairs[1], case let CBOR.data(data) = dataItem else {
            throw LibAukError.other(reason: "ur:crypto-seed: CBOR doesn't contain data field.")
        }
        
        let creationDate: Date?
        if let dateItem = pairs[2] {
            guard case let CBOR.date(d) = dateItem else {
                throw LibAukError.other(reason: "ur:crypto-seed: CreationDate field doesn't contain a date.")
            }
            creationDate = d
        } else {
            creationDate = nil
        }
        
        let name: String
        if let nameItem = pairs[3] {
            guard case let CBOR.utf8String(s) = nameItem else {
                throw LibAukError.other(reason: "ur:crypto-seed: Name field doesn't contain string.")
            }
            name = s
        } else {
            name = ""
        }
        
        self.init(data: data, name: name, creationDate: creationDate)
    }
}
