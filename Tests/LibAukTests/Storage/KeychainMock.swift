//
//  KeychainMock.swift
//
//
//  Created by Ho Hien on 8/10/21.
//  Copyright © 2021 Bitmark Inc. All rights reserved.
//

import Foundation
@testable import LibAuk

class KeychainMock: KeychainProtocol {

    var values = [String: (Data, Bool)]()
    
    @discardableResult
    func set(_ data: Data, forKey: String, isSync: Bool) -> Bool {
        values[forKey] = (data, isSync)
        return true
    }
    
    func getData(_ key: String, isSync: Bool) -> Data? {
        if let value = values[key], value.1 == isSync {
            return value.0
        } else {
            return nil
        }
    }
    
    @discardableResult
    func remove(key: String, isSync: Bool) -> Bool {
        values.removeValue(forKey: key)
        return true
    }
    
    func getData(_ key: String) -> Data? {
        values[key]?.0
    }
    
    func getSync(_ key: String) -> Bool? {
        values[key]?.1
    }
}
