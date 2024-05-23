//
//  KeyCreator.swift
//  
//
//  Created by Ho Hien on 8/9/21.
//

import Foundation
import BCFoundation

class KeyCreator {
    
    static func createEntropy() -> Data? {
        guard let hex = Data.secureRandom(16)?.hexString,
              let entropy = try? BIP39(hex: hex) else {
            return nil
        }
        
        return entropy.data
    }
}
