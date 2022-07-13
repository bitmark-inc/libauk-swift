//
//  Constant.swift
//  
//
//  Created by Ho Hien on 8/9/21.
//

import Foundation

struct Constant {
    
    static let ethDerivationPath = "m/44'/60'/0'/0/0"
    static let bitmarkDerivationPath = "m/44'/731'/0'/0/0"
    static let accountDerivationPath = "m/44'/985'/0'/0/0"
    static let encryptionKeyDerivationPath = "m/44'/985'/0'/0/1"

    struct KeychainKey {
        static func personaPrefix(at uuid: UUID) -> String {
            "persona.\(uuid.uuidString)"
        }

        static let seed = "seed"
        static let ethInfoKey = "ethInfo"

        static func shardKey(type: ShardType) -> String {
            "shards.\(type.rawValue)"
        }
    }
}
