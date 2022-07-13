//
//  Shard.swift
//  
//
//  Created by Thuyên Trương on 04/07/2022.
//

import Foundation

struct Shard: Codable {
    let shard: Data
    let type: ShardType
}

public enum ShardType: Int, CaseIterable, Codable {
    case platform = 0
    case shardService = 1
    case contact = 2

    var isSync: Bool {
        true // Issue#298: store in iCloud Keychain for all types
    }
}
