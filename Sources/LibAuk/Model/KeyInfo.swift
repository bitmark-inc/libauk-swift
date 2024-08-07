//
//  Key.swift
//  
//
//  Created by Ho Hien on 8/9/21.
//

import Foundation

public struct KeyInfo: Codable {
    let fingerprint, ethAddress: String
    let creationDate: Date
}
