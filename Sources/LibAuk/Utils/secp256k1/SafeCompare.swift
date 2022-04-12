//
//  SafeCompare.swift
//  secp256-swift
//
//  Created by Ho Hien on 2/25/21.
//  Copyright © 2020 Bitmark Inc. All rights reserved.
//

import Foundation

internal func safeCompare<LHS: ContiguousBytes, RHS: ContiguousBytes>(_ lhs: LHS, _ rhs: RHS) -> Bool {
    return openSSLSafeCompare(lhs, rhs)
}
