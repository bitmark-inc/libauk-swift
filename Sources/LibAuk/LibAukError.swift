//
//  LibAukError.swift
//  
//
//  Created by Ho Hien on 8/9/21.
//

import Foundation

public enum LibAukError: Error {
    case initEncryptionError
    case keyCreationError
    case invalidMnemonicError
    case emptyKey
    case keyCreationExistingError(key: String)
    case keyDerivationError
    case other(reason: String)
}

extension LibAukError: LocalizedError {
    public var errorDescription: String? {
        errorMessage
    }

    public var failureReason: String? {
        errorMessage
    }

    public var recoverySuggestion: String? {
        errorMessage
    }

    var errorMessage: String {
        switch self {
        case .initEncryptionError:
            return "init encryption error"
        case .keyCreationError:
            return "create key error"
        case .invalidMnemonicError:
            return "invalid mnemonic error"
        case .emptyKey:
            return "empty Key"
        case .keyCreationExistingError:
            return "create key error: key exists"
        case .keyDerivationError:
            return "key derivation error"
        case .other(let reason):
            return reason
        }
    }
}
