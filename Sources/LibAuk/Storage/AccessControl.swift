//
//  AccessControl.swift
//
//
//  Created by Nguyen Phuoc Sang on 27/03/2024.
//

import Foundation
import LocalAuthentication


class AccessControl {

    // MARK: - Singleton
    public static let shared = AccessControl()

    // Policy
    private var policy: LAPolicy = .deviceOwnerAuthentication

    var accessible: CFString = kSecAttrAccessibleWhenUnlocked

    // Reason
    var reason: String = NSLocalizedString("Access your password on the keychain", comment: "")

    // Context
    lazy var context: LAContext = {
        let mainContext = LAContext()
        mainContext.touchIDAuthenticationAllowableReuseDuration = Double(5)
        mainContext.localizedReason = reason
        return mainContext
    }()
}
