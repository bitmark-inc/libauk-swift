//
//  Secp256k1.swift
//  secp256-swift
//
//  Created by Ho Hien on 2/25/21.
//  Copyright © 2020 Bitmark Inc. All rights reserved.
//

import Foundation
import CryptoKit
import secp256k1

public enum Secp256k1 {
}

extension Secp256k1 {
    
    public enum Signing {
    
        public struct PublicKey {
            
            private let baseKey: Secp256k1.Signing.PublicKeyImplementation

            public init<D: ContiguousBytes>(rawRepresentation data: D) throws {
                self.baseKey = try Secp256k1.Signing.PublicKeyImplementation(rawRepresentation: data)
            }

            fileprivate init(baseKey: Secp256k1.Signing.PublicKeyImplementation) {
                self.baseKey = baseKey
            }

            public var rawRepresentation: Data {
                self.baseKey.rawRepresentation
            }
        }
        
        public struct PrivateKey {
            
            private let baseKey: Secp256k1.Signing.PrivateKeyImplementation

            public init() {
                self.baseKey = Secp256k1.Signing.PrivateKeyImplementation()
            }

            public var publicKey: PublicKey {
                PublicKey(baseKey: self.baseKey.publicKey)
            }

            public init<D: ContiguousBytes>(rawRepresentation data: D) throws {
                self.baseKey = try Secp256k1.Signing.PrivateKeyImplementation(rawRepresentation: data)
            }

            public var rawRepresentation: Data {
                self.baseKey.rawRepresentation
            }
        }
        
        public struct ECDSASignature : ContiguousBytes {
            
            private let signature: Secp256k1.Signing.ECDSASignatureImplementation

            public init<D: ContiguousBytes>(rawRepresentation data: D) throws {
                self.signature = try Secp256k1.Signing.ECDSASignatureImplementation(rawRepresentation: data)
            }

            public init<D: ContiguousBytes>(derRepresentation data: D) throws {
                self.signature = try Secp256k1.Signing.ECDSASignatureImplementation(derRepresentation: data)
            }

            public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
                try rawRepresentation.withUnsafeBytes(body)
            }
            
            public var rawRepresentation: Data {
                signature.rawRepresentation
            }

            public var derRepresentation: Data {
                signature.derRepresentation
            }
        }
    }
}

extension Secp256k1.Signing.PrivateKey {

    /// Generates an ECDSA signature over the Secp256k1 elliptic curve.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: ContiguousBytes>(for data: D) throws -> Secp256k1.Signing.ECDSASignature {
        try baseKey.signature(for: data)
    }
}

extension Secp256k1.Signing.PublicKey {

    /// Verifies an EdDSA signature over Secp256k1.
    ///
    /// - Parameters:
    ///   - signature: The 64-bytes signature to verify.
    ///   - data: The digest that was signed.
    /// - Returns: True if the signature is valid. False otherwise.
    public func isValidSignature<D: ContiguousBytes>(_ signature: Secp256k1.Signing.ECDSASignature, for data: D) -> Bool {
        baseKey.isValidSignature(signature, for: data)
    }
}

extension Secp256k1.Signing {

    @usableFromInline struct PrivateKeyImplementation {

        private let privateKeyBytes: SecureBytes

        private let publicKeyBytes: [UInt8]
        
        @usableFromInline var publicKey: Secp256k1.Signing.PublicKeyImplementation {
            return PublicKeyImplementation(self.publicKeyBytes)
        }

        @usableFromInline init() {
            
            // Initialize context
            let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!

            defer {
                // Destory context after creation
                secp256k1_context_destroy(context)
            }

            // Setup private and public key variables
            var pubkeyLen = 33
            var cPubkey = secp256k1_pubkey()
            var pubkey = [UInt8](repeating: 0, count: 33)
            let privatekey = SecureBytes(count: 128)
            let privkey = Data(privatekey).withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })

            // Verify the context and keys are setup correctly
            guard secp256k1_context_randomize(context, privkey) == 1,
                secp256k1_ec_pubkey_create(context, &cPubkey, privkey) == 1,
                secp256k1_ec_pubkey_serialize(context, &pubkey, &pubkeyLen, &cPubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 1 else {
                self.privateKeyBytes = privatekey
                self.publicKeyBytes = pubkey
                return
            }

            // Save
            self.privateKeyBytes = privatekey
            self.publicKeyBytes = pubkey
        }

        init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            // Initialize context
            let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!

            defer {
                // Destory context after creation
                secp256k1_context_destroy(context)
            }

            // Setup private and public key variables
            var pubkeyLen = 33
            var cPubkey = secp256k1_pubkey()
            var pubkey = [UInt8](repeating: 0, count: 33)
            let privatekey = SecureBytes(bytes: data)
            let privkey = data.withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })

            // Verify the context and keys are setup correctly
            guard privkey.count == 32,
                  secp256k1_context_randomize(context, privkey) == 1,
                  secp256k1_ec_pubkey_create(context, &cPubkey, privkey) == 1,
                  secp256k1_ec_pubkey_serialize(context, &pubkey, &pubkeyLen, &cPubkey, UInt32(SECP256K1_EC_COMPRESSED)) == 1 else {
                self.privateKeyBytes = privatekey
                self.publicKeyBytes = pubkey
                return
            }

            // Save
            self.privateKeyBytes = privatekey
            self.publicKeyBytes = pubkey            
        }

        @usableFromInline var rawRepresentation: Data {
            Data(self.privateKeyBytes)
        }
        
        func signature<D: ContiguousBytes>(for data: D) throws -> Secp256k1.Signing.ECDSASignature {
            // Initialize context
            let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!

            defer {
                // Destory context after creation
                secp256k1_context_destroy(context)
            }
            
            let privkey = Data(privateKeyBytes).withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })
            let message = SHA256.hash(data: data.withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })).withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })
            
            var signature = [UInt8](repeating: 0, count: 64)
            var cSig = secp256k1_ecdsa_signature()
            
            // Generate and serialize signature
            guard secp256k1_ecdsa_sign(context, &cSig, message, privkey, nil, nil) == 1,
                  secp256k1_ecdsa_signature_serialize_compact(context, &signature, &cSig) == 1 else {
                throw Secp256k1Error.signingError
            }
            
            return try ECDSASignature(rawRepresentation: signature)
        }
    }

    @usableFromInline struct PublicKeyImplementation {

        private let keyBytes: [UInt8]

        @usableFromInline init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            self.keyBytes = data.withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })
        }

        init(_ keyBytes: [UInt8]) {
            self.keyBytes = keyBytes
        }

        @usableFromInline var rawRepresentation: Data {
            Data(self.keyBytes)
        }
        
        func isValidSignature<D: ContiguousBytes>(_ signature: Secp256k1.Signing.ECDSASignature, for data: D) -> Bool {
            let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY))!

            defer { secp256k1_context_destroy(context) }
            
            var cPubkey = secp256k1_pubkey()
            var cSig = secp256k1_ecdsa_signature()
            let sig = signature.rawRepresentation.withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })
            let msg = SHA256.hash(data: data.withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })).withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })
            
            guard secp256k1_ec_pubkey_parse(context, &cPubkey, keyBytes, keyBytes.count) == 1,
                  secp256k1_ecdsa_signature_parse_compact(context, &cSig, sig) == 1,
                  secp256k1_ecdsa_verify(context, &cSig, msg, &cPubkey) == 1 else {
                return false
            }
            return true
        }
    }
    
    @usableFromInline struct ECDSASignatureImplementation {
        private let rawSignatureBytes: [UInt8]
        private let derSignatureBytes: [UInt8]

        @usableFromInline init<D: ContiguousBytes>(rawRepresentation data: D) throws {
            self.rawSignatureBytes = data.withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })
            
            // Initialize context
            let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))!

            defer {
                // Destory context after creation
                secp256k1_context_destroy(context)
            }
            
            var derSize: Int = 72
            var derSignature = [UInt8](repeating: 0, count: derSize)
            var cSig = secp256k1_ecdsa_signature()

            // parse and serialize der
            guard rawSignatureBytes.count == 64,
                secp256k1_ecdsa_signature_parse_compact(context, &cSig, rawSignatureBytes) == 1,
                  secp256k1_ecdsa_signature_serialize_der(context, &derSignature, &derSize, &cSig) == 1 else {
                throw Secp256k1Error.invalidSignature
            }
            
            while (derSignature.last == 0) {
                derSignature.removeLast()
            }
            
            self.derSignatureBytes = derSignature
        }
        
        @usableFromInline init<D: ContiguousBytes>(derRepresentation data: D) throws {
            self.derSignatureBytes = data.withUnsafeBytes({ keyBytesPtr in Array(keyBytesPtr) })
            
            // Initialize context
            let context = secp256k1_context_create(UInt32(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))!

            defer {
                // Destory context after creation
                secp256k1_context_destroy(context)
            }
            
            var signature = [UInt8](repeating: 0, count: 64)
            var cSig = secp256k1_ecdsa_signature()
            
            // Parse signature
            guard secp256k1_ecdsa_signature_parse_der(context, &cSig, derSignatureBytes, derSignatureBytes.count) == 1,
                  secp256k1_ecdsa_signature_serialize_compact(context, &signature, &cSig) == 1 else {
                throw Secp256k1Error.signingError
            }
            
            self.rawSignatureBytes = signature
        }
        
        @usableFromInline var rawRepresentation: Data {
            Data(self.rawSignatureBytes)
        }
        
        @usableFromInline var derRepresentation: Data {
            Data(self.derSignatureBytes)
        }
    }
}
