//
//  MFTKeyGenerator.swift
//  mft
//
//  Copyright © 2026 Marcin Labenski. All rights reserved.
//

import Foundation
@_implementationOnly import libssh

/// A newly generated SSH key pair.
///
/// The private half is what the client keeps and must be protected. The
/// public half is what goes in the server's authorized_keys.
@objcMembers public class MFTKeyPair: NSObject {
    /// The private key, PEM wrapped and encrypted when a passphrase was given.
    /// Ed25519 keys come out in OpenSSH format, RSA and ECDSA keys in PKCS#8.
    public let privateKey: String
    /// One authorized_keys line, without a trailing comment.
    public let publicKey: String
    /// The algorithm, as named on the wire, such as "ssh-ed25519".
    public let keyType: String

    init(privateKey: String, publicKey: String, keyType: String) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.keyType = keyType
    }
}

/// Which kind of key to generate.
@objc public enum MFTKeyType: Int {
    /// Small, fast, and the sensible default for a new key.
    case ed25519
    case rsa4096
    case ecdsa256

    var sshType: ssh_keytypes_e {
        switch self {
        case .ed25519: return SSH_KEYTYPE_ED25519
        case .rsa4096: return SSH_KEYTYPE_RSA
        case .ecdsa256: return SSH_KEYTYPE_ECDSA_P256
        }
    }

    /// The RSA modulus size to ask for, where the type does not already imply
    /// the key size. libssh defaults to 3072 bits, so 4096 has to be requested.
    var rsaKeySize: Int32? {
        switch self {
        case .rsa4096: return 4096
        case .ed25519, .ecdsa256: return nil
        }
    }
}

@objcMembers public class MFTKeyGenerator: NSObject {

    /// Generates an SSH key pair.
    ///
    /// Needs no connection: this is local key material, made before there is
    /// anything to connect to.
    /// - Parameters:
    ///     - type: The algorithm to use.
    ///     - passphrase: Encrypts the private half. Pass nil or a blank string
    ///       to leave it unencrypted.
    /// - Returns: The generated pair.
    /// - Throws: NSError on error.
    public static func generate(type: MFTKeyType, passphrase: String? = nil) throws -> MFTKeyPair {
        var context: ssh_pki_ctx?
        if var bits = type.rsaKeySize {
            context = ssh_pki_ctx_new()
            guard let context,
                  ssh_pki_ctx_options_set(context, SSH_PKI_OPTION_RSA_KEY_SIZE, &bits) == SSH_OK
            else {
                throw NSError(
                    domain: "mft",
                    code: MFTErrorCode.wrong_keyfile.rawValue,
                    userInfo: [NSLocalizedDescriptionKey: "Could not set the key size."]
                )
            }
        }
        defer { if let context { ssh_pki_ctx_free(context) } }

        var key: ssh_key?
        guard ssh_pki_generate_key(type.sshType, context, &key) == SSH_OK, let key else {
            throw NSError(
                domain: "mft",
                code: MFTErrorCode.wrong_keyfile.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Could not generate a key."]
            )
        }
        defer { ssh_key_free(key) }

        var privateBuffer: UnsafeMutablePointer<CChar>?
        let secret = (passphrase?.isEmpty == false) ? passphrase : nil
        guard ssh_pki_export_privkey_base64(key, secret, nil, nil, &privateBuffer) == SSH_OK,
              let privateBuffer
        else {
            throw NSError(
                domain: "mft",
                code: MFTErrorCode.wrong_keyfile.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Could not export the generated private key."]
            )
        }
        defer { ssh_string_free_char(privateBuffer) }

        var publicBuffer: UnsafeMutablePointer<CChar>?
        guard ssh_pki_export_pubkey_base64(key, &publicBuffer) == SSH_OK, let publicBuffer else {
            throw NSError(
                domain: "mft",
                code: MFTErrorCode.wrong_keyfile.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Could not export the generated public key."]
            )
        }
        defer { ssh_string_free_char(publicBuffer) }

        let typeName = String(cString: ssh_key_type_to_char(ssh_key_type(key)))
        // ssh_pki_export_pubkey_base64 returns the payload alone, while
        // authorized_keys wants the algorithm in front of it.
        let publicLine = "\(typeName) \(String(cString: publicBuffer))"

        return MFTKeyPair(
            privateKey: String(cString: privateBuffer),
            publicKey: publicLine,
            keyType: typeName
        )
    }
}
