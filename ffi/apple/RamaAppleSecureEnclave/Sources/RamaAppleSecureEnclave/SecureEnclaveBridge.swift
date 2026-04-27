import CryptoKit
import Darwin
import Foundation
import RamaAppleSEFFI
import Security

// MARK: - Envelope format
//
// Envelope layout produced by `rama_apple_se_p256_encrypt` and consumed by
// `rama_apple_se_p256_decrypt`:
//
//   [ 1 byte  version (= 1)                                  ]
//   [65 bytes ephemeral P-256 public key (X9.63 uncompressed)]
//   [12 bytes AES-GCM nonce                                  ]
//   [ N bytes ciphertext                                     ]
//   [16 bytes AES-GCM tag                                    ]
//
// Total overhead: 94 bytes.
//
// Hybrid scheme: ECDH(ephemeral, recipient SE key) → HKDF-SHA256 → AES-GCM.
// HKDF salt binds both public keys; HKDF info domain-separates this scheme.

private let envelopeVersion: UInt8 = 1
private let p256X963PublicKeySize = 65
private let aesGcmNonceSize = 12
private let aesGcmTagSize = 16
private let envelopeHeaderSize = 1 + p256X963PublicKeySize  // 66
private let envelopeMinSize = envelopeHeaderSize + aesGcmNonceSize + aesGcmTagSize  // 94
private let hkdfInfo = Data("rama-apple-se-p256-ecies-v1".utf8)

// MARK: - Memory helpers

private let emptySeBytes = RamaSeBytes(ptr: nil, len: 0)

private func allocSeBytes(_ data: Data) -> RamaSeBytes? {
    if data.isEmpty {
        return emptySeBytes
    }
    let n = data.count
    guard let raw = malloc(n) else {
        return nil
    }
    let typed = raw.assumingMemoryBound(to: UInt8.self)
    data.copyBytes(to: typed, count: n)
    return RamaSeBytes(ptr: typed, len: n)
}

private func writeOut(_ outPtr: UnsafeMutablePointer<RamaSeBytes>?, _ value: RamaSeBytes) {
    guard let outPtr else { return }
    outPtr.pointee = value
}

private func zeroOut(_ outPtr: UnsafeMutablePointer<RamaSeBytes>?) {
    writeOut(outPtr, emptySeBytes)
}

private func borrowedData(_ ptr: UnsafePointer<UInt8>?, _ len: Int) -> Data? {
    if len == 0 {
        return Data()
    }
    guard let ptr else {
        return nil
    }
    return Data(bytes: ptr, count: len)
}

// MARK: - Access control

// `kSecAttrAccessibleAlways` is deprecated by Apple but is the only accessibility
// class that lets a Network Extension System Extension daemon use the SE before
// any user has logged in. Apple acknowledges this in
// https://developer.apple.com/forums/thread/804612 and notes that Swift has no
// good way to silence the deprecation diagnostic — we accept the warning here
// for the one intentional call site.
@available(macOS 10.15, *)
private func makeAccessControl(
    _ accessibility: RamaSeAccessibility
) -> SecAccessControl? {
    let protection: CFString
    switch accessibility {
    case RAMA_SE_ACCESSIBILITY_ALWAYS:
        protection = kSecAttrAccessibleAlways
    case RAMA_SE_ACCESSIBILITY_AFTER_FIRST_UNLOCK:
        protection = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    default:
        return nil
    }
    return SecAccessControlCreateWithFlags(nil, protection, [], nil)
}

// MARK: - HKDF salt + key derivation

@available(macOS 10.15, *)
private func deriveSymmetricKey(
    sharedSecret: SharedSecret,
    ephemeralPub: P256.KeyAgreement.PublicKey,
    recipientPub: P256.KeyAgreement.PublicKey
) -> SymmetricKey {
    var salt = Data()
    salt.append(ephemeralPub.x963Representation)
    salt.append(recipientPub.x963Representation)
    return sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: salt,
        sharedInfo: hkdfInfo,
        outputByteCount: 32
    )
}

// MARK: - Public bridge entry points

@_cdecl("rama_apple_se_is_available")
public func rama_apple_se_is_available() -> Bool {
    if #available(macOS 10.15, *) {
        return SecureEnclave.isAvailable
    }
    return false
}

@_cdecl("rama_apple_se_p256_create")
public func rama_apple_se_p256_create(
    _ accessibility: RamaSeAccessibility,
    _ outBlob: UnsafeMutablePointer<RamaSeBytes>?
) -> Int32 {
    zeroOut(outBlob)

    guard #available(macOS 10.15, *), SecureEnclave.isAvailable else {
        return RAMA_SE_ERR_UNAVAILABLE
    }
    guard let ac = makeAccessControl(accessibility) else {
        return RAMA_SE_ERR_BAD_INPUT
    }

    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: true,
            accessControl: ac,
            authenticationContext: nil
        )
        guard let bytes = allocSeBytes(key.dataRepresentation) else {
            return RAMA_SE_ERR_SYSTEM
        }
        writeOut(outBlob, bytes)
        return RAMA_SE_OK
    } catch {
        return RAMA_SE_ERR_SYSTEM
    }
}

@_cdecl("rama_apple_se_p256_encrypt")
public func rama_apple_se_p256_encrypt(
    _ blob: UnsafePointer<UInt8>?, _ blobLen: Int,
    _ pt: UnsafePointer<UInt8>?, _ ptLen: Int,
    _ outCt: UnsafeMutablePointer<RamaSeBytes>?
) -> Int32 {
    zeroOut(outCt)

    guard #available(macOS 10.15, *) else {
        return RAMA_SE_ERR_UNAVAILABLE
    }
    guard let blobData = borrowedData(blob, blobLen), !blobData.isEmpty else {
        return RAMA_SE_ERR_BAD_INPUT
    }
    guard let ptData = borrowedData(pt, ptLen) else {
        return RAMA_SE_ERR_BAD_INPUT
    }

    let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blobData,
            authenticationContext: nil
        )
    } catch {
        return RAMA_SE_ERR_BAD_INPUT
    }

    do {
        let recipientPub = seKey.publicKey
        let ephemeralPriv = P256.KeyAgreement.PrivateKey()
        let ephemeralPub = ephemeralPriv.publicKey
        let shared = try ephemeralPriv.sharedSecretFromKeyAgreement(with: recipientPub)
        let symmetric = deriveSymmetricKey(
            sharedSecret: shared,
            ephemeralPub: ephemeralPub,
            recipientPub: recipientPub
        )
        let sealed = try AES.GCM.seal(ptData, using: symmetric)
        guard let combined = sealed.combined else {
            return RAMA_SE_ERR_CRYPTO
        }

        let ephemeralRepr = ephemeralPub.x963Representation
        guard ephemeralRepr.count == p256X963PublicKeySize else {
            return RAMA_SE_ERR_CRYPTO
        }

        var envelope = Data(capacity: envelopeHeaderSize + combined.count)
        envelope.append(envelopeVersion)
        envelope.append(ephemeralRepr)
        envelope.append(combined)

        guard let bytes = allocSeBytes(envelope) else {
            return RAMA_SE_ERR_SYSTEM
        }
        writeOut(outCt, bytes)
        return RAMA_SE_OK
    } catch {
        return RAMA_SE_ERR_CRYPTO
    }
}

@_cdecl("rama_apple_se_p256_decrypt")
public func rama_apple_se_p256_decrypt(
    _ blob: UnsafePointer<UInt8>?, _ blobLen: Int,
    _ ct: UnsafePointer<UInt8>?, _ ctLen: Int,
    _ outPt: UnsafeMutablePointer<RamaSeBytes>?
) -> Int32 {
    zeroOut(outPt)

    guard #available(macOS 10.15, *) else {
        return RAMA_SE_ERR_UNAVAILABLE
    }
    guard let blobData = borrowedData(blob, blobLen), !blobData.isEmpty else {
        return RAMA_SE_ERR_BAD_INPUT
    }
    guard let ctData = borrowedData(ct, ctLen), ctData.count >= envelopeMinSize else {
        return RAMA_SE_ERR_BAD_INPUT
    }
    guard ctData[ctData.startIndex] == envelopeVersion else {
        return RAMA_SE_ERR_BAD_INPUT
    }

    let ephemRange =
        ctData.index(ctData.startIndex, offsetBy: 1)..<ctData.index(
            ctData.startIndex, offsetBy: envelopeHeaderSize)
    let combinedRange =
        ctData.index(ctData.startIndex, offsetBy: envelopeHeaderSize)..<ctData.endIndex
    let ephemBytes = ctData.subdata(in: ephemRange)
    let combined = ctData.subdata(in: combinedRange)

    let seKey: SecureEnclave.P256.KeyAgreement.PrivateKey
    do {
        seKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blobData,
            authenticationContext: nil
        )
    } catch {
        return RAMA_SE_ERR_BAD_INPUT
    }

    let ephemeralPub: P256.KeyAgreement.PublicKey
    do {
        ephemeralPub = try P256.KeyAgreement.PublicKey(x963Representation: ephemBytes)
    } catch {
        return RAMA_SE_ERR_BAD_INPUT
    }

    do {
        let shared = try seKey.sharedSecretFromKeyAgreement(with: ephemeralPub)
        let symmetric = deriveSymmetricKey(
            sharedSecret: shared,
            ephemeralPub: ephemeralPub,
            recipientPub: seKey.publicKey
        )
        let sealed = try AES.GCM.SealedBox(combined: combined)
        let plaintext = try AES.GCM.open(sealed, using: symmetric)
        guard let bytes = allocSeBytes(plaintext) else {
            return RAMA_SE_ERR_SYSTEM
        }
        writeOut(outPt, bytes)
        return RAMA_SE_OK
    } catch {
        return RAMA_SE_ERR_CRYPTO
    }
}
