// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use der;
use signature;
use untrusted;

/// An error that occurs during certificate validation or name validation.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VerifyWithSPKIError {
    /// The encoding of some ASN.1 DER-encoded item is invalid.
    BadDER,

    /// The signature is invalid for the given public key.
    InvalidSignatureForPublicKey,

    /// The SignatureAlgorithm does not match the algorithm of the SPKI.
    /// A mismatch could be because of the algorithm (RSA vs DSA, etc) or the
    /// parameters (ECDSA_p256 vs ECDSA_384, etc).
    UnsupportedSignatureAlgorithmForPublicKey,
}

/// Verify the signature `signature` of message `msg` with the public key
/// `spki_public_key` using the algorithm `alg`.
/// `signature::verify` is suitable when the public key bytes you have are the
/// DER ASN.1 of the key. This method is suitable when the public key is in
/// SubjectPublicKeyInfo form (https://tools.ietf.org/html/rfc5280#section-4.1),
/// which is a wrapper containing both the key and an identifier.
///
/// A common situation where this encoding is encountered is when using public keys
/// exported by OpenSSL. If you export an RSA or ECDSA public key from a keypair
/// with `-pubout` and friends, you will get DER of an SPKI wrapper containing
/// a public key. You could extract the bitstring of the key itself and use
/// `signature:;verify`, but that is often inconvient.
pub fn verify(signature_alg: &Algorithm,
              public_key_spki: untrusted::Input,
              msg: untrusted::Input,
              signature: untrusted::Input) -> Result<(), VerifyWithSPKIError> {
    let unwrapped_spki_der = public_key_spki.read_all(VerifyWithSPKIError::BadDER, |input| {
        der::expect_tag_and_get_value(input, der::Tag::Sequence)
            .map_err(|_| VerifyWithSPKIError::BadDER)
    }).unwrap();

    let spki = try!(parse_spki_value(unwrapped_spki_der));
    if !signature_alg.public_key_alg_id
        .matches_algorithm_id_value(spki.algorithm_id_value) {
        return Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey);
    }
    signature::verify(signature_alg.verification_alg, spki.key_value, msg,
                      signature)
        .map_err(|_| VerifyWithSPKIError::InvalidSignatureForPublicKey)
}

struct SubjectPublicKeyInfo<'a> {
    algorithm_id_value: untrusted::Input<'a>,
    key_value: untrusted::Input<'a>,
}

// Parse the public key into an algorithm OID, an optional curve OID, and the
// key value. The caller needs to check whether these match the
// `PublicKeyAlgorithm` for the `SignatureAlgorithm` that is matched when
// parsing the signature.
fn parse_spki_value(input: untrusted::Input)
                    -> Result<SubjectPublicKeyInfo, VerifyWithSPKIError> {
    input.read_all(VerifyWithSPKIError::BadDER, |input| {
        let algorithm_id_value =
        try!(der::expect_tag_and_get_value(input, der::Tag::Sequence)
            .map_err(|_| VerifyWithSPKIError::BadDER));
        let key_value = try!(der::bit_string_with_no_unused_bits(input)
            .map_err(|_| VerifyWithSPKIError::BadDER));
        Ok(SubjectPublicKeyInfo {
            algorithm_id_value: algorithm_id_value,
            key_value: key_value,
        })
    })
}

/// A signature algorithm for use when validating a signature with an SPKI-formatted public key.
pub struct Algorithm {
    /// The `algorithm` member in SPKI from https://tools.ietf.org/html/rfc5280#section-4.1.
    public_key_alg_id: AlgorithmIdentifier,
    verification_alg: &'static signature::VerificationAlgorithm,
}

// RFC 5758 Section 3.2 (ECDSA with SHA-2), and RFC 3279 Section 2.2.3 (ECDSA
// with SHA-1) say that parameters must be omitted. RFC 4055 Section 5 and RFC
// 3279 Section 2.2.1 both say that parameters for RSA must be encoded as NULL;
// we relax that requirement by allowing the NULL to be omitted, to match all
// the other signature algorithms we support and for compatibility.

/// ECDSA signatures using the P-256 curve and SHA-256.
pub static ECDSA_P256_SHA256: Algorithm = Algorithm {
    public_key_alg_id: ECDSA_P256,
    verification_alg: &signature::ECDSA_P256_SHA256_ASN1,
};

/// ECDSA signatures using the P-256 curve and SHA-384. Deprecated.
pub static ECDSA_P256_SHA384: Algorithm = Algorithm {
    public_key_alg_id: ECDSA_P256,
    verification_alg: &signature::ECDSA_P256_SHA384_ASN1,
};

/// ECDSA signatures using the P-384 curve and SHA-256. Deprecated.
pub static ECDSA_P384_SHA256: Algorithm = Algorithm {
    public_key_alg_id: ECDSA_P384,
    verification_alg: &signature::ECDSA_P384_SHA256_ASN1,
};

/// ECDSA signatures using the P-384 curve and SHA-384.
pub static ECDSA_P384_SHA384: Algorithm = Algorithm {
    public_key_alg_id: ECDSA_P384,
    verification_alg: &signature::ECDSA_P384_SHA384_ASN1,
};

/// RSA PKCS#1 1.5 signatures using SHA-1 for keys of 2048-8192 bits.
/// Deprecated.
pub static RSA_PKCS1_2048_8192_SHA1: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA1,
};

/// RSA PKCS#1 1.5 signatures using SHA-256 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA256: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA256,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA384: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA384,
};

/// RSA PKCS#1 1.5 signatures using SHA-512 for keys of 2048-8192 bits.
pub static RSA_PKCS1_2048_8192_SHA512: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_2048_8192_SHA512,
};

/// RSA PKCS#1 1.5 signatures using SHA-384 for keys of 3072-8192 bits.
pub static RSA_PKCS1_3072_8192_SHA384: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PKCS1_3072_8192_SHA384,
};

/// RSA PSS signatures using SHA-256 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA256_LEGACY_KEY: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA256,
};

/// RSA PSS signatures using SHA-384 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA384_LEGACY_KEY: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA384,
};

/// RSA PSS signatures using SHA-512 for keys of 2048-8192 bits and of
/// type rsaEncryption; see https://tools.ietf.org/html/rfc4055#section-1.2
pub static RSA_PSS_2048_8192_SHA512_LEGACY_KEY: Algorithm = Algorithm {
    public_key_alg_id: RSA_ENCRYPTION,
    verification_alg: &signature::RSA_PSS_2048_8192_SHA512,
};

struct AlgorithmIdentifier {
    /// Binary DER for ASN.1 AlgorithmIdentifier without outer SEQUENCE or length.
    asn1_id_value: &'static [u8],
}

impl AlgorithmIdentifier {
    fn matches_algorithm_id_value(&self, encoded: untrusted::Input) -> bool {
        encoded == self.asn1_id_value
    }
}

// See src/data/README.md.

const ECDSA_P256: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-p256.der"),
};

const ECDSA_P384: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-ecdsa-p384.der"),
};

const RSA_ENCRYPTION: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: include_bytes!("data/alg-rsa-encryption.der"),
};

