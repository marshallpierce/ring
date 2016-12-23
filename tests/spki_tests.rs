extern crate ring;
extern crate untrusted;
extern crate rustc_serialize;

use std::io::BufRead;
use std::path::Path;
use std::vec::Vec;
use std::io::Read;
use std::fs::File;
use rustc_serialize::base64::FromBase64;
use ring::der;
use ring::signature::spki;
use ring::signature::spki::VerifyWithSPKIError;
use ring::signature;
#[cfg(feature = "rsa_signing")]
use ring::rand;

// TODO: The expected results need to be modified for SHA-1 deprecation.

macro_rules! test_verify_signature_pem {
    ($fn_name:ident, $file_name:expr, $signature_alg:expr, $expected_result:expr) => {
        #[test]
        fn $fn_name() {
            test_verify_signature_pem($file_name, $signature_alg, $expected_result);
        }
    }
}

fn test_verify_signature_pem(file_name: &str,
                             signature_algorithm: &'static spki::Algorithm,
                             expected_result: Result<(), VerifyWithSPKIError>) {
    let tsd = parse_test_signed_data(file_name);
    let spki_value = untrusted::Input::from(&tsd.spki);

    let signature = untrusted::Input::from(&tsd.signature);
    let signature = signature.read_all(VerifyWithSPKIError::BadDER, |input| {
        der::bit_string_with_no_unused_bits(input)
            .map_err(|_| VerifyWithSPKIError::BadDER)
    }).unwrap();

    assert_eq!(expected_result,
    spki::verify(signature_algorithm,
                 spki_value,
                 untrusted::Input::from(&tsd.data),
                 signature));
}

macro_rules! test_rsa_sign_verify_spki {
    ($fn_name:ident, $signing_encoding:expr, $algorithm:expr, $key_id:expr) => {
        #[cfg(feature = "rsa_signing")]
        #[test]
        fn $fn_name() {
            rsa_sign_and_verify_spki($signing_encoding, $algorithm, $key_id);
        }
    }
}

macro_rules! test_rsa_verify_sig_file_spki {
    ($fn_name:ident,
     $algorithm:expr,
     $key_id:expr,
     $padding_alg:expr,
     $digest_alg:expr,
     $wrong_key_id:expr,
     $wrong_digest_alg:expr) => {
        #[cfg(feature = "rsa_signing")]
        #[test]
        fn $fn_name() {
            // check existing signature file with spki pub key
            rsa_verify_signature_file_with_spki($algorithm,
                                                $key_id,
                                                $key_id,
                                                $padding_alg,
                                                $digest_alg,
                                                "msg1",
                                                "msg1",
                                                Ok(()));

            // fails when compared to signature file for other input
            rsa_verify_signature_file_with_spki($algorithm,
                                                $key_id,
                                                $key_id,
                                                $padding_alg,
                                                $digest_alg,
                                                "msg1",
                                                "msg2",
                                                Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));

            // fails when compared to signature file with wrong digest alg
            rsa_verify_signature_file_with_spki($algorithm,
                                                $key_id,
                                                $key_id,
                                                $padding_alg,
                                                $wrong_digest_alg,
                                                "msg1",
                                                "msg1",
                                                Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));

            // fails when compared to signature file with wrong key
            rsa_verify_signature_file_with_spki($algorithm,
                                                $key_id,
                                                $wrong_key_id,
                                                $padding_alg,
                                                $digest_alg,
                                                "msg1",
                                                "msg1",
                                                Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
        }
    }
}

macro_rules! test_ec_verify_sig_file_spki {
    ($fn_name:ident,
     $algorithm:expr,
     $key_id:expr,
     $digest_alg:expr,
     $wrong_key_id:expr,
     $wrong_digest_alg:expr) => {
        #[test]
        fn $fn_name() {
            // check existing signature file with spki pub key
            ec_verify_signature_file_with_spki($algorithm,
                                               $key_id,
                                               $key_id,
                                               $digest_alg,
                                               "msg1",
                                               "msg1",
                                               Ok(()));

            // fails when compared to signature file for other input
            ec_verify_signature_file_with_spki($algorithm,
                                               $key_id,
                                               $key_id,
                                               $digest_alg,
                                               "msg1",
                                               "msg2",
                                               Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));

            // fails when compared to signature file with wrong digest alg
            ec_verify_signature_file_with_spki($algorithm,
                                               $key_id,
                                               $key_id,
                                               $wrong_digest_alg,
                                               "msg1",
                                               "msg1",
                                               Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));

            // fails when compared to signature file with wrong key
            ec_verify_signature_file_with_spki($algorithm,
                                               $key_id,
                                               $wrong_key_id,
                                               $digest_alg,
                                               "msg1",
                                               "msg1",
                                               Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
        }
    }
}

/// Load key pair and sign input, then verify signature with pub key loaded from SPKI DER
#[cfg(feature = "rsa_signing")]
fn rsa_sign_and_verify_spki(signing_encoding: &'static signature::RSAEncoding,
                            algorithm: &spki::Algorithm,
                            key_id: &str) {
    let key_pair_der = read_file_completely(Path::new(&format!("tests/test-data/keys/{}.der", key_id)));
    let key_pair = signature::RSAKeyPair::from_der(untrusted::Input::from(&key_pair_der)).unwrap();

    // Create a signing state.
    let key_pair = std::sync::Arc::new(key_pair);
    let mut signing_state = signature::RSASigningState::new(key_pair).unwrap();

    // Generate signature
    let input = read_file_completely(Path::new("tests/test-data/messages/msg1.bin"));
    let rng = rand::SystemRandom::new();
    let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
    signing_state.sign(signing_encoding, &rng, &input, &mut signature).unwrap();

    // load pub key spki
    let spki_path = format!("tests/test-data/keys/{}_pub_spki.der", key_id);
    let spki_bytes = read_file_completely(Path::new(&spki_path));
    let spki_input = untrusted::Input::from(&spki_bytes);

    // Verify the signature.
    spki::verify(algorithm,
                 spki_input,
                 untrusted::Input::from(&input),
                 untrusted::Input::from(&signature))
        .unwrap();
}

/// Verify signature of input compared with pre-calculated signature loaded from file.
///
/// Allows signature verification with various flavors of right and wrong parameters: using
/// one key to sign but comparing against another key's signature, etc.
///
/// This loads keys, input files, signatures, etc from the hierarchy in tests/test-data/.
///
/// algorithm: spki verification algorithm
/// key_id: the key ("rsa_2048", "ecdsa_secp256k1", etc) when loading the key pair
/// key_sig_id: the key when loading a pre-calculated signature file. If different from key_id,
///     verification will fail, of course.
/// padding_alg: padding alg when loading a signature file. If it doesn't match the padding in
///     `algorithm`, verification will fail.
/// digest_alg: digest alg when loading a signature file.  If it doesn't match the digest in
///     `algorithm`, verification will fail.
/// message_id: the input file to verify the signature of. Either "msg1" or "msg2".
/// msg_sig_id: the input file to load the pre-existing signature of. If different from
///     `message_id`, verification will fail.
#[cfg(feature = "rsa_signing")]
fn rsa_verify_signature_file_with_spki(algorithm: &spki::Algorithm,
                                       key_id: &str,
                                       key_sig_id: &str,
                                       padding_alg: &str,
                                       digest_alg: &str,
                                       message_id: &str,
                                       msg_sig_id: &str,
                                       expected: Result<(), VerifyWithSPKIError>) {
    verify_signature_with_spki(algorithm,
                               Path::new(&format!("tests/test-data/messages/{}.bin", message_id)),
                               Path::new(&format!("tests/test-data/signatures/{}_{}_{}_{}_sig.bin",
                                                  msg_sig_id,
                                                  key_sig_id,
                                                  padding_alg,
                                                  digest_alg)),
                               Path::new(&format!("tests/test-data/keys/{}_pub_spki.der", key_id)),
                               expected);
}

/// Verify signature of input compared with pre-calculated signature loaded from file.
///
/// Allows signature verification with various flavors of right and wrong parameters: using
/// one key to sign but comparing against another key's signature, etc.
///
/// This loads keys, input files, signatures, etc from the hierarchy in tests/test-data/.
///
/// algorithm: spki verification algorithm
/// key_id: the key ("rsa_2048", "ecdsa_secp256k1", etc) when loading the key pair
/// key_sig_id: the key when loading a pre-calculated signature file. If different from key_id,
///     verification will fail, of course.
/// digest_alg: digest alg when loading a signature file.  If it doesn't match the digest in
///     `algorithm`, verification will fail.
/// message_id: the input file to verify the signature of. Either "msg1" or "msg2".
/// msg_sig_id: the input file to load the pre-existing signature of. If different from
///     `message_id`, verification will fail.
fn ec_verify_signature_file_with_spki(algorithm: &spki::Algorithm,
                                      key_id: &str,
                                      key_sig_id: &str,
                                      digest_alg: &str,
                                      message_id: &str,
                                      msg_sig_id: &str,
                                      expected: Result<(), VerifyWithSPKIError>) {
    verify_signature_with_spki(algorithm,
                               Path::new(&format!("tests/test-data/messages/{}.bin", message_id)),
                               Path::new(&format!("tests/test-data/signatures/{}_{}_{}_sig.bin",
                                                  msg_sig_id,
                                                  key_sig_id,
                                                  digest_alg)),
                               Path::new(&format!("tests/test-data/keys/{}_pub_spki.der", key_id)),
                               expected);
}

fn verify_signature_with_spki(algorithm: &spki::Algorithm,
                              message_path: &Path,
                              sig_path: &Path,
                              spki_path: &Path,
                              expected: Result<(), VerifyWithSPKIError>) {
    let input = read_file_completely(message_path);
    let signature = read_file_completely(sig_path);

    let spki_bytes = read_file_completely(spki_path);
    let spki_input = untrusted::Input::from(&spki_bytes);

    // Verify the signature.
    assert_eq!(expected, spki::verify(algorithm,
                                      spki_input,
                                      untrusted::Input::from(&input),
                                      untrusted::Input::from(&signature)));
}

fn read_file_completely(path: &Path) -> Vec<u8> {
    let mut f = File::open(path).unwrap();
    let mut vec = Vec::new();
    assert!(f.read_to_end(&mut vec).unwrap() > 0);
    return vec;
}

// TODO sha1 support?
//    test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_2048_sha1,
//                              &spki::RSA_PKCS1_2048_8192_SHA1,
//                              "rsa_2048");

// 2048 bit rsa
// pkcs1
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_2048_pkcs1_sha256,
                          &signature::RSA_PKCS1_SHA256,
                          &spki::RSA_PKCS1_2048_8192_SHA256,
                          "rsa_2048");
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_2048_pkcs1_sha384,
                          &signature::RSA_PKCS1_SHA384,
                          &spki::RSA_PKCS1_2048_8192_SHA384,
                          "rsa_2048");
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_2048_pkcs1_sha512,
                          &signature::RSA_PKCS1_SHA512,
                          &spki::RSA_PKCS1_2048_8192_SHA512,
                          "rsa_2048");
// pss
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_2048_pss_sha256,
                          &signature::RSA_PSS_SHA256,
                          &spki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                          "rsa_2048");
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_2048_pss_sha384,
                          &signature::RSA_PSS_SHA384,
                          &spki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                          "rsa_2048");
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_2048_pss_sha512,
                          &signature::RSA_PSS_SHA512,
                          &spki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                          "rsa_2048");
// pkcs1
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_2048_pkcs1_sha256,
                               &spki::RSA_PKCS1_2048_8192_SHA256,
                               "rsa_2048",
                               "pkcs1",
                               "sha256",
                               "rsa_4096",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_2048_pkcs1_sha384,
                               &spki::RSA_PKCS1_2048_8192_SHA384,
                               "rsa_2048",
                               "pkcs1",
                               "sha384",
                               "rsa_4096",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_2048_pkcs1_sha512,
                               &spki::RSA_PKCS1_2048_8192_SHA512,
                               "rsa_2048",
                               "pkcs1",
                               "sha512",
                               "rsa_4096",
                               "sha1");
// pss
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_2048_pss_sha256,
                               &spki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                               "rsa_2048",
                               "pss",
                               "sha256",
                               "rsa_4096",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_2048_pss_sha384,
                               &spki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                               "rsa_2048",
                               "pss",
                               "sha384",
                               "rsa_4096",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_2048_pss_sha512,
                               &spki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                               "rsa_2048",
                               "pss",
                               "sha512",
                               "rsa_4096",
                               "sha1");

// 4096 bit rsa in 2048_8192 modes
//    test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_4096_sha1_2048,
//                              &signature::RSA_PKCS1_SHA256,
//                              &spki::RSA_PKCS1_2048_8192_SHA1,
//                              "rsa_4096");
// pkcs1
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_4096_sha256_pkcs1_2048,
                          &signature::RSA_PKCS1_SHA256,
                          &spki::RSA_PKCS1_2048_8192_SHA256,
                          "rsa_4096");
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_4096_sha384_pkcs1_2048,
                          &signature::RSA_PKCS1_SHA384,
                          &spki::RSA_PKCS1_2048_8192_SHA384,
                          "rsa_4096");
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_4096_sha512_pkcs1_2048,
                          &signature::RSA_PKCS1_SHA512,
                          &spki::RSA_PKCS1_2048_8192_SHA512,
                          "rsa_4096");
// pss
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_4096_sha256_pss_2048,
                          &signature::RSA_PSS_SHA256,
                          &spki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                          "rsa_4096");
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_4096_sha384_pss_2048,
                          &signature::RSA_PSS_SHA384,
                          &spki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                          "rsa_4096");
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_4096_sha512_pss_2048,
                          &signature::RSA_PSS_SHA512,
                          &spki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                          "rsa_4096");
// pkcs1
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_4096_sha256_pkcs1_2048,
                               &spki::RSA_PKCS1_2048_8192_SHA256,
                               "rsa_4096",
                               "pkcs1",
                               "sha256",
                               "rsa_2048",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_4096_sha384_pkcs1_2048,
                               &spki::RSA_PKCS1_2048_8192_SHA384,
                               "rsa_4096",
                               "pkcs1",
                               "sha384",
                               "rsa_2048",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_4096_sha512_pkcs1_2048,
                               &spki::RSA_PKCS1_2048_8192_SHA512,
                               "rsa_4096",
                               "pkcs1",
                               "sha512",
                               "rsa_2048",
                               "sha1");
// pss
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_4096_sha256_pss_2048,
                               &spki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                               "rsa_4096",
                               "pss",
                               "sha256",
                               "rsa_2048",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_4096_sha384_pss_2048,
                               &spki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                               "rsa_4096",
                               "pss",
                               "sha384",
                               "rsa_2048",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_4096_sha512_pss_2048,
                               &spki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                               "rsa_4096",
                               "pss",
                               "sha512",
                               "rsa_2048",
                               "sha1");

// 4096 bit rsa in 3072_8192 modes
// pkcs1
test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_4096_sha384_pkcs1_3072,
                          &signature::RSA_PKCS1_SHA384,
                          &spki::RSA_PKCS1_3072_8192_SHA384,
                          "rsa_4096");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_4096_sha384_pkcs1_3072,
                               &spki::RSA_PKCS1_3072_8192_SHA384,
                               "rsa_4096",
                               "pkcs1",
                               "sha384",
                               "rsa_2048",
                               "sha1");
// TODO PSS for 3072-8192?

// 8192 bit rsa in 2048_8192 modes
// TODO loading 8192 key pairs isn't working
//    test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_8192_sha256_pkcs1_2048,
//                              &signature::RSA_PKCS1_SHA256,
//                              &spki::RSA_PKCS1_2048_8192_SHA256,
//                              "rsa_8192");
//    test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_8192_sha384_pkcs1_2048,
//                              &signature::RSA_PKCS1_SHA384,
//                              &spki::RSA_PKCS1_2048_8192_SHA384,
//                              "rsa_8192");
//    test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_8192_sha512_pkcs1_2048,
//                              &signature::RSA_PKCS1_SHA512,
//                              &spki::RSA_PKCS1_2048_8192_SHA512,
//                              "rsa_8192");
// pkcs1
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_8192_sha256_pkcs1_2048,
                               &spki::RSA_PKCS1_2048_8192_SHA256,
                               "rsa_8192",
                               "pkcs1",
                               "sha256",
                               "rsa_2048",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_8192_sha384_pkcs1_2048,
                               &spki::RSA_PKCS1_2048_8192_SHA384,
                               "rsa_8192",
                               "pkcs1",
                               "sha384",
                               "rsa_2048",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_8192_sha512_pkcs1_2048,
                               &spki::RSA_PKCS1_2048_8192_SHA512,
                               "rsa_8192",
                               "pkcs1",
                               "sha512",
                               "rsa_2048",
                               "sha1");
// pss
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_8192_sha256_pss_2048,
                               &spki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                               "rsa_8192",
                               "pss",
                               "sha256",
                               "rsa_2048",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_8192_sha384_pss_2048,
                               &spki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                               "rsa_8192",
                               "pss",
                               "sha384",
                               "rsa_2048",
                               "sha1");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_8192_sha512_pss_2048,
                               &spki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                               "rsa_8192",
                               "pss",
                               "sha512",
                               "rsa_2048",
                               "sha1");

// 8192 bit rsa in 3072_8192 modes
//
//    test_rsa_sign_verify_spki!(test_rsa_sign_verify_spki_rsa_8192_sha384_pkcs1_3072,
//                              &signature::RSA_PKCS1_SHA384,
//                              &spki::RSA_PKCS1_3072_8192_SHA384,
//                              "rsa_8192");
test_rsa_verify_sig_file_spki!(test_rsa_verify_sig_file_spki_rsa_8192_sha384_pkcs1_3072,
                               &spki::RSA_PKCS1_3072_8192_SHA384,
                               "rsa_8192",
                               "pkcs1",
                               "sha384",
                               "rsa_2048",
                               "sha1");


// TODO ecdsa signing?
// ecdsa p256
test_ec_verify_sig_file_spki!(test_ec_verify_sig_file_spki_ecdsa_p256_sha256,
                              &spki::ECDSA_P256_SHA256,
                              "ecdsa_prime256v1",
                              "sha256",
                              "ecdsa_secp384r1",
                              "sha384");
test_ec_verify_sig_file_spki!(test_ec_verify_sig_file_spki_ecdsa_p256_sha384,
                              &spki::ECDSA_P256_SHA384,
                              "ecdsa_prime256v1",
                              "sha384",
                              "ecdsa_secp384r1",
                              "sha256");

// ecdsa p384
test_ec_verify_sig_file_spki!(test_ec_verify_sig_file_spki_ecdsa_p384_sha256,
                              &spki::ECDSA_P384_SHA256,
                              "ecdsa_secp384r1",
                              "sha256",
                              "ecdsa_prime256v1",
                              "sha384");
test_ec_verify_sig_file_spki!(test_ec_verify_sig_file_spki_ecdsa_p384_sha384,
                              &spki::ECDSA_P384_SHA384,
                              "ecdsa_secp384r1",
                              "sha384",
                              "ecdsa_prime256v1",
                              "sha256");

// XXX: Some of the BadDER tests should have better error codes, maybe?

test_verify_signature_pem!(test_ecdsa_secp384r1_sha256_corrupted_data,
                         "ecdsa-secp384r1-sha256-corrupted-data.pem",
                         &spki::ECDSA_P384_SHA256,
                         Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
test_verify_signature_pem!(test_ecdsa_secp384r1_sha256,
                         "ecdsa-secp384r1-sha256.pem",
                          &spki::ECDSA_P384_SHA256,
                          Ok(()));
test_verify_signature_pem!(
    test_ecdsa_using_rsa_key, "ecdsa-using-rsa-key.pem",
    &spki::ECDSA_P256_SHA256,
    Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));

test_verify_signature_pem!(test_rsa_pkcs1_sha1_key_params_absent,
                         "rsa-pkcs1-sha1-key-params-absent.pem",
                         &spki::RSA_PKCS1_2048_8192_SHA1,
                         Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));
// We only support rsa keys identified as "rsaEncyrption", not rsa pss, so this is really only
// a test that "rsaEncryption" != "rsassapss", not about params.
test_verify_signature_pem!( test_rsa_pkcs1_sha1_using_pss_key_no_params,
    "rsa-pkcs1-sha1-using-pss-key-no-params.pem",
    &spki::RSA_PKCS1_2048_8192_SHA1,
    Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));
// XXX: RSA PKCS#1 with SHA-1 is a supported algorithm, but we only accept
// 2048-8192 bit keys, and this test file is using a 1024 bit key. Thus,
// our results differ from Chromium's. TODO: this means we need a 2048+ bit
// version of this test.
test_verify_signature_pem!(test_rsa_pkcs1_sha1,
                       "rsa-pkcs1-sha1.pem",
                       &spki::RSA_PKCS1_2048_8192_SHA1,
                       Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
// XXX: RSA PKCS#1 with SHA-1 is a supported algorithm, but we only accept
// 2048-8192 bit keys, and this test file is using a 1024 bit key. Thus,
// our results differ from Chromium's. TODO: this means we need a 2048+ bit
// version of this test.
test_verify_signature_pem!(test_rsa_pkcs1_sha256,
                       "rsa-pkcs1-sha256.pem",
                       &spki::RSA_PKCS1_2048_8192_SHA256,
                       Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));

test_verify_signature_pem!(test_rsa_pkcs1_sha256_spki_non_null_params,
                         "rsa-pkcs1-sha256-spki-non-null-params.pem",
                         &spki::RSA_PKCS1_2048_8192_SHA256,
                         Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));
test_verify_signature_pem!(
    test_rsa_pkcs1_sha256_using_id_ea_rsa,
    "rsa-pkcs1-sha256-using-id-ea-rsa.pem",
    &spki::RSA_PKCS1_2048_8192_SHA256,
    Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));

/// Our PSS tests that should work.
test_verify_signature_pem!(
    test_rsa_pss_sha256_salt32,
    "ours/rsa-pss-sha256-salt32.pem",
    &spki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    Ok(()));
test_verify_signature_pem!(
    test_rsa_pss_sha384_salt48,
    "ours/rsa-pss-sha384-salt48.pem",
    &spki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    Ok(()));
test_verify_signature_pem!(
    test_rsa_pss_sha512_salt64,
    "ours/rsa-pss-sha512-salt64.pem",
    &spki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    Ok(()));
test_verify_signature_pem!(
    test_rsa_pss_sha256_salt32_corrupted_data,
    "ours/rsa-pss-sha256-salt32-corrupted-data.pem",
    &spki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
test_verify_signature_pem!(
    test_rsa_pss_sha384_salt48_corrupted_data,
    "ours/rsa-pss-sha384-salt48-corrupted-data.pem",
    &spki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));
test_verify_signature_pem!(
    test_rsa_pss_sha512_salt64_corrupted_data,
    "ours/rsa-pss-sha512-salt64-corrupted-data.pem",
    &spki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    Err(VerifyWithSPKIError::InvalidSignatureForPublicKey));

test_verify_signature_pem!(
    test_rsa_using_ec_key, "rsa-using-ec-key.pem",
    &spki::RSA_PKCS1_2048_8192_SHA256,
    Err(VerifyWithSPKIError::UnsupportedSignatureAlgorithmForPublicKey));
test_verify_signature_pem!(test_rsa2048_pkcs1_sha512,
                       "rsa2048-pkcs1-sha512.pem",
                       &spki::RSA_PKCS1_2048_8192_SHA512,
                       Ok(()));

struct TestSignedData {
    spki: std::vec::Vec<u8>,
    data: std::vec::Vec<u8>,
    signature: std::vec::Vec<u8>
}

fn parse_test_signed_data(file_name: &str) -> TestSignedData {
    let path =
    std::path::PathBuf::from(
        "third-party/chromium/data/verify_signed_data").join(file_name);
    let file = std::fs::File::open(path).unwrap();
    let mut lines = std::io::BufReader::new(&file).lines();

    let spki = read_pem_section(&mut lines, "PUBLIC KEY");
    let data = read_pem_section(&mut lines, "DATA");
    let signature = read_pem_section(&mut lines, "SIGNATURE");

    TestSignedData {
        spki: spki,
        data: data,
        signature: signature
    }
}

type FileLines<'a> = std::io::Lines<std::io::BufReader<&'a std::fs::File>>;

fn read_pem_section(lines: & mut FileLines, section_name: &str)
                        -> std::vec::Vec<u8> {
    // Skip comments and header
    let begin_section = format!("-----BEGIN {}-----", section_name);
    loop {
        let line = lines.next().unwrap().unwrap();
        if line == begin_section {
            break;
        }
    }

    let mut base64 = std::string::String::new();

    let end_section = format!("-----END {}-----", section_name);
    loop {
        let line = lines.next().unwrap().unwrap();
        if line == end_section {
            break;
        }
        base64.push_str(&line);
    }

    base64.from_base64().unwrap()
}
