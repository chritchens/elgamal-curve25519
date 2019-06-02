// Copyright 2019 Christian Nyumbayire. See the LICENSE-APACHE and
// LICENSE-MIT files at the top-level directory.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # ElGamal Homomorphic Encryption Library
//!
//! A Rust library for [ElGamal Homomorphic Encryption](https://en.wikipedia.org/wiki/ElGamal_encryption). ElGamal encryption is only
//! usable for small values (32 bytes) and so it's generally used in hybrid encryption
//! schemes.<br>
//! This library implements ElGamal multiplicative [homomorphic encryption](https://en.wikipedia.org/wiki/Homomorphic_encryption), so
//! messages can be multiplicatevely aggregated by multiplying their cyphertexts.
//! Aggregated cyphertexts can be decrypted only if they have the same recipient
//! and only by that recipient.<br>
//! The scheme has different applications, ranging from online voting systems to
//! secure multy-party computation for cryptocurrencies.

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::{BASEPOINT_ORDER, RISTRETTO_BASEPOINT_TABLE};
use digest::Digest;
use typenum::consts::U64;
use rand_core::{RngCore, CryptoRng};
use rand_os::OsRng;
use subtle::ConstantTimeEq;
use std::result::Result as StdResult;
//use std::error::Error as StdError;
use std::ops::{Mul, Add};

/// `Error` is the library error type.
pub type Error = String;

/// `Result` is the type used for fallible outputs. It's an
/// alias to the Result type in standard library whith error
/// the library Error type.
pub type Result<T> = StdResult<T, Error>;

/// `Message` is an ElGamal message.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Message([u8; 32]);

impl Message {
    /// `new` creates a new `Message` from a slice of bytes.
    pub fn new(msg: [u8; 32]) -> Message {
        Message(msg)
    }

    /// `random` creates a new random `Message`.
    pub fn random() -> Result<Message> {
        let mut rng = OsRng::new()
            .map_err(|e| format!("{}", e))?;

        let msg = Message::from_rng(&mut rng);
        Ok(msg)
    }

    /// `from_rng` creates a new random `Message`, but requires
    /// to specify a random generator.
    pub fn from_rng<R>(mut rng: &mut R) -> Message
        where R: RngCore + CryptoRng
    {
        let point = RistrettoPoint::random(&mut rng).compress();
        Message::from_point(&point)
    }

    /// `from_hash` creates a new `Message` from a 64 bytes hash.
    pub fn from_hash<D>(digest: D) -> Message
        where D: Digest<OutputSize = U64> + Default
    {
        let point = RistrettoPoint::from_hash(digest).compress();
        Message::from_point(&point)
    }

    /// `from_point` creates a new `Message` from a `CompressedRistretto`.
    pub fn from_point(point: &CompressedRistretto) -> Message {
        Message(point.to_bytes())
    }

    /// `to_point` returns the inner `CompressedRistretto` of the `Message`.
    pub fn to_point(&self) -> CompressedRistretto {
        CompressedRistretto::from_slice(&self.0[..])
    }
}

impl Mul<PrivateKey> for Message {
    type Output = Option<Message>;

    fn mul(self, sk: PrivateKey) -> Option<Message> {

        if let Some(point) = self.to_point().decompress() {
            let scalar = sk.to_scalar();
            let point = (scalar * point).compress();
            let msg = Message::from_point(&point);
            Some(msg)
        } else {
            None
        }
    }
}

impl Add<Message> for Message {
    type Output = Option<Message>;

    fn add(self, other: Message) -> Option<Message> {

        if let Some(point) = self.to_point().decompress() {
            if let Some(other_point) = other.to_point().decompress() {
                let point = (point + other_point).compress();
                let msg = Message::from_point(&point);
                Some(msg)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// `PrivateKey` is an ElGamal private key. It's just a
/// wrapper around `Scalar`. The key is just an integer
/// between 1 and q-1, where q is the order of the group
/// G.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PrivateKey(Scalar);

impl PrivateKey {
    /// `new` creates a new random `PrivateKey`.
    pub fn new() -> Result<PrivateKey> {
        PrivateKey::random()
    }

    /// `random` creates a random `PrivateKey`.
    pub fn random() -> Result<PrivateKey> {
        let mut rng = OsRng::new()
            .map_err(|e| format!("{}", e))?;

        PrivateKey::from_rng(&mut rng)
    }

    /// `from_rng` creates a new random `PrivateKey`, but requires
    /// to specify a random generator.
    pub fn from_rng<R>(mut rng: &mut R) -> Result<PrivateKey>
        where R: RngCore + CryptoRng
    {
        let mut scalar = Scalar::random(&mut rng).reduce();
        while scalar.ct_eq(&Scalar::zero()).unwrap_u8() == 1u8 {
            scalar = Scalar::random(&mut rng).reduce();
        }

        let private = PrivateKey(scalar);
        Ok(private)
    }

    /// `from_hash` creates a new `PrivateKey` from a 64 bytes hash.
    pub fn from_hash<D>(digest: D) -> PrivateKey
        where D: Digest<OutputSize = U64>
    {
        let scalar = Scalar::from_hash(digest).reduce();
        PrivateKey(scalar)
    }

    /// `from_scalar` creates a new `PrivateKey` from a `Scalar`.
    /// The `Scalar` value cannot be 0.
    pub fn from_scalar(scalar: Scalar) -> Result<PrivateKey> {
        if scalar.ct_eq(&Scalar::zero()).unwrap_u8() == 1u8 {
            return Err("0 scalar".into());
        }

        let private = PrivateKey(scalar);
        Ok(private)
    }

    /// `to_scalar` returns the inner `Scalar` of the `PrivateKey`.
    pub fn to_scalar(&self) -> Scalar {
        self.0
    }

    /// `from_bytes` creates a new `PrivateKey` from a slice of bytes.
    pub fn from_bytes(buf: [u8; 32]) -> Result<PrivateKey> {
        if let Some(scalar) = Scalar::from_canonical_bytes(buf) {
            let private = PrivateKey::from_scalar(scalar)?;
            Ok(private)
        } else {
            Err("not canonical bytes".into())
        }
    }

    /// `to_bytes` returns the `PrivateKey` as an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `to_public` returns the `PublicKey` of the `PrivateKey`.
    pub fn to_public(&self) -> PublicKey {
        let point = &RISTRETTO_BASEPOINT_TABLE * &self.0;
        PublicKey(point.compress())
    }
}

impl Add<PrivateKey> for PrivateKey {
    type Output = Option<PrivateKey>;

    fn add(self, other: PrivateKey) -> Option<PrivateKey> {
        let scalar = self.to_scalar();
        let other_scalar = other.to_scalar();

        let scalar = scalar + other_scalar;

        match PrivateKey::from_scalar(scalar) {
            Ok(sk) => Some(sk),
            Err(_) => None,
        }
    }
}

/// `PublicKey` is an ElGamal public key. It's just a
/// wrapper around `CompressedRistretto`.
/// The key is computed as g^x, where g is the generator
/// of the group G of order q, and x a `PrivateKey`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct PublicKey(CompressedRistretto);

impl PublicKey {
    /// `new` creates a new `PublicKey` from a `PrivateKey`.
    pub fn new(private: PrivateKey) -> PublicKey {
        PublicKey::from_private(private)
    }

    /// `from_private` creates a new `PublicKey` from a `PrivateKey`.
    pub fn from_private(private: PrivateKey) -> PublicKey {
        private.to_public()
    }

    /// `random` creates a new random `PublicKey`.
    pub fn random() -> Result<PublicKey> {
        let sk = PrivateKey::random()?;
        let pk = PublicKey::from_private(sk);
        Ok(pk)
    }

    /// `from_point` creates a new `PublicKey` from a `CompressedRistretto`.
    pub fn from_point(point: CompressedRistretto) -> PublicKey {
        PublicKey(point)
    }

    /// `to_point` returns the inner `CompressedRistretto` of the `PublicKey`.
    pub fn to_point(&self) -> CompressedRistretto {
        self.0
    }

    /// `from_hash` creates a new `PublicKey` from a 64 bytes hash.
    pub fn from_hash<D>(digest: D) -> PublicKey
        where D: Digest<OutputSize = U64> + Default
    {
        let point = RistrettoPoint::from_hash(digest);
        PublicKey(point.compress())
    }

    /// `from_bytes` creates a new `PublicKey` from a slice of bytes.
    pub fn from_bytes(buf: [u8; 32]) -> PublicKey {
        let point = CompressedRistretto::from_slice(&buf[..]);
        PublicKey(point)
    }

    /// `to_bytes` returns the `PublicKey` as an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl Mul<PrivateKey> for PublicKey {
    type Output = Option<PublicKey>;

    fn mul(self, sk: PrivateKey) -> Option<PublicKey> {

        if let Some(point) = self.to_point().decompress() {
            let scalar = sk.to_scalar();
            let point = (scalar * point).compress();
            let pk = PublicKey::from_point(point);
            Some(pk)
        } else {
            None
        }
    }
}

impl Add<PublicKey> for PublicKey {
    type Output = Option<PublicKey>;

    fn add(self, other: PublicKey) -> Option<PublicKey> {

        if let Some(point) = self.to_point().decompress() {
            if let Some(other_point) = other.to_point().decompress() {
                let point = (point + other_point).compress();
                let pk = PublicKey::from_point(point);
                Some(pk)
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// `KeyPair` is a pair of ElGamal `PublicKey` and `PrivateKey`.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// `new` creates a new random `KeyPair`.
    pub fn new() -> Result<KeyPair> {
        let private_key = PrivateKey::new()?;
        let public_key = private_key.to_public();

        let keys = KeyPair { public_key, private_key };
        Ok(keys)
    }

    /// `from_rng` creates a new random `KeyPair`, but requires
    /// to specify a random generator.
    pub fn from_rng<R>(mut rng: &mut R) -> Result<KeyPair>
        where R: RngCore + CryptoRng
    {
        let private_key = PrivateKey::from_rng(&mut rng)?;
        let public_key = private_key.to_public();

        let keys = KeyPair { public_key, private_key };
        Ok(keys)
    }

    /// `from_hash` creates a new `KeyPair` from a 64 bytes hash.
    pub fn from_hash<D>(digest: D) -> KeyPair
        where D: Digest<OutputSize = U64>
    {
        let private_key = PrivateKey::from_hash(digest);
        let public_key = private_key.to_public();

        KeyPair { public_key, private_key }
    }

    /// `from_scalar` creates a new `KeyPair` from a `Scalar`.
    /// The `Scalar` value cannot be 0.
    pub fn from_scalar(scalar: Scalar) -> Result<KeyPair> {
        let private_key = PrivateKey::from_scalar(scalar)?;
        let public_key = private_key.to_public();

        let keys = KeyPair { public_key, private_key };
        Ok(keys)
    }

    /// `from_bytes` creates a new `KeyPair` from a bytes of bytes.
    pub fn from_bytes(buf: [u8; 32]) -> Result<KeyPair> {
        let private_key = PrivateKey::from_bytes(buf)?;
        let public_key = private_key.to_public();

        let keys = KeyPair { public_key, private_key };
        Ok(keys)
    }
}

/// `CypherText` is the cyphertext generated by ElGamal encryption.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CypherText {
    gamma: PublicKey,
    delta: CompressedRistretto,
}

impl CypherText {
    /// `random` creates a new random `CypherText`.
    pub fn random() -> Result<CypherText> {
        let gamma = PublicKey::random()?;
        let delta = PublicKey::random()?.to_point();

        let cyph = CypherText { gamma, delta };
        Ok(cyph)
    }

    /// `from_bytes` creates a new `CypherText` from an array of bytes.
    pub fn from_bytes(buf: [u8; 64]) -> Result<CypherText> {
        let mut gamma_buf = [0u8; 32];
        for (i, v) in buf[0..32].iter().enumerate() {
            gamma_buf[i] = *v;
        }

        let mut delta_buf = [0u8; 32];
        for (i, v) in buf[32..].iter().enumerate() {
            delta_buf[i] = *v;
        }

        let gamma = PublicKey::from_bytes(gamma_buf);
        let delta = CompressedRistretto::from_slice(&delta_buf);

        let cyph = CypherText { gamma, delta };
        Ok(cyph)
    }

    /// `to_bytes` returns the `CypherText` as an array of bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        for (i, v) in self.gamma.to_bytes().iter().enumerate() {
            buf[i] = *v;
        }

        for (i, v) in self.gamma.to_bytes().iter().enumerate() {
            buf[i+32] = *v;
        }

        buf
    }
}

impl Add<CypherText> for CypherText {
    type Output = Option<CypherText>;

    fn add(self, other: CypherText) -> Option<CypherText> {
        if let Some(gamma) = self.gamma + other.gamma {
            if let Some(delta_point) = self.delta.decompress() {
                if let Some(other_delta_point) = other.delta.decompress() {
                    let delta = (delta_point + other_delta_point).compress();
                    let cyph = CypherText { gamma, delta };
                    Some(cyph)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// `shared` returns the shared key between a `PublicKey` and a `PrivateKey` of different `KeyPair`s.
fn shared(pk: PublicKey, sk: PrivateKey) -> Result<CompressedRistretto> {
    if sk.to_public().to_point().ct_eq(&pk.to_point()).unwrap_u8() == 1u8 {
        return Err("same private keys".into());
    }

    let shared = pk * sk;

    if let Some(shared) = shared {
        Ok(shared.to_point())
    } else {
        Err("invalid public key".into())
    }
}

/// `inverse_shared` returns the inverse of the shared point by using the Lagrange's Theorem.
fn inverse_shared(pk: PublicKey, sk: PrivateKey) -> Result<CompressedRistretto> {
    if sk.to_public().to_point().ct_eq(&pk.to_point()).unwrap_u8() == 1u8 {
        return Err("same private keys".into());
    }

    if let Some(pk_point) = pk.to_point().decompress() {
        let sk_scalar = sk.to_scalar();

        let inv_shared = pk_point * (BASEPOINT_ORDER - sk_scalar);
        Ok(inv_shared.compress())
    } else {
        Err("invalid public key".into())
    }
}

/// `encrypt` encrypts a `Message` into a `CypherText`.
pub fn encrypt(msg: Message, pk: PublicKey, sk: PrivateKey) -> Result<CypherText> {
    if sk.to_public().to_point().ct_eq(&pk.to_point()).unwrap_u8() == 1u8 {
        return Err("same private keys".into());
    }

    if let Some(msg_point) = msg.to_point().decompress() {
        if let Some(shared_point) = shared(pk, sk)?.decompress() {
            let delta = (msg_point + shared_point).compress();
            let gamma = sk.to_public();

            let cyph = CypherText { gamma, delta };
            Ok(cyph)
        } else {
            Err("invalid shared secret".into())
        }
    } else {
        Err("invalid message".into())
    }
}

/// `decrypt` decrypts a `CypherText` into a `Message`.
pub fn decrypt(cyph: CypherText, sk: PrivateKey) -> Result<Message> {
    if sk.to_public().to_point().ct_eq(&cyph.gamma.to_point()).unwrap_u8() == 1u8 {
        return Err("same private keys".into());
    }

    if let Some(delta_point) = cyph.delta.decompress() {
        if let Some(inv_shared_point) = inverse_shared(cyph.gamma, sk)?.decompress() {
            let msg_point = (delta_point + inv_shared_point).compress();

            let msg = Message::from_point(&msg_point);
            Ok(msg)
        } else {
            Err("invalid shared secret".into())
        }
    } else {
        Err("invalid cyphertext".into())
    }
}

#[test]
fn test_shared() {
    let sk1 = PrivateKey::new().unwrap();
    let pk1 = PublicKey::new(sk1);
    let sk2 = PrivateKey::new().unwrap();
    let pk2 = PublicKey::new(sk2);

    let s1 = shared(pk2, sk1).unwrap();
    let s2 = shared(pk1, sk2).unwrap();

    assert_eq!(s1, s2)
}

#[test]
fn test_inverse_shared() {
    use curve25519_dalek::traits::Identity;

    let sk1 = PrivateKey::new().unwrap();
    let pk1 = PublicKey::new(sk1);
    let sk2 = PrivateKey::new().unwrap();
    let pk2 = PublicKey::new(sk2);

    let s = shared(pk2, sk1).unwrap();
    let inv_s1 = inverse_shared(pk2, sk1).unwrap();
    let inv_s2 = inverse_shared(pk1, sk2).unwrap();

    assert_eq!(inv_s1, inv_s2);

    let s_point = s.decompress().unwrap();
    let inv_s1_point = inv_s1.decompress().unwrap();
    let inv_s2_point = inv_s2.decompress().unwrap();

    let id = RistrettoPoint::identity();
    let id1 = s_point + inv_s1_point;
    let id2 = s_point + inv_s2_point;

    assert_eq!(id, id1);
    assert_eq!(id, id2);
    assert_eq!(id1, id2);
}

#[test]
fn test_encryption() {
    for _ in 0..10 {
        let msg1 = Message::random().unwrap();
        let sk1 = PrivateKey::new().unwrap();
        let sk2 = PrivateKey::new().unwrap();
        let pk2 = PublicKey::new(sk2);

        let cyph = encrypt(msg1, pk2, sk1).unwrap();
        let msg2 = decrypt(cyph, sk2).unwrap();

        assert_eq!(msg1, msg2)
    }
}

#[test]
fn test_message_add() {
    let msg1 = Message::random().unwrap();
    let msg2 = Message::random().unwrap();
    let msg3 = (msg1 + msg2).unwrap();

    let msg1_point = msg1.to_point().decompress().unwrap();
    let msg2_point = msg2.to_point().decompress().unwrap();
    let msg3_point = msg3.to_point().decompress().unwrap();

    assert_eq!(msg3_point, msg1_point + msg2_point);
}

#[test]
fn test_cyphertext_add() {
    let cyph1 = CypherText::random().unwrap();
    let cyph2 = CypherText::random().unwrap();
    let cyph3 = (cyph1 + cyph2).unwrap();
    let cyph3_gamma = (cyph1.gamma + cyph2.gamma).unwrap();
    let cyph3_delta = (cyph1.delta.decompress().unwrap() +
                       cyph2.delta.decompress().unwrap())
                      .compress();

    assert_eq!(cyph3.gamma, cyph3_gamma);
    assert_eq!(cyph3.delta, cyph3_delta);
}

#[test]
fn test_encryption_message_sum() {
    for _ in 0..10 {
        let msg1 = Message::random().unwrap();
        let msg2 = Message::random().unwrap();
        let msg3_from_sum = (msg1 + msg2).unwrap();

        let sk1 = PrivateKey::new().unwrap();
        let sk2 = PrivateKey::new().unwrap();
        let pk2 = PublicKey::new(sk2);

        let cyph3 = encrypt(msg3_from_sum, pk2, sk1).unwrap();

        let msg3_from_decrypt = decrypt(cyph3, sk2).unwrap();

        assert_eq!(msg3_from_sum, msg3_from_decrypt)
    }
}

#[test]
fn test_encryption_cyphertext_sum() {
    for _ in 0..10 {
        let msg1 = Message::random().unwrap();
        let msg2 = Message::random().unwrap();
        let msg3_from_sum = (msg1 + msg2).unwrap();

        let sk1 = PrivateKey::new().unwrap();
        let sk2 = PrivateKey::new().unwrap();
        let pk2 = PublicKey::new(sk2);

        let cyph1 = encrypt(msg1, pk2, sk1).unwrap();
        let cyph2 = encrypt(msg2, pk2, sk1).unwrap();
        let cyph3_from_sum = (cyph1 + cyph2).unwrap();

        let msg3_from_decrypt = decrypt(cyph3_from_sum, sk2).unwrap();

        assert_eq!(msg3_from_sum, msg3_from_decrypt)
    }
}

#[test]
fn test_encryption_cyphertext_sum_2() {
    for _ in 0..10 {
        let msg1 = Message::random().unwrap();
        let msg2 = Message::random().unwrap();
        let msg3 = Message::random().unwrap();
        let msg4_from_sum = ((msg1 + msg2).unwrap() + msg3).unwrap();

        let sk1 = PrivateKey::new().unwrap();
        let sk2 = PrivateKey::new().unwrap();
        let pk2 = PublicKey::new(sk2);

        let cyph1 = encrypt(msg1, pk2, sk1).unwrap();
        let cyph2 = encrypt(msg2, pk2, sk1).unwrap();
        let cyph3 = encrypt(msg3, pk2, sk1).unwrap();
        let cyph4_from_sum = ((cyph1 + cyph2).unwrap() + cyph3).unwrap();

        let msg4_from_decrypt = decrypt(cyph4_from_sum, sk2).unwrap();

        assert_eq!(msg4_from_sum, msg4_from_decrypt)
    }
}
