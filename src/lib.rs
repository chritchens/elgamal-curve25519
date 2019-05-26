use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use digest::Digest;
use typenum::consts::U64;
use rand_core::{RngCore, CryptoRng};
use rand_os::OsRng;
use subtle::ConstantTimeEq;

/// `Message` is an ElGamal message.
#[derive(Copy, Clone, Debug)]
pub struct Message([u8; 32]);

impl Message {
    /// `new` creates a new `Message` from a slice of bytes.
    pub fn new(msg: [u8; 32]) -> Message {
        Message(msg)
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

/// `PrivateKey` is an ElGamal private key. It's just a
/// wrapper around `Scalar`. The key is just an integer
/// between 1 and q-1, where q is the order of the group
/// G.
#[derive(Copy, Clone, Debug)]
pub struct PrivateKey(Scalar);

impl PrivateKey {
    /// `new` creates a new random `PrivateKey`.
    pub fn new() -> Result<PrivateKey, String> {
        let mut rng = OsRng::new()
            .map_err(|e| format!("{}", e))?;

        PrivateKey::from_rng(&mut rng)
    }

    /// `from_rng` creates a new random `PrivateKey`, but requires
    /// to specify a random generator.
    pub fn from_rng<R>(mut rng: &mut R) -> Result<PrivateKey, String>
        where R: RngCore + CryptoRng
    {
        let mut scalar = Scalar::random(&mut rng);
        while scalar.ct_eq(&Scalar::zero()).unwrap_u8() == 1u8 {
            scalar = Scalar::random(&mut rng);
        }

        let private = PrivateKey(scalar);
        Ok(private)
    }

    /// `from_hash` creates a new `PrivateKey` from a 64 bytes hash.
    pub fn from_hash<D>(digest: D) -> PrivateKey
        where D: Digest<OutputSize = U64>
    {
        let scalar = Scalar::from_hash(digest);
        PrivateKey(scalar)
    }

    /// `from_scalar` creates a new `PrivateKey` from a `Scalar`.
    /// The `Scalar` value cannot be 0.
    pub fn from_scalar(scalar: Scalar) -> Result<PrivateKey, String> {
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

    /// `from_slice` creates a new `PrivateKey` from a slice of bytes.
    pub fn from_slice(buf: [u8; 32]) -> Result<PrivateKey, String> {
        if let Some(scalar) = Scalar::from_canonical_bytes(buf) {
            let private = PrivateKey(scalar);
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
        let point = &self.0 * &RISTRETTO_BASEPOINT_TABLE;
        PublicKey(point.compress())
    }
}

/// `PublicKey` is an ElGamal public key. It's just a
/// wrapper around `CompressedRistretto`.
/// The key is computed as g^x, where g is the generator
/// of the group G of order q, and x a `PrivateKey`.
#[derive(Copy, Clone, Debug)]
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

    /// `from_slice` creates a new `PublicKey` from a slice of bytes.
    pub fn from_slice(buf: [u8; 32]) -> PublicKey {
        let point = CompressedRistretto::from_slice(&buf[..]);
        PublicKey(point)
    }

    /// `to_bytes` returns the `PublicKey` as an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// `KeyPair` is a pair of ElGamal `PublicKey` and `PrivateKey`.
#[derive(Copy, Clone, Debug)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// `new` creates a new random `KeyPair`.
    pub fn new() -> Result<KeyPair, String> {
        let private_key = PrivateKey::new()?;
        let public_key = private_key.to_public();

        let keys = KeyPair { public_key, private_key };
        Ok(keys)
    }

    /// `from_rng` creates a new random `KeyPair`, but requires
    /// to specify a random generator.
    pub fn from_rng<R>(mut rng: &mut R) -> Result<KeyPair, String>
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
    pub fn from_scalar(scalar: Scalar) -> Result<KeyPair, String> {
        let private_key = PrivateKey::from_scalar(scalar)?;
        let public_key = private_key.to_public();

        let keys = KeyPair { public_key, private_key };
        Ok(keys)
    }

    /// `from_slice` creates a new `KeyPair` from a slice of bytes.
    pub fn from_slice(buf: [u8; 32]) -> Result<KeyPair, String> {
        let private_key = PrivateKey::from_slice(buf)?;
        let public_key = private_key.to_public();

        let keys = KeyPair { public_key, private_key };
        Ok(keys)
    }
}

/// `CypherText` is the cyphertext generated by ElGamal encryption.
#[derive(Copy, Clone, Debug)]
pub struct CypherText {
    pub gamma: CompressedRistretto,
    pub delta: CompressedRistretto,
}

/// `encrypt` encrypts a `Message` into a `CypherText`.
pub fn encrypt(_msg: Message, _pk: PublicKey, _sk: PrivateKey) -> Result<CypherText, String> {
    unreachable!()
}

/// `decrypt` decrypts a `CypherText` into a `Message`.
pub fn decrypt(_cyph: CypherText, _sk: PrivateKey) -> Result<Message, String> {
    unreachable!()
}
