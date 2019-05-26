use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
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
}

/// `PublicKey` is an ElGamal public key. It's just a
/// wrapper around `CompressedRistretto`.
/// The key is computed as g^x, where g is the generator
/// of the group G of order q, and x a `PrivateKey`.
#[derive(Copy, Clone, Debug)]
pub struct PublicKey(CompressedRistretto);

impl PublicKey {
    /// `new` creates a new random `PublicKey` from a `PrivateKey`.
    pub fn new() -> Result<PublicKey, String> {
        unreachable!()
    }

    /// `from_point` creates a new `PublicKey` from a `CompressedRistretto`.
    pub fn from_point() -> Result<PublicKey, String> {
        unreachable!()
    }

    /// `to_point` returns the inner `CompressedRistretto` of the `PublicKey`.
    pub fn to_point(&self) -> Result<CompressedRistretto, String> {
        unreachable!()
    }

    /// `from_hash` creates a new `PublicKey` from a 64 bytes hash.
    pub fn from_hash<D>(_d: D) -> Result<PublicKey, String>
        where D: Digest<OutputSize = U64>
    {
        unreachable!()
    }

    /// `from_slice` creates a new `PublicKey` from a slice of bytes.
    pub fn from_slice(_s: [u8; 32]) -> Result<PublicKey, String> {
        unreachable!()
    }

    /// `to_bytes` returns the `PublicKey` as an array of bytes.
    pub fn to_bytes(&self) -> Result<[u8; 32], String> {
        unreachable!()
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
        unreachable!()
    }

    /// `from_rng` creates a new random `KeyPair`, but requires
    /// to specify a random generator.
    pub fn from_rng<R>(_rng: &mut R) -> Result<KeyPair, String>
        where R: RngCore + CryptoRng
    {
        unreachable!()
    }

    /// `from_hash` creates a new `KeyPair` from a 64 bytes hash.
    pub fn from_hash<D>(_d: D) -> Result<KeyPair, String>
        where D: Digest<OutputSize = U64>
    {
        unreachable!()
    }

    /// `from_scalar` creates a new `KeyPair` from a `Scalar`.
    /// The `Scalar` value cannot be 0.
    pub fn from_scalar(_s: Scalar) -> Result<KeyPair, String> {
        unreachable!()
    }

    /// `from_slice` creates a new `KeyPair` from a slice of bytes.
    pub fn from_slice(_s: [u8; 32]) -> Result<KeyPair, String> {
        unreachable!()
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
