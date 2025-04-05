//! # Cryptographic Pseudonym Implementation
//!
//! This module implements the cryptographic foundation for anonymous voting:
//! - Anonymous credential issuance protocol
//! - Pseudonym creation using zero-knowledge proofs
//! - Verification of pseudonyms without revealing voter identity
//!
//! The implementation is based on BLS12-381 elliptic curve cryptography and uses
//! a combination of blind signatures and zero-knowledge proofs to provide strong
//! anonymity and security guarantees.

use bls12_381::{Bls12, G1Affine, G1Projective, G2Affine, Scalar};
use pairing::Engine;
use pairing::group::ff::Field;
use pairing::group::{Group, GroupEncoding};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRngCore, SeedableRng};
use subtle::{Choice, ConstantTimeEq, CtOption};

use std::ops::Neg;
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use serde::ser::SerializeStruct;
use serde::de::{Visitor, MapAccess};
use std::fmt;

// Helper function to convert CtOption to Result with custom error
fn ctoption_to_result<T, E, F>(option: subtle::CtOption<T>, err_fn: F) -> Result<T, E>
where
    F: FnOnce() -> E,
{
    if bool::from(option.is_some()) {
        Ok(option.unwrap())
    } else {
        Err(err_fn())
    }
}

/// Label used during the credential issuance protocol
const CLIENT_ISSUANCE_LABEL: &[u8] = b"CLIENT_ISSUANCE";
/// Label used during pseudonym generation
const PSEUDONYM_LABEL: &[u8] = b"PSEUDONYM";
/// Global domain separator for the entire protocol
const GLOBAL_LABEL: &[u8] = b"SOCIAL_LOGIN";

/// Parameters for the cryptographic protocol.
///
/// These parameters are public and shared by all participants in the system.
/// They include common reference points for the cryptographic operations.
#[derive(Clone, Debug)]
pub struct Params {
    /// A generator point used in the protocol
    h: G1Affine,
}

impl Serialize for Params {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Params", 1)?;
        state.serialize_field("h", &self.h.to_compressed().as_ref())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Params {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ParamsVisitor;

        impl<'de> Visitor<'de> for ParamsVisitor {
            type Value = Params;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Params")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Params, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut h_bytes = None;

                while let Some(key) = map.next_key::<String>()? {
                    if key == "h" {
                        if h_bytes.is_some() {
                            return Err(serde::de::Error::duplicate_field("h"));
                        }
                        h_bytes = Some(map.next_value::<Vec<u8>>()?);
                    } else {
                        return Err(serde::de::Error::unknown_field(&key, &["h"]));
                    }
                }

                let h_bytes = h_bytes.ok_or_else(|| serde::de::Error::missing_field("h"))?;
                let mut fixed_bytes = [0u8; 48];
                if h_bytes.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes for G1Affine"));
                }
                fixed_bytes.copy_from_slice(&h_bytes);

                let h = ctoption_to_result(
                    G1Affine::from_compressed(&fixed_bytes),
                    || serde::de::Error::custom("invalid G1Affine compressed data")
                )?;

                Ok(Params { h })
            }
        }

        deserializer.deserialize_map(ParamsVisitor)
    }
}

impl Params {
    /// Create default protocol parameters.
    ///
    /// Generates deterministic parameters using a secure hash function.
    /// These parameters are derived from a fixed seed to ensure consistency
    /// across all participants.
    pub fn default() -> Self {
        let mut hasher = blake3::Hasher::default();
        hasher.update(b"VOTING_SCHEME_PARAMS");
        let mut rng = ChaCha20Rng::from_seed(*hasher.finalize().as_bytes());
        Params {
            h: G1Projective::random(&mut rng).into(),
        }
    }
}

/// Implements the Fiat-Shamir heuristic to make interactive zero-knowledge proofs non-interactive.
///
/// This transforms interactive proofs into non-interactive ones by deriving 
/// challenges from the transcript of the protocol execution, making the proof verifiable
/// without back-and-forth communication.
struct FiatShamir {
    hasher: blake3::Hasher,
}

impl FiatShamir {
    /// Create a new Fiat-Shamir transcript with the given label and nonce.
    ///
    /// # Arguments
    /// * `label` - Context-specific label to domain-separate different protocol usages
    /// * `nonce` - Unique value for this protocol execution to prevent replay attacks
    fn new(label: &[u8], nonce: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(GLOBAL_LABEL);
        hasher.update(G1Affine::label());
        hasher.update(label);
        hasher.update(nonce);
        FiatShamir { hasher }
    }

    /// Add data to the transcript.
    ///
    /// # Arguments
    /// * `bytes` - Data to add to the transcript
    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    /// Derive a deterministic RNG from the current transcript state.
    ///
    /// This creates a cryptographic RNG whose output depends deterministically
    /// on all data that has been added to the transcript so far.
    fn rng(&self) -> impl CryptoRngCore {
        ChaCha20Rng::from_seed(*self.hasher.finalize().as_bytes())
    }
}

/// Trait for types that have an associated domain label.
trait HasLabel {
    /// Get the domain label for this type.
    fn label() -> &'static [u8];
}

impl HasLabel for G1Affine {
    fn label() -> &'static [u8] {
        b"BLS12_381"
    }
}

/// The private key of the credential issuer.
///
/// This key is held by the authority that issues voting credentials.
/// It must be kept secure as it allows creation of valid credentials.
#[derive(Debug, Clone)]
pub struct IssuerPrivateKey {
    /// Secret scalar value
    x: Scalar,
}

impl Serialize for IssuerPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("IssuerPrivateKey", 1)?;
        state.serialize_field("x", &self.x.to_bytes().as_ref())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for IssuerPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssuerPrivateKeyVisitor;

        impl<'de> Visitor<'de> for IssuerPrivateKeyVisitor {
            type Value = IssuerPrivateKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct IssuerPrivateKey")
            }

            fn visit_map<V>(self, mut map: V) -> Result<IssuerPrivateKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut x_bytes = None;

                while let Some(key) = map.next_key::<String>()? {
                    if key == "x" {
                        if x_bytes.is_some() {
                            return Err(serde::de::Error::duplicate_field("x"));
                        }
                        x_bytes = Some(map.next_value::<Vec<u8>>()?);
                    } else {
                        return Err(serde::de::Error::unknown_field(&key, &["x"]));
                    }
                }

                let x_bytes = x_bytes.ok_or_else(|| serde::de::Error::missing_field("x"))?;
                let mut fixed_bytes = [0u8; 32];
                if x_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                fixed_bytes.copy_from_slice(&x_bytes);

                let x = Option::from(Scalar::from_bytes(&fixed_bytes))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes"))?;

                Ok(IssuerPrivateKey { x })
            }
        }

        deserializer.deserialize_map(IssuerPrivateKeyVisitor)
    }
}

/// The public key of the credential issuer.
///
/// This key is published and used by voters to verify that their
/// credentials were issued by the legitimate authority.
#[derive(Debug, Clone)]
pub struct IssuerPublicKey {
    /// Public commitment to the issuer's private key
    w: G2Affine,
}

impl Serialize for IssuerPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("IssuerPublicKey", 1)?;
        state.serialize_field("w", &self.w.to_compressed().as_ref())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for IssuerPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssuerPublicKeyVisitor;

        impl<'de> Visitor<'de> for IssuerPublicKeyVisitor {
            type Value = IssuerPublicKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct IssuerPublicKey")
            }

            fn visit_map<V>(self, mut map: V) -> Result<IssuerPublicKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut w_bytes = None;

                while let Some(key) = map.next_key::<String>()? {
                    if key == "w" {
                        if w_bytes.is_some() {
                            return Err(serde::de::Error::duplicate_field("w"));
                        }
                        w_bytes = Some(map.next_value::<Vec<u8>>()?);
                    } else {
                        return Err(serde::de::Error::unknown_field(&key, &["w"]));
                    }
                }

                let w_bytes = w_bytes.ok_or_else(|| serde::de::Error::missing_field("w"))?;
                let mut fixed_bytes = [0u8; 96];
                if w_bytes.len() != 96 {
                    return Err(serde::de::Error::custom("expected 96 bytes for G2Affine"));
                }
                fixed_bytes.copy_from_slice(&w_bytes);

                let w = ctoption_to_result(
                    G2Affine::from_compressed(&fixed_bytes),
                    || serde::de::Error::custom("invalid G2Affine compressed data")
                )?;

                Ok(IssuerPublicKey { w })
            }
        }

        deserializer.deserialize_map(IssuerPublicKeyVisitor)
    }
}

/// The private key held by a voter (client).
///
/// This key is used to request and create credentials, and later to
/// derive pseudonyms for voting. It must be kept secret by the voter.
#[derive(Debug, Clone)]
pub struct ClientPrivateKey {
    /// Secret scalar value
    k: Scalar,
}

impl Serialize for ClientPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ClientPrivateKey", 1)?;
        state.serialize_field("k", &self.k.to_bytes().as_ref())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ClientPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClientPrivateKeyVisitor;

        impl<'de> Visitor<'de> for ClientPrivateKeyVisitor {
            type Value = ClientPrivateKey;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct ClientPrivateKey")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ClientPrivateKey, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut k_bytes = None;

                while let Some(key) = map.next_key::<String>()? {
                    if key == "k" {
                        if k_bytes.is_some() {
                            return Err(serde::de::Error::duplicate_field("k"));
                        }
                        k_bytes = Some(map.next_value::<Vec<u8>>()?);
                    } else {
                        return Err(serde::de::Error::unknown_field(&key, &["k"]));
                    }
                }

                let k_bytes = k_bytes.ok_or_else(|| serde::de::Error::missing_field("k"))?;
                let mut fixed_bytes = [0u8; 32];
                if k_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                fixed_bytes.copy_from_slice(&k_bytes);

                let k = Option::from(Scalar::from_bytes(&fixed_bytes))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes"))?;

                Ok(ClientPrivateKey { k })
            }
        }

        deserializer.deserialize_map(ClientPrivateKeyVisitor)
    }
}

/// A request for credential issuance sent by a voter to the issuer.
///
/// This contains a commitment to the voter's private key and a zero-knowledge
/// proof that the voter knows the private key, without revealing it.
#[derive(Debug, Clone)]
pub struct CredentialRequest {
    /// Public commitment to the voter's private key
    big_k: G1Affine,
    /// Challenge value in the zero-knowledge proof
    // This zkp is not currently necessary (the commitment still is though), however if other
    // fields were to be included in this proof you'd need this, so it is useful to keep around.
    gamma: Scalar,
    /// Response value in the zero-knowledge proof
    k_bar: Scalar,
}

impl Serialize for CredentialRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CredentialRequest", 3)?;
        state.serialize_field("big_k", &self.big_k.to_compressed().as_ref())?;
        state.serialize_field("gamma", &self.gamma.to_bytes().as_ref())?;
        state.serialize_field("k_bar", &self.k_bar.to_bytes().as_ref())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CredentialRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CredentialRequestVisitor;

        impl<'de> Visitor<'de> for CredentialRequestVisitor {
            type Value = CredentialRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CredentialRequest")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CredentialRequest, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut big_k_bytes = None;
                let mut gamma_bytes = None;
                let mut k_bar_bytes = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "big_k" => {
                            if big_k_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("big_k"));
                            }
                            big_k_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "gamma" => {
                            if gamma_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("gamma"));
                            }
                            gamma_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "k_bar" => {
                            if k_bar_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("k_bar"));
                            }
                            k_bar_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(&key, &["big_k", "gamma", "k_bar"]));
                        }
                    }
                }

                let big_k_bytes = big_k_bytes.ok_or_else(|| serde::de::Error::missing_field("big_k"))?;
                let gamma_bytes = gamma_bytes.ok_or_else(|| serde::de::Error::missing_field("gamma"))?;
                let k_bar_bytes = k_bar_bytes.ok_or_else(|| serde::de::Error::missing_field("k_bar"))?;

                let mut big_k_fixed_bytes = [0u8; 48];
                if big_k_bytes.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes for G1Affine"));
                }
                big_k_fixed_bytes.copy_from_slice(&big_k_bytes);

                let mut gamma_fixed_bytes = [0u8; 32];
                if gamma_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                gamma_fixed_bytes.copy_from_slice(&gamma_bytes);

                let mut k_bar_fixed_bytes = [0u8; 32];
                if k_bar_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                k_bar_fixed_bytes.copy_from_slice(&k_bar_bytes);

                let big_k = ctoption_to_result(
                    G1Affine::from_compressed(&big_k_fixed_bytes),
                    || serde::de::Error::custom("invalid G1Affine compressed data")
                )?;
                
                let gamma = Option::from(Scalar::from_bytes(&gamma_fixed_bytes))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for gamma"))?;
                
                let k_bar = Option::from(Scalar::from_bytes(&k_bar_fixed_bytes))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for k_bar"))?;

                Ok(CredentialRequest { big_k, gamma, k_bar })
            }
        }

        deserializer.deserialize_map(CredentialRequestVisitor)
    }
}

impl ClientPrivateKey {
    /// Generate a new client private key.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        ClientPrivateKey {
            k: Scalar::random(&mut rng),
        }
    }

    /// Recover a client private key from a backup.
    pub fn recover(k: Scalar) -> Self {
        ClientPrivateKey { k }
    }

    /// Create a request for a new credential issuance associated to the given private key.
    pub fn request(&self, params: &Params, mut rng: impl CryptoRngCore) -> CredentialRequest {
        let big_k = params.h * self.k;
        let k_prime = Scalar::random(&mut rng);
        let big_k_1 = params.h * k_prime;

        let gamma = {
            let mut fiat_shamir = FiatShamir::new(CLIENT_ISSUANCE_LABEL, b"");
            fiat_shamir.update(GroupEncoding::to_bytes(&big_k).as_ref());
            fiat_shamir.update(GroupEncoding::to_bytes(&big_k_1).as_ref());
            let mut fiat_shamir_rng = fiat_shamir.rng();

            Scalar::random(&mut fiat_shamir_rng)
        };

        let k_bar = gamma * self.k + k_prime;

        CredentialRequest {
            big_k: big_k.into(),
            gamma,
            k_bar,
        }
    }
}

/// The response the server sends back upon a request for issuance.
#[derive(Debug, Clone)]
pub struct CredentialResponse {
    a: G1Affine,
    e: Scalar,
}

impl Serialize for CredentialResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("CredentialResponse", 2)?;
        state.serialize_field("a", &self.a.to_compressed().as_ref())?;
        state.serialize_field("e", &self.e.to_bytes().as_ref())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for CredentialResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CredentialResponseVisitor;

        impl<'de> Visitor<'de> for CredentialResponseVisitor {
            type Value = CredentialResponse;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct CredentialResponse")
            }

            fn visit_map<V>(self, mut map: V) -> Result<CredentialResponse, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut a_bytes = None;
                let mut e_bytes = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "a" => {
                            if a_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("a"));
                            }
                            a_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "e" => {
                            if e_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("e"));
                            }
                            e_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(&key, &["a", "e"]));
                        }
                    }
                }

                let a_bytes = a_bytes.ok_or_else(|| serde::de::Error::missing_field("a"))?;
                let e_bytes = e_bytes.ok_or_else(|| serde::de::Error::missing_field("e"))?;

                let mut a_fixed_bytes = [0u8; 48];
                if a_bytes.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes for G1Affine"));
                }
                a_fixed_bytes.copy_from_slice(&a_bytes);

                let mut e_fixed_bytes = [0u8; 32];
                if e_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                e_fixed_bytes.copy_from_slice(&e_bytes);

                let a = ctoption_to_result(
                    G1Affine::from_compressed(&a_fixed_bytes),
                    || serde::de::Error::custom("invalid G1Affine compressed data for a")
                )?;
                
                let e = Option::from(Scalar::from_bytes(&e_fixed_bytes))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for e"))?;

                Ok(CredentialResponse { a, e })
            }
        }

        deserializer.deserialize_map(CredentialResponseVisitor)
    }
}

impl CredentialRequest {
    /// Responds to the given credential request with the data needed for the client to construct a
    /// new credential.
    pub fn respond(
        &self,
        issuer_private_key: &IssuerPrivateKey,
        params: &Params,
        mut rng: impl CryptoRngCore,
    ) -> Option<CredentialResponse> {
        let big_k_1 = params.h * self.k_bar + self.big_k * self.gamma.neg();
        let client_gamma = {
            let mut fiat_shamir = FiatShamir::new(CLIENT_ISSUANCE_LABEL, b"");
            fiat_shamir.update(G1Affine::from(self.big_k).to_compressed().as_ref());
            fiat_shamir.update(G1Affine::from(big_k_1).to_compressed().as_ref());
            let mut fiat_shamir_rng = fiat_shamir.rng();
            Scalar::random(&mut fiat_shamir_rng)
        };

        if client_gamma != self.gamma {
            return None;
        }

        let e = Scalar::random(&mut rng);
        let a = (G1Affine::generator() + G1Projective::from(&self.big_k))
            * (e + issuer_private_key.x).invert().unwrap();
        Some(CredentialResponse { a: a.into(), e })
    }
}

impl IssuerPrivateKey {
    /// Generate random private key for the issuer.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        IssuerPrivateKey {
            x: Scalar::random(&mut rng),
        }
    }

    /// Computes the public key of the issuer given the private one.
    pub fn public(&self) -> IssuerPublicKey {
        IssuerPublicKey {
            w: (G2Affine::generator() * self.x).into(),
        }
    }
}

/// A credential which the client holds privately.
#[derive(Debug, Clone)]
pub struct Credential {
    a: G1Affine,
    e: Scalar,
    k: Scalar,
}

impl Serialize for Credential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Credential", 3)?;
        state.serialize_field("a", &self.a.to_compressed().as_ref())?;
        state.serialize_field("e", &self.e.to_bytes().as_ref())?;
        state.serialize_field("k", &self.k.to_bytes().as_ref())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Credential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CredentialVisitor;

        impl<'de> Visitor<'de> for CredentialVisitor {
            type Value = Credential;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Credential")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Credential, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut a_bytes = None;
                let mut e_bytes = None;
                let mut k_bytes = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "a" => {
                            if a_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("a"));
                            }
                            a_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "e" => {
                            if e_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("e"));
                            }
                            e_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "k" => {
                            if k_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("k"));
                            }
                            k_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(&key, &["a", "e", "k"]));
                        }
                    }
                }

                let a_bytes = a_bytes.ok_or_else(|| serde::de::Error::missing_field("a"))?;
                let e_bytes = e_bytes.ok_or_else(|| serde::de::Error::missing_field("e"))?;
                let k_bytes = k_bytes.ok_or_else(|| serde::de::Error::missing_field("k"))?;

                let mut a_fixed_bytes = [0u8; 48];
                if a_bytes.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes for G1Affine"));
                }
                a_fixed_bytes.copy_from_slice(&a_bytes);

                let mut e_fixed_bytes = [0u8; 32];
                if e_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                e_fixed_bytes.copy_from_slice(&e_bytes);

                let mut k_fixed_bytes = [0u8; 32];
                if k_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                k_fixed_bytes.copy_from_slice(&k_bytes);

                let a = ctoption_to_result(
                    G1Affine::from_compressed(&a_fixed_bytes),
                    || serde::de::Error::custom("invalid G1Affine compressed data")
                )?;
                let e = Option::from(Scalar::from_bytes(&e_fixed_bytes))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for e"))?;
                let k = Option::from(Scalar::from_bytes(&k_fixed_bytes))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for k"))?;

                Ok(Credential { a, e, k })
            }
        }

        deserializer.deserialize_map(CredentialVisitor)
    }
}

impl ClientPrivateKey {
    /// Creates a new credential using the original request, response from the server, and the
    /// client's private PRF key.
    pub fn create_credential(
        &self,
        request: &CredentialRequest,
        response: &CredentialResponse,
        issuer_public_key: &IssuerPublicKey,
    ) -> Option<Credential> {
        if Bls12::pairing(&response.a, &issuer_public_key.w)
            != Bls12::pairing(
                &(response.a * response.e.neg() + G1Affine::generator() + request.big_k).into(),
                &G2Affine::generator(),
            )
        {
            return None;
        }

        Some(Credential {
            a: response.a,
            e: response.e,
            k: self.k,
        })
    }
}

impl Credential {
    /// Verify the validity of the given credential.
    pub fn verify(&self, params: &Params, issuer_public_key: &IssuerPublicKey) -> Choice {
        Bls12::pairing(&self.a, &issuer_public_key.w).ct_eq(&Bls12::pairing(
            &G1Affine::from(&self.a * self.e.neg() + G1Affine::generator() + params.h * self.k),
            &G2Affine::generator(),
        ))
    }

    pub fn vrf_key(&self) -> &Scalar {
        &self.k
    }
}

/// A cryptographic pseudonym used to cast votes anonymously.
///
/// This pseudonym is unlinkable, meaning that even if multiple election authorities
/// (relying parties) collude with each other and with the credential issuer, they cannot 
/// link two pseudonyms derived from the same voter's credential. This provides strong 
/// anonymity guarantees while still allowing verification of vote authenticity.
///
/// Each pseudonym contains a zero-knowledge proof that:
/// 1. It was derived from a valid credential
/// 2. The voter knows the private key for this credential
/// 3. The pseudonym is properly bound to the specific election
///
/// This proof can be verified without compromising the voter's anonymity.
#[derive(Debug, Clone)]
pub struct Pseudonym {
    /// Identifier for the election this pseudonym is for
    relying_party_id: Scalar,
    /// Modified credential signature point
    a_prime: G1Affine,
    /// Commitment to the voter's private key
    b_bar: G1Affine,
    /// Proof component for credential validity
    a_bar: G1Affine,
    /// The actual pseudonym identifier (unique for each voter+election combination)
    y: G1Affine,
    /// Challenge value in the zero-knowledge proof
    gamma: Scalar,
    /// First response value in the zero-knowledge proof
    z_e: Scalar,
    /// Second response value in the zero-knowledge proof
    z_r2: Scalar,
    /// Third response value in the zero-knowledge proof
    z_r3: Scalar,
    /// Fourth response value in the zero-knowledge proof
    z_k: Scalar,
}

impl Serialize for Pseudonym {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Pseudonym", 10)?;
        state.serialize_field("relying_party_id", &self.relying_party_id.to_bytes().as_ref())?;
        state.serialize_field("a_prime", &self.a_prime.to_compressed().as_ref())?;
        state.serialize_field("b_bar", &self.b_bar.to_compressed().as_ref())?;
        state.serialize_field("a_bar", &self.a_bar.to_compressed().as_ref())?;
        state.serialize_field("y", &self.y.to_compressed().as_ref())?;
        state.serialize_field("gamma", &self.gamma.to_bytes().as_ref())?;
        state.serialize_field("z_e", &self.z_e.to_bytes().as_ref())?;
        state.serialize_field("z_r2", &self.z_r2.to_bytes().as_ref())?;
        state.serialize_field("z_r3", &self.z_r3.to_bytes().as_ref())?;
        state.serialize_field("z_k", &self.z_k.to_bytes().as_ref())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Pseudonym {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PseudonymVisitor;

        impl<'de> Visitor<'de> for PseudonymVisitor {
            type Value = Pseudonym;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Pseudonym")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Pseudonym, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut relying_party_id_bytes = None;
                let mut a_prime_bytes = None;
                let mut b_bar_bytes = None;
                let mut a_bar_bytes = None;
                let mut y_bytes = None;
                let mut gamma_bytes = None;
                let mut z_e_bytes = None;
                let mut z_r2_bytes = None;
                let mut z_r3_bytes = None;
                let mut z_k_bytes = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "relying_party_id" => {
                            if relying_party_id_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("relying_party_id"));
                            }
                            relying_party_id_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "a_prime" => {
                            if a_prime_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("a_prime"));
                            }
                            a_prime_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "b_bar" => {
                            if b_bar_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("b_bar"));
                            }
                            b_bar_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "a_bar" => {
                            if a_bar_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("a_bar"));
                            }
                            a_bar_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "y" => {
                            if y_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("y"));
                            }
                            y_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "gamma" => {
                            if gamma_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("gamma"));
                            }
                            gamma_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "z_e" => {
                            if z_e_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("z_e"));
                            }
                            z_e_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "z_r2" => {
                            if z_r2_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("z_r2"));
                            }
                            z_r2_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "z_r3" => {
                            if z_r3_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("z_r3"));
                            }
                            z_r3_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        "z_k" => {
                            if z_k_bytes.is_some() {
                                return Err(serde::de::Error::duplicate_field("z_k"));
                            }
                            z_k_bytes = Some(map.next_value::<Vec<u8>>()?);
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                &key,
                                &[
                                    "relying_party_id", "a_prime", "b_bar", "a_bar", "y",
                                    "gamma", "z_e", "z_r2", "z_r3", "z_k",
                                ],
                            ));
                        }
                    }
                }

                let relying_party_id_bytes = relying_party_id_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("relying_party_id"))?;
                let a_prime_bytes = a_prime_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("a_prime"))?;
                let b_bar_bytes = b_bar_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("b_bar"))?;
                let a_bar_bytes = a_bar_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("a_bar"))?;
                let y_bytes = y_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("y"))?;
                let gamma_bytes = gamma_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("gamma"))?;
                let z_e_bytes = z_e_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("z_e"))?;
                let z_r2_bytes = z_r2_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("z_r2"))?;
                let z_r3_bytes = z_r3_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("z_r3"))?;
                let z_k_bytes = z_k_bytes
                    .ok_or_else(|| serde::de::Error::missing_field("z_k"))?;

                // Convert bytes to fixed-length arrays
                let mut relying_party_id_fixed = [0u8; 32];
                if relying_party_id_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                relying_party_id_fixed.copy_from_slice(&relying_party_id_bytes);

                let mut a_prime_fixed = [0u8; 48];
                if a_prime_bytes.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes for G1Affine"));
                }
                a_prime_fixed.copy_from_slice(&a_prime_bytes);

                let mut b_bar_fixed = [0u8; 48];
                if b_bar_bytes.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes for G1Affine"));
                }
                b_bar_fixed.copy_from_slice(&b_bar_bytes);

                let mut a_bar_fixed = [0u8; 48];
                if a_bar_bytes.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes for G1Affine"));
                }
                a_bar_fixed.copy_from_slice(&a_bar_bytes);

                let mut y_fixed = [0u8; 48];
                if y_bytes.len() != 48 {
                    return Err(serde::de::Error::custom("expected 48 bytes for G1Affine"));
                }
                y_fixed.copy_from_slice(&y_bytes);

                let mut gamma_fixed = [0u8; 32];
                if gamma_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                gamma_fixed.copy_from_slice(&gamma_bytes);

                let mut z_e_fixed = [0u8; 32];
                if z_e_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                z_e_fixed.copy_from_slice(&z_e_bytes);

                let mut z_r2_fixed = [0u8; 32];
                if z_r2_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                z_r2_fixed.copy_from_slice(&z_r2_bytes);

                let mut z_r3_fixed = [0u8; 32];
                if z_r3_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                z_r3_fixed.copy_from_slice(&z_r3_bytes);

                let mut z_k_fixed = [0u8; 32];
                if z_k_bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32 bytes for Scalar"));
                }
                z_k_fixed.copy_from_slice(&z_k_bytes);

                // Convert bytes to actual types
                let relying_party_id = Option::from(Scalar::from_bytes(&relying_party_id_fixed))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for relying_party_id"))?;
                
                let a_prime = ctoption_to_result(
                    G1Affine::from_compressed(&a_prime_fixed),
                    || serde::de::Error::custom("invalid G1Affine compressed data for a_prime")
                )?;
                
                let b_bar = ctoption_to_result(
                    G1Affine::from_compressed(&b_bar_fixed),
                    || serde::de::Error::custom("invalid G1Affine compressed data for b_bar")
                )?;
                
                let a_bar = ctoption_to_result(
                    G1Affine::from_compressed(&a_bar_fixed),
                    || serde::de::Error::custom("invalid G1Affine compressed data for a_bar")
                )?;
                
                let y = ctoption_to_result(
                    G1Affine::from_compressed(&y_fixed),
                    || serde::de::Error::custom("invalid G1Affine compressed data for y")
                )?;
                
                let gamma = Option::from(Scalar::from_bytes(&gamma_fixed))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for gamma"))?;
                
                let z_e = Option::from(Scalar::from_bytes(&z_e_fixed))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for z_e"))?;
                
                let z_r2 = Option::from(Scalar::from_bytes(&z_r2_fixed))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for z_r2"))?;
                
                let z_r3 = Option::from(Scalar::from_bytes(&z_r3_fixed))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for z_r3"))?;
                
                let z_k = Option::from(Scalar::from_bytes(&z_k_fixed))
                    .ok_or_else(|| serde::de::Error::custom("invalid Scalar bytes for z_k"))?;

                Ok(Pseudonym {
                    relying_party_id,
                    a_prime,
                    b_bar,
                    a_bar,
                    y,
                    gamma,
                    z_e,
                    z_r2,
                    z_r3,
                    z_k,
                })
            }
        }

        deserializer.deserialize_map(PseudonymVisitor)
    }
}

impl Credential {
    /// Compute a pseudonym for the given context.
    pub fn pseudonym_for(
        &self,
        params: &Params,
        relying_party_id: Scalar,
        nonce: &[u8],
        mut rng: impl CryptoRngCore,
    ) -> CtOption<Pseudonym> {
        let mut fiat_shamir = FiatShamir::new(PSEUDONYM_LABEL, nonce);

        let r1 = Scalar::random(&mut rng);
        let r2 = Scalar::random(&mut rng);
        let e_prime = Scalar::random(&mut rng);
        let r2_prime = Scalar::random(&mut rng);
        let r3_prime = Scalar::random(&mut rng);
        let k_prime = Scalar::random(&mut rng);

        let b = G1Affine::generator() + params.h * self.k;
        let a_prime = self.a * (r1 * r2);
        let b_bar = b * r1;
        let a_bar = a_prime * self.e.neg() + b_bar * r2;
        let r3 = r1.invert();

        fiat_shamir.update(GroupEncoding::to_bytes(&a_prime).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&b_bar).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&a_bar).as_ref());

        let a1 = a_prime * e_prime + b_bar * r2_prime;
        let a2 = b_bar * r3_prime + params.h * k_prime;

        fiat_shamir.update(GroupEncoding::to_bytes(&a1).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&a2).as_ref());

        let y = G1Affine::generator() * (self.k + relying_party_id).invert().unwrap();

        fiat_shamir.update(GroupEncoding::to_bytes(&y).as_ref());

        let y1 = y * k_prime.neg();

        fiat_shamir.update(GroupEncoding::to_bytes(&y1).as_ref());

        let gamma = Scalar::random(fiat_shamir.rng());

        let z_e = gamma.neg() * self.e + e_prime;
        let z_r2 = gamma * r2 + r2_prime;
        let z_r3 = r3.map(|r3| gamma * r3 + r3_prime);
        let z_k = gamma.neg() * self.k + k_prime;

        z_r3.map(|z_r3| Pseudonym {
            relying_party_id,
            a_prime: a_prime.into(),
            b_bar: b_bar.into(),
            a_bar: a_bar.into(),
            y: y.into(),
            gamma,
            z_e,
            z_r2,
            z_r3,
            z_k,
        })
    }
}

impl Pseudonym {
    /// Verify the pseudonym's correctness.
    pub fn verify(
        &self,
        params: &Params,
        issuer_public_key: &IssuerPublicKey,
        nonce: &[u8],
    ) -> Choice {
        let mut choice = Choice::from(1);

        choice &= !self.a_prime.ct_eq(&G1Affine::identity());
        choice &= Bls12::pairing(&self.a_prime, &issuer_public_key.w)
            .ct_eq(&Bls12::pairing(&self.a_bar, &G2Affine::generator()));

        let mut fiat_shamir = FiatShamir::new(PSEUDONYM_LABEL, nonce);

        fiat_shamir.update(GroupEncoding::to_bytes(&self.a_prime).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&self.b_bar).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&self.a_bar).as_ref());

        let a1 = self.a_prime * self.z_e + self.b_bar * self.z_r2 + self.a_bar * self.gamma.neg();
        let a2 =
            self.b_bar * self.z_r3 + params.h * self.z_k + G1Affine::generator() * self.gamma.neg();

        fiat_shamir.update(GroupEncoding::to_bytes(&a1).as_ref());
        fiat_shamir.update(GroupEncoding::to_bytes(&a2).as_ref());

        fiat_shamir.update(GroupEncoding::to_bytes(&self.y).as_ref());

        let y1 = self.y * self.z_k.neg()
            + (G1Affine::generator() - self.y * self.relying_party_id) * self.gamma.neg();

        fiat_shamir.update(GroupEncoding::to_bytes(&y1).as_ref());

        let gamma = Scalar::random(fiat_shamir.rng());

        choice &= gamma.ct_eq(&self.gamma);

        choice
    }

    /// Return which relying party this pseudonym is meant for.
    pub fn relying_party_id(&self) -> &Scalar {
        &self.relying_party_id
    }

    /// Return the pseudonym ID which can be compared to other pseudonym IDs.
    pub fn pseudonym_id(&self) -> &G1Affine {
        &self.y
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::G1Projective;
    use serde_json;
        use rand_core::{OsRng, RngCore};

    #[test]
    fn test_params_serialization() {
        let params = Params::default();
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&params).expect("Failed to serialize Params");
        
        // Deserialize from JSON
        let deserialized: Params = serde_json::from_str(&serialized).expect("Failed to deserialize Params");
        
        // Verify that serialization preserves the G1Affine point
        assert_eq!(
            params.h.to_compressed(),
            deserialized.h.to_compressed()
        );
        
        // Check equivalence by creating pseudonyms with both and verifying them
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq
            .respond(&issuer_private_key, &params, OsRng)
            .unwrap();
        let credential = client_private_key
            .create_credential(&credreq, &credresp, &issuer_private_key.public())
            .unwrap();
            
        let relying_party_id = Scalar::random(OsRng);
        let pseudonym = credential
            .pseudonym_for(&params, relying_party_id, b"nonce", OsRng)
            .unwrap();
        
        // Verify that both original and deserialized parameters work the same
        assert!(bool::from(pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        assert!(bool::from(pseudonym.verify(
            &deserialized,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test for error handling with invalid input
        let invalid_json = r#"{"h": [1, 2, 3]}"#; // Wrong length
        let result: Result<Params, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        let invalid_json = r#"{"wrong_field": []}"#; // Wrong field name
        let result: Result<Params, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_issuer_private_key_serialization() {
        // Create a private key
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        
        // Generate its public key for later comparison
        let original_public_key = issuer_private_key.public();
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&issuer_private_key)
            .expect("Failed to serialize IssuerPrivateKey");
        
        // Check that serialized output looks correct (should contain "x" field)
        assert!(serialized.contains(r#""x":"#));
        
        // Deserialize from JSON
        let deserialized: IssuerPrivateKey = serde_json::from_str(&serialized)
            .expect("Failed to deserialize IssuerPrivateKey");
        
        // Verify cryptographic equality by deriving the public key from the deserialized private key
        let derived_public_key = deserialized.public();
        
        // The public keys should match exactly
        assert_eq!(
            original_public_key.w.to_compressed(),
            derived_public_key.w.to_compressed()
        );
        
        // Test the serialized scalar value directly
        assert_eq!(
            issuer_private_key.x.to_bytes(),
            deserialized.x.to_bytes()
        );
        
        // Test for error handling with invalid input
        let invalid_json = r#"{"x": [1, 2, 3]}"#; // Wrong length
        let result: Result<IssuerPrivateKey, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        let invalid_json = r#"{"wrong_field": []}"#; // Wrong field name
        let result: Result<IssuerPrivateKey, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_issuer_public_key_serialization() {
        // Create keys
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let issuer_public_key = issuer_private_key.public();
        
        // Serialize public key to JSON
        let serialized = serde_json::to_string(&issuer_public_key)
            .expect("Failed to serialize IssuerPublicKey");
        
        // Check that serialized output looks correct (should contain "w" field)
        assert!(serialized.contains(r#""w":"#));
        
        // Deserialize from JSON
        let deserialized: IssuerPublicKey = serde_json::from_str(&serialized)
            .expect("Failed to deserialize IssuerPublicKey");
        
        // Verify cryptographic equality of the keys
        assert_eq!(
            issuer_public_key.w.to_compressed(),
            deserialized.w.to_compressed()
        );
        
        // Functionality test: both public keys should verify the same credentials
        let params = Params::default();
        let client_private_key = ClientPrivateKey::random(OsRng);
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq
            .respond(&issuer_private_key, &params, OsRng)
            .unwrap();
        
        let credential = client_private_key
            .create_credential(&credreq, &credresp, &issuer_public_key)
            .unwrap();
            
        // Original public key verifies the credential
        assert!(bool::from(credential.verify(&params, &issuer_public_key)));
        
        // Deserialized public key should also verify
        assert!(bool::from(credential.verify(&params, &deserialized)));
        
        // Test for error handling with invalid input
        let invalid_json = r#"{"w": [1, 2, 3]}"#; // Wrong length
        let result: Result<IssuerPublicKey, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        let invalid_json = r#"{"wrong_field": []}"#; // Wrong field name
        let result: Result<IssuerPublicKey, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_client_private_key_serialization() {
        // Create a client private key
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&client_private_key)
            .expect("Failed to serialize ClientPrivateKey");
        
        // Check that serialized output looks correct (should contain "k" field)
        assert!(serialized.contains(r#""k":"#));
        
        // Deserialize from JSON
        let deserialized: ClientPrivateKey = serde_json::from_str(&serialized)
            .expect("Failed to deserialize ClientPrivateKey");
        
        // Test scalar value equality
        assert_eq!(
            client_private_key.k.to_bytes(),
            deserialized.k.to_bytes()
        );
        
        // Functionality test: create credential requests using both keys
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        
        // Create credential requests
        let request1 = client_private_key.request(&params, OsRng);
        let request2 = deserialized.request(&params, OsRng);
        
        // Both requests should produce valid credential responses
        let response1 = request1.respond(&issuer_private_key, &params, OsRng);
        let response2 = request2.respond(&issuer_private_key, &params, OsRng);
        
        assert!(response1.is_some());
        assert!(response2.is_some());
        
        // Go further and create full credentials
        let credential1 = client_private_key
            .create_credential(&request1, &response1.unwrap(), &issuer_private_key.public())
            .unwrap();
        let credential2 = deserialized
            .create_credential(&request2, &response2.unwrap(), &issuer_private_key.public())
            .unwrap();
            
        // Both credentials should be valid
        assert!(bool::from(credential1.verify(&params, &issuer_private_key.public())));
        assert!(bool::from(credential2.verify(&params, &issuer_private_key.public())));
        
        // Test for error handling with invalid input
        let invalid_json = r#"{"k": [1, 2, 3]}"#; // Wrong length
        let result: Result<ClientPrivateKey, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        let invalid_json = r#"{"wrong_field": []}"#; // Wrong field name
        let result: Result<ClientPrivateKey, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_credential_request_serialization() {
        // Create a credential request
        let params = Params::default();
        let client_private_key = ClientPrivateKey::random(OsRng);
        let credreq = client_private_key.request(&params, OsRng);
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&credreq).expect("Failed to serialize CredentialRequest");
        
        // Check that serialized output contains all fields
        assert!(serialized.contains(r#""big_k":"#));
        assert!(serialized.contains(r#""gamma":"#));
        assert!(serialized.contains(r#""k_bar":"#));
        
        // Deserialize from JSON
        let deserialized: CredentialRequest = serde_json::from_str(&serialized).expect("Failed to deserialize CredentialRequest");
        
        // Compare the serialized forms of both objects to check equality
        let re_serialized = serde_json::to_string(&deserialized).expect("Failed to re-serialize CredentialRequest");
        assert_eq!(serialized, re_serialized);
        
        // Functional test: verify that the deserialized request can be used in the protocol
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        
        // Original request should work
        let credresp1 = credreq.respond(&issuer_private_key, &params, OsRng);
        assert!(credresp1.is_some());
        
        // Deserialized request should also work
        let credresp2 = deserialized.respond(&issuer_private_key, &params, OsRng);
        assert!(credresp2.is_some());
        
        // Test error handling with invalid input
        let invalid_json = r#"{"big_k": [1, 2, 3], "gamma": [], "k_bar": []}"#; // Wrong format
        let result: Result<CredentialRequest, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        let invalid_json = r#"{"wrong_field": [], "other_wrong": [], "also_wrong": []}"#; // Wrong field names
        let result: Result<CredentialRequest, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        // Test with missing fields
        let invalid_json = r#"{"big_k": []}"#; // Missing fields
        let result: Result<CredentialRequest, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_credential_response_serialization() {
        // Create a credential response
        let params = Params::default();
        let client_private_key = ClientPrivateKey::random(OsRng);
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq.respond(&issuer_private_key, &params, OsRng).unwrap();
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&credresp).expect("Failed to serialize CredentialResponse");
        
        // Check that serialized output contains all fields
        assert!(serialized.contains(r#""a":"#));
        assert!(serialized.contains(r#""e":"#));
        
        // Deserialize from JSON
        let deserialized: CredentialResponse = serde_json::from_str(&serialized).expect("Failed to deserialize CredentialResponse");
        
        // Compare the serialized forms of both objects to check equality
        let re_serialized = serde_json::to_string(&deserialized).expect("Failed to re-serialize CredentialResponse");
        assert_eq!(serialized, re_serialized);
        
        // Check that individual fields match
        assert_eq!(
            credresp.a.to_compressed(),
            deserialized.a.to_compressed()
        );
        assert_eq!(
            credresp.e.to_bytes(),
            deserialized.e.to_bytes()
        );
        
        // Functional test: create credentials with both the original and deserialized response
        let credential1 = client_private_key
            .create_credential(&credreq, &credresp, &issuer_private_key.public());
        assert!(credential1.is_some());
        
        let credential2 = client_private_key
            .create_credential(&credreq, &deserialized, &issuer_private_key.public());
        assert!(credential2.is_some());
        
        // Both credentials should be valid
        assert!(bool::from(credential1.unwrap().verify(&params, &issuer_private_key.public())));
        assert!(bool::from(credential2.unwrap().verify(&params, &issuer_private_key.public())));
        
        // Test error handling with invalid input
        let invalid_json = r#"{"a": [1, 2, 3], "e": []}"#; // Wrong format
        let result: Result<CredentialResponse, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        let invalid_json = r#"{"wrong_field1": [], "wrong_field2": []}"#; // Wrong field names
        let result: Result<CredentialResponse, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        // Test with missing fields
        let invalid_json = r#"{"a": []}"#; // Missing fields
        let result: Result<CredentialResponse, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_credential_serialization() {
        // Create credential and associated objects
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq
            .respond(&issuer_private_key, &params, OsRng)
            .unwrap();
        let credential = client_private_key
            .create_credential(&credreq, &credresp, &issuer_private_key.public())
            .unwrap();
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&credential)
            .expect("Failed to serialize Credential");
        
        // Check that serialized output looks correct (should contain all fields)
        assert!(serialized.contains(r#""a":"#));
        assert!(serialized.contains(r#""e":"#));
        assert!(serialized.contains(r#""k":"#));
        
        // Deserialize from JSON
        let deserialized: Credential = serde_json::from_str(&serialized)
            .expect("Failed to deserialize Credential");
        
        // Check that fields match
        assert_eq!(
            credential.a.to_compressed(),
            deserialized.a.to_compressed()
        );
        assert_eq!(
            credential.e.to_bytes(),
            deserialized.e.to_bytes()
        );
        assert_eq!(
            credential.k.to_bytes(),
            deserialized.k.to_bytes()
        );
        
        // Functional test: Verify both credentials
        assert!(bool::from(credential.verify(&params, &issuer_private_key.public())));
        assert!(bool::from(deserialized.verify(&params, &issuer_private_key.public())));
        
        // Test VRF key access
        assert_eq!(
            credential.vrf_key().to_bytes(),
            deserialized.vrf_key().to_bytes()
        );
        
        // Create pseudonyms with both credentials for multiple relying parties
        for _ in 0..3 {
            let relying_party_id = Scalar::random(OsRng);
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            
            let original_pseudonym = credential
                .pseudonym_for(&params, relying_party_id, &nonce, OsRng)
                .unwrap();
            let deserialized_pseudonym = deserialized
                .pseudonym_for(&params, relying_party_id, &nonce, OsRng)
                .unwrap();
                
            // Both pseudonyms should verify
            assert!(bool::from(original_pseudonym.verify(&params, &issuer_private_key.public(), &nonce)));
            assert!(bool::from(deserialized_pseudonym.verify(&params, &issuer_private_key.public(), &nonce)));
            
            // For the same relying party and nonce, pseudonym IDs should match
            assert_eq!(
                original_pseudonym.pseudonym_id().to_compressed(),
                deserialized_pseudonym.pseudonym_id().to_compressed()
            );
        }
        
        // Test for error handling with invalid input
        let invalid_json = r#"{"a": [], "e": [], "k": []}"#; // Wrong format
        let result: Result<Credential, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        let invalid_json = r#"{"wrong_field": [], "other_wrong": [], "also_wrong": []}"#; // Wrong field names
        let result: Result<Credential, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        // Test with missing fields
        let invalid_json = r#"{"a": []}"#; // Missing fields
        let result: Result<Credential, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_pseudonym_serialization() {
        // Create all necessary components
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        // Generate credential
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq
            .respond(&issuer_private_key, &params, OsRng)
            .unwrap();
        let credential = client_private_key
            .create_credential(&credreq, &credresp, &issuer_private_key.public())
            .unwrap();
            
        // Create a list of pseudonyms for different relying parties
        let mut pseudonyms = Vec::new();
        // Use Vec instead of HashSet since Scalar is not Hash
        let mut relying_party_ids = Vec::new();
        
        for _ in 0..3 {
            let relying_party_id = Scalar::random(OsRng);
            relying_party_ids.push(relying_party_id);
            
            let mut nonce = [0u8; 32];
            OsRng.fill_bytes(&mut nonce);
            
            let pseudonym = credential
                .pseudonym_for(&params, relying_party_id, &nonce, OsRng)
                .unwrap();
                
            pseudonyms.push((pseudonym, nonce));
        }
        
        // Test serialization and deserialization for each pseudonym
        for (pseudonym, nonce) in pseudonyms {
            // Serialize to JSON
            let serialized = serde_json::to_string(&pseudonym)
                .expect("Failed to serialize Pseudonym");
            
            // Check that serialized output contains all fields
            assert!(serialized.contains(r#""relying_party_id":"#));
            assert!(serialized.contains(r#""a_prime":"#));
            assert!(serialized.contains(r#""b_bar":"#));
            assert!(serialized.contains(r#""a_bar":"#));
            assert!(serialized.contains(r#""y":"#));
            assert!(serialized.contains(r#""gamma":"#));
            assert!(serialized.contains(r#""z_e":"#));
            assert!(serialized.contains(r#""z_r2":"#));
            assert!(serialized.contains(r#""z_r3":"#));
            assert!(serialized.contains(r#""z_k":"#));
            
            // Deserialize from JSON
            let deserialized: Pseudonym = serde_json::from_str(&serialized)
                .expect("Failed to deserialize Pseudonym");
            
            // Verify deserialized pseudonym
            assert!(bool::from(deserialized.verify(
                &params,
                &issuer_private_key.public(),
                &nonce
            )));
            
            // Check that all individual components match
            assert_eq!(
                pseudonym.relying_party_id().to_bytes(),
                deserialized.relying_party_id().to_bytes()
            );
            
            assert_eq!(
                pseudonym.pseudonym_id().to_compressed(),
                deserialized.pseudonym_id().to_compressed()
            );
            
            assert_eq!(
                pseudonym.a_prime.to_compressed(),
                deserialized.a_prime.to_compressed()
            );
            
            assert_eq!(
                pseudonym.b_bar.to_compressed(),
                deserialized.b_bar.to_compressed()
            );
            
            assert_eq!(
                pseudonym.a_bar.to_compressed(),
                deserialized.a_bar.to_compressed()
            );
            
            assert_eq!(
                pseudonym.y.to_compressed(),
                deserialized.y.to_compressed()
            );
            
            assert_eq!(
                pseudonym.gamma.to_bytes(),
                deserialized.gamma.to_bytes()
            );
            
            assert_eq!(
                pseudonym.z_e.to_bytes(),
                deserialized.z_e.to_bytes()
            );
            
            assert_eq!(
                pseudonym.z_r2.to_bytes(),
                deserialized.z_r2.to_bytes()
            );
            
            assert_eq!(
                pseudonym.z_r3.to_bytes(),
                deserialized.z_r3.to_bytes()
            );
            
            assert_eq!(
                pseudonym.z_k.to_bytes(),
                deserialized.z_k.to_bytes()
            );
        }
        
        // Test error handling with various invalid inputs
        
        // Missing fields
        let invalid_json = r#"{"relying_party_id": []}"#; // Missing fields
        let result: Result<Pseudonym, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        // Wrong field names
        let invalid_json = r#"{
            "wrong_field1": [],
            "wrong_field2": [],
            "wrong_field3": [],
            "wrong_field4": [],
            "wrong_field5": [],
            "wrong_field6": [],
            "wrong_field7": [],
            "wrong_field8": [],
            "wrong_field9": [],
            "wrong_field10": []
        }"#;
        let result: Result<Pseudonym, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
        
        // Wrong data types
        let invalid_json = r#"{
            "relying_party_id": "not_bytes",
            "a_prime": "not_bytes",
            "b_bar": "not_bytes",
            "a_bar": "not_bytes",
            "y": "not_bytes",
            "gamma": "not_bytes",
            "z_e": "not_bytes",
            "z_r2": "not_bytes",
            "z_r3": "not_bytes",
            "z_k": "not_bytes"
        }"#;
        let result: Result<Pseudonym, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_credential_recovery() {
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        // Serialize the private key for "backup"
        let serialized = serde_json::to_string(&client_private_key).unwrap();
        
        // Recover from serialized backup
        let recovered_key: ClientPrivateKey = serde_json::from_str(&serialized).unwrap();
        
        // Test that both keys produce identical credential requests
        let credreq1 = client_private_key.request(&params, OsRng);
        let credreq2 = recovered_key.request(&params, OsRng);
        
        // Verify that the private components match
        assert_eq!(client_private_key.k, recovered_key.k);
        
        // Create credentials from both keys
        let credresp1 = credreq1.respond(&issuer_private_key, &params, OsRng).unwrap();
        let credential1 = client_private_key
            .create_credential(&credreq1, &credresp1, &issuer_private_key.public())
            .unwrap();
            
        let credresp2 = credreq2.respond(&issuer_private_key, &params, OsRng).unwrap();
        let credential2 = recovered_key
            .create_credential(&credreq2, &credresp2, &issuer_private_key.public())
            .unwrap();
            
        // Test both credentials with identical parameters
        let relying_party_id = Scalar::random(OsRng);
        let user_data = b"test_data";
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        
        let mut rng1 = ChaCha20Rng::from_seed(seed);
        let mut rng2 = ChaCha20Rng::from_seed(seed); // Using same seed for deterministic comparison
        
        let pseudonym1 = credential1.pseudonym_for(&params, relying_party_id, user_data, &mut rng1).unwrap();
        let pseudonym2 = credential2.pseudonym_for(&params, relying_party_id, user_data, &mut rng2).unwrap();
        
        // Both credentials should produce verifiable pseudonyms
        assert!(bool::from(pseudonym1.verify(&params, &issuer_private_key.public(), user_data)));
        assert!(bool::from(pseudonym2.verify(&params, &issuer_private_key.public(), user_data)));
        
        // Pseudonyms created from recovered credentials should be identical
        assert_eq!(pseudonym1.pseudonym_id().to_compressed(), pseudonym2.pseudonym_id().to_compressed());
    }
    
    #[test]
    fn test_pseudonym_zero_knowledge_proof_validation() {
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        // Complete credential issuance protocol
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq.respond(&issuer_private_key, &params, OsRng).unwrap();
        let credential = client_private_key
            .create_credential(&credreq, &credresp, &issuer_private_key.public())
            .unwrap();
        
        // Create a legitimate pseudonym
        let relying_party_id = Scalar::random(OsRng);
        let user_data = b"test_data";
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let pseudonym = credential.pseudonym_for(&params, relying_party_id, user_data, &mut rng).unwrap();
        
        // Test serialization and deserialization of the zero-knowledge proof
        let serialized = serde_json::to_string(&pseudonym).unwrap();
        let deserialized: Pseudonym = serde_json::from_str(&serialized).unwrap();
        
        // Verify original and deserialized pseudonyms
        assert!(bool::from(pseudonym.verify(&params, &issuer_private_key.public(), user_data)));
        assert!(bool::from(deserialized.verify(&params, &issuer_private_key.public(), user_data)));
        
        // Test validation failures
        // 1. Wrong user data
        assert!(!bool::from(pseudonym.verify(&params, &issuer_private_key.public(), b"wrong_data")));
        
        // 2. Wrong issuer
        let wrong_issuer = IssuerPrivateKey::random(OsRng);
        assert!(!bool::from(pseudonym.verify(&params, &wrong_issuer.public(), user_data)));
        
        // 3. Invalid ZK proof components
        let mut tampered = pseudonym;
        tampered.z_e = Scalar::random(OsRng);
        assert!(!bool::from(tampered.verify(&params, &issuer_private_key.public(), user_data)));
    }
    
    #[test]
    fn test_batch_serialization_deserialization() {
        // Create a batch of different types to test all at once
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let issuer_public_key = issuer_private_key.public();
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        // Generate credential request, response, and credential
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq
            .respond(&issuer_private_key, &params, OsRng)
            .unwrap();
        let credential = client_private_key
            .create_credential(&credreq, &credresp, &issuer_public_key)
            .unwrap();
            
        // Create pseudonym
        let relying_party_id = Scalar::random(OsRng);
        let pseudonym = credential
            .pseudonym_for(&params, relying_party_id, b"batch_test", OsRng)
            .unwrap();
            
        // Serialize all types
        let params_json = serde_json::to_string(&params).unwrap();
        let issuer_private_key_json = serde_json::to_string(&issuer_private_key).unwrap();
        let issuer_public_key_json = serde_json::to_string(&issuer_public_key).unwrap();
        let client_private_key_json = serde_json::to_string(&client_private_key).unwrap();
        let credential_request_json = serde_json::to_string(&credreq).unwrap();
        let credential_response_json = serde_json::to_string(&credresp).unwrap();
        let credential_json = serde_json::to_string(&credential).unwrap();
        let pseudonym_json = serde_json::to_string(&pseudonym).unwrap();
        
        // Create a combined JSON object with all serialized types
        let combined_json = format!(
            r#"{{
                "params": {},
                "issuer_private_key": {},
                "issuer_public_key": {},
                "client_private_key": {},
                "credential_request": {},
                "credential_response": {},
                "credential": {},
                "pseudonym": {}
            }}"#,
            params_json, issuer_private_key_json, issuer_public_key_json,
            client_private_key_json, credential_request_json, credential_response_json,
            credential_json, pseudonym_json
        );
        
        // Parse the combined JSON to verify structural integrity
        let parsed: serde_json::Value = serde_json::from_str(&combined_json).unwrap();
        
        // Deserialize each component
        let deserialized_params: Params = serde_json::from_value(parsed["params"].clone()).unwrap();
        let deserialized_issuer_private_key: IssuerPrivateKey = serde_json::from_value(parsed["issuer_private_key"].clone()).unwrap();
        let deserialized_issuer_public_key: IssuerPublicKey = serde_json::from_value(parsed["issuer_public_key"].clone()).unwrap();
        // Mark as unused with underscore
        let _deserialized_client_private_key: ClientPrivateKey = serde_json::from_value(parsed["client_private_key"].clone()).unwrap();
        let deserialized_credential_request: CredentialRequest = serde_json::from_value(parsed["credential_request"].clone()).unwrap();
        let _deserialized_credential_response: CredentialResponse = serde_json::from_value(parsed["credential_response"].clone()).unwrap();
        let deserialized_credential: Credential = serde_json::from_value(parsed["credential"].clone()).unwrap();
        let deserialized_pseudonym: Pseudonym = serde_json::from_value(parsed["pseudonym"].clone()).unwrap();
        
        // Verify all components still work together
        assert!(bool::from(deserialized_credential.verify(&deserialized_params, &deserialized_issuer_public_key)));
        assert!(bool::from(deserialized_pseudonym.verify(&deserialized_params, &deserialized_issuer_public_key, b"batch_test")));
        
        // Verify that the deserialized credential request can be responded to
        let response_from_deserialized = deserialized_credential_request
            .respond(&deserialized_issuer_private_key, &deserialized_params, OsRng);
        assert!(response_from_deserialized.is_some());
        
        // Note: We can't directly create a credential using deserialized_credential_response
        // because it needs to match with the original credreq. Instead, we'll verify that
        // a new credential request can get a valid response and credential using the
        // deserialized components.
        
        let client_private_key2 = ClientPrivateKey::random(OsRng);
        let credreq2 = client_private_key2.request(&deserialized_params, OsRng);
        let credresp2 = credreq2.respond(&deserialized_issuer_private_key, &deserialized_params, OsRng).unwrap();
        
        let credential2 = client_private_key2
            .create_credential(&credreq2, &credresp2, &deserialized_issuer_public_key);
        assert!(credential2.is_some());
        
        // Verify that the new credential works
        assert!(bool::from(credential2.unwrap().verify(&deserialized_params, &deserialized_issuer_public_key)));
        
        // Verify that public key generated from deserialized private key matches
        let regenerated_public_key = deserialized_issuer_private_key.public();
        assert_eq!(
            regenerated_public_key.w.to_compressed(),
            deserialized_issuer_public_key.w.to_compressed()
        );
    }
    
    #[test]
    fn test_pseudonym_e2e() {
        // Test the core pseudonym functionality with 10 iterations
        for _ in 0..10 {
            use rand_core::OsRng;
            let params = Params::default();
            let issuer_private_key = IssuerPrivateKey::random(OsRng);
            let client_private_key = ClientPrivateKey::random(OsRng);
            
            // Complete credential issuance protocol
            let credreq = client_private_key.request(&params, OsRng);
            let credresp = credreq
                .respond(&issuer_private_key, &params, OsRng)
                .unwrap();
            let cred1 = client_private_key
                .create_credential(&credreq, &credresp, &issuer_private_key.public())
                .unwrap();
                
            // Verify credential
            assert!(bool::from(
                cred1.verify(&params, &issuer_private_key.public())
            ));
            
            // Create and verify pseudonym
            let relying_party_id = Scalar::random(OsRng);
            let pseudonym1 = cred1
                .pseudonym_for(&params, relying_party_id, b"nonce", OsRng)
                .unwrap();
            assert!(bool::from(pseudonym1.verify(
                &params,
                &issuer_private_key.public(),
                b"nonce"
            )));
            assert_eq!(pseudonym1.relying_party_id(), &relying_party_id);
        }
    }

    #[test]
    fn test_pseudonym_tampering_fails_verification() {
        use rand_core::OsRng;
        
        // Set up test environment
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        // Complete credential issuance protocol
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq
            .respond(&issuer_private_key, &params, OsRng)
            .unwrap();
        let credential = client_private_key
            .create_credential(&credreq, &credresp, &issuer_private_key.public())
            .unwrap();
            
        // Create valid pseudonym
        let relying_party_id = Scalar::random(OsRng);
        let valid_pseudonym = credential
            .pseudonym_for(&params, relying_party_id, b"nonce", OsRng)
            .unwrap();
            
        // Verify the valid pseudonym passes verification
        assert!(bool::from(valid_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 1: Tamper with the relying party ID
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.relying_party_id = Scalar::random(OsRng);
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 2: Tamper with a_prime (modified credential signature point)
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.a_prime = (G1Projective::from(tampered_pseudonym.a_prime) * Scalar::random(OsRng)).into();
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 3: Tamper with b_bar (commitment to voter's private key)
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.b_bar = (G1Projective::from(tampered_pseudonym.b_bar) * Scalar::random(OsRng)).into();
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 4: Tamper with a_bar (proof component for credential validity)
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.a_bar = (G1Projective::from(tampered_pseudonym.a_bar) * Scalar::random(OsRng)).into();
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 5: Tamper with y (the actual pseudonym identifier)
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.y = (G1Projective::from(tampered_pseudonym.y) * Scalar::random(OsRng)).into();
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 6: Tamper with gamma (challenge value in the zero-knowledge proof)
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.gamma = Scalar::random(OsRng);
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 7: Tamper with z_e (first response value in the zero-knowledge proof)
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.z_e = Scalar::random(OsRng);
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 8: Tamper with z_r2 (second response value in the zero-knowledge proof)
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.z_r2 = Scalar::random(OsRng);
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 9: Tamper with z_r3 (third response value in the zero-knowledge proof)
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.z_r3 = Scalar::random(OsRng);
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
        
        // Test 10: Tamper with z_k (fourth response value in the zero-knowledge proof)
        let mut tampered_pseudonym = valid_pseudonym.clone();
        tampered_pseudonym.z_k = Scalar::random(OsRng);
        assert!(!bool::from(tampered_pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"nonce"
        )));
    }
    
    #[test]
    fn test_pseudonym_verification_wrong_nonce() {
        use rand_core::OsRng;
        
        // Set up test environment
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        // Complete credential issuance protocol
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq
            .respond(&issuer_private_key, &params, OsRng)
            .unwrap();
        let credential = client_private_key
            .create_credential(&credreq, &credresp, &issuer_private_key.public())
            .unwrap();
            
        // Create valid pseudonym with specific nonce
        let relying_party_id = Scalar::random(OsRng);
        let pseudonym = credential
            .pseudonym_for(&params, relying_party_id, b"original_nonce", OsRng)
            .unwrap();
            
        // Verify with correct nonce succeeds
        assert!(bool::from(pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"original_nonce"
        )));
        
        // Verify with wrong nonce fails
        assert!(!bool::from(pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b"different_nonce"
        )));
        
        // Verify with empty nonce fails
        assert!(!bool::from(pseudonym.verify(
            &params,
            &issuer_private_key.public(),
            b""
        )));
    }
    
    #[test]
    fn test_pseudonym_verification_wrong_issuer() {
        use rand_core::OsRng;
        
        // Set up test environment with two different issuers
        let params = Params::default();
        let issuer_private_key1 = IssuerPrivateKey::random(OsRng);
        let issuer_private_key2 = IssuerPrivateKey::random(OsRng);
        let client_private_key = ClientPrivateKey::random(OsRng);
        
        // Complete credential issuance protocol with first issuer
        let credreq = client_private_key.request(&params, OsRng);
        let credresp = credreq
            .respond(&issuer_private_key1, &params, OsRng)
            .unwrap();
        let credential = client_private_key
            .create_credential(&credreq, &credresp, &issuer_private_key1.public())
            .unwrap();
            
        // Create valid pseudonym
        let relying_party_id = Scalar::random(OsRng);
        let pseudonym = credential
            .pseudonym_for(&params, relying_party_id, b"nonce", OsRng)
            .unwrap();
            
        // Verify with correct issuer succeeds
        assert!(bool::from(pseudonym.verify(
            &params,
            &issuer_private_key1.public(),
            b"nonce"
        )));
        
        // Verify with wrong issuer fails
        assert!(!bool::from(pseudonym.verify(
            &params,
            &issuer_private_key2.public(),
            b"nonce"
        )));
    }
}
