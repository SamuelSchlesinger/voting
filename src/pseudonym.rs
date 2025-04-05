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

/// The public key of the credential issuer.
///
/// This key is published and used by voters to verify that their
/// credentials were issued by the legitimate authority.
#[derive(Debug, Clone)]
pub struct IssuerPublicKey {
    /// Public commitment to the issuer's private key
    w: G2Affine,
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
