//! # Anonymous Voting Library
//! 
//! This library implements a secure anonymous voting system based on cryptographic pseudonyms.
//! It allows voters to cast votes that can be verified as authentic while preserving the
//! anonymity of the voter. The system provides:
//! 
//! - **Anonymity**: Votes cannot be linked to the voter's identity
//! - **Non-transferability**: Credentials cannot be shared or delegated
//! - **Double-voting prevention**: The system detects if a voter attempts to vote multiple times
//! - **Distributed verification**: Multiple vote collectors can combine databases and verify results
//!
//! The library uses BLS12-381 elliptic curve cryptography and zero-knowledge proofs to provide
//! these security properties without requiring a trusted third party during the voting process.

use std::collections::HashMap;

pub mod pseudonym;

use bls12_381::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, OsRng, SeedableRng};
use pseudonym::{IssuerPublicKey, Params, Pseudonym, Credential};
use serde::{Serialize, Deserialize};
use serde::ser::SerializeTuple;

/// A vote cast by a voter, consisting of their choice and an anonymous pseudonym
/// that proves their eligibility to vote without revealing their identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    /// The voter's selection or ballot choice (e.g., "Candidate A", "Yes", etc.)
    pub choice: String,
    /// Cryptographic pseudonym that proves the voter's eligibility without revealing their identity
    pseudonym: Pseudonym,
}

/// A unique identifier derived from a pseudonym that prevents double voting.
/// This nonce is derived from the pseudonym ID and cannot be linked back to the voter.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Nonce {
    bytes: [u8; 48],
}

/// A unique identifier for an election.
/// Different elections have different ElectionIDs to ensure votes for one election
/// cannot be used in another.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct ElectionID {
    bytes: [u8; 32],
}

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize bytes as a sequence
        let mut seq = serializer.serialize_tuple(self.bytes.len())?;
        for byte in &self.bytes {
            seq.serialize_element(byte)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct NonceVisitor;

        impl<'de> serde::de::Visitor<'de> for NonceVisitor {
            type Value = Nonce;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a sequence of 48 bytes")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 48];
                for i in 0..bytes.len() {
                    bytes[i] = seq.next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(Nonce { bytes })
            }
        }

        deserializer.deserialize_tuple(48, NonceVisitor)
    }
}

impl Credential {
    /// Create a vote for a specific election with the given choice.
    ///
    /// This function:
    /// 1. Generates a cryptographic pseudonym bound to this election
    /// 2. Creates a vote object that can be submitted to a vote database
    ///
    /// # Arguments
    /// * `election_id` - The unique identifier for the election
    /// * `choice` - The voter's selection
    ///
    /// # Returns
    /// * `Some(Vote)` if the vote was successfully created
    /// * `None` if any cryptographic operation failed
    pub fn vote(&self, election_id: ElectionID, choice: String) -> Option<Vote> {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut rng = ChaCha20Rng::from_seed(seed);
        let relying_party_id = match Option::from(Scalar::from_bytes(&election_id.bytes)) {
            Some(election_id) => election_id,
            None => { return None; }
        };
        let pseudonym = match Option::from(self.pseudonym_for(&Params::default(), relying_party_id, choice.as_ref(), &mut rng)) {
            Some(pseudonym) => pseudonym,
            None => { return None; }
        };
        Some(Vote { pseudonym, choice })
    }
}

impl Vote {
    /// Extract the nonce from this vote.
    /// The nonce is derived from the pseudonym ID and is used to detect double voting.
    pub fn nonce(&self) -> Nonce {
        Nonce {
            bytes: self.pseudonym.pseudonym_id().to_compressed(),
        }
    }

    /// Extract the election ID from this vote.
    /// The election ID identifies which election this vote belongs to.
    pub fn election_id(&self) -> ElectionID {
        ElectionID {
            bytes: self.pseudonym.relying_party_id().to_bytes(),
        }
    }

    /// Verify that this vote was created by an eligible voter.
    /// 
    /// This checks the cryptographic proof attached to the vote without revealing 
    /// the voter's identity. It ensures the vote was created using a valid credential
    /// issued by the authority represented by `issuer_public_key`.
    ///
    /// # Arguments
    /// * `issuer_public_key` - The public key of the credential issuer
    ///
    /// # Returns
    /// `true` if the vote is verified as authentic, `false` otherwise
    pub fn verify(&self, issuer_public_key: &IssuerPublicKey) -> bool {
        self.pseudonym
            .verify(&Params::default(), issuer_public_key, self.choice.as_ref())
            .into()
    }
}

/// A database that stores votes for multiple elections.
///
/// The database maintains two collections:
/// - `votes`: Valid votes indexed by election ID and nonce
/// - `liars`: Detected double-vote attempts, for auditing and security purposes
#[derive(Debug, Clone)]
pub struct VoteDatabase {
    votes: HashMap<ElectionID, HashMap<Nonce, Vote>>,
    liars: HashMap<ElectionID, HashMap<Nonce, HashMap<String, Vote>>>,
}

impl Serialize for VoteDatabase {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        
        let mut map = serializer.serialize_map(Some(2))?;
        
        // Convert the votes HashMap into a serializable format
        let votes_vec: Vec<(ElectionID, Vec<(Nonce, Vote)>)> = self.votes
            .iter()
            .map(|(election_id, vote_map)| {
                let votes: Vec<(Nonce, Vote)> = vote_map
                    .iter()
                    .map(|(nonce, vote)| (nonce.clone(), vote.clone()))
                    .collect();
                (election_id.clone(), votes)
            })
            .collect();
        
        // Convert the liars HashMap into a serializable format
        let liars_vec: Vec<(ElectionID, Vec<(Nonce, Vec<(String, Vote)>)>)> = self.liars
            .iter()
            .map(|(election_id, liars_map)| {
                let liars: Vec<(Nonce, Vec<(String, Vote)>)> = liars_map
                    .iter()
                    .map(|(nonce, choices_map)| {
                        let choices: Vec<(String, Vote)> = choices_map
                            .iter()
                            .map(|(choice, vote)| (choice.clone(), vote.clone()))
                            .collect();
                        (nonce.clone(), choices)
                    })
                    .collect();
                (election_id.clone(), liars)
            })
            .collect();
        
        map.serialize_entry("votes", &votes_vec)?;
        map.serialize_entry("liars", &liars_vec)?;
        
        map.end()
    }
}

impl<'de> Deserialize<'de> for VoteDatabase {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{MapAccess, Visitor};
        use std::fmt;
        use std::marker::PhantomData;

        struct VoteDatabaseVisitor {
            marker: PhantomData<fn() -> VoteDatabase>,
        }

        impl<'de> Visitor<'de> for VoteDatabaseVisitor {
            type Value = VoteDatabase;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a VoteDatabase")
            }

            fn visit_map<M>(self, mut map: M) -> Result<VoteDatabase, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut votes = None;
                let mut liars = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "votes" => {
                            if votes.is_some() {
                                return Err(serde::de::Error::duplicate_field("votes"));
                            }
                            let votes_vec: Vec<(ElectionID, Vec<(Nonce, Vote)>)> = map.next_value()?;
                            let mut votes_map = HashMap::new();
                            
                            for (election_id, vote_pairs) in votes_vec {
                                let mut inner_map = HashMap::new();
                                for (nonce, vote) in vote_pairs {
                                    inner_map.insert(nonce, vote);
                                }
                                votes_map.insert(election_id, inner_map);
                            }
                            
                            votes = Some(votes_map);
                        }
                        "liars" => {
                            if liars.is_some() {
                                return Err(serde::de::Error::duplicate_field("liars"));
                            }
                            let liars_vec: Vec<(ElectionID, Vec<(Nonce, Vec<(String, Vote)>)>)> = map.next_value()?;
                            let mut liars_map = HashMap::new();
                            
                            for (election_id, liar_pairs) in liars_vec {
                                let mut election_map = HashMap::new();
                                for (nonce, choice_pairs) in liar_pairs {
                                    let mut choices_map = HashMap::new();
                                    for (choice, vote) in choice_pairs {
                                        choices_map.insert(choice, vote);
                                    }
                                    election_map.insert(nonce, choices_map);
                                }
                                liars_map.insert(election_id, election_map);
                            }
                            
                            liars = Some(liars_map);
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(&key, &["votes", "liars"]));
                        }
                    }
                }

                let votes = votes.unwrap_or_else(HashMap::new);
                let liars = liars.unwrap_or_else(HashMap::new);

                Ok(VoteDatabase { votes, liars })
            }
        }

        deserializer.deserialize_map(VoteDatabaseVisitor {
            marker: PhantomData,
        })
    }
}

/// Errors that can occur during the voting process.
#[derive(Debug)]
pub enum VotingError {
    /// The vote could not be verified as authentic
    Unauthenticated,
    /// The voter has already cast a vote in this election
    DoubleVote {
        /// The choice in the new vote attempt
        new_choice: String,
        /// The choice in the original vote
        original_choice: String,
    },
    /// The specified election does not exist or is not currently active
    NonexistentElection(ElectionID),
}

impl VoteDatabase {
    /// Record a vote in the database.
    ///
    /// This function:
    /// 1. Verifies that the vote is authentic using the issuer's public key
    /// 2. Checks that the election exists and is active
    /// 3. Checks if the voter has already voted (using the nonce derived from their pseudonym)
    /// 4. Records the vote if all checks pass
    ///
    /// # Arguments
    /// * `vote` - The vote to record
    /// * `issuer_public_key` - The public key of the credential issuer to verify the vote
    ///
    /// # Returns
    /// * `Ok(())` if the vote was successfully recorded
    /// * `Err(VotingError)` if any verification check fails
    pub fn add_vote(
        &mut self,
        vote: Vote,
        issuer_public_key: &IssuerPublicKey,
    ) -> Result<(), VotingError> {
        if !vote.verify(&issuer_public_key) {
            return Err(VotingError::Unauthenticated);
        }
        let election_id = vote.election_id();
        let nonce = vote.nonce();
        if let Some(votes_for_election) = self.votes.get_mut(&election_id) {
            if let Some(original_vote) = votes_for_election.get(&nonce) {
                if original_vote.choice == vote.choice {
                    return Ok(());
                }
                let liars_for_election = self.liars.entry(election_id).or_insert(HashMap::new());
                let set = liars_for_election.entry(nonce).or_insert(HashMap::new());
                set.insert(vote.choice.clone(), vote.clone());
                set.insert(original_vote.choice.clone(), original_vote.clone());
                return Err(VotingError::DoubleVote {
                    new_choice: vote.choice.clone(),
                    original_choice: original_vote.choice.clone(),
                });
            } else {
                votes_for_election.insert(nonce, vote);
                return Ok(());
            }
        } else {
            return Err(VotingError::NonexistentElection(election_id));
        }
    }

    /// Verify the integrity of the entire vote database.
    ///
    /// This function verifies that:
    /// 1. All votes are authentic (cryptographically verified)
    /// 2. All votes are correctly indexed by their election ID and nonce
    /// 3. Any detected double-vote attempts ("liars") are also authentic and correctly indexed
    ///
    /// This verification can be performed by any third party with access to the database
    /// and the issuer's public key, without compromising voter anonymity.
    ///
    /// # Arguments
    /// * `issuer_public_key` - The public key of the credential issuer
    ///
    /// # Returns
    /// `true` if all votes in the database are valid, `false` otherwise
    pub fn verify(
        &self,
        issuer_public_key: &IssuerPublicKey
    ) -> bool {
        // Verify every vote in the votes data structure
        for (election_id, votes_for_election) in &self.votes {
            for (nonce, vote) in votes_for_election {
                // Verify the vote itself
                if !vote.verify(issuer_public_key) {
                    return false;
                }
                
                // Verify that the vote corresponds to the correct election_id and nonce
                if &vote.election_id() != election_id || &vote.nonce() != nonce {
                    return false;
                }
            }
        }
        
        // Verify every vote in the liars data structure
        for (election_id, liars_for_election) in &self.liars {
            for (nonce, choices) in liars_for_election {
                for (choice, vote) in choices {
                    // Verify the vote itself
                    if !vote.verify(issuer_public_key) {
                        return false;
                    }
                    
                    // Verify that the vote corresponds to the correct election_id, nonce, and choice
                    if &vote.election_id() != election_id || 
                       &vote.nonce() != nonce || 
                       &vote.choice != choice {
                        return false;
                    }
                }
            }
        }
        
        true
    }
    
    /// Create a new empty vote database
    pub fn new() -> Self {
        VoteDatabase {
            votes: HashMap::new(),
            liars: HashMap::new(),
        }
    }

    /// Combine this vote database with another one.
    ///
    /// This function enables distributed vote collection by merging two databases:
    /// 1. It adds all non-conflicting votes from the other database
    /// 2. It detects and records any conflicts (same voter/nonce with different choices)
    ///    as potential double-voting attempts
    ///
    /// This allows multiple vote collectors to operate independently and later combine
    /// their results while maintaining the system's security properties.
    ///
    /// # Arguments
    /// * `other` - Another vote database to combine with this one
    pub fn combine(
        &mut self,
        other: &VoteDatabase
    ) {
        // Combine votes from other database
        for (election_id, votes_for_election) in &other.votes {
            let self_votes = self.votes
                .entry(election_id.clone())
                .or_insert(HashMap::new());
                
            for (nonce, vote) in votes_for_election {
                if let Some(existing_vote) = self_votes.get(nonce) {
                    // Found conflicting votes, add to liars
                    if existing_vote.choice != vote.choice {
                        let liars_for_election = self.liars
                            .entry(election_id.clone())
                            .or_insert(HashMap::new());
                            
                        let choices = liars_for_election
                            .entry(nonce.clone())
                            .or_insert(HashMap::new());
                            
                        choices.insert(existing_vote.choice.clone(), existing_vote.clone());
                        choices.insert(vote.choice.clone(), vote.clone());
                    }
                } else {
                    // No conflict, insert the vote
                    self_votes.insert(nonce.clone(), vote.clone());
                }
            }
        }
        
        // Combine liars from other database
        for (election_id, liars_for_election) in &other.liars {
            let self_liars = self.liars
                .entry(election_id.clone())
                .or_insert(HashMap::new());
                
            for (nonce, choices) in liars_for_election {
                let self_choices = self_liars
                    .entry(nonce.clone())
                    .or_insert(HashMap::new());
                    
                for (choice, vote) in choices {
                    self_choices.insert(choice.clone(), vote.clone());
                }
            }
        }
    }

    /// Enable a new election in the database.
    ///
    /// Before votes can be recorded for an election, the election must be enabled.
    /// This ensures that only authorized elections can receive votes.
    ///
    /// # Arguments
    /// * `election_id` - The unique identifier for the election to enable
    pub fn enable_election(&mut self, election_id: ElectionID) {
        self.votes.entry(election_id).or_insert(HashMap::new());
    }

    /// Check if an election is enabled in the database.
    ///
    /// # Arguments
    /// * `election_id` - The election ID to check
    ///
    /// # Returns
    /// `true` if the election is enabled, `false` otherwise
    pub fn election_enabled(&self, election_id: &ElectionID) -> bool {
        self.votes.get(election_id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use bls12_381::Scalar;
    use pairing::group::ff::Field;
    use crate::pseudonym::{IssuerPrivateKey, ClientPrivateKey, Params};

    // Helper function to create a valid election ID
    fn create_election_id() -> ElectionID {
        let scalar = Scalar::random(OsRng);
        ElectionID { bytes: scalar.to_bytes() }
    }
    
    // Helper function to create an invalid election ID (all zeros, which is not a valid scalar)
    fn create_invalid_election_id() -> ElectionID {
        // The scalar value 0 is not a valid scalar in BLS12-381
        ElectionID { bytes: [0u8; 32] }
    }
    
    // Helper function to setup testing credentials
    fn setup_credentials() -> (Params, IssuerPrivateKey, Credential) {
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
        
        (params, issuer_private_key, credential)
    }

    #[test]
    fn test_vote_creation_and_verification() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        let vote = credential.vote(election_id.clone(), choice.clone()).unwrap();
        
        assert!(vote.verify(&issuer_private_key.public()));
        assert_eq!(vote.election_id(), election_id);
        assert_eq!(vote.choice, choice);
    }

    #[test]
    fn test_vote_unique_nonce() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        
        let vote1 = credential.vote(election_id.clone(), "Candidate A".to_string()).unwrap();
        let vote2 = credential.vote(election_id.clone(), "Candidate B".to_string()).unwrap();
        
        // Same credential for same election should generate identical nonce to prevent double voting
        assert_eq!(vote1.nonce(), vote2.nonce());
        assert_eq!(vote1.election_id(), vote2.election_id());
        assert!(vote1.verify(&issuer_private_key.public()));
        assert!(vote2.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_different_elections() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id1 = create_election_id();
        let election_id2 = create_election_id();
        
        let vote1 = credential.vote(election_id1.clone(), "Yes".to_string()).unwrap();
        let vote2 = credential.vote(election_id2.clone(), "Yes".to_string()).unwrap();
        
        assert_ne!(vote1.election_id(), vote2.election_id());
        assert!(vote1.verify(&issuer_private_key.public()));
        assert!(vote2.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_database_basic() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        let vote = credential.vote(election_id.clone(), choice).unwrap();
        
        let mut db = VoteDatabase::new();
        db.enable_election(election_id.clone());
        
        assert!(db.election_enabled(&election_id));
        
        let result = db.add_vote(vote.clone(), &issuer_private_key.public());
        assert!(result.is_ok());
        
        assert!(db.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_database_nonexistent_election() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        let vote = credential.vote(election_id.clone(), choice).unwrap();
        
        // Create database without enabling the election
        let mut db = VoteDatabase::new();
        
        assert!(!db.election_enabled(&election_id));
        
        let result = db.add_vote(vote, &issuer_private_key.public());
        
        // Test properly detects missing election
        match result {
            Err(VotingError::NonexistentElection(_)) => (),
            _ => panic!("Expected NonexistentElection error"),
        }
    }

    #[test]
    fn test_vote_database_double_vote() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        
        // Create two different votes from same credential for same election
        let vote1 = credential.vote(election_id.clone(), "Candidate A".to_string()).unwrap();
        let vote2 = credential.vote(election_id.clone(), "Candidate B".to_string()).unwrap();
        
        let mut db = VoteDatabase::new();
        db.enable_election(election_id);
        
        let result1 = db.add_vote(vote1.clone(), &issuer_private_key.public());
        assert!(result1.is_ok());
        
        // Second vote should be rejected as double-voting
        let result2 = db.add_vote(vote2.clone(), &issuer_private_key.public());
        
        match result2 {
            Err(VotingError::DoubleVote { new_choice, original_choice }) => {
                assert_eq!(new_choice, "Candidate B");
                assert_eq!(original_choice, "Candidate A");
            },
            _ => panic!("Expected DoubleVote error"),
        }
        
        assert!(db.verify(&issuer_private_key.public()));
    }
    
    #[test]
    fn test_same_choice_not_lying() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        // Create two votes with the same choice
        let vote1 = credential.vote(election_id.clone(), choice.clone()).unwrap();
        let vote2 = credential.vote(election_id.clone(), choice.clone()).unwrap();
        
        let mut db = VoteDatabase::new();
        db.enable_election(election_id);
        
        // First vote should succeed
        let result1 = db.add_vote(vote1.clone(), &issuer_private_key.public());
        assert!(result1.is_ok());
        
        // Second vote with same choice should also succeed (not counted as lying)
        let result2 = db.add_vote(vote2.clone(), &issuer_private_key.public());
        assert!(result2.is_ok());
        
        // Database should still validate
        assert!(db.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_database_multiple_elections() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id1 = create_election_id();
        let election_id2 = create_election_id();
        
        let vote1 = credential.vote(election_id1.clone(), "Yes".to_string()).unwrap();
        let vote2 = credential.vote(election_id2.clone(), "No".to_string()).unwrap();
        
        let mut db = VoteDatabase::new();
        db.enable_election(election_id1.clone());
        db.enable_election(election_id2.clone());
        
        let result1 = db.add_vote(vote1, &issuer_private_key.public());
        let result2 = db.add_vote(vote2, &issuer_private_key.public());
        
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        
        assert!(db.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_database_unauthenticated() {
        // Testing with two different issuers to demonstrate credential validation
        let (_, issuer_private_key1, credential1) = setup_credentials();
        let (_, issuer_private_key2, _) = setup_credentials(); 
        let election_id1 = create_election_id();
        let election_id2 = election_id1.clone();
        let choice1 = "Candidate A".to_string();
        let choice2 = "Candidate A".to_string();
        
        let vote = credential1.vote(election_id1.clone(), choice1).unwrap();
        
        let mut db = VoteDatabase::new();
        db.enable_election(election_id1.clone());
        
        // Using wrong issuer's public key should fail authentication
        let result = db.add_vote(vote, &issuer_private_key2.public());
        
        match result {
            Err(VotingError::Unauthenticated) => (),
            _ => panic!("Expected Unauthenticated error"),
        }
        
        // Verify that correct issuer works
        let mut db2 = VoteDatabase::new();
        db2.enable_election(election_id2.clone());
        let vote2 = credential1.vote(election_id2, choice2).unwrap();
        let result2 = db2.add_vote(vote2, &issuer_private_key1.public());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_vote_database_combine() {
        let (params, issuer_private_key, _) = setup_credentials();
        let issuer_public_key = issuer_private_key.public();
        
        let election_id1 = create_election_id();
        let election_id2 = create_election_id();
        
        let mut db1 = VoteDatabase::new();
        let mut db2 = VoteDatabase::new();
        
        db1.enable_election(election_id1.clone());
        db1.enable_election(election_id2.clone());
        db2.enable_election(election_id1.clone());
        db2.enable_election(election_id2.clone());
        
        // Create four different voters
        let client_key1 = ClientPrivateKey::random(OsRng);
        let client_key2 = ClientPrivateKey::random(OsRng);
        let client_key3 = ClientPrivateKey::random(OsRng);
        let client_key4 = ClientPrivateKey::random(OsRng);
        
        // Create credentials with the same issuer
        let req1 = client_key1.request(&params, OsRng);
        let resp1 = req1.respond(&issuer_private_key, &params, OsRng).unwrap();
        let cred1 = client_key1.create_credential(&req1, &resp1, &issuer_public_key).unwrap();
        
        let req2 = client_key2.request(&params, OsRng);
        let resp2 = req2.respond(&issuer_private_key, &params, OsRng).unwrap();
        let cred2 = client_key2.create_credential(&req2, &resp2, &issuer_public_key).unwrap();
        
        let req3 = client_key3.request(&params, OsRng);
        let resp3 = req3.respond(&issuer_private_key, &params, OsRng).unwrap();
        let cred3 = client_key3.create_credential(&req3, &resp3, &issuer_public_key).unwrap();
        
        let req4 = client_key4.request(&params, OsRng);
        let resp4 = req4.respond(&issuer_private_key, &params, OsRng).unwrap();
        let cred4 = client_key4.create_credential(&req4, &resp4, &issuer_public_key).unwrap();
        
        // DB1: first two voters vote in different elections
        let vote1 = cred1.vote(election_id1.clone(), "Yes".to_string()).unwrap();
        let vote2 = cred2.vote(election_id2.clone(), "No".to_string()).unwrap();
        
        // DB2: other two voters vote in different elections
        let vote3 = cred3.vote(election_id1.clone(), "Maybe".to_string()).unwrap();
        let vote4 = cred4.vote(election_id2.clone(), "Abstain".to_string()).unwrap();
        
        assert!(db1.add_vote(vote1, &issuer_public_key).is_ok());
        assert!(db1.add_vote(vote2, &issuer_public_key).is_ok());
        assert!(db2.add_vote(vote3, &issuer_public_key).is_ok());
        assert!(db2.add_vote(vote4, &issuer_public_key).is_ok());
        
        assert!(db1.verify(&issuer_public_key));
        assert!(db2.verify(&issuer_public_key));
        
        // Test database combining
        db1.combine(&db2);
        assert!(db1.verify(&issuer_public_key));
        
        db2.combine(&db1);
        assert!(db1.verify(&issuer_public_key));
        assert!(db2.verify(&issuer_public_key));
    }

    #[test]
    fn test_vote_database_combine_conflict() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        
        // Create two contradictory votes from same credential
        let vote1 = credential.vote(election_id.clone(), "Candidate A".to_string()).unwrap();
        let vote2 = credential.vote(election_id.clone(), "Candidate B".to_string()).unwrap();
        
        let mut db1 = VoteDatabase::new();
        let mut db2 = VoteDatabase::new();
        
        db1.enable_election(election_id.clone());
        db2.enable_election(election_id.clone());
        
        // Put first vote in first database
        let result1 = db1.add_vote(vote1.clone(), &issuer_private_key.public());
        assert!(result1.is_ok());
        
        // Put second vote in second database
        let result2 = db2.add_vote(vote2.clone(), &issuer_private_key.public());
        assert!(result2.is_ok());
        
        // Combining databases should detect conflict (recorded as "liar")
        db1.combine(&db2);
        assert!(db1.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_nonce_serialization() {
        // Create a nonce directly with test data
        let bytes = [1u8; 48];
        let nonce = Nonce { bytes };
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&nonce).expect("Failed to serialize nonce");
        
        // Deserialize from JSON
        let deserialized: Nonce = serde_json::from_str(&serialized).expect("Failed to deserialize nonce");
        
        // Check the values match
        assert_eq!(nonce, deserialized);
        assert_eq!(nonce.bytes, deserialized.bytes);
    }
    
    #[test]
    fn test_election_id_serialization() {
        // Create an election ID directly with test data
        let bytes = [2u8; 32];
        let election_id = ElectionID { bytes };
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&election_id).expect("Failed to serialize ElectionID");
        
        // Deserialize from JSON
        let deserialized: ElectionID = serde_json::from_str(&serialized).expect("Failed to deserialize ElectionID");
        
        // Check the values match
        assert_eq!(election_id, deserialized);
        assert_eq!(election_id.bytes, deserialized.bytes);
    }
    
    #[test]
    fn test_vote_serialization() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        // Create vote
        let vote = credential.vote(election_id.clone(), choice.clone()).unwrap();
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&vote).expect("Failed to serialize Vote");
        
        // Deserialize from JSON
        let deserialized: Vote = serde_json::from_str(&serialized).expect("Failed to deserialize Vote");
        
        // Check that the deserialized vote still verifies
        assert!(deserialized.verify(&issuer_private_key.public()));
        assert_eq!(vote.choice, deserialized.choice);
        assert_eq!(vote.nonce(), deserialized.nonce());
        assert_eq!(vote.election_id(), deserialized.election_id());
    }
    
    #[test]
    fn test_vote_database_serialization() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        // Create vote and database
        let vote = credential.vote(election_id.clone(), choice).unwrap();
        
        let mut db = VoteDatabase::new();
        db.enable_election(election_id.clone());
        let result = db.add_vote(vote.clone(), &issuer_private_key.public());
        assert!(result.is_ok());
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&db).expect("Failed to serialize VoteDatabase");
        
        // Deserialize from JSON
        let deserialized: VoteDatabase = serde_json::from_str(&serialized).expect("Failed to deserialize VoteDatabase");
        
        // Verify database integrity after deserialization
        assert!(deserialized.verify(&issuer_private_key.public()));
        assert!(deserialized.election_enabled(&election_id));
    }
    
    #[test]
    fn test_vote_with_invalid_election_id() {
        // We're testing that all-zero bytes aren't valid for election IDs
        // We need to specifically use a truly invalid scalar, not just zeros
        // One way is to use bytes that represent a value >= the field modulus
        let (_, _, credential) = setup_credentials();
        
        // Create an election ID with bytes that would represent a value larger than the BLS12-381 field modulus
        let mut invalid_bytes = [0xFF; 32]; // All ones, definitely greater than modulus
        let election_id = ElectionID { bytes: invalid_bytes };
        let choice = "Candidate A".to_string();
        
        // Try to create a vote with an invalid election ID
        let vote_result = credential.vote(election_id, choice);
        
        // Should return None since the election ID is invalid
        assert!(vote_result.is_none());
    }
    
    #[test]
    fn test_malformed_nonce_serialization() {
        // Create a unique nonce
        let nonce = Nonce { bytes: [99u8; 48] };
        
        // Serialize to JSON
        let serialized = serde_json::to_string(&nonce).expect("Failed to serialize nonce");
        
        // Alter the serialized data to make it invalid (truncate it)
        let truncated_json = serialized.split(',').take(20).collect::<Vec<_>>().join(",") + "]}";
        
        // Deserialize from invalid JSON - should fail
        let result: Result<Nonce, _> = serde_json::from_str(&truncated_json);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_database_verification_with_tampered_vote() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        // Create legitimate vote
        let vote = credential.vote(election_id.clone(), choice).unwrap();
        let nonce = vote.nonce();
        
        // Create database and add vote
        let mut db = VoteDatabase::new();
        db.enable_election(election_id.clone());
        db.add_vote(vote.clone(), &issuer_private_key.public()).unwrap();
        
        // Create a tampered vote with a different choice but same nonce
        // This is done by direct manipulation of the vote data structure
        let mut tampered_vote = vote.clone();
        tampered_vote.choice = "Tampered Choice".to_string();
        
        // Manually insert tampered vote to bypass verification
        let votes_for_election = db.votes.get_mut(&election_id).unwrap();
        votes_for_election.insert(nonce, tampered_vote);
        
        // Database verification should fail
        assert!(!db.verify(&issuer_private_key.public()));
    }
    
    #[test]
    fn test_detailed_database_liars_handling() {
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        
        // Create two contradictory votes from same credential
        let vote1 = credential.vote(election_id.clone(), "Candidate A".to_string()).unwrap();
        let vote2 = credential.vote(election_id.clone(), "Candidate B".to_string()).unwrap();
        let vote3 = credential.vote(election_id.clone(), "Candidate C".to_string()).unwrap();
        
        // Create two databases
        let mut db1 = VoteDatabase::new();
        let mut db2 = VoteDatabase::new();
        
        db1.enable_election(election_id.clone());
        db2.enable_election(election_id.clone());
        
        // Put first vote in first database
        db1.add_vote(vote1.clone(), &issuer_private_key.public()).unwrap();
        
        // Put second vote in second database
        db2.add_vote(vote2.clone(), &issuer_private_key.public()).unwrap();
        
        // Combine databases to trigger liar detection
        db1.combine(&db2);
        
        // Add third vote to test multiple conflicts
        let result = db1.add_vote(vote3.clone(), &issuer_private_key.public());
        assert!(matches!(result, Err(VotingError::DoubleVote { .. })));
        
        // Verify internal liar structures were correctly populated
        let liars = db1.liars.get(&election_id).unwrap();
        let nonce = vote1.nonce();
        let liar_choices = liars.get(&nonce).unwrap();
        
        // Should have at least two choices recorded
        assert!(liar_choices.len() >= 2);
        assert!(liar_choices.contains_key(&vote1.choice));
        assert!(liar_choices.contains_key(&vote2.choice));
        
        // Database should still verify correctly
        assert!(db1.verify(&issuer_private_key.public()));
    }
    
    #[test]
    fn test_random_voting_scenario() {
        // Complex test with multiple voters and elections
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let issuer_public_key = issuer_private_key.public();
        
        let num_elections = 5;
        let mut election_ids = Vec::with_capacity(num_elections);
        for _ in 0..num_elections {
            election_ids.push(create_election_id());
        }
        
        let num_voters = 20;
        let mut credentials = Vec::with_capacity(num_voters);
        for _ in 0..num_voters {
            let client_private_key = ClientPrivateKey::random(OsRng);
            let credreq = client_private_key.request(&params, OsRng);
            let credresp = credreq
                .respond(&issuer_private_key, &params, OsRng)
                .unwrap();
            let credential = client_private_key
                .create_credential(&credreq, &credresp, &issuer_public_key)
                .unwrap();
            credentials.push(credential);
        }
        
        let mut db = VoteDatabase::new();
        for election_id in &election_ids {
            db.enable_election(election_id.clone());
        }
        
        // Track which credential voted in which election
        let mut voted_credential_elections = std::collections::HashMap::new();
        
        let choices = ["Yes", "No", "Maybe", "Abstain"];
        let mut _vote_count = 0;
        
        for (i, credential) in credentials.iter().enumerate() {
            // Random number of votes per voter
            let num_votes = (OsRng.next_u32() % num_elections as u32) + 1;
            let mut voted_elections = std::collections::HashSet::new();
            
            for _ in 0..num_votes {
                let election_idx = (OsRng.next_u32() % num_elections as u32) as usize;
                if voted_elections.contains(&election_idx) {
                    continue;
                }
                voted_elections.insert(election_idx);
                
                voted_credential_elections.insert((i, election_idx), true);
                
                let choice_idx = (OsRng.next_u32() % choices.len() as u32) as usize;
                let choice = choices[choice_idx].to_string();
                
                let vote = credential.vote(election_ids[election_idx].clone(), choice).unwrap();
                let result = db.add_vote(vote, &issuer_public_key);
                assert!(result.is_ok());
                _vote_count += 1;
            }
        }
        
        assert!(db.verify(&issuer_public_key));
        
        // Test double-voting detection
        for (i, credential) in credentials.iter().enumerate() {
            for election_idx in 0..num_elections {
                if voted_credential_elections.contains_key(&(i, election_idx)) {
                    // Try to vote again with same credential
                    let vote = credential.vote(election_ids[election_idx].clone(), "Double Vote".to_string()).unwrap();
                    let result = db.add_vote(vote, &issuer_public_key);
                    
                    assert!(matches!(result, Err(VotingError::DoubleVote { .. })));
                    return;
                }
            }
        }
        
        assert!(db.verify(&issuer_public_key));
        
        // Test database combination with non-conflicting votes
        let mut db2 = VoteDatabase::new();
        for election_id in &election_ids {
            db2.enable_election(election_id.clone());
        }
        
        if !credentials.is_empty() {
            for i in 0..std::cmp::min(credentials.len(), num_elections) {
                for election_idx in 0..num_elections {
                    if !voted_credential_elections.contains_key(&(i, election_idx)) {
                        let credential = &credentials[i];
                        let vote = credential.vote(election_ids[election_idx].clone(), "Db2 Vote".to_string()).unwrap();
                        let result = db2.add_vote(vote, &issuer_public_key);
                        assert!(result.is_ok());
                        _vote_count += 1;
                        break;
                    }
                }
            }
        }
        
        db.combine(&db2);
        assert!(db.verify(&issuer_public_key));
    }
}
