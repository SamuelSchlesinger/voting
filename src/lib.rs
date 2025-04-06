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
use pairing::group::ff::Field;
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

impl ElectionID {
    /// Creates a new random ElectionID using the provided random number generator.
    ///
    /// This generates a cryptographically secure random ElectionID that can be used
    /// to identify a unique election in the system.
    ///
    /// # Arguments
    /// * `rng` - A random number generator implementing the `RngCore` trait
    ///
    /// # Returns
    /// A new randomly generated `ElectionID`
    ///
    /// # Example
    /// ```
    /// use voting::ElectionID;
    /// use rand_core::OsRng;
    ///
    /// let election_id = ElectionID::random(OsRng);
    /// ```
    pub fn random<R: RngCore>(rng: R) -> Self {
        let scalar = Scalar::random(rng);
        ElectionID {
            bytes: scalar.to_bytes(),
        }
    }
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
mod tests;

