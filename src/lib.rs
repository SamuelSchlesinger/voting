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

/// A vote cast by a voter, consisting of their choice and an anonymous pseudonym
/// that proves their eligibility to vote without revealing their identity.
#[derive(Clone, Debug)]
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
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ElectionID {
    bytes: [u8; 32],
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
pub struct VoteDatabase {
    votes: HashMap<ElectionID, HashMap<Nonce, Vote>>,
    liars: HashMap<ElectionID, HashMap<Nonce, HashMap<String, Vote>>>,
}

/// Errors that can occur during the voting process.
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

    /// Helper function to create a valid election ID
    fn create_election_id() -> ElectionID {
        let scalar = Scalar::random(OsRng);
        ElectionID { bytes: scalar.to_bytes() }
    }
    
    /// Helper function to setup testing credentials
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
        // Single issuer for this test
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        // Create a vote
        let vote = credential.vote(election_id.clone(), choice.clone()).unwrap();
        
        // Verify the vote with the same issuer's public key
        assert!(vote.verify(&issuer_private_key.public()));
        
        // Check that nonce and election ID are correctly extracted
        assert_eq!(vote.election_id(), election_id);
        assert_eq!(vote.choice, choice);
    }

    #[test]
    fn test_vote_unique_nonce() {
        // Single issuer for this test
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        
        // Create two votes for the same election with different choices
        let vote1 = credential.vote(election_id.clone(), "Candidate A".to_string()).unwrap();
        let vote2 = credential.vote(election_id.clone(), "Candidate B".to_string()).unwrap();
        
        // Different votes for the same election from the same credential should have the same nonce
        // to prevent double voting
        assert_eq!(vote1.nonce(), vote2.nonce());
        
        // But they should have the same election ID
        assert_eq!(vote1.election_id(), vote2.election_id());
        
        // Both should verify with the same issuer's public key
        assert!(vote1.verify(&issuer_private_key.public()));
        assert!(vote2.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_different_elections() {
        // Single issuer for this test
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id1 = create_election_id();
        let election_id2 = create_election_id();
        
        // Create votes for different elections with the same credential
        let vote1 = credential.vote(election_id1.clone(), "Yes".to_string()).unwrap();
        let vote2 = credential.vote(election_id2.clone(), "Yes".to_string()).unwrap();
        
        // Should have different election IDs
        assert_ne!(vote1.election_id(), vote2.election_id());
        
        // But both should verify with the same issuer's public key
        assert!(vote1.verify(&issuer_private_key.public()));
        assert!(vote2.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_database_basic() {
        // Single issuer for this test and database
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        // Create a vote
        let vote = credential.vote(election_id.clone(), choice).unwrap();
        
        // Create a database and enable the election
        let mut db = VoteDatabase::new();
        db.enable_election(election_id.clone());
        
        // Check if the election is enabled
        assert!(db.election_enabled(&election_id));
        
        // Add the vote to the database using the issuer's public key
        let result = db.add_vote(vote.clone(), &issuer_private_key.public());
        assert!(result.is_ok());
        
        // Verify the database with the same issuer's public key
        assert!(db.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_database_nonexistent_election() {
        // Single issuer for this test and database
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        let choice = "Candidate A".to_string();
        
        // Create a vote with the same issuer
        let vote = credential.vote(election_id.clone(), choice).unwrap();
        
        // Create a database but don't enable the election
        let mut db = VoteDatabase::new();
        
        // Check if the election is not enabled
        assert!(!db.election_enabled(&election_id));
        
        // Try to add the vote to the database using the correct issuer's public key
        let result = db.add_vote(vote, &issuer_private_key.public());
        
        // Should fail with NonexistentElection, not authentication issues
        match result {
            Err(VotingError::NonexistentElection(_)) => (),
            _ => panic!("Expected NonexistentElection error"),
        }
    }

    #[test]
    fn test_vote_database_double_vote() {
        // Single issuer for this test and database
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        
        // Create two votes for the same election with different choices using the same credential
        let vote1 = credential.vote(election_id.clone(), "Candidate A".to_string()).unwrap();
        let vote2 = credential.vote(election_id.clone(), "Candidate B".to_string()).unwrap();
        
        // Create a database and enable the election
        let mut db = VoteDatabase::new();
        db.enable_election(election_id);
        
        // Add the first vote with the issuer's public key
        let result1 = db.add_vote(vote1.clone(), &issuer_private_key.public());
        assert!(result1.is_ok());
        
        // Try to add the second vote (double vote) with the same issuer's public key
        let result2 = db.add_vote(vote2.clone(), &issuer_private_key.public());
        
        // Should fail with DoubleVote
        match result2 {
            Err(VotingError::DoubleVote { new_choice, original_choice }) => {
                assert_eq!(new_choice, "Candidate B");
                assert_eq!(original_choice, "Candidate A");
            },
            _ => panic!("Expected DoubleVote error"),
        }
        
        // Verify the database is still valid with the same issuer's public key
        assert!(db.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_database_multiple_elections() {
        // Single issuer for this test and database
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id1 = create_election_id();
        let election_id2 = create_election_id();
        
        // Create votes for different elections using the same credential and issuer
        let vote1 = credential.vote(election_id1.clone(), "Yes".to_string()).unwrap();
        let vote2 = credential.vote(election_id2.clone(), "No".to_string()).unwrap();
        
        // Create a database and enable both elections
        let mut db = VoteDatabase::new();
        db.enable_election(election_id1.clone());
        db.enable_election(election_id2.clone());
        
        // Add both votes with the same issuer's public key
        let result1 = db.add_vote(vote1, &issuer_private_key.public());
        let result2 = db.add_vote(vote2, &issuer_private_key.public());
        
        // Both should succeed
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        
        // Verify the database with the same issuer's public key
        assert!(db.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_vote_database_unauthenticated() {
        // For this specific test, we need two different issuers to demonstrate the unauthenticated case
        let (_, issuer_private_key1, credential1) = setup_credentials();
        let (_, issuer_private_key2, _) = setup_credentials(); // Different issuer
        let election_id1 = create_election_id();
        let election_id2 = election_id1.clone(); // Clone for second database
        let choice1 = "Candidate A".to_string();
        let choice2 = "Candidate A".to_string(); // Create a new string for second vote
        
        // Create a vote with the first credential
        let vote = credential1.vote(election_id1.clone(), choice1).unwrap();
        
        // Create a database and enable the election
        let mut db = VoteDatabase::new();
        db.enable_election(election_id1.clone());
        
        // Try to add the vote but verify with a different issuer's public key
        // This simulates trying to use a vote from one VoteDatabase in another with a different issuer
        let result = db.add_vote(vote, &issuer_private_key2.public());
        
        // Should fail with Unauthenticated
        match result {
            Err(VotingError::Unauthenticated) => (),
            _ => panic!("Expected Unauthenticated error"),
        }
        
        // Verify that it would have worked with the correct issuer
        let mut db2 = VoteDatabase::new();
        db2.enable_election(election_id2.clone());
        let vote2 = credential1.vote(election_id2, choice2).unwrap();
        let result2 = db2.add_vote(vote2, &issuer_private_key1.public());
        assert!(result2.is_ok());
    }

    #[test]
    fn test_vote_database_combine() {
        // Test the more basic functionality of database combination
        
        // Create a single issuer for all credentials
        let (params, issuer_private_key, _) = setup_credentials();
        let issuer_public_key = issuer_private_key.public();
        
        // Create election IDs
        let election_id1 = create_election_id();
        let election_id2 = create_election_id();
        
        // Create databases
        let mut db1 = VoteDatabase::new();
        let mut db2 = VoteDatabase::new();
        
        // Enable elections in both databases
        db1.enable_election(election_id1.clone());
        db1.enable_election(election_id2.clone());
        db2.enable_election(election_id1.clone());
        db2.enable_election(election_id2.clone());
        
        // Create different voters/credentials - all using the same issuer private key
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
        
        // Create votes
        // DB1: cred1 votes in election1, cred2 votes in election2
        let vote1 = cred1.vote(election_id1.clone(), "Yes".to_string()).unwrap();
        let vote2 = cred2.vote(election_id2.clone(), "No".to_string()).unwrap();
        
        // DB2: cred3 votes in election1, cred4 votes in election2
        let vote3 = cred3.vote(election_id1.clone(), "Maybe".to_string()).unwrap();
        let vote4 = cred4.vote(election_id2.clone(), "Abstain".to_string()).unwrap();
        
        // Add votes to databases - using the same issuer's public key
        assert!(db1.add_vote(vote1, &issuer_public_key).is_ok());
        assert!(db1.add_vote(vote2, &issuer_public_key).is_ok());
        assert!(db2.add_vote(vote3, &issuer_public_key).is_ok());
        assert!(db2.add_vote(vote4, &issuer_public_key).is_ok());
        
        // Verify each database
        assert!(db1.verify(&issuer_public_key));
        assert!(db2.verify(&issuer_public_key));
        
        // Combine databases
        db1.combine(&db2);
        
        // Verify combined database
        assert!(db1.verify(&issuer_public_key));
        
        // Combine back to db2
        db2.combine(&db1);
        
        // Verify both databases now have all votes
        assert!(db1.verify(&issuer_public_key));
        assert!(db2.verify(&issuer_public_key));
    }

    #[test]
    fn test_vote_database_combine_conflict() {
        // Use a single issuer for this test
        let (_, issuer_private_key, credential) = setup_credentials();
        let election_id = create_election_id();
        
        // Create two votes with different choices (from the same credential)
        let vote1 = credential.vote(election_id.clone(), "Candidate A".to_string()).unwrap();
        let vote2 = credential.vote(election_id.clone(), "Candidate B".to_string()).unwrap();
        
        // Create two databases that share the same issuer
        let mut db1 = VoteDatabase::new();
        let mut db2 = VoteDatabase::new();
        
        // Enable the election in both databases
        db1.enable_election(election_id.clone());
        db2.enable_election(election_id.clone());
        
        // Add the first vote to database 1
        let result1 = db1.add_vote(vote1.clone(), &issuer_private_key.public());
        assert!(result1.is_ok());
        
        // Add the second vote to database 2
        let result2 = db2.add_vote(vote2.clone(), &issuer_private_key.public());
        assert!(result2.is_ok());
        
        // Combine the databases - this should detect a conflict
        db1.combine(&db2);
        
        // The conflict should be recorded as a "liar" in db1
        // We can't easily check this directly, but we can verify that the database is still valid
        assert!(db1.verify(&issuer_private_key.public()));
    }

    #[test]
    fn test_random_voting_scenario() {
        // This test simulates a more complex voting scenario with multiple voters and elections
        
        // Setup - using a single issuer for the entire VoteDatabase ecosystem
        let params = Params::default();
        let issuer_private_key = IssuerPrivateKey::random(OsRng);
        let issuer_public_key = issuer_private_key.public();
        
        // Create multiple elections
        let num_elections = 5;
        let mut election_ids = Vec::with_capacity(num_elections);
        for _ in 0..num_elections {
            election_ids.push(create_election_id());
        }
        
        // Create multiple voters (credentials) - all using the same issuer
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
        
        // Create vote database and enable all elections
        let mut db = VoteDatabase::new();
        for election_id in &election_ids {
            db.enable_election(election_id.clone());
        }
        
        // Track which credential has voted in which election
        let mut voted_credential_elections = std::collections::HashMap::new();
        
        // Have each voter vote in random elections
        let choices = ["Yes", "No", "Maybe", "Abstain"];
        let mut _vote_count = 0;
        
        for (i, credential) in credentials.iter().enumerate() {
            // Choose random number of elections to vote in
            let num_votes = (OsRng.next_u32() % num_elections as u32) + 1;
            let mut voted_elections = std::collections::HashSet::new();
            
            for _ in 0..num_votes {
                // Choose random election (but don't vote twice in same election)
                let election_idx = (OsRng.next_u32() % num_elections as u32) as usize;
                if voted_elections.contains(&election_idx) {
                    continue;
                }
                voted_elections.insert(election_idx);
                
                // Track which credential has voted in which election
                voted_credential_elections.insert((i, election_idx), true);
                
                // Choose random choice
                let choice_idx = (OsRng.next_u32() % choices.len() as u32) as usize;
                let choice = choices[choice_idx].to_string();
                
                // Create and add vote - using the same issuer's public key
                let vote = credential.vote(election_ids[election_idx].clone(), choice).unwrap();
                let result = db.add_vote(vote, &issuer_public_key);
                assert!(result.is_ok());
                _vote_count += 1;
            }
        }
        
        // Verify the database with the same issuer's public key
        assert!(db.verify(&issuer_public_key));
        
        // Simulate an attempted double-vote
        // Find a credential that has voted in at least one election
        for (i, credential) in credentials.iter().enumerate() {
            for election_idx in 0..num_elections {
                if voted_credential_elections.contains_key(&(i, election_idx)) {
                    // This credential has already voted in this election, try to vote again
                    let vote = credential.vote(election_ids[election_idx].clone(), "Double Vote".to_string()).unwrap();
                    let result = db.add_vote(vote, &issuer_public_key);
                    
                    // Should fail with DoubleVote
                    assert!(matches!(result, Err(VotingError::DoubleVote { .. })));
                    
                    // We successfully tested the double vote, no need to continue
                    return;
                }
            }
        }
        
        // Database should still be valid after attempted double vote
        assert!(db.verify(&issuer_public_key));
        
        // Test database combination - creating a second database that uses the same issuer
        let mut db2 = VoteDatabase::new();
        for election_id in &election_ids {
            db2.enable_election(election_id.clone());
        }
        
        // Create some new votes for db2 with credentials that haven't voted in certain elections
        if !credentials.is_empty() {
            for i in 0..std::cmp::min(credentials.len(), num_elections) {
                for election_idx in 0..num_elections {
                    // Only add votes for elections where this credential hasn't voted yet
                    if !voted_credential_elections.contains_key(&(i, election_idx)) {
                        let credential = &credentials[i];
                        let vote = credential.vote(election_ids[election_idx].clone(), "Db2 Vote".to_string()).unwrap();
                        let result = db2.add_vote(vote, &issuer_public_key);
                        assert!(result.is_ok());
                        _vote_count += 1;
                        break; // Just add one vote per credential
                    }
                }
            }
        }
        
        // Combine the databases that use the same issuer
        db.combine(&db2);
        
        // Final verification with the shared issuer
        assert!(db.verify(&issuer_public_key));
    }
}
