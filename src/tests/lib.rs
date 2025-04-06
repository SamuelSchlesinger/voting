use crate::*;
use rand_core::OsRng;
use crate::pseudonym::{IssuerPrivateKey, ClientPrivateKey, Params};

// Helper function to create a valid election ID
fn create_election_id() -> ElectionID {
    ElectionID::random(OsRng)
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
    let invalid_bytes = [0xFF; 32]; // All ones, definitely greater than modulus
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
