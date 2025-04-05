use std::collections::HashMap;

pub mod pseudonym;

use pseudonym::{IssuerPublicKey, Params, Pseudonym};

#[derive(Clone)]
pub struct Vote {
    choice: String,
    pseudonym: Pseudonym,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Nonce {
    bytes: [u8; 48],
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ElectionID {
    bytes: [u8; 32],
}

impl Vote {
    pub fn nonce(&self) -> Nonce {
        Nonce {
            bytes: self.pseudonym.pseudonym_id().to_compressed(),
        }
    }

    pub fn election_id(&self) -> ElectionID {
        ElectionID {
            bytes: self.pseudonym.relying_party_id().to_bytes(),
        }
    }
}

impl Vote {
    pub fn verify(&self, issuer_public_key: &IssuerPublicKey) -> bool {
        self.pseudonym
            .verify(&Params::default(), issuer_public_key, self.choice.as_ref())
            .into()
    }
}

pub struct VoteDatabase {
    votes: HashMap<ElectionID, HashMap<Nonce, Vote>>,
    liars: HashMap<ElectionID, HashMap<Nonce, HashMap<String, Vote>>>,
}

pub enum VotingError {
    Unauthenticated,
    DoubleVote {
        new_choice: String,
        original_choice: String,
    },
    NonexistentElection(ElectionID),
}

impl VoteDatabase {
    pub fn vote(
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

    pub fn enable_election(&mut self, election_id: ElectionID) {
        self.votes.entry(election_id).or_insert(HashMap::new());
    }

    pub fn election_enabled(&self, election_id: &ElectionID) -> bool {
        self.votes.get(election_id).is_some()
    }
}
