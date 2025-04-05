use std::collections::HashMap;

pub mod pseudonym;

use pseudonym::{IssuerPublicKey, Params, Pseudonym};

#[derive(Clone)]
pub struct Vote {
    choice: String,
    pseudonym: Pseudonym,
}

#[derive(PartialEq, Eq, Hash)]
pub struct Nonce {
    bytes: [u8; 48],
}

#[derive(PartialEq, Eq, Hash)]
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
}
