# Anonymous Voting Library

[Interactive Demo](https://samuelschlesinger.github.io/voting/)

This library implements a cryptographically secure anonymous voting system. It
enables voters to participate in elections while maintaining their anonymity,
preventing double voting, and allowing for public auditability of results
without compromising privacy.

## WARNING

This library is unaudited and contains experimental cryptography. Please do not
rely on this in any production environment.

## Key Features

- **Strong Anonymity**: Votes cannot be linked back to the voter's identity,
  even if election authorities and credential issuers collude.
- **Sybil Resistance**: The system prevents a single entity from casting
  multiple votes through cryptographic authentication.
- **Double-Voting Prevention**: Any attempt to vote multiple times is
  automatically detected and recorded.
- **Distributed Vote Collection**: Multiple vote collectors can operate
  independently and later combine their results.
- **End-to-End Verification**: The integrity of the voting process can be
  verified without compromising voter anonymity.

## Technical Overview

### Cryptographic Foundation

The system uses BLS12-381 elliptic curve cryptography and a suite of
zero-knowledge proofs to provide its security guarantees:

1. **Anonymous Credentials**: Voters receive cryptographic credentials from an
   issuing authority without revealing their private keys.
2. **Unlinkable Pseudonyms**: For each election, voters derive unique
   pseudonyms from their credentials in a way that prevents different
   pseudonyms from being linked to the same voter.
3. **Zero-Knowledge Proofs**: Voters prove their eligibility without revealing
   their identity through non-interactive zero-knowledge proofs.

### System Architecture

The library consists of two main components:

- **Pseudonym Module**: Implements the cryptographic protocols for credential
  issuance and pseudonym generation.
- **Voting Module**: Manages the voting process, vote verification, and
  database operations.

### Security Properties

- **Anonymity**: The use of unlinkable pseudonyms ensures voters remain
  anonymous.
- **Non-transferability**: Credentials are bound to the voter's private key and
  cannot be transferred to another person.
- **Integrity**: All votes can be verified for authenticity without
  compromising anonymity.

## How It Works

1. **Credential Issuance**:
   - A trusted authority generates a key pair and publishes its public key
   - Voters generate their own private keys and request credentials from the
     authority
   - The authority issues credentials without learning the voter's private key

2. **Voting**:
   - For each election, a voter derives a pseudonym from their credential
   - The pseudonym is specific to that election and cannot be linked to
     pseudonyms from other elections
   - The voter casts their ballot along with this pseudonym as proof of
     eligibility

3. **Verification**:
   - Vote collectors verify each vote's authenticity using the issuer's public
     key
   - The system detects any attempts to vote multiple times
   - Results can be independently verified by any third party with access to
     the vote database

## Academic Context

This library implements concepts from the following areas of cryptography and
security:

- **Anonymous Credentials**: Based on the work of Camenisch and Lysyanskaya
- **Zero-Knowledge Proofs**: Uses non-interactive proofs via the Fiat-Shamir
  heuristic
- **Verifiable Random Functions**: For generating pseudonyms that are
  deterministic yet unlinkable

## Limitations and Considerations

- **Trusted Setup**: The system relies on a trusted credential issuer during
  the initial setup phase
- **Credential Security**: Voters must keep their private keys secure
- **No Coercion Resistance**: The current implementation does not address vote
  buying or coercion

## Future Work

Potential areas for extension include:
- Receipt-free voting to prevent vote selling
- Threshold cryptography for distributing trust among multiple authorities
- Integration with decentralized identity systems

## Usage Examples

### Setting Up an Election Authority

```rust
use anonymous_voting::{pseudonym::{IssuerPrivateKey, Params}, ElectionID, VoteDatabase};
use rand_core::OsRng;

// Create a new credential issuer (election authority)
let params = Params::default();
let issuer_private_key = IssuerPrivateKey::random(OsRng);
let issuer_public_key = issuer_private_key.public();

// Create a unique election ID
let election_id = ElectionID::random(OsRng);

// Initialize the vote database and enable the election
let mut vote_db = VoteDatabase::new();
vote_db.enable_election(election_id);
```

### Voter Registration and Voting

```rust
use anonymous_voting::pseudonym::{ClientPrivateKey, Params};
use rand_core::OsRng;

// A voter creates their private key and requests a credential
let client_private_key = ClientPrivateKey::random(OsRng);
let credreq = client_private_key.request(&params, OsRng);

// The issuer processes the request and returns a response
let credresp = credreq
    .respond(&issuer_private_key, &params, OsRng)
    .unwrap();

// The voter creates their credential using the response
let credential = client_private_key
    .create_credential(&credreq, &credresp, &issuer_public_key)
    .unwrap();

// The voter casts their vote
let vote = credential
    .vote(election_id.clone(), "Candidate A".to_string())
    .unwrap();

// The vote is submitted to the database
match vote_db.add_vote(vote, &issuer_public_key) {
    Ok(()) => println!("Vote successfully recorded!"),
    Err(e) => println!("Error recording vote: {:?}", e),
}
```

### Verification and Counting

```rust
// Verify the integrity of the entire vote database
if vote_db.verify(&issuer_public_key) {
    println!("All votes verified as authentic!");
} else {
    println!("Vote database verification failed!");
}

// Count votes for a specific election (simplified example)
let mut vote_counts = std::collections::HashMap::new();
if let Some(votes_for_election) = vote_db.votes.get(&election_id) {
    for (_, vote) in votes_for_election {
        *vote_counts.entry(vote.choice.clone()).or_insert(0) += 1;
    }
}

// Display results
for (choice, count) in &vote_counts {
    println!("{}: {} votes", choice, count);
}
```

### Distributed Vote Collection

```rust
// Create a second vote database (e.g., on another server)
let mut vote_db2 = VoteDatabase::new();
vote_db2.enable_election(election_id.clone());

// Collect votes in both databases independently
// ...

// Later, combine the databases
vote_db.combine(&vote_db2);

// Verify the combined database
assert!(vote_db.verify(&issuer_public_key));
```

## References

- [A Graduate Course in Applied Cryptography by Boneh & Shoup (version 0.6)](https://toc.cryptobook.us/)
- [A Verifiable Random Function with Short Proofs and Keys by Dodis & Yampolskiy](https://eprint.iacr.org/2004/310.pdf)
