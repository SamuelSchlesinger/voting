use crate::pseudonym::*;
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
