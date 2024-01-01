// Copyright (c) 2018-2024 The MobileCoin Foundation

// Test that mc_grapevine_types structs match the protos defined in .proto files,
// by testing that they round-trip through the proto-generated rust types

use mc_grapevine_api::grapevine;
use mc_serial::{encode, round_trip_message};
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{get_seeded_rng, run_with_several_seeds};

/// Test that many random instances of prosty QueryRequest round trip with
/// protobufy QueryRequest
#[test]
fn grapevine_query_request_round_trip() {
    run_with_several_seeds(|mut rng| {
        let test_val: mc_grapevine_types::QueryRequest = FromRandom::from_random(&mut rng);
        round_trip_message::<mc_grapevine_types::QueryRequest, grapevine::QueryRequest>(&test_val);
    });
}

/// Test that many random instances of prosty QueryRequest have the same size on the wire
#[test]
fn grapevine_query_request_constant_size() {
    let mut rng = get_seeded_rng();
    let test_val = mc_grapevine_types::QueryRequest::from_random(&mut rng);
    let expected_size = encode(&test_val).len();
    run_with_several_seeds(|mut rng| {
        let test_val = mc_grapevine_types::QueryRequest::from_random(&mut rng);
        assert_eq!(encode(&test_val).len(), expected_size);
    });
}

/// Test that many random instances of prosty QueryResponse round trip with
/// protobufy QueryRequest
#[test]
fn grapevine_query_response_round_trip() {
    run_with_several_seeds(|mut rng| {
        let test_val = mc_grapevine_types::QueryResponse::from_random(&mut rng);
        round_trip_message::<mc_grapevine_types::QueryResponse, grapevine::QueryResponse>(
            &test_val,
        );
    });
}

/// Test that many random instances of prosty QueryRequest have the same size on the wire
#[test]
fn grapevine_query_response_constant_size() {
    let mut rng = get_seeded_rng();
    let test_val = mc_grapevine_types::QueryResponse::from_random(&mut rng);
    let expected_size = encode(&test_val).len();
    run_with_several_seeds(|mut rng| {
        let test_val = mc_grapevine_types::QueryResponse::from_random(&mut rng);
        assert_eq!(encode(&test_val).len(), expected_size);
    });
}

/// Test that .proto StatusCode enum values match what is in mc-grapevine-types
#[test]
fn test_status_code_enum_values() {
    assert_eq!(
        mc_grapevine_types::STATUS_CODE_SUCCESS,
        grapevine::StatusCode::SUCCESS as u32
    );
    assert_eq!(
        mc_grapevine_types::STATUS_CODE_NOT_FOUND,
        grapevine::StatusCode::NOT_FOUND as u32
    );
    assert_eq!(
        mc_grapevine_types::STATUS_CODE_MESSAGE_ID_ALREADY_IN_USE,
        grapevine::StatusCode::MESSAGE_ID_ALREADY_IN_USE as u32
    );
    assert_eq!(
        mc_grapevine_types::STATUS_CODE_INVALID_RECIPIENT,
        grapevine::StatusCode::INVALID_RECIPIENT as u32
    );
    assert_eq!(
        mc_grapevine_types::STATUS_CODE_TOO_MANY_MESSAGES_FOR_RECIPIENT,
        grapevine::StatusCode::TOO_MANY_MESSAGES_FOR_RECIPIENT as u32
    );
    assert_eq!(
        mc_grapevine_types::STATUS_CODE_TOO_MANY_RECIPIENTS,
        grapevine::StatusCode::TOO_MANY_RECIPIENTS as u32
    );
    assert_eq!(
        mc_grapevine_types::STATUS_CODE_TOO_MANY_MESSAGES,
        grapevine::StatusCode::TOO_MANY_MESSAGES as u32
    );
    assert_eq!(
        mc_grapevine_types::STATUS_CODE_INTERNAL_ERROR,
        grapevine::StatusCode::INTERNAL_ERROR as u32
    );
}

/// Test that .proto RequestType enum values match what is in mc-grapevine-types
#[test]
fn test_request_type_enum_values() {
    assert_eq!(
        mc_grapevine_types::REQUEST_TYPE_CREATE,
        grapevine::RequestType::CREATE as u32
    );
    assert_eq!(
        mc_grapevine_types::REQUEST_TYPE_READ,
        grapevine::RequestType::READ as u32
    );
    assert_eq!(
        mc_grapevine_types::REQUEST_TYPE_UPDATE,
        grapevine::RequestType::UPDATE as u32
    );
    assert_eq!(
        mc_grapevine_types::REQUEST_TYPE_DELETE,
        grapevine::RequestType::DELETE as u32
    );
}
