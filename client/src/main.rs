// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Example BOMB client

use chrono::{DateTime, NaiveDateTime, Utc};
use mc_attest_verifier::{Verifier, DEBUG_ENCLAVE};
use mc_bomb_connection::{BombGrpcConnection, Error, PAYLOAD_SIZE};
use mc_bomb_types::{QueryResponse, STATUS_CODE_NOT_FOUND, STATUS_CODE_SUCCESS};
use mc_common::logger::{create_root_logger, log, Logger};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_crypto_rand::McRng;
use mc_util_cli::ParserWithBuildInfo;
use mc_util_from_random::FromRandom;
use mc_util_grpc::GrpcRetryConfig;
use std::{process::exit, sync::Arc};

mod config;
use config::{BombClientCommand, BombClientConfig};

fn main() {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");

    let logger = create_root_logger();

    let config = BombClientConfig::parse();

    if let Err(err) = do_work(config, logger) {
        eprintln!("Error: {}", err);
        exit(1);
    }
    eprintln!("Success");
}

// This function exists because returning errors directly from main debug prints
// them instead of display printing them.
fn do_work(config: BombClientConfig, logger: Logger) -> Result<(), Error> {
    let get_conn = || -> BombGrpcConnection<RistrettoPrivate> {
        let uri = config
            .uri
            .clone()
            .expect("uri is required for this operation");
        let secret_key = RistrettoPrivate::try_from(
            config
                .secret_key
                .as_ref()
                .expect("secret key required for this operation"),
        )
        .expect("invalid secret key");

        let grpcio_env = Arc::new(grpcio::EnvBuilder::new().build());

        let retry_config = GrpcRetryConfig::default();

        let mut verifier = Verifier::default();
        let mr_signer_verifier = mc_bomb_enclave_measurement::get_mr_signer_verifier(None);
        verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);

        log::debug!(logger, "Attestation verifier: {:?}", &verifier);
        BombGrpcConnection::new(
            uri,
            retry_config,
            secret_key,
            verifier,
            grpcio_env,
            logger.clone(),
        )
    };

    let mut rng = McRng::default();

    match config.cmd {
        BombClientCommand::GenerateKey => {
            let secret_key = RistrettoPrivate::from_random(&mut rng);

            println!("secret key hex: \"{}\"", hex::encode(secret_key.to_bytes()));

            let public_key = CompressedRistrettoPublic::from(RistrettoPublic::from(&secret_key));

            println!("public key hex: \"{}\"", hex::encode(public_key.as_bytes()));
        }
        BombClientCommand::ShowPublicKey => {
            let secret_key = RistrettoPrivate::try_from(
                config
                    .secret_key
                    .as_ref()
                    .expect("secret key required for this operation"),
            )
            .expect("invalid secret key");

            let public_key = CompressedRistrettoPublic::from(RistrettoPublic::from(&secret_key));

            println!("public key hex: \"{}\"", hex::encode(public_key.as_bytes()));
        }
        BombClientCommand::Create {
            msg_id,
            recipient,
            message,
        } => {
            let msg_id = msg_id.unwrap_or(FromRandom::from_random(&mut rng));
            let recipient = CompressedRistrettoPublic::from(&recipient);
            let message = string_to_payload(&message);

            let mut conn = get_conn();
            let resp = conn.create(&msg_id, &recipient, &message)?;
            println!("{}", pretty_print_response(&resp));
        }
        BombClientCommand::Read { msg_id } => {
            let msg_id = msg_id.unwrap_or([0u8; 16]);

            let mut conn = get_conn();
            let resp = conn.read(&msg_id)?;
            println!("{}", pretty_print_response(&resp));
        }

        BombClientCommand::Update {
            msg_id,
            recipient,
            message,
        } => {
            let recipient = CompressedRistrettoPublic::from(&recipient);
            let message = string_to_payload(&message);

            let mut conn = get_conn();
            let resp = conn.update(&msg_id, &recipient, &message)?;
            println!("{}", pretty_print_response(&resp));
        }

        BombClientCommand::Delete { msg_id, recipient } => {
            let msg_id = msg_id.unwrap_or([0u8; 16]);
            let recipient = recipient
                .as_ref()
                .map(CompressedRistrettoPublic::from)
                .unwrap_or_else(|| {
                    let secret_key = RistrettoPrivate::try_from(
                        config
                            .secret_key
                            .as_ref()
                            .expect("secret key required for this operation"),
                    )
                    .expect("invalid secret key");
                    CompressedRistrettoPublic::from(&RistrettoPublic::from(&secret_key))
                });

            let mut conn = get_conn();
            let resp = conn.delete(&msg_id, &recipient)?;
            println!("{}", pretty_print_response(&resp));
        }
    }
    Ok(())
}

// Encode a string to the fixed payload size, using framing and zero padding,
// which the payload schema this example app uses.
fn string_to_payload(string_data: &str) -> Vec<u8> {
    assert!(string_data.len() <= PAYLOAD_SIZE - 2, "string too long");
    let mut result = vec![0u8; PAYLOAD_SIZE];
    (&mut result[0..2]).copy_from_slice(&(string_data.len() as u16).to_le_bytes()[..]);
    (&mut result[2..(2 + string_data.len())]).copy_from_slice(string_data.as_bytes());
    result
}

// Decode a string from the framed payload format.
fn payload_to_string(payload_data: &[u8]) -> String {
    assert_eq!(payload_data.len(), PAYLOAD_SIZE);
    let length = u16::from_le_bytes(payload_data[0..2].try_into().unwrap()) as usize;

    assert!(
        length <= PAYLOAD_SIZE - 2,
        "recorded encoding length is out of bounds"
    );
    std::str::from_utf8(&payload_data[2..2 + length])
        .expect("utf-8 decoding error")
        .to_owned()
}

fn pretty_print_response(resp: &QueryResponse) -> String {
    use serde_json::{json, to_string_pretty};

    let status_code_string = match resp.status_code {
        STATUS_CODE_SUCCESS => "SUCCESS".to_string(),
        STATUS_CODE_NOT_FOUND => "NOT_FOUND".to_string(),
        other => other.to_string(),
    };

    let time_string = NaiveDateTime::from_timestamp_opt(resp.record.timestamp as i64, 0)
        .map(|naive| DateTime::<Utc>::from_utc(naive, Utc).to_string())
        .unwrap_or_else(|| "???".to_string());

    let record = json!({
        "msg_id": hex::encode(&resp.record.msg_id),
        "sender": hex::encode(&resp.record.sender),
        "recipient": hex::encode(&resp.record.recipient),
        "timestamp": time_string,
        "message": payload_to_string(&resp.record.payload),
    });

    to_string_pretty(&json!({
        "record": record,
        "status_code": status_code_string,
    }))
    .expect("pretty printing failed")
}
