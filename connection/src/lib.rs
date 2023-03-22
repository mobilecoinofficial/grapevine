// Copyright (c) 2018-2023 The MobileCoin Foundation

//! A client object that creates an attested connection with a mc-bomb enclave
//! mediated over grpc. Can be used to make high-level requests.

#![deny(missing_docs)]

use mc_attest_core::VerificationReport;
use mc_attest_verifier::Verifier;
use mc_bomb_api::{
    attest,
    bomb_grpc::{self, BombApiClient},
};
use mc_bomb_types::{
    QueryRequest, QueryResponse, Record, MC_BOMB_CHALLENGE_SIGNING_CONTEXT, REQUEST_TYPE_CREATE,
    REQUEST_TYPE_DELETE, REQUEST_TYPE_READ, REQUEST_TYPE_UPDATE,
};
use mc_bomb_uri::{BombUri, ConnectionUri};
use mc_common::{
    logger::{log, o, Logger},
    trace_time,
};
use mc_connection::{AttestationError, AttestedConnection, Connection};
use mc_crypto_keys::{CompressedRistrettoPublic, Signature, X25519};
use mc_crypto_rand::McRng;
use mc_util_grpc::{
    BasicCredentials, ConnectionUriGrpcioChannel, GrpcCookieStore, GrpcRetryConfig,
};
use mc_util_telemetry::{tracer, Tracer};
//use mc_util_repr_bytes::{ReprBytes};
use aes_gcm::Aes256Gcm;
use cookie::CookieJar;
use grpcio::{CallOption, ChannelBuilder, Environment, MetadataBuilder};
use mc_attest_ake::{AuthResponseInput, ClientInitiate, Ready, Start, Transition};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use retry::{Error as RetryError, OperationResult};
use sha2::Sha512;
use std::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    sync::Arc,
};

mod error;
mod signer;

pub use error::Error;
use error::{EnclaveConnectionError, RequestError};
pub use signer::RistrettoSigner;

/// A high-level object mediating requests to the bomb service using grpcio
pub struct BombGrpcConnection<S: RistrettoSigner + Send + Sync> {
    /// The grpc connection
    grpc: BombApiClient,
    /// The AKE state machine object, if one is available.
    attest_cipher: Option<Ready<Aes256Gcm>>,
    /// The shared challenge generator object, if available.
    challenge_generator: Option<ChaCha20Rng>,
    /// The most recently generated challenge bytes.
    challenge_bytes: [u8; 32],
    /// The signer entity for signing auth challenges
    signer: S,
    /// An object which can verify a the enclave provided IAS report
    verifier: Verifier,
    /// Credentials to use for all GRPC calls (this allows authentication
    /// username/password to go through, if provided).
    creds: BasicCredentials,
    /// A hash map of metadata to set on outbound requests, filled by inbound
    /// `Set-Cookie` metadata
    cookies: CookieJar,
    /// The grpc retry config
    grpc_retry_config: GrpcRetryConfig,
    /// The uri we connected to
    uri: BombUri,
    /// A logger object
    logger: Logger,
}

/// The payload size that bomb enclave was configured for.
// TODO: Can this be discoverable at runtime maybe? It may be too disruptive to
// the caller if their payload size is changing though.
pub const PAYLOAD_SIZE: usize = 936;

impl<S: RistrettoSigner + Send + Sync> BombGrpcConnection<S> {
    /// Create a new bomb grpc connection
    ///
    /// Arguments:
    /// * uri: The Uri to connect to
    /// * grpc_retry_config: Retry policy to use for connection issues
    /// * signer: A ristretto signer to use for signing auth challenges
    /// * verifier: The attestation verifier
    /// * env: A grpc environment (thread pool) to use for this connection
    /// * logger
    pub fn new(
        uri: BombUri,
        grpc_retry_config: GrpcRetryConfig,
        signer: S,
        verifier: Verifier,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let logger = logger.new(o!("mc.bomb.cxn" => uri.to_string()));

        let creds = BasicCredentials::new(&uri.username(), &uri.password());
        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);

        let grpc = bomb_grpc::BombApiClient::new(ch);

        Self {
            grpc,
            attest_cipher: None,
            challenge_generator: None,
            challenge_bytes: Default::default(),
            signer,
            verifier,
            creds,
            cookies: CookieJar::default(),
            grpc_retry_config,
            uri,
            logger,
        }
    }

    /// Create a new message in the broker
    ///
    /// The msg_id must be nonzero.
    pub fn create(
        &mut self,
        msg_id: &[u8; 16],
        recipient: &CompressedRistrettoPublic,
        payload: &[u8],
    ) -> Result<QueryResponse, Error> {
        tracer!().in_span("bomb_grpc_request_create", |_cx_| {
            trace_time!(self.logger, "BombGrpcClient::create");

            let signer_id = self.signer.get_public_key().map_err(|err| Error {
                uri: self.uri.clone(),
                error: RequestError::Signer(err.to_string()),
            })?;

            let rec = Record {
                msg_id: (&msg_id[..]).to_vec(),
                sender: signer_id.as_bytes().to_vec(),
                recipient: recipient.as_bytes().to_vec(),
                timestamp: u64::MAX,
                payload: payload.to_vec(),
            };

            self.request(REQUEST_TYPE_CREATE, rec)
        })
    }

    /// Read a message that exists in the broker.
    ///
    /// To read a specific message, pass the message id.
    /// To read your next message, pass all zeroes.
    pub fn read(&mut self, msg_id: &[u8; 16]) -> Result<QueryResponse, Error> {
        let signer_id = self.signer.get_public_key().map_err(|err| Error {
            uri: self.uri.clone(),
            error: RequestError::Signer(err.to_string()),
        })?;

        tracer!().in_span("bomb_grpc_request_read", |_cx_| {
            trace_time!(self.logger, "BombGrpcClient::read");

            // Setting recipient = signer_id here is needed in the case that you are
            // searching for your next message. It doesn't hurt in other cases.
            let rec = Record {
                msg_id: (&msg_id[..]).to_vec(),
                sender: vec![0u8; 32],
                recipient: signer_id.as_bytes().to_vec(),
                timestamp: u64::MAX,
                payload: vec![0u8; PAYLOAD_SIZE],
            };

            self.request(REQUEST_TYPE_READ, rec)
        })
    }

    /// Update a message that exists in the broker
    ///
    /// Note that the sender and recipient cannot be updated, and the timestamp
    /// will be updated by the server.
    pub fn update(
        &mut self,
        msg_id: &[u8; 16],
        recipient: &CompressedRistrettoPublic,
        new_payload: &[u8],
    ) -> Result<QueryResponse, Error> {
        tracer!().in_span("bomb_grpc_request_update", |_cx_| {
            trace_time!(self.logger, "BombGrpcClient::update");

            let rec = Record {
                msg_id: (&msg_id[..]).to_vec(),
                sender: vec![0u8; 32],
                recipient: recipient.as_bytes().to_vec(),
                timestamp: u64::MAX,
                payload: new_payload.to_vec(),
            };

            self.request(REQUEST_TYPE_UPDATE, rec)
        })
    }

    /// Delete a message that exists in the broker
    ///
    /// You must know the recipient as well as the message id.
    pub fn delete(
        &mut self,
        msg_id: &[u8; 16],
        recipient: &CompressedRistrettoPublic,
    ) -> Result<QueryResponse, Error> {
        tracer!().in_span("bomb_grpc_request_update", |_cx_| {
            trace_time!(self.logger, "BombGrpcClient::update");

            let rec = Record {
                msg_id: (&msg_id[..]).to_vec(),
                sender: vec![0u8; 32],
                recipient: recipient.as_bytes().to_vec(),
                timestamp: u64::MAX,
                payload: vec![0u8; PAYLOAD_SIZE],
            };

            self.request(REQUEST_TYPE_DELETE, rec)
        })
    }

    fn request(&mut self, request_type: u32, rec: Record) -> Result<QueryResponse, Error> {
        let signer_id = self.signer.get_public_key().map_err(|err| Error {
            uri: self.uri.clone(),
            error: RequestError::Signer(err.to_string()),
        })?;

        let sig = self
            .signer
            .sign(MC_BOMB_CHALLENGE_SIGNING_CONTEXT, &self.challenge_bytes)
            .map_err(|err| Error {
                uri: self.uri.clone(),
                error: RequestError::Signer(err.to_string()),
            })?;

        let req = QueryRequest {
            auth_identity: signer_id.as_bytes().to_vec(),
            auth_signature: sig.as_bytes().to_vec(),
            request_type,
            record: rec,
        };

        tracer!().in_span("bomb_grpc_request", |_cx_| {
            trace_time!(self.logger, "BombGrpcClient::request");
            let retry_config = self.grpc_retry_config;
            retry_config
                .retry(|| self.retriable_encrypted_enclave_request(&req))
                .map_err(|error| Error {
                    uri: self.uri.clone(),
                    error: RequestError::Connection(error),
                })
        })
    }

    /// Same as encrypted_enclave_request, but convert result to an
    /// OperationResult for use with the retry crate
    fn retriable_encrypted_enclave_request<
        RequestMessage: mc_util_serial::Message,
        ResponseMessage: mc_util_serial::Message + Default,
    >(
        &mut self,
        plaintext_request: &RequestMessage,
    ) -> OperationResult<ResponseMessage, EnclaveConnectionError> {
        match self.encrypted_enclave_request(plaintext_request, &[]) {
            Ok(value) => OperationResult::Ok(value),
            Err(err) => {
                if err.should_retry() {
                    log::debug!(self.logger, "retriable enclave connection error: {}", err);
                    OperationResult::Retry(err)
                } else {
                    OperationResult::Err(err)
                }
            }
        }
    }

    /// Produce a "call option" object appropriate for this grpc connection.
    /// This includes the http headers needed for credentials and cookies.
    fn call_option(&mut self) -> CallOption {
        let retval = CallOption::default();

        // Create metadata from cookies and credentials
        let mut metadata_builder = self
            .cookies
            .to_client_metadata()
            .unwrap_or_else(|_| MetadataBuilder::new());
        if !self.creds.username().is_empty() && !self.creds.password().is_empty() {
            metadata_builder
                .add_str("Authorization", &self.creds.authorization_header())
                .expect("Error setting authorization header");
        }

        retval.headers(metadata_builder.build())
    }

    /// Make an attested request to the enclave, given the plaintext to go to
    /// enclave, and any aad data, which will be nonmalleable, but visible
    /// to untrusted. Returns the decrypted and deserialized response
    /// object.
    fn encrypted_enclave_request<
        RequestMessage: mc_util_serial::Message,
        ResponseMessage: mc_util_serial::Message + Default,
    >(
        &mut self,
        plaintext_request: &RequestMessage,
        aad: &[u8],
    ) -> Result<ResponseMessage, EnclaveConnectionError> {
        if !self.is_attested() {
            let _verification_report = self.attest()?;
        }

        // Build encrypted request, scope attest_cipher borrow
        let msg = {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let mut msg = attest::Message::new();
            msg.set_channel_id(Vec::from(attest_cipher.binding()));

            let plaintext_bytes = mc_util_serial::encode(plaintext_request);

            let request_ciphertext = attest_cipher.encrypt(aad, &plaintext_bytes)?;
            msg.set_data(request_ciphertext);
            msg
        };

        // make an attested call to EnclaveGrpcChannel::enclave_request,
        // and handle cookies
        let message = self.attested_call(|this| {
            let call_opt = this.call_option();
            let (header, message, trailer) = this
                .grpc
                .query_async_opt(&msg, call_opt)
                .map_err(|err| {
                    this.deattest();
                    err
                })?
                .receive_sync()?;

            // The server processed our query in some sense, so advance the challenge buffer
            this.next_challenge();

            // Update cookies from server-sent metadata
            if let Err(e) = this
                .cookies
                .update_from_server_metadata(Some(&header), Some(&trailer))
            {
                log::warn!(
                    this.logger,
                    "Could not update cookies from gRPC metadata: {}",
                    e
                )
            }

            Ok(message)
        })?;

        // Decrypt request, scope attest_cipher borrow
        {
            let attest_cipher = self
                .attest_cipher
                .as_mut()
                .expect("no enclave_connection even though attest succeeded");

            let plaintext_bytes = attest_cipher.decrypt(message.get_aad(), message.get_data())?;
            let plaintext_response: ResponseMessage = mc_util_serial::decode(&plaintext_bytes)?;
            Ok(plaintext_response)
        }
    }

    // Advance the challenge buffer
    fn next_challenge(&mut self) {
        if let Some(generator) = self.challenge_generator.as_mut() {
            generator.fill_bytes(&mut self.challenge_bytes[..]);
        } else {
            panic!("no generator available, this is a logic error");
        }
    }
}

impl<S: RistrettoSigner + Send + Sync> Connection for BombGrpcConnection<S> {
    type Uri = BombUri;

    fn uri(&self) -> Self::Uri {
        self.uri.clone()
    }
}

// This is adapted from Fog EnclaveConnection object, with extra details about
// the challenge generator The main place the challenge generator enters the
// flow is in the attest and deattest calls.
impl<S: RistrettoSigner + Send + Sync> AttestedConnection for BombGrpcConnection<S> {
    type Error = EnclaveConnectionError;

    fn is_attested(&self) -> bool {
        self.attest_cipher.is_some()
    }

    fn attest(&mut self) -> Result<VerificationReport, Self::Error> {
        trace_time!(self.logger, "FogClient::attest");
        // If we have an existing attestation, nuke it.
        self.deattest();

        let mut csprng = McRng::default();

        let initiator = Start::new(self.uri.responder_id()?.to_string());

        let init_input = ClientInitiate::<X25519, Aes256Gcm, Sha512>::default();
        let (initiator, auth_request_output) = initiator.try_next(&mut csprng, init_input)?;

        // Make the auth request with the server
        let call_opt = self.call_option();
        let (header, auth_response_msg, trailer) = self
            .grpc
            .auth_async_opt(&auth_request_output.into(), call_opt)?
            .receive_sync()?;

        // Update cookies from server-sent metadata
        if let Err(e) = self
            .cookies
            .update_from_server_metadata(Some(&header), Some(&trailer))
        {
            log::warn!(
                self.logger,
                "Could not update cookies from gRPC metadata: {}",
                e
            )
        }

        // Process server response, check if key exchange is successful
        let auth_response_event = AuthResponseInput::new(
            auth_response_msg.get_auth_message().clone().into(),
            self.verifier.clone(),
        );
        let (initiator, verification_report) =
            initiator.try_next(&mut csprng, auth_response_event)?;

        self.attest_cipher = Some(initiator);

        // Decrypt the challenge generator seed, and seed our challenge generator
        let attest_cipher = self
            .attest_cipher
            .as_mut()
            .expect("no attest_cipher even though attest succeeded");

        let challenge_seed =
            attest_cipher.decrypt(&[], auth_response_msg.get_encrypted_challenge_seed())?;
        let challenge_seed: [u8; 32] = (&challenge_seed[..])
            .try_into()
            .map_err(|_| EnclaveConnectionError::InvalidChallengeSeed(challenge_seed.len()))?;

        self.challenge_generator = Some(ChaCha20Rng::from_seed(challenge_seed));
        // Initialize the buffer with the first challenge value.
        // When the a request is made, we advance the buffer after the request succeeds
        // without an RPC failure.
        self.next_challenge();

        Ok(verification_report)
    }

    fn deattest(&mut self) {
        if self.is_attested() {
            log::trace!(
                self.logger,
                "Tearing down existing attested connection and clearing cookies, challenge rng."
            );
            self.attest_cipher = None;
            self.cookies = CookieJar::default();
            self.challenge_generator = None;
        }
    }
}

// boilerplate

impl<S: RistrettoSigner + Send + Sync> Display for BombGrpcConnection<S> {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.uri)
    }
}

impl<S: RistrettoSigner + Send + Sync> Eq for BombGrpcConnection<S> {}

impl<S: RistrettoSigner + Send + Sync> Hash for BombGrpcConnection<S> {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.uri.addr().hash(hasher);
    }
}

impl<S: RistrettoSigner + Send + Sync> PartialEq for BombGrpcConnection<S> {
    fn eq(&self, other: &Self) -> bool {
        self.uri.addr() == other.uri.addr()
    }
}

impl<S: RistrettoSigner + Send + Sync> Ord for BombGrpcConnection<S> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.uri.addr().cmp(&other.uri.addr())
    }
}

impl<S: RistrettoSigner + Send + Sync> PartialOrd for BombGrpcConnection<S> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.uri.addr().partial_cmp(&other.uri.addr())
    }
}
