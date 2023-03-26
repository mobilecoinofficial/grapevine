// Copyright (c) 2018-2023 The MobileCoin Foundation

#![no_std]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
#![allow(clippy::result_large_err)]
#![allow(clippy::large-enum-variant)]

extern crate alloc;

use alloc::vec::Vec;
use core::result::Result as StdResult;
use displaydoc::Display;
use mc_attest_core::{Quote, Report, SgxError, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage,
    Error as AttestEnclaveError,
};
use mc_common::ResponderId;
use mc_crypto_keys::{KeyError, SchnorrkelError, SignatureError, X25519Public};
use mc_sgx_compat::sync::PoisonError;
use mc_sgx_report_cache_api::ReportableEnclave;
use mc_sgx_types::{sgx_enclave_id_t, sgx_status_t};
use serde::{Deserialize, Serialize};

/// Represents a serialized request for the Grapevine enclave to handle
#[derive(Serialize, Deserialize)]
pub enum GrapevineEnclaveRequest {
    /// The enclave eid, and the AKE responder id
    Init(GrapevineEnclaveInitParams),

    /// Ake related
    /// Get the public identity assoicated to the enclave, for AKE
    GetIdentity,

    /// Get a new report
    NewEReport(TargetInfo),

    /// Verify a quote
    /// The report part should be a quoting enclave report
    VerifyQuote(Quote, Report),

    /// Verify an IAS report, and cache it if it is accepted
    VerifyIasReport(VerificationReport),

    /// Get the cached verification report if any
    GetIasReport,

    // View-enclave specific
    /// Accept a client connection
    ClientAccept(ClientAuthRequest),

    /// Close a client connection
    ClientClose(ClientSession),

    /// An encrypted grapevine_types::QueryRequest
    /// Respond with grapevine_types::QueryResponse
    Query(EnclaveMessage<ClientSession>),

    /// Set the current timestamp assigned to new messages in the bus
    SetCurrentTimestamp(u64),

    /// Set the message time-to-live value which controls when messages in the
    /// bus expire
    SetMessageTimeToLive(u64),
}

/// The parameters needed to initialize the GrapevineEnclave
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GrapevineEnclaveInitParams {
    /// The sgx_enclave_id_t for this enclave. This is needed to pass to some
    /// OCALL's back to untrusted as an id for the enclave making the call.
    pub eid: sgx_enclave_id_t,
    /// The responder id for this enclave to use for client connections.
    pub self_client_id: ResponderId,
    /// The desired capacity of the store of records
    pub desired_capacity: u64,
    /// The intiial timestamp
    pub current_timestamp: u64,
    /// The message time-to-live value (seconds)
    pub msg_ttl: u64,
}

/// The ClientAuthResponseWithChallengeSeed structure, returned by the enclave
/// in response to an attestation request. This conceptually consists of an
/// AuthResponse, together with an EnclaveMessage which encrypts a random
/// 32-byte value for the client. This share secret is used to generate
/// challenges which the client has to sign, without creating additional rounds
/// of communication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientAuthResponseWithChallengeSeed {
    /// The auth message response for the client. This is the response in a
    /// noise handshake.
    pub client_auth_response: ClientAuthResponse,

    /// The encrypted challenge seed, which the client should preserve with the
    /// ciphers etc. for this connection. The client must sign 32-byte draws
    /// from an RNG seeded with this in order to authenticate control of a
    /// particular key with the server.
    pub encrypted_challenge_seed: Vec<u8>,
}

/// The API for the Grapevine enclave
pub trait GrapevineEnclaveApi: ReportableEnclave {
    /// Perform one-time initialization upon enclave startup.
    fn init(&self, params: GrapevineEnclaveInitParams) -> Result<()>;

    //
    // AKE related
    //

    /// Retrieve the public identity of the enclave.
    fn get_identity(&self) -> Result<X25519Public>;

    //
    // Grapevine-enclave specific
    //

    // CLIENT-FACING METHODS

    /// Accept an inbound authentication request
    fn client_accept(
        &self,
        req: ClientAuthRequest,
    ) -> Result<(ClientAuthResponseWithChallengeSeed, ClientSession)>;

    /// Destroy a peer association
    fn client_close(&self, channel_id: ClientSession) -> Result<()>;

    /// Service a user's encrypted QueryRequest
    fn query(
        &self,
        payload: EnclaveMessage<ClientSession>,
    ) -> Result<EnclaveMessage<ClientSession>>;

    /// SERVER-FACING

    /// Set the current timestamp, which is used to tag new records.
    fn set_current_timestamp(&self, timestamp: u64) -> Result<()>;

    /// Set the message time to live value, which is used to determine when a
    /// record can be evicted.
    fn set_message_time_to_live(&self, timestamp: u64) -> Result<()>;
}

/// Helper trait which reduces boiler-plate in untrusted side
/// The trusted object which implements the above api usually cannot implement
/// Clone, Send, Sync, etc., but the untrusted side can and usually having a
/// "handle to an enclave" is what is most useful for a webserver.
/// This marker trait can be implemented for the untrusted-side representation
/// of the enclave.
pub trait GrapevineEnclaveProxy: GrapevineEnclaveApi + Clone + Send + Sync + 'static {}

impl<T> GrapevineEnclaveProxy for T where T: GrapevineEnclaveApi + Clone + Send + Sync + 'static {}

// Error

/// A generic result type for enclave calls
pub type Result<T> = StdResult<T, Error>;

/// An error when something goes wrong with handling a query
#[derive(Serialize, Deserialize, Debug, Display, Clone)]
pub enum QueryError {
    /// Invalid message id length: {0}, expected {1}
    InvalidMessageIdLength(usize, usize),
    /// Invalid sender length: {0}
    InvalidSenderLength(usize, usize),
    /// Invalid recipient length: {0}
    InvalidRecipientLength(usize, usize),
    /// Invalid payload length: {0}
    InvalidPayloadLength(usize, usize),
    /// Invalid auth identity length: {0}, expected {1}
    InvalidAuthIdentityLength(usize, usize),
    /// Key error: {0}
    Key(KeyError),
    /// Signature conversion error
    SignatureConversion,
    /// Signature verification error
    SignatureVerification,
    /// Cannot update zeroes entry
    CannotUpdateZeroesEntry,
    /// Invalid request type
    InvalidRequestType,
}

impl From<KeyError> for QueryError {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<SignatureError> for QueryError {
    fn from(_: SignatureError) -> Self {
        Self::SignatureConversion
    }
}

impl From<SchnorrkelError> for QueryError {
    fn from(_: SchnorrkelError) -> Self {
        Self::SignatureVerification
    }
}

/// An error returned by the Grapevine enclave
#[derive(Serialize, Deserialize, Debug, Display, Clone)]
pub enum Error {
    /// Sgx error: {0}
    Sgx(SgxError),
    /// Serde encode error
    SerdeEncode,
    /// Serde decode error
    SerdeDecode,
    /// Prost encode error
    ProstEncode,
    /// Prost decode error
    ProstDecode,
    /// Attest enclave error: {0}
    AttestEnclave(AttestEnclaveError),
    /// Query error: {0}
    Query(QueryError),
    /// An panic occurred on another thread
    Poison,
    /// Enclave not initialized
    EnclaveNotInitialized,
    /// Could not find user challenge
    CouldNotFindUserChallenge,
}

impl From<SgxError> for Error {
    fn from(src: SgxError) -> Self {
        Self::Sgx(src)
    }
}

impl From<sgx_status_t> for Error {
    fn from(src: sgx_status_t) -> Self {
        Self::Sgx(src.into())
    }
}

impl From<mc_util_serial::encode::Error> for Error {
    fn from(_: mc_util_serial::encode::Error) -> Self {
        Self::SerdeEncode
    }
}

impl From<mc_util_serial::decode::Error> for Error {
    fn from(_: mc_util_serial::decode::Error) -> Self {
        Self::SerdeDecode
    }
}

impl From<mc_util_serial::EncodeError> for Error {
    fn from(_: mc_util_serial::EncodeError) -> Self {
        Self::ProstEncode
    }
}

impl From<mc_util_serial::DecodeError> for Error {
    fn from(_: mc_util_serial::DecodeError) -> Self {
        Self::ProstDecode
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_src: PoisonError<T>) -> Self {
        Error::Poison
    }
}

impl From<AttestEnclaveError> for Error {
    fn from(src: AttestEnclaveError) -> Self {
        Error::AttestEnclave(src)
    }
}

impl From<QueryError> for Error {
    fn from(src: QueryError) -> Self {
        Error::Query(src)
    }
}
