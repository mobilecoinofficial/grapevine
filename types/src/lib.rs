// Copyright (c) 2018-2023 The MobileCoin Foundation

#![no_std]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

extern crate alloc;

use alloc::vec::Vec;
use prost::Message;

/// The signing context string used for signing and verifying challenges
pub const GRAPEVINE_CHALLENGE_SIGNING_CONTEXT: &[u8; 19] = b"grapevine-challenge";

/// The RequestType enum value for CREATE request
pub const REQUEST_TYPE_CREATE: u32 = 1;
/// The RequestType enum value for READ request
pub const REQUEST_TYPE_READ: u32 = 2;
/// The RequestType enum value for UPDATE request
pub const REQUEST_TYPE_UPDATE: u32 = 3;
/// The RequestType enum value for DELETE request
pub const REQUEST_TYPE_DELETE: u32 = 4;

/// The QueryResponse structure, returned by the enclave in response to an
/// attested request
#[derive(Clone, Eq, PartialEq, Message)]
pub struct QueryRequest {
    /// The request type of this message.
    /// This corresponds to the enum RequestType in grapevine.proto.
    ///
    /// 1 = CREATE
    /// 2 = READ
    /// 3 = UPDATE
    /// 4 = DELETE
    #[prost(fixed32, tag = "1")]
    pub request_type: u32,

    /// The identity which authorizes this request.
    /// This is a 32-byte ristretto public key, which typically must correspond
    /// to the sender or recipient of the message you want to interact with.
    #[prost(bytes, tag = "2")]
    pub auth_identity: Vec<u8>,

    /// The signature which proves control of the identity.
    /// This is a 64-byte ristretto signature, over the "challenge bytes" for
    /// this request associated to your attested connection.
    /// A 32 byte seed is returned to the client in the auth response
    /// when you establish an attested connection, and this is used to seed an
    /// RNG which produces 32-byte challenges which the client signs and the
    /// server verifies. See .proto file for more detailed explanation.
    #[prost(bytes, tag = "3")]
    pub auth_signature: Vec<u8>,

    /// The record associated to this request.
    /// In all cases this must be a fully populated fized-size RequestRecord
    /// to ensure constant size on the wire.
    #[prost(message, required, tag = "4")]
    pub record: RequestRecord,
}

/// The parts of a record that appear in a request
#[derive(Clone, Eq, PartialEq, Message)]
pub struct RequestRecord {
    /// The id number of this message. Must be exactly 16 bytes, typically
    /// random. All zeroes is an invalid key and typically is used to mean
    /// "show me my next message" in the API, which will have a different ID
    /// from all zeroes.
    #[prost(bytes, tag = "1")]
    pub msg_id: Vec<u8>,

    /// The recipient of this message. Must be a 32 byte ristretto public key.
    #[prost(bytes, tag = "2")]
    pub recipient: Vec<u8>,

    /// The (opaque) payload of this message. This is a fixed number of bytes.
    #[prost(bytes, tag = "3")]
    pub payload: Vec<u8>,
}

/// A record (alternatively, a "message") in the message bus
#[derive(Clone, Eq, PartialEq, Message)]
pub struct Record {
    /// The id number of this message. Must be exactly 16 bytes, typically
    /// random. All zeroes is an invalid key and typically is used to mean
    /// "show me my next message" in the API, which will have a different ID
    /// from all zeroes.
    #[prost(bytes, tag = "1")]
    pub msg_id: Vec<u8>,

    /// The sender of this message. Must be a 32 byte ristretto public key.
    #[prost(bytes, tag = "2")]
    pub sender: Vec<u8>,

    /// The recipient of this message. Must be a 32 byte ristretto public key.
    #[prost(bytes, tag = "3")]
    pub recipient: Vec<u8>,

    /// The timestamp of this message. This is an approximate
    /// number of UTC seconds since the unix epoch.
    #[prost(fixed64, tag = "4")]
    pub timestamp: u64,

    /// The (opaque) payload of this message. This is a fixed number of bytes.
    #[prost(bytes, tag = "5")]
    pub payload: Vec<u8>,
}

/// The QueryResponse structure, returned by the enclave in response to an
/// attested request
#[derive(Clone, Eq, PartialEq, Message)]
pub struct QueryResponse {
    /// The record produced by the response.
    #[prost(message, required, tag = "1")]
    pub record: Record,

    /// The status code which results from the response
    /// This matches a nonzero value from the StatusCode enum in grapevine.proto
    #[prost(fixed32, tag = "2")]
    pub status_code: u32,
}

/// The operation was successful
pub const STATUS_CODE_SUCCESS: u32 = 1;
/// No matching record was found
pub const STATUS_CODE_NOT_FOUND: u32 = 2;
/// This message id is already in use, so we cannot create the new message
pub const STATUS_CODE_MESSAGE_ID_ALREADY_IN_USE: u32 = 3;
/// The message id is invalid in this context. (All zeroes has special meaning.)
pub const STATUS_CODE_INVALID_MESSAGE_ID: u32 = 4;
/// The recipient id is invalid.
pub const STATUS_CODE_INVALID_RECIPIENT: u32 = 5;
/// There are too many in-flight messages for this recipient.
pub const STATUS_CODE_TOO_MANY_MESSAGES_FOR_RECIPIENT: u32 = 6;
/// There are too many recipients with in-flight messages
pub const STATUS_CODE_TOO_MANY_RECIPIENTS: u32 = 7;
/// There are too many messages in flight, we are close to capacity.
pub const STATUS_CODE_TOO_MANY_MESSAGES: u32 = 8;
/// An internal error has occurred.
pub const STATUS_CODE_INTERNAL_ERROR: u32 = 9;
