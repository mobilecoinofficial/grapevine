// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::RetryError;
use displaydoc::Display;
use mc_attest_ake::Error as AkeError;
use mc_bomb_uri::{BombUri, UriConversionError};
use mc_connection::AttestationError;
use mc_crypto_noise::CipherError;
use mc_util_serial::DecodeError;
use std::fmt::{Debug, Display};

/// An error that can occur when making a bomb request
#[derive(Debug)]
pub struct Error {
    /// The uri which we made the request from
    pub uri: BombUri,
    /// The error which occurred
    pub error: RequestError,
}

impl Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            formatter,
            "BombGrpcConnection error ({}): {}",
            &self.uri, &self.error
        )
    }
}

#[derive(Display, Debug)]
pub enum RequestError {
    /// A signer error: {0}
    Signer(String),
    /// A connection error: {0}
    Connection(RetryError<EnclaveConnectionError>),
}

impl From<RetryError<EnclaveConnectionError>> for RequestError {
    fn from(src: RetryError<EnclaveConnectionError>) -> Self {
        Self::Connection(src)
    }
}

/// A lower level error that occurs when a particular retry fails
#[derive(Display, Debug)]
pub enum EnclaveConnectionError {
    /// gRPC Error: {0}
    Rpc(grpcio::Error),
    /// Attestation AKE error: {0}
    Ake(AkeError),
    /// mc-crypto-noise cipher error: {0}
    Cipher(CipherError),
    /// Invalid Uri: {0}
    InvalidUri(UriConversionError),
    /// Protobuf deserialization: {0}
    ProtoDecode(DecodeError),
    /// Invalid challenge seed: Expected 32 bytes, found {0}
    InvalidChallengeSeed(usize),
    /// A signer error: {0}
    Signer(String),
}

impl AttestationError for EnclaveConnectionError {
    fn should_reattest(&self) -> bool {
        matches!(self, Self::Rpc(_) | Self::Ake(_) | Self::Cipher(_))
    }

    fn should_retry(&self) -> bool {
        match self {
            Self::Rpc(_) | Self::Cipher(_) | Self::ProtoDecode(_) => true,
            Self::Ake(AkeError::ReportVerification(_)) => false,
            Self::Ake(_) => true,
            Self::InvalidUri(_) => false,
            Self::InvalidChallengeSeed(_) => true,
            Self::Signer(_) => true,
        }
    }
}

impl From<grpcio::Error> for EnclaveConnectionError {
    fn from(err: grpcio::Error) -> Self {
        Self::Rpc(err)
    }
}

impl From<AkeError> for EnclaveConnectionError {
    fn from(err: AkeError) -> Self {
        Self::Ake(err)
    }
}

impl From<CipherError> for EnclaveConnectionError {
    fn from(err: CipherError) -> Self {
        Self::Cipher(err)
    }
}

impl From<UriConversionError> for EnclaveConnectionError {
    fn from(src: UriConversionError) -> Self {
        Self::InvalidUri(src)
    }
}

impl From<DecodeError> for EnclaveConnectionError {
    fn from(src: DecodeError) -> Self {
        Self::ProtoDecode(src)
    }
}
