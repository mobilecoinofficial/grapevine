// Copyright (c) 2018-2023 The MobileCoin Foundation

#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use mc_util_uri::{Uri, UriScheme};

pub use mc_util_uri::{ConnectionUri, FogUri, UriConversionError, UriParseError};

/// Grapevine Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct GrapevineScheme {}

impl UriScheme for GrapevineScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "grapevine";
    const SCHEME_INSECURE: &'static str = "insecure-grapevine";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 443;
    const DEFAULT_INSECURE_PORT: u16 = 3229;
}

/// Uri used when talking to grapevine service, with the right default ports and
/// scheme.
pub type GrapevineUri = Uri<GrapevineScheme>;
