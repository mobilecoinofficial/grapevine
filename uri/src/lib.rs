// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_util_uri::{Uri, UriScheme};

pub use mc_util_uri::{ConnectionUri, FogUri, UriParseError};

/// Bomb Uri Scheme
#[derive(Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Clone)]
pub struct BombScheme {}

impl UriScheme for BombScheme {
    /// The part before the '://' of a URL.
    const SCHEME_SECURE: &'static str = "mc-bomb";
    const SCHEME_INSECURE: &'static str = "insecure-mc-bomb";

    /// Default port numbers
    const DEFAULT_SECURE_PORT: u16 = 443;
    const DEFAULT_INSECURE_PORT: u16 = 3229;
}

/// Uri used when talking to mc-bomb service, with the right default ports and
/// scheme.
pub type BombUri = Uri<BombScheme>;
