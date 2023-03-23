// Copyright (c) 2018-2023 The MobileCoin Foundation
#![deny(missing_docs)]

//! Configuration parameters for the example BOMB client

use clap::{Parser, Subcommand};
use mc_bomb_uri::BombUri;
use mc_util_parse::parse_hex;

/// Configuration parameters for the example BOMB client
#[derive(Clone, Debug, Parser)]
#[clap(version)]
pub struct BombClientConfig {
    /// URI for bomb server
    #[clap(long, env = "MC_URI")]
    pub uri: Option<BombUri>,

    /// Secret key which we use to authenticate.
    #[clap(long, value_parser = parse_hex::<[u8; 32]>, env = "MC_SECRET_KEY")]
    pub secret_key: Option<[u8; 32]>,

    /// The command to run.
    #[clap(subcommand)]
    pub cmd: BombClientCommand,
}

/// The command to run.
#[derive(Clone, Debug, Subcommand)]
pub enum BombClientCommand {
    /// Generate a private / public hex key pair
    GenerateKey,

    /// Show public key hex corresponding to our secret key
    ShowPublicKey,

    /// Create a record in the bomb server
    Create {
        /// The id of the message we wish to create. Will be chosen randomly if
        /// not provided.
        #[clap(long, value_parser = parse_hex::<[u8; 16]>, env = "MC_MSG_ID")]
        msg_id: Option<[u8; 16]>,

        /// The recipient of the message.
        #[clap(long, value_parser = parse_hex::<[u8; 32]>, env = "MC_RECIPIENT")]
        recipient: [u8; 32],

        /// The text message we wish to send.
        #[clap(long, env = "MC_MESSAGE")]
        message: String,
    },

    /// Read a record in the bomb server
    Read {
        /// The id of the message we wish to read. If not provided, the server
        /// will return an arbitrary message directed at us, if any exists.
        ///
        /// We will only be able to read the message if we were the sender or
        /// the recipient.
        #[clap(long, value_parser = parse_hex::<[u8; 16]>, env = "MC_MSG_ID")]
        msg_id: Option<[u8; 16]>,
    },

    /// Update a record in the bomb server
    Update {
        /// The id of the message we wish to update.
        #[clap(long, value_parser = parse_hex::<[u8; 16]>, env = "MC_MSG_ID")]
        msg_id: [u8; 16],

        /// The recipient of the message.
        /// Update will fail if this is not correct.
        /// (This is needed in order to update the timestamp also, in the other
        /// table. We cannot access the tables in the other order if we
        /// want to have the same access pattern as a READ operation)
        #[clap(long, value_parser = parse_hex::<[u8; 32]>, env = "MC_RECIPIENT")]
        recipient: [u8; 32],

        /// The new message contents.
        #[clap(long, env = "MC_MESSAGE")]
        message: String,
    },

    /// Delete a record in the bomb server
    Delete {
        /// The id of the message we wish to delete.
        #[clap(long, value_parser = parse_hex::<[u8; 16]>, env = "MC_MSG_ID")]
        msg_id: Option<[u8; 16]>,

        /// The recipient of the message.
        /// Defaults to ourself.
        /// Delete will fail if this is not correct.
        /// (This is needed in order to delete the record in the other table as
        /// well. We cannot access the tables in the other order if we
        /// want to have the same access pattern as a READ operation)
        #[clap(long, value_parser = parse_hex::<[u8; 32]>, env = "MC_RECIPIENT")]
        recipient: Option<[u8; 32]>,
    },
}
