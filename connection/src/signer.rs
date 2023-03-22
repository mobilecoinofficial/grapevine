// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_crypto_keys::{
    CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic, RistrettoSignature,
    SchnorrkelError,
};
use std::fmt::{Debug, Display};

/// Trait for an abstraction of a Ristretto signer. This is implemented by
/// RistrettoPrivate, but if the private key lives on a hardware device, this
/// might be an abstraction over the hardware device.
pub trait RistrettoSigner {
    /// Error type returned by the signer
    type Error: Display + Debug;

    /// Get the public key corresponding to the signer's private key
    fn get_public_key(&self) -> Result<CompressedRistrettoPublic, Self::Error>;

    /// Sign a message with the private key, with a given context string
    fn sign(
        &self,
        context: &'static [u8],
        message: &[u8],
    ) -> Result<RistrettoSignature, Self::Error>;
}

impl RistrettoSigner for RistrettoPrivate {
    type Error = SchnorrkelError;

    fn get_public_key(&self) -> Result<CompressedRistrettoPublic, Self::Error> {
        Ok(CompressedRistrettoPublic::from(RistrettoPublic::from(self)))
    }

    fn sign(
        &self,
        context: &'static [u8],
        message: &[u8],
    ) -> Result<RistrettoSignature, Self::Error> {
        Ok(self.sign_schnorrkel(context, message))
    }
}
