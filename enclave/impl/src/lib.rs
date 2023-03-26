// Copyright (c) 2018-2023 The MobileCoin Foundation

#![no_std]
#![deny(missing_docs)]
#![allow(clippy::result_large_err)]
#![doc = include_str!("../README.md")]

extern crate alloc;

mod message_bus;
use message_bus::{MessageBus, StorageDataSize, StorageMetaSize};

use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientSession, EnclaveMessage};
use mc_common::{
    logger::{log, Logger},
    LruCache,
};
use mc_crypto_ake_enclave::{AkeEnclaveState, NullIdentity};
use mc_crypto_keys::X25519Public;
use mc_crypto_rand::{McRng, RngCore};
use mc_grapevine_enclave_api::{
    ClientAuthResponseWithChallengeSeed, Error, GrapevineEnclaveApi, GrapevineEnclaveInitParams,
    Result,
};
use mc_grapevine_types::QueryRequest;
use mc_oblivious_traits::ORAMStorageCreator;
use mc_sgx_compat::sync::Mutex;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

/// The business logic of a grapevine enclave
pub struct GrapevineEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    /// The encrypted storage
    message_bus: Mutex<Option<MessageBus<OSC>>>,

    /// The state associated to attestation and key exchange
    ake: AkeEnclaveState<NullIdentity>,

    /// The state associated to generators for user challenges
    challenge_generators: Mutex<LruCache<ClientSession, ChaCha20Rng>>,

    /// Logger object
    logger: Logger,
}

impl<OSC> GrapevineEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    /// Create a new grapevine enclave, from logger.
    /// Note that there is a separate init function.
    pub fn new(logger: Logger) -> Self {
        Self {
            message_bus: Mutex::new(None),
            ake: Default::default(),
            challenge_generators: Mutex::new(LruCache::new(10000)),
            logger,
        }
    }
}

impl<OSC> ReportableEnclave for GrapevineEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn new_ereport(&self, qe_info: TargetInfo) -> ReportableEnclaveResult<(Report, QuoteNonce)> {
        Ok(self.ake.new_ereport(qe_info)?)
    }

    fn verify_quote(&self, quote: Quote, qe_report: Report) -> ReportableEnclaveResult<IasNonce> {
        Ok(self.ake.verify_quote(quote, qe_report)?)
    }

    fn verify_ias_report(&self, ias_report: VerificationReport) -> ReportableEnclaveResult<()> {
        self.ake.verify_ias_report(ias_report)?;
        Ok(())
    }

    fn get_ias_report(&self) -> ReportableEnclaveResult<VerificationReport> {
        Ok(self.ake.get_ias_report()?)
    }
}

impl<OSC> GrapevineEnclaveApi for GrapevineEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn init(&self, params: GrapevineEnclaveInitParams) -> Result<()> {
        // Note: eid is passed to sgx_enclave_id crate earlier in the system, because
        // that crate is not under sgx_compat and isn't meant to be used outside of
        // enclave
        self.ake.init(Default::default(), params.self_client_id)?;
        {
            let mut lk = self.message_bus.lock()?;
            *lk = Some(MessageBus::new(
                params.desired_capacity,
                params.current_timestamp,
                params.msg_ttl,
                self.logger.clone(),
            ));
        }
        Ok(())
    }

    // AKE-related

    fn get_identity(&self) -> Result<X25519Public> {
        Ok(self.ake.get_kex_identity())
    }

    // Grapevine-Enclave specific
    fn client_accept(
        &self,
        req: ClientAuthRequest,
    ) -> Result<(ClientAuthResponseWithChallengeSeed, ClientSession)> {
        // This part is common to all of our enclaves
        let (client_auth_response, client_session) = self.ake.client_accept(req)?;

        // Everything after this has to do with challenge-seeds
        let challenge_seed = {
            let mut challenge_seed = [0u8; 32];
            McRng::default().fill_bytes(&mut challenge_seed[..]);

            let mut lk = self.challenge_generators.lock()?;
            lk.put(
                client_session.clone(),
                ChaCha20Rng::from_seed(challenge_seed),
            );

            challenge_seed
        };

        // Encrypt the challenge seed to return to user
        let encrypted_challenge_seed =
            self.ake
                .client_encrypt(&client_session, &[], &challenge_seed)?;

        Ok((
            ClientAuthResponseWithChallengeSeed {
                client_auth_response,
                encrypted_challenge_seed: encrypted_challenge_seed.data,
            },
            client_session,
        ))
    }

    fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        self.ake.client_close(channel_id.clone())?;
        // Also remove their RNG from the challenge generators set
        let mut lk = self.challenge_generators.lock()?;
        lk.pop(&channel_id);
        Ok(())
    }

    fn query(&self, msg: EnclaveMessage<ClientSession>) -> Result<EnclaveMessage<ClientSession>> {
        let channel_id = msg.channel_id.clone();
        let user_plaintext = self.ake.client_decrypt(msg)?;

        let req: QueryRequest = mc_util_serial::decode(&user_plaintext).map_err(|e| {
            log::error!(self.logger, "Could not decode user request: {}", e);
            Error::ProstDecode
        })?;

        // Get a challenge for this user
        let challenge = {
            let mut challenge = [0u8; 32];

            let mut lk = self.challenge_generators.lock()?;
            let rng = lk
                .get_mut(&channel_id)
                .ok_or(Error::CouldNotFindUserChallenge)?;
            rng.fill_bytes(&mut challenge[..]);
            challenge
        };

        // Pass query and challenge to message bus
        let resp = {
            let mut lk = self.message_bus.lock()?;
            let bus = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;
            bus.handle_query(&req, &challenge)?
        };

        // Encrypt result for user
        let response_plaintext_bytes = mc_util_serial::encode(&resp);

        let response = self
            .ake
            .client_encrypt(&channel_id, &[], &response_plaintext_bytes)?;

        Ok(response)
    }

    fn set_current_timestamp(&self, timestamp: u64) -> Result<()> {
        let mut lk = self.message_bus.lock()?;
        let bus = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;
        bus.set_current_timestamp(timestamp);
        Ok(())
    }

    fn set_message_time_to_live(&self, msg_ttl: u64) -> Result<()> {
        let mut lk = self.message_bus.lock()?;
        let bus = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;
        bus.set_message_time_to_live(msg_ttl);
        Ok(())
    }
}