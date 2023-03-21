// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Bomb Enclave Implementation

#![no_std]
#![allow(clippy::result_large_err)]

extern crate alloc;

mod message_bus;
use message_bus::{MessageBus, StorageDataSize, StorageMetaSize};

use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientSession, EnclaveMessage};
use mc_bomb_enclave_api::{
    BombEnclaveApi, BombEnclaveInitParams, ClientAuthResponseWithChallengeSeed, Error, Result,
};
use mc_bomb_types::QueryRequest;
use mc_common::{
    logger::{log, Logger},
    LruCache,
};
use mc_crypto_ake_enclave::{AkeEnclaveState, NullIdentity};
use mc_crypto_keys::X25519Public;
use mc_crypto_rand::{McRng, RngCore};
use mc_oblivious_traits::ORAMStorageCreator;
use mc_sgx_compat::sync::Mutex;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

pub struct BombEnclave<OSC>
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

impl<OSC> BombEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    pub fn new(logger: Logger) -> Self {
        Self {
            message_bus: Mutex::new(None),
            ake: Default::default(),
            challenge_generators: Mutex::new(LruCache::new(10000)),
            logger,
        }
    }
}

impl<OSC> ReportableEnclave for BombEnclave<OSC>
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

impl<OSC> BombEnclaveApi for BombEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn init(&self, params: BombEnclaveInitParams) -> Result<()> {
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
            ));
        }
        Ok(())
    }

    // AKE-related

    fn get_identity(&self) -> Result<X25519Public> {
        Ok(self.ake.get_kex_identity())
    }

    // Bomb-Enclave specific
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
        let mut lk = self.challenge_generators.lock()?;
        // Also remove their RNG from the challenge generators queue
        lk.pop(&channel_id);
        Ok(())
    }

    fn query(&self, msg: EnclaveMessage<ClientSession>) -> Result<EnclaveMessage<ClientSession>> {
        let channel_id = msg.channel_id.clone();
        let user_plaintext = self.ake.client_decrypt(msg)?;

        let challenge = {
            let mut challenge = [0u8; 32];

            let mut lk = self.challenge_generators.lock()?;
            let rng = lk
                .get_mut(&channel_id)
                .ok_or(Error::CouldNotFindUserChallenge)?;
            rng.fill_bytes(&mut challenge[..]);
            challenge
        };

        let req: QueryRequest = mc_util_serial::decode(&user_plaintext).map_err(|e| {
            log::error!(self.logger, "Could not decode user request: {}", e);
            Error::ProstDecode
        })?;

        let resp = {
            let mut lk = self.message_bus.lock()?;
            let bus = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;
            bus.handle_query(&req, &challenge)?
        };

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
