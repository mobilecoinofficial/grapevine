// Copyright (c) 2018-2023 The MobileCoin Foundation

//! BOMB Enclave Application-side Proxy object.

#![deny(missing_docs)]

extern crate mc_fog_ocall_oram_storage_untrusted;

use std::{path, result::Result as StdResult, sync::Arc};

use mc_attest_core::{
    IasNonce, Quote, QuoteNonce, Report, SgxError, TargetInfo, VerificationReport,
};
use mc_attest_enclave_api::{ClientAuthRequest, ClientSession, EnclaveMessage};
use mc_attest_verifier::DEBUG_ENCLAVE;
use mc_bomb_enclave_api::ClientAuthResponseWithChallengeSeed;
use mc_common::{logger::Logger, ResponderId};
use mc_crypto_keys::X25519Public;
use mc_enclave_boundary::untrusted::make_variable_length_ecall;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use mc_sgx_types::{sgx_attributes_t, sgx_enclave_id_t, sgx_launch_token_t, sgx_misc_attribute_t};
use mc_sgx_urts::SgxEnclave;

pub use mc_bomb_enclave_api::{
    BombEnclaveApi, BombEnclaveInitParams, BombEnclaveProxy, BombEnclaveRequest, Error, Result,
};

mod ecall;

/// The default filename of the fog view's SGX enclave binary.
pub const ENCLAVE_FILE: &str = "libbomb-enclave.signed.so";

/// A clone-able handle to a BombEnclave suitable for use in servers
#[derive(Clone)]
pub struct SgxBombEnclave {
    enclave: Arc<SgxEnclave>,
}

impl SgxBombEnclave {
    /// Create a new sgx view enclave
    ///
    /// Arguments:
    /// * enclave_path: The path to the signed enclave .so file
    /// * client_responder_id: The responder_id to be used when connecting to
    ///   clients
    /// * db: The recovery db to read data from. This is used when servicing
    ///   seeds requests
    /// * desired_capacity: The desired capacity for ETxOutRecords in the
    ///   oblivious map. Must be a power of two. Actual capacity will be ~70% of
    ///   this. Memory utilization will be about 256 bytes * this + some
    ///   overhead
    /// * current timestamp: The current timestamp, used for message expiry
    ///   calculations
    /// * message_time_to_live: How many seconds a message can live in the
    ///   buffer before expiring
    /// * logger: Logger to use
    pub fn new(
        enclave_path: path::PathBuf,
        client_responder_id: ResponderId,
        desired_capacity: u64,
        current_timestamp: u64,
        message_time_to_live: u64,
        _logger: Logger,
    ) -> Self {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        // FIXME: this must be filled in from the build.rs
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
            misc_select: 0,
        };

        let result = Self {
            enclave: Arc::new(
                SgxEnclave::create(
                    &enclave_path,
                    DEBUG_ENCLAVE as i32,
                    &mut launch_token,
                    &mut launch_token_updated,
                    &mut misc_attr,
                )
                .unwrap_or_else(|e| {
                    panic!(
                        "SgxEnclave::create(file_name={:?}, debug={}) failed: {:?}",
                        &enclave_path, DEBUG_ENCLAVE as i32, e
                    )
                }),
            ),
        };

        // Do sgx_enclave id and ake init
        let eid = result.enclave.geteid();
        let params = BombEnclaveInitParams {
            eid,
            self_client_id: client_responder_id,
            desired_capacity,
            current_timestamp,
            msg_ttl: message_time_to_live,
        };

        result.init(params).expect("Could not initialize enclave");

        result
    }

    fn eid(&self) -> sgx_enclave_id_t {
        self.enclave.geteid()
    }

    /// Takes serialized data, and fires to the corresponding ECALL.
    fn enclave_call(&self, inbuf: &[u8]) -> StdResult<Vec<u8>, SgxError> {
        Ok(make_variable_length_ecall(
            self.eid(),
            ecall::viewenclave_call,
            inbuf,
        )?)
    }
}

impl ReportableEnclave for SgxBombEnclave {
    fn new_ereport(&self, qe_info: TargetInfo) -> ReportableEnclaveResult<(Report, QuoteNonce)> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::NewEReport(qe_info))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn verify_quote(&self, quote: Quote, qe_report: Report) -> ReportableEnclaveResult<IasNonce> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::VerifyQuote(quote, qe_report))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn verify_ias_report(&self, ias_report: VerificationReport) -> ReportableEnclaveResult<()> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::VerifyIasReport(ias_report))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_ias_report(&self) -> ReportableEnclaveResult<VerificationReport> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::GetIasReport)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }
}

impl BombEnclaveApi for SgxBombEnclave {
    fn init(&self, params: BombEnclaveInitParams) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::Init(params))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn get_identity(&self) -> Result<X25519Public> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::GetIdentity)?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn client_accept(
        &self,
        req: ClientAuthRequest,
    ) -> Result<(ClientAuthResponseWithChallengeSeed, ClientSession)> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::ClientAccept(req))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::ClientClose(channel_id))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn query(
        &self,
        payload: EnclaveMessage<ClientSession>,
    ) -> Result<EnclaveMessage<ClientSession>> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::Query(payload))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn set_current_timestamp(&self, current_timestamp: u64) -> Result<()> {
        let inbuf =
            mc_util_serial::serialize(&BombEnclaveRequest::SetCurrentTimestamp(current_timestamp))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }

    fn set_message_time_to_live(&self, msg_ttl: u64) -> Result<()> {
        let inbuf = mc_util_serial::serialize(&BombEnclaveRequest::SetMessageTimeToLive(msg_ttl))?;
        let outbuf = self.enclave_call(&inbuf)?;
        mc_util_serial::deserialize(&outbuf[..])?
    }
}
