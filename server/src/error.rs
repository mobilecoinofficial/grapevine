// Copyright (c) 2018-2023 The MobileCoin Foundation

use displaydoc::Display;
use mc_bomb_enclave::Error as BombEnclaveError;
use mc_sgx_report_cache_untrusted::Error as ReportCacheError;

#[derive(Debug, Display)]
pub enum BombServerError {
    /// Bomb Enclave error: {0}
    Enclave(BombEnclaveError),
    /// Failed to join thread: {0}
    ThreadJoin(String),
    /// RPC shutdown failure: {0}
    RpcShutdown(String),
    /// Report cache error: {0}
    ReportCache(ReportCacheError),
}

impl From<BombEnclaveError> for BombServerError {
    fn from(src: BombEnclaveError) -> Self {
        BombServerError::Enclave(src)
    }
}

impl From<ReportCacheError> for BombServerError {
    fn from(src: ReportCacheError) -> Self {
        Self::ReportCache(src)
    }
}
