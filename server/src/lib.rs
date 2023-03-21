// Copyright (c) 2018-2023 The MobileCoin Foundation

//! MobileCoin Bomb Server target
#![allow(clippy::result_large_err)]
use mc_util_metrics::ServiceMetrics;

pub mod bomb_service;
pub mod config;
pub mod error;
pub mod server;

mod counters;

lazy_static::lazy_static! {
    pub static ref SVC_COUNTERS: ServiceMetrics = ServiceMetrics::new_and_registered("bomb");
}
