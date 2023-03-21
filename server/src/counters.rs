// Copyright (c) 2018-2023 The MobileCoin Foundation

use mc_util_metrics::{Histogram, IntCounter, IntGauge, OpMetrics};

lazy_static::lazy_static! {
    pub static ref OP_COUNTERS: OpMetrics = OpMetrics::new_and_registered("bomb");

    // Enclave report timestamp, represented as seconds of UTC time since Unix epoch 1970-01-01T00:00:00Z.
    pub static ref ENCLAVE_REPORT_TIMESTAMP: IntGauge = OP_COUNTERS.gauge("enclave_report_timestamp");

    // Number of queries handled since startup.
    pub static ref QUERY_COUNT: IntCounter = OP_COUNTERS.counter("query_count");

    // Time it takes to perform the enclave query call.
    pub static ref ENCLAVE_QUERY_TIME: Histogram = OP_COUNTERS.histogram("enclave_query_time");
}
