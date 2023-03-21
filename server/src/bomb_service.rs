// Copyright (c) 2018-2023 The MobileCoin Foundation

use crate::{config::BombServerConfig, SVC_COUNTERS};
use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_attest_api::attest;
use mc_bomb_api::{bomb, bomb_grpc::BombApi};
use mc_bomb_enclave::{BombEnclaveProxy, Error as EnclaveError};
use mc_common::logger::{log, Logger};
use mc_util_grpc::{
    rpc_internal_error, rpc_invalid_arg_error, rpc_logger, rpc_permissions_error, send_result,
    Authenticator,
};
use mc_util_telemetry::{tracer, Tracer};
use std::sync::Arc;

#[derive(Clone)]
pub struct BombService<E: BombEnclaveProxy> {
    /// Server Config
    #[allow(unused)]
    config: BombServerConfig,

    /// Enclave containing messages
    enclave: E,

    /// GRPC request authenticator.
    authenticator: Arc<dyn Authenticator + Send + Sync>,

    /// Slog logger object
    logger: Logger,
}

impl<E: BombEnclaveProxy> BombService<E> {
    /// Creates a new bomb-service API handler
    pub fn new(
        config: BombServerConfig,
        enclave: E,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            config,
            enclave,
            authenticator,
            logger,
        }
    }

    /// Unwrap and forward to enclave
    pub fn query_impl(&mut self, request: attest::Message) -> Result<attest::Message, RpcStatus> {
        log::trace!(self.logger, "Getting encrypted request");
        let tracer = tracer!();

        tracer.in_span("query_impl", |_cx| {
            let result = tracer.in_span("enclave_query", |_cx| {
                self.enclave
                    .query(request.into())
                    .map_err(|e| self.enclave_err_to_rpc_status("enclave request", e))
            })?;

            Ok(result.into())
        })
    }

    // Helper function that is common
    fn enclave_err_to_rpc_status(&self, context: &str, src: EnclaveError) -> RpcStatus {
        // Treat prost-decode error as an invalid arg,
        // treat attest error as permission denied,
        // everything else is an internal error
        match src {
            EnclaveError::ProstDecode => {
                rpc_invalid_arg_error(context, "Prost decode failed", &self.logger)
            }
            EnclaveError::AttestEnclave(err) => rpc_permissions_error(context, err, &self.logger),
            other => rpc_internal_error(context, format!("{}", &other), &self.logger),
        }
    }
}

// Implement grpc trait
impl<E: BombEnclaveProxy> BombApi for BombService<E> {
    fn auth(
        &mut self,
        ctx: RpcContext,
        mut request: attest::AuthMessage,
        sink: UnarySink<bomb::AuthMessageWithChallengeSeed>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            match self.enclave.client_accept(request.take_data().into()) {
                Ok((response, _client_session)) => {
                    let mut auth_message = attest::AuthMessage::new();
                    auth_message.set_data(response.client_auth_response.into());

                    let mut result = bomb::AuthMessageWithChallengeSeed::new();
                    result.set_auth_message(auth_message);
                    result.set_encrypted_challenge_seed(response.encrypted_challenge_seed);

                    send_result(ctx, sink, Ok(result), logger);
                }
                Err(client_error) => {
                    // This is debug because there's no requirement on the remote party to trigger
                    // it.
                    log::debug!(
                        logger,
                        "BombEnclaveApi::client_accept failed: {}",
                        client_error
                    );
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_permissions_error(
                            "client_auth",
                            format!("Permission denied: {client_error}"),
                            logger,
                        )),
                        logger,
                    );
                }
            }
        });
    }

    fn query(
        &mut self,
        ctx: RpcContext,
        request: attest::Message,
        sink: UnarySink<attest::Message>,
    ) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), logger);
            }

            send_result(ctx, sink, self.query_impl(request), logger)
        })
    }
}
