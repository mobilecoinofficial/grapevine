// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Bomb server object

use crate::{bomb_service::BombService, config::BombServerConfig, counters};
use futures::executor::block_on;
use mc_attest_net::RaClient;
use mc_bomb_api::bomb_grpc;
use mc_bomb_enclave::BombEnclaveProxy;
use mc_common::{
    logger::{log, Logger},
    time::TimeProvider,
};
use mc_sgx_report_cache_untrusted::ReportCacheThread;
use mc_util_grpc::{
    AnonymousAuthenticator, Authenticator, ConnectionUriGrpcioServer, ReadinessIndicator,
    TokenAuthenticator,
};
use mc_util_uri::ConnectionUri;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{sleep, Builder as ThreadBuilder, JoinHandle},
    time::Duration,
};

pub struct BombServer<E, RC>
where
    E: BombEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    #[allow(unused)]
    config: BombServerConfig,
    server: grpcio::Server,
    enclave: E,
    ra_client: RC,
    report_cache_thread: Option<ReportCacheThread>,
    time_provider_poll_thread: TimeProviderPollThread,
    readiness_indicator: ReadinessIndicator,
    logger: Logger,
}

impl<E, RC> BombServer<E, RC>
where
    E: BombEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    /// Make a new view server instance
    pub fn new(
        config: BombServerConfig,
        enclave: E,
        ra_client: RC,
        time_provider: impl TimeProvider + Clone + 'static,
        logger: Logger,
    ) -> BombServer<E, RC> {
        let readiness_indicator = ReadinessIndicator::default();

        let time_provider_poll_thread =
            TimeProviderPollThread::new(enclave.clone(), time_provider.clone(), logger.clone());

        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Main-RPC".to_string())
                .build(),
        );

        let client_authenticator: Arc<dyn Authenticator + Sync + Send> =
            if let Some(shared_secret) = config.client_auth_token_secret.as_ref() {
                Arc::new(TokenAuthenticator::new(
                    *shared_secret,
                    config.client_auth_token_max_lifetime,
                    time_provider,
                ))
            } else {
                Arc::new(AnonymousAuthenticator::default())
            };

        let bomb_service = bomb_grpc::create_bomb_api(BombService::new(
            config.clone(),
            enclave.clone(),
            client_authenticator,
            logger.clone(),
        ));
        log::debug!(logger, "Constructed BOMB GRPC Service");

        // Health check service
        let health_service = mc_util_grpc::HealthService::new(
            Some(readiness_indicator.clone().into()),
            logger.clone(),
        )
        .into_service();

        // Package service into grpc server
        log::info!(
            logger,
            "Starting Bomb server on {}",
            config.client_listen_uri.addr(),
        );
        let server_builder = grpcio::ServerBuilder::new(env)
            .register_service(bomb_service)
            .register_service(health_service);

        let server = server_builder
            .build_using_uri(&config.client_listen_uri, logger.clone())
            .expect("Could not bind to client listen URI");

        Self {
            config,
            server,
            enclave,
            ra_client,
            report_cache_thread: None,
            time_provider_poll_thread,
            readiness_indicator,
            logger,
        }
    }

    /// Start the server, which starts all the worker threads
    pub fn start(&mut self) {
        self.report_cache_thread = Some(
            ReportCacheThread::start(
                self.enclave.clone(),
                self.ra_client.clone(),
                self.config.ias_spid,
                &counters::ENCLAVE_REPORT_TIMESTAMP,
                self.logger.clone(),
            )
            .expect("failed starting report cache thread"),
        );

        self.server.start();
        log::info!(
            self.logger,
            "API listening on {}",
            self.config.client_listen_uri.addr()
        );
        // We are ready when we hit this point
        self.readiness_indicator.set_ready();
    }

    /// Stop the server and all worker threads
    pub fn stop(&mut self) {
        if let Some(ref mut thread) = self.report_cache_thread.take() {
            thread.stop().expect("Could not stop report cache thread");
        }

        self.time_provider_poll_thread.stop();

        block_on(self.server.shutdown()).expect("Could not stop grpc server");
    }
}

impl<E, RC> Drop for BombServer<E, RC>
where
    E: BombEnclaveProxy,
    RC: RaClient + Send + Sync + 'static,
{
    fn drop(&mut self) {
        self.stop();
    }
}

/// A thread that polls the time provider and updates the enclave
pub struct TimeProviderPollThread {
    /// Join handle used to wait for the thread to terminate.
    join_handle: Option<JoinHandle<()>>,

    /// Stop request trigger, used to signal the thread to stop.
    stop_requested: Arc<AtomicBool>,
}

impl TimeProviderPollThread {
    /// Initialize and start a new DbPollThread object.
    pub fn new(
        enclave: impl BombEnclaveProxy,
        time_provider: impl TimeProvider + 'static,
        logger: Logger,
    ) -> Self {
        let stop_requested = Arc::new(AtomicBool::new(false));
        let thread_stop_requested = stop_requested.clone();

        let join_handle = Some(
            ThreadBuilder::new()
                .name("TimeProviderPoll".to_string())
                .spawn(move || loop {
                    if thread_stop_requested.load(Ordering::SeqCst) {
                        break;
                    }

                    match time_provider.since_epoch() {
                        Ok(dur) => {
                            if let Err(err) = enclave.set_current_timestamp(dur.as_secs()) {
                                log::error!(logger, "Error setting current timestamp: {}", err);
                            }
                        }
                        Err(err) => {
                            log::error!(logger, "Error getting current time: {:?}", err);
                        }
                    }

                    sleep(Duration::from_millis(1000));
                })
                .expect("Could not spawn thread"),
        );

        Self {
            stop_requested,
            join_handle,
        }
    }

    /// Stop and join the DbPollThread
    pub fn stop(&mut self) {
        self.stop_requested.store(true, Ordering::SeqCst);
        if let Some(thread) = self.join_handle.take() {
            thread.join().expect("Error joining time provider thread");
        }
    }
}

impl Drop for TimeProviderPollThread {
    fn drop(&mut self) {
        self.stop();
    }
}
