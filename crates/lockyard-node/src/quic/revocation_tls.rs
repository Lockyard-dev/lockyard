// Copyright 2026 The Lockyard Authors. Licensed under the Apache License, Version 2.0.
//! Revocation checks wrap normal WebPKI verification; they never replace TLS trust.
use super::PeerPin;
use crate::revocations::RevocationManager;
use rustls::{
    DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use std::sync::Arc;
fn check(state: &Option<Arc<RevocationManager>>, cert: &CertificateDer<'_>) -> Result<(), Error> {
    if let Some(state) = state {
        state
            .authorize_pin(&PeerPin::certificate(cert.as_ref()).to_hex())
            .map_err(|e| Error::General(e.to_string()))?;
    }
    Ok(())
}
pub(super) struct ServerVerifier {
    pub inner: Arc<dyn ServerCertVerifier>,
    pub state: Option<Arc<RevocationManager>>,
    pub local_pin: String,
}
impl std::fmt::Debug for ServerVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevocationServerVerifier")
    }
}
impl ServerCertVerifier for ServerVerifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if let Some(state) = &self.state {
            state
                .authorize_pin(&self.local_pin)
                .map_err(|e| Error::General(e.to_string()))?;
        }
        check(&self.state, end)?;
        self.inner
            .verify_server_cert(end, intermediates, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
pub(super) struct ClientVerifier {
    pub inner: Arc<dyn ClientCertVerifier>,
    pub state: Option<Arc<RevocationManager>>,
    pub local_pin: String,
}
impl std::fmt::Debug for ClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevocationClientVerifier")
    }
}
impl ClientCertVerifier for ClientVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }
    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        end: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        if let Some(state) = &self.state {
            state
                .authorize_pin(&self.local_pin)
                .map_err(|e| Error::General(e.to_string()))?;
        }
        check(&self.state, end)?;
        self.inner.verify_client_cert(end, intermediates, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
