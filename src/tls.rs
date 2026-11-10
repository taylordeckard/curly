//! TLS client configuration for protocols curly speaks itself (WebSocket, gRPC).
//! HTTP requests use the system curl and its TLS settings instead.
//!
//! Policy: the OS trust store plus an optional collection CA bundle; TLS 1.3
//! only unless the request opts into TLS 1.2 (`tlsv1.2`, as in curl).

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

/// Builds a rustls client config. `alpn` lists protocols to offer (e.g. `h2`).
pub fn client_config(
    root: &Path,
    tls12: bool,
    cacert: Option<&Path>,
    alpn: &[&[u8]],
) -> Result<Arc<rustls::ClientConfig>> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    if let Some(ca) = cacert {
        let path = root.join(ca);
        for cert in CertificateDer::pem_file_iter(&path)
            .with_context(|| format!("reading cacert {}", ca.display()))?
        {
            roots.add(cert.with_context(|| format!("parsing cacert {}", ca.display()))?)?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if tls12 {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    } else {
        &[&rustls::version::TLS13]
    };
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_configs() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(client_config(tmp.path(), false, None, &[]).is_ok());
        let c = client_config(tmp.path(), true, None, &[b"h2"]).unwrap();
        assert_eq!(c.alpn_protocols, vec![b"h2".to_vec()]);
        let err = client_config(tmp.path(), false, Some(Path::new("missing.pem")), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("reading cacert missing.pem"), "{err}");
    }
}
