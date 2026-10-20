//! End-to-end reverse-proxy coverage for multi-header credential injection
//! against a local mock upstream.

#![allow(clippy::unwrap_used)]

use nono_proxy::config::{HeaderInjectionConfig, InjectMode, ProxyConfig, RouteConfig};
use nono_proxy::server;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[allow(clippy::disallowed_methods)] // sole test in this binary: no concurrent env access
async fn test_reverse_proxy_injects_secret_into_every_configured_header() {
    // SAFETY: only test in this binary; no concurrent env access.
    unsafe { std::env::set_var("NONO_PROXY_TEST_MULTI_HEADER_KEY", "sk-real") };

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind mock upstream");
    let upstream_port = listener.local_addr().expect("upstream addr").port();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_task = Arc::clone(&captured);
    let upstream = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.expect("read request");
            captured_task
                .lock()
                .expect("capture lock")
                .push(String::from_utf8_lossy(&buf[..n]).to_string());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("write response");
            stream.flush().await.expect("flush response");
        }
    });

    let route = RouteConfig {
        redeem_phantoms: Vec::new(),
        inject_headers: Some(vec![
            HeaderInjectionConfig {
                header: "x-api-key".to_string(),
                format: Some("{}".to_string()),
            },
            HeaderInjectionConfig {
                header: "Authorization".to_string(),
                format: Some("Bearer {}".to_string()),
            },
        ]),
        prefix: "multi".to_string(),
        upstream: format!("http://127.0.0.1:{upstream_port}"),
        credential_key: Some("env://NONO_PROXY_TEST_MULTI_HEADER_KEY".to_string()),
        inject_mode: InjectMode::Header,
        inject_header: "Authorization".to_string(),
        credential_format: Some("Bearer {}".to_string()),
        path_pattern: None,
        path_replacement: None,
        query_param_name: None,
        proxy: None,
        env_var: None,
        endpoint_rules: vec![],
        endpoint_policy: None,
        tls_ca: None,
        tls_client_cert: None,
        tls_client_key: None,
        oauth2: None,
        aws_auth: None,
        spiffe: None,
        upgrades: vec![],
        rate_limit: None,
    };

    let handle = server::start(ProxyConfig {
        routes: vec![route],
        ..ProxyConfig::default()
    })
    .await
    .expect("proxy starts");
    let token = handle.token.as_str().to_string();

    // Each inbound connection serves one request, so each phantom variant needs
    // a fresh connection; both injected headers must authenticate.
    for (phantom_header, phantom_value) in [
        ("x-api-key", token.clone()),
        ("Authorization", format!("Bearer {token}")),
    ] {
        let mut client = tokio::net::TcpStream::connect(("127.0.0.1", handle.port))
            .await
            .expect("connect proxy");
        let request = format!(
            "GET /multi/models HTTP/1.1\r\nHost: 127.0.0.1:{handle_port}\r\n{phantom_header}: {phantom_value}\r\nConnection: close\r\n\r\n",
            handle_port = handle.port
        );
        client
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read proxy response");
        assert!(
            String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
            "unexpected proxy response for {phantom_header}: {}",
            String::from_utf8_lossy(&response)
        );
    }

    // A phantom in a header the route does not list must not authenticate: the
    // list is the whole accepted surface, and the 401 names the header used.
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", handle.port))
        .await
        .expect("connect proxy");
    let request = format!(
        "GET /multi/models HTTP/1.1\r\nHost: 127.0.0.1:{handle_port}\r\nX-Other: Bearer {token}\r\nConnection: close\r\n\r\n",
        handle_port = handle.port
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read proxy response");
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 401"),
        "phantom in an unlisted header must not authenticate: {}",
        String::from_utf8_lossy(&response)
    );

    upstream.await.expect("mock upstream task");
    let captured = captured.lock().expect("capture lock");
    assert_eq!(captured.len(), 2, "two requests expected");
    for forwarded_raw in captured.iter() {
        let forwarded = forwarded_raw.to_lowercase();
        assert!(
            forwarded.contains("x-api-key: sk-real"),
            "missing x-api-key header: {forwarded}"
        );
        assert!(
            forwarded.contains("authorization: bearer sk-real"),
            "missing Authorization header: {forwarded}"
        );
        assert!(
            !forwarded.contains(&token.to_lowercase()),
            "phantom token must not reach the upstream: {forwarded}"
        );
    }

    handle.shutdown();
}

#[tokio::test]
#[allow(clippy::disallowed_methods)] // sole test in this binary: no concurrent env access
async fn test_extra_headers_are_added_to_the_inject_header() {
    // A provider needing an extra header must not force the profile to repeat
    // Authorization: the client authenticates with Authorization, which the
    // route injects through the inject_header default, and still gets x-api-key.
    // SAFETY: only test in this binary; no concurrent env access.
    unsafe { std::env::set_var("NONO_PROXY_TEST_ADDITIVE_KEY", "sk-additive") };

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind mock upstream");
    let upstream_port = listener.local_addr().expect("upstream addr").port();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let captured_task = Arc::clone(&captured);
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.expect("read request");
        captured_task
            .lock()
            .expect("capture lock")
            .push(String::from_utf8_lossy(&buf[..n]).to_string());
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("write response");
        stream.flush().await.expect("flush response");
    });

    let route = RouteConfig {
        redeem_phantoms: Vec::new(),
        inject_headers: Some(vec![HeaderInjectionConfig {
            header: "x-api-key".to_string(),
            format: None,
        }]),
        prefix: "additive".to_string(),
        upstream: format!("http://127.0.0.1:{upstream_port}"),
        credential_key: Some("env://NONO_PROXY_TEST_ADDITIVE_KEY".to_string()),
        inject_mode: InjectMode::Header,
        inject_header: "Authorization".to_string(),
        credential_format: None,
        path_pattern: None,
        path_replacement: None,
        query_param_name: None,
        proxy: None,
        env_var: None,
        endpoint_rules: vec![],
        endpoint_policy: None,
        tls_ca: None,
        tls_client_cert: None,
        tls_client_key: None,
        oauth2: None,
        aws_auth: None,
        spiffe: None,
        upgrades: vec![],
        rate_limit: None,
    };

    let handle = server::start(ProxyConfig {
        routes: vec![route],
        ..ProxyConfig::default()
    })
    .await
    .expect("proxy starts");
    let token = handle.token.as_str().to_string();

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", handle.port))
        .await
        .expect("connect proxy");
    let request = format!(
        "GET /additive/models HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n",
        handle.port
    );
    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read proxy response");
    assert!(
        String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"),
        "unexpected proxy response: {}",
        String::from_utf8_lossy(&response)
    );

    upstream.await.expect("mock upstream task");
    let captured = captured.lock().expect("capture lock");
    let forwarded = captured
        .first()
        .expect("one forwarded request")
        .to_lowercase();
    assert!(
        forwarded.contains("authorization: bearer sk-additive"),
        "inject_header must still be injected: {forwarded}"
    );
    assert!(
        forwarded.contains("x-api-key: sk-additive"),
        "listed header must be injected as an extra: {forwarded}"
    );
    assert!(
        !forwarded.contains(&token.to_lowercase()),
        "phantom token must not reach the upstream: {forwarded}"
    );

    handle.shutdown();
}
