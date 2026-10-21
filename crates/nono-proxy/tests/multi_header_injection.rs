//! End-to-end reverse-proxy coverage for multi-header credential injection
//! against a local mock upstream.

#![allow(clippy::unwrap_used)]

use nono_proxy::config::{HeaderInjectionConfig, InjectMode, ProxyConfig, RouteConfig};
use nono_proxy::server::{self, ProxyHandle};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

/// Mock upstream that records the raw request of each of `count` connections
/// and answers `200 ok`.
async fn capture_upstream(count: usize) -> (u16, Arc<Mutex<Vec<String>>>, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind mock upstream");
    let port = listener.local_addr().expect("upstream addr").port();
    let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&captured);
    let task = tokio::spawn(async move {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.expect("read request");
            sink.lock()
                .expect("capture lock")
                .push(String::from_utf8_lossy(&buf[..n]).to_string());
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("write response");
            stream.flush().await.expect("flush response");
        }
    });
    (port, captured, task)
}

/// Route with the header defaults these tests start from: `Authorization` with
/// `Bearer {}`, overridden through `inject_headers` and `credential_format`.
fn base_route(prefix: &str, upstream: String, credential_key: &str) -> RouteConfig {
    RouteConfig {
        redeem_phantoms: Vec::new(),
        inject_headers: None,
        prefix: prefix.to_string(),
        upstream,
        credential_key: Some(credential_key.to_string()),
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
    }
}

async fn start_proxy(route: RouteConfig) -> ProxyHandle {
    server::start(ProxyConfig {
        routes: vec![route],
        ..ProxyConfig::default()
    })
    .await
    .expect("proxy starts")
}

/// Each inbound connection serves one request, so every request needs its own
/// connection.
async fn send_request(proxy_port: u16, request: String) -> String {
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect proxy");
    client
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .await
        .expect("read proxy response");
    String::from_utf8_lossy(&response).to_string()
}

#[tokio::test]
#[allow(clippy::disallowed_methods)] // sole test in this binary: no concurrent env access
async fn test_reverse_proxy_injects_secret_into_every_configured_header() {
    // SAFETY: only test in this binary; no concurrent env access.
    unsafe { std::env::set_var("NONO_PROXY_TEST_MULTI_HEADER_KEY", "sk-real") };

    let (upstream_port, captured, upstream) = capture_upstream(2).await;
    let mut route = base_route(
        "multi",
        format!("http://127.0.0.1:{upstream_port}"),
        "env://NONO_PROXY_TEST_MULTI_HEADER_KEY",
    );
    route.inject_headers = Some(vec![
        HeaderInjectionConfig {
            header: "x-api-key".to_string(),
            format: Some("{}".to_string()),
        },
        HeaderInjectionConfig {
            header: "Authorization".to_string(),
            format: Some("Bearer {}".to_string()),
        },
    ]);

    let handle = start_proxy(route).await;
    let token = handle.token.as_str().to_string();

    // Both injected headers must authenticate the same phantom token.
    for (phantom_header, phantom_value) in [
        ("x-api-key", token.clone()),
        ("Authorization", format!("Bearer {token}")),
    ] {
        let request = format!(
            "GET /multi/models HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{phantom_header}: {phantom_value}\r\nConnection: close\r\n\r\n",
            handle.port
        );
        let response = send_request(handle.port, request).await;
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "unexpected proxy response for {phantom_header}: {response}"
        );
    }

    // A phantom in a header the route does not list must not authenticate: the
    // list is the whole accepted surface, and the 401 names the header used.
    let request = format!(
        "GET /multi/models HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Other: Bearer {token}\r\nConnection: close\r\n\r\n",
        handle.port
    );
    let response = send_request(handle.port, request).await;
    assert!(
        response.starts_with("HTTP/1.1 401"),
        "phantom in an unlisted header must not authenticate: {response}"
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

    let (upstream_port, captured, upstream) = capture_upstream(1).await;
    let mut route = base_route(
        "additive",
        format!("http://127.0.0.1:{upstream_port}"),
        "env://NONO_PROXY_TEST_ADDITIVE_KEY",
    );
    route.credential_format = None;
    route.inject_headers = Some(vec![HeaderInjectionConfig {
        header: "x-api-key".to_string(),
        format: None,
    }]);

    let handle = start_proxy(route).await;
    let token = handle.token.as_str().to_string();

    let request = format!(
        "GET /additive/models HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n",
        handle.port
    );
    let response = send_request(handle.port, request).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected proxy response: {response}"
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

#[tokio::test]
#[allow(clippy::disallowed_methods)] // sole test in this binary: no concurrent env access
async fn test_unlisted_header_carrying_the_phantom_is_dropped() {
    // SAFETY: only test in this binary; no concurrent env access.
    unsafe { std::env::set_var("NONO_PROXY_TEST_DROP_KEY", "sk-drop") };

    let (upstream_port, captured, upstream) = capture_upstream(1).await;
    let route = base_route(
        "drop",
        format!("http://127.0.0.1:{upstream_port}"),
        "env://NONO_PROXY_TEST_DROP_KEY",
    );

    let handle = start_proxy(route).await;
    let token = handle.token.as_str().to_string();

    // Authorization authenticates the request; the same token in x-other is a
    // header the route does not inject, so it must not be forwarded.
    let request = format!(
        "GET /drop/models HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {token}\r\nX-Other: {token}\r\nConnection: close\r\n\r\n",
        handle.port
    );
    let response = send_request(handle.port, request).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected proxy response: {response}"
    );

    upstream.await.expect("mock upstream task");
    let captured = captured.lock().expect("capture lock");
    let forwarded = captured
        .first()
        .expect("one forwarded request")
        .to_lowercase();
    assert!(
        forwarded.contains("authorization: bearer sk-drop"),
        "authenticated header must carry the real credential: {forwarded}"
    );
    assert!(
        !forwarded.contains("x-other:"),
        "header carrying the phantom must be dropped: {forwarded}"
    );
    assert!(
        !forwarded.contains(&token.to_lowercase()),
        "phantom token must not reach the upstream: {forwarded}"
    );

    handle.shutdown();
}
