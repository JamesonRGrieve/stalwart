/*
 * SPDX-FileCopyrightText: 2026 Jameson
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

use crate::{
    smtp::session::TestSession,
    utils::{dns::DnsCache, server::TestServerBuilder},
};
use base64::{Engine, engine::general_purpose};
use registry::schema::{
    enums::MtaProtocol,
    structs::{
        Expression, MtaOutboundStrategy, MtaRoute, MtaRouteRelay, MtaStageRcpt, SecretKeyOptional,
        SecretKeyValue,
    },
};
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

const OAUTH2_USER: &str = "relayuser@test.org";
const OAUTH2_TOKEN: &str = "tok-remote-1";
const RELAY_NAME: &str = "relay.example.org";

/// What the raw relay observed on the wire.
struct RelayCapture {
    base64_auth_payload: Option<String>,
    data: Option<String>,
}

/// Minimal SMTP relay that requires `AUTH XOAUTH2` before accepting mail and
/// records the base64 AUTH payload and the DATA body.
async fn serve_relay(listener: TcpListener, tx: oneshot::Sender<RelayCapture>) {
    let (mut stream, _) = match listener.accept().await {
        Ok(pair) => pair,
        Err(_) => return,
    };
    let _ = stream
        .write_all(b"220 relay.example.org ESMTP ready\r\n")
        .await;

    let mut buf: Vec<u8> = Vec::new();
    let mut in_data = false;
    let mut base64_auth_payload = None;
    let mut data = None;

    'conn: loop {
        let mut chunk = [0u8; 8192];
        let n = match stream.read(&mut chunk).await {
            Ok(n) if n > 0 => n,
            _ => break 'conn,
        };
        buf.extend_from_slice(&chunk[..n]);

        if in_data {
            if let Some(pos) = buf.windows(5).position(|w| w == b"\r\n.\r\n") {
                data = Some(String::from_utf8_lossy(&buf[..pos]).into_owned());
                buf.drain(..=pos + 4);
                in_data = false;
                let _ = stream.write_all(b"250 2.0.0 OK: queued\r\n").await;
            }
            continue 'conn;
        }

        while let Some(pos) = buf.iter().position(|&b| b == b'\r') {
            if buf.get(pos + 1) != Some(&b'\n') {
                break;
            }
            let line: Vec<u8> = buf.drain(..pos + 2).collect();
            let cmd = String::from_utf8_lossy(&line).trim_end().to_string();
            let up = cmd.to_ascii_uppercase();
            if up.starts_with("EHLO") {
                let _ = stream
                    .write_all(b"250-relay.example.org\r\n250 AUTH XOAUTH2\r\n")
                    .await;
            } else if up.starts_with("AUTH") {
                let rest = cmd[4..].trim();
                let (mech, token) = match rest.split_once(' ') {
                    Some(pair) => pair,
                    None => ("", ""),
                };
                if mech.eq_ignore_ascii_case("XOAUTH2") {
                    base64_auth_payload = Some(token.to_string());
                    let _ = stream
                        .write_all(b"235 2.7.0 Authentication succeeded\r\n")
                        .await;
                } else {
                    let _ = stream
                        .write_all(b"504 5.5.4 Mechanism not supported\r\n")
                        .await;
                }
            } else if up.starts_with("MAIL") {
                let _ = stream.write_all(b"250 2.1.0 OK\r\n").await;
            } else if up.starts_with("RCPT") {
                let _ = stream.write_all(b"250 2.1.5 OK\r\n").await;
            } else if up.starts_with("DATA") {
                buf.clear();
                in_data = true;
                let _ = stream.write_all(b"354 Go ahead\r\n").await;
                break;
            } else if up.starts_with("QUIT") {
                let _ = stream.write_all(b"221 2.0.0 Bye\r\n").await;
                break 'conn;
            } else {
                let _ = stream.write_all(b"250 2.0.0 OK\r\n").await;
            }
        }
    }

    let _ = tx.send(RelayCapture {
        base64_auth_payload,
        data,
    });
}

#[tokio::test]
#[serial_test::serial]
async fn oauth2_relay() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_port = listener.local_addr().unwrap().port();
    let (capture_tx, capture_rx) = oneshot::channel();
    tokio::spawn(serve_relay(listener, capture_tx));

    let mut local = TestServerBuilder::new("smtp_oauth2_local")
        .await
        .with_http_listener(19024)
        .await
        .disable_services()
        .capture_queue()
        .build()
        .await;

    let local_admin = local.account("admin");
    local_admin
        .registry_create_object(MtaStageRcpt {
            max_recipients: Expression {
                else_: "100".into(),
                ..Default::default()
            },
            allow_relaying: Expression {
                else_: "true".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    local_admin
        .registry_create_object(MtaOutboundStrategy {
            route: Expression {
                else_: "'oauth2'".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .await;
    local_admin
        .registry_create_object(MtaRoute::Relay(MtaRouteRelay {
            address: RELAY_NAME.into(),
            auth_username: Some(OAUTH2_USER.into()),
            auth_oauth2_token: SecretKeyOptional::Value(SecretKeyValue {
                secret: OAUTH2_TOKEN.into(),
            }),
            port: relay_port as u64,
            protocol: MtaProtocol::Smtp,
            name: "oauth2".into(),
            ..Default::default()
        }))
        .await;
    local_admin.mta_no_auth().await;
    local_admin.mta_all_extensions().await;
    local_admin.reload_settings().await;
    local.reload_core();
    local.expect_reload_settings().await;

    local.server.ipv4_add(
        RELAY_NAME,
        vec!["127.0.0.1".parse().unwrap()],
        Instant::now() + Duration::from_secs(10),
    );

    let mut session = local.new_mta_session();
    session.data.remote_ip_str = "10.0.0.1".into();
    session.eval_session_params().await;
    session.ehlo("mx.test.org").await;
    session
        .send_message("john@test.org", &["bill@foobar.org"], "test:no_dkim", "250")
        .await;

    local
        .expect_message_then_deliver()
        .await
        .try_deliver(local.server.clone());

    let capture = tokio::time::timeout(Duration::from_secs(10), capture_rx)
        .await
        .expect("relay connection did not complete in time")
        .expect("relay task ended");

    let expected_payload = format!("user={OAUTH2_USER}\x01auth=Bearer {OAUTH2_TOKEN}\x01\x01");
    assert_eq!(
        capture.base64_auth_payload.as_deref(),
        Some(general_purpose::STANDARD.encode(&expected_payload).as_str()),
        "client must authenticate the relay with XOAUTH2 carrying the configured token"
    );
    let data = capture
        .data
        .expect("relay did not receive the message data");
    assert!(
        data.contains("Is dinner ready?"),
        "unexpected data body: {data:?}"
    );
}
