/*
 * SPDX-FileCopyrightText: 2026 Jameson
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

//! Outbound OAuth2 token provider for SMTP relay authentication.
//!
//! Supplies a valid access token for a configured relay so the outbound SMTP
//! client can authenticate with `XOAUTH2`/`OAUTHBEARER`. A static token is
//! returned as-is; otherwise the provider fetches and caches a token from the
//! configured token endpoint using the `refresh_token` or `client_credentials`
//! grant.

use std::{
    hash::{Hash, Hasher},
    ops::Add,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use utils::http::http_client_builder;

const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Refresh margin: a cached token is re-fetched this long before expiry so
/// deliveries never attempt AUTH with a token that expires mid-session.
const CACHE_SKEW: Duration = Duration::from_secs(60);
const DEFAULT_EXPIRES_IN: u64 = 3600;

/// Failure to obtain an access token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Oauth2Error {
    /// The failure is likely transient (network error, 5xx, timeout) — the
    /// queue should retry.
    Temporary(String),
    /// The failure is permanent (bad credentials, rejected grant) — retrying
    /// without operator action will not succeed.
    Permanent(String),
}

impl std::fmt::Display for Oauth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Oauth2Error::Temporary(msg) => write!(f, "OAuth2 token error: {msg}"),
            Oauth2Error::Permanent(msg) => write!(f, "OAuth2 token error: {msg}"),
        }
    }
}

/// Resolved OAuth2 configuration for a relay. All secret material is resolved
/// to plain values at bootstrap time; `Debug` reports only whether each secret
/// is present.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Oauth2Config {
    /// Identity advertised in the XOAUTH2 `user=` field.
    pub username: Option<String>,
    /// Static access token; when present it takes precedence over the token
    /// endpoint.
    pub token: Option<String>,
    /// OAuth2 token endpoint; when present a token is fetched and cached from
    /// it.
    pub token_url: Option<String>,
    /// Refresh token for the `refresh_token` grant.
    pub refresh_token: Option<String>,
    /// Client id for `client_credentials` grant (and to harden the refresh
    /// grant).
    pub client_id: Option<String>,
    /// Client secret for `client_credentials` grant.
    pub client_secret: Option<String>,
    /// Scope requested on the token endpoint.
    pub scope: Option<String>,
}

impl std::fmt::Debug for Oauth2Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oauth2Config")
            .field("username", &self.username)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("token_url", &self.token_url)
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "<redacted>"))
            .field("client_id", &self.client_id)
            .field("client_secret", &self.client_secret.as_ref().map(|_| "<redacted>"))
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Default)]
struct TokenCache {
    token: Option<String>,
    expires_at: Option<Instant>,
    /// The current refresh token — token endpoints may rotate it on each use.
    refresh_token: Option<String>,
}

struct Oauth2Inner {
    config: Oauth2Config,
    client: reqwest::Client,
    cache: Mutex<TokenCache>,
}

/// Token provider for one relay route. Cheap to clone; clones of the same
/// route share the token cache and, value-wise, compare equal.
#[derive(Clone)]
pub struct OutboundOauth2 {
    inner: std::sync::Arc<Oauth2Inner>,
}

impl OutboundOauth2 {
    /// Builds a provider from resolved config. Returns `None` when the route
    /// has no usable OAuth2 configuration (neither a static token nor a token
    /// endpoint) — the caller should then fall back to basic auth or no auth.
    pub fn try_new(config: &Oauth2Config) -> Option<Self> {
        if config.token.is_none() && config.token_url.is_none() {
            return None;
        }

        Some(Self {
            inner: std::sync::Arc::new(Oauth2Inner {
                config: config.clone(),
                client: http_client_builder(false)
                    .timeout(TOKEN_REQUEST_TIMEOUT)
                    .build()
                    .unwrap_or_default(),
                cache: Mutex::new(TokenCache {
                    token: None,
                    expires_at: None,
                    refresh_token: config.refresh_token.clone(),
                }),
            }),
        })
    }

    /// Identity for the XOAUTH2 `user=` field.
    pub fn username(&self) -> Option<&str> {
        self.inner.config.username.as_deref()
    }

    /// Returns a valid access token, fetching and caching one from the token
    /// endpoint when necessary.
    pub async fn access_token(&self) -> Result<String, Oauth2Error> {
        if let Some(token) = &self.inner.config.token {
            return Ok(token.clone());
        }

        let token_url =
            self.inner.config.token_url.clone().ok_or_else(|| {
                Oauth2Error::Permanent("no OAuth2 token endpoint configured".into())
            })?;

        let mut cache = self.inner.cache.lock().await;
        if let (Some(token), Some(expires_at)) = (cache.token.clone(), cache.expires_at)
            && expires_at > Instant::now().add(CACHE_SKEW)
        {
            return Ok(token);
        }

        let config = &self.inner.config;
        // Copy values out of the cache first: the fetch needs mutable access
        // to it, so the request fields must be owned.
        let refresh_token = cache
            .refresh_token
            .as_deref()
            .or(config.refresh_token.as_deref())
            .map(str::to_string);

        let mut fields: Vec<String> = Vec::new();
        if let Some(refresh_token) = refresh_token {
            fields.push("grant_type=refresh_token".into());
            fields.push(format!("refresh_token={}", percent_encode(&refresh_token)));
            if let Some(client_id) = &config.client_id {
                fields.push(format!("client_id={}", percent_encode(client_id)));
            }
            if let Some(client_secret) = &config.client_secret {
                fields.push(format!("client_secret={}", percent_encode(client_secret)));
            }
            if let Some(scope) = &config.scope {
                fields.push(format!("scope={}", percent_encode(scope)));
            }
        } else if let (Some(client_id), Some(client_secret)) =
            (&config.client_id, &config.client_secret)
        {
            fields.push("grant_type=client_credentials".into());
            fields.push(format!("client_id={}", percent_encode(client_id)));
            fields.push(format!("client_secret={}", percent_encode(client_secret)));
            if let Some(scope) = &config.scope {
                fields.push(format!("scope={}", percent_encode(scope)));
            }
        } else {
            return Err(Oauth2Error::Permanent(
                "OAuth2 route has neither a refresh token nor client credentials".to_string(),
            ));
        }

        // Token is stale or absent: fetch a fresh one from the endpoint.
        self.fetch(&fields.join("&"), &token_url, &mut cache)
            .await?;
        cache
            .token
            .clone()
            .ok_or_else(|| Oauth2Error::Permanent("token endpoint returned no access token".into()))
    }

    async fn fetch(
        &self,
        form_body: &str,
        token_url: &str,
        cache: &mut TokenCache,
    ) -> Result<(), Oauth2Error> {
        let response = self
            .inner
            .client
            .post(token_url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form_body.to_string())
            .send()
            .await
            .map_err(|err| Oauth2Error::Temporary(format!("token endpoint unreachable: {err}")))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return if (400..500).contains(&status.as_u16()) {
                Err(Oauth2Error::Permanent(format!(
                    "token endpoint rejected the grant ({} {})",
                    status, body
                )))
            } else {
                Err(Oauth2Error::Temporary(format!(
                    "token endpoint failed ({} {})",
                    status, body
                )))
            };
        }

        let payload: TokenResponse =
            serde_json::from_str(&response.text().await.unwrap_or_default()).map_err(|err| {
                Oauth2Error::Temporary(format!("invalid token endpoint response: {err}"))
            })?;

        cache.token = Some(payload.access_token);
        cache.expires_at = Some(
            Instant::now() + Duration::from_secs(payload.expires_in.unwrap_or(DEFAULT_EXPIRES_IN)),
        );
        if let Some(refresh_token) = payload.refresh_token {
            cache.refresh_token = Some(refresh_token);
        }

        Ok(())
    }
}

const FORM_UNRESERVED: &[u8; 66] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";

/// Percent-encodes a form field value (`application/x-www-form-urlencoded`).
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if FORM_UNRESERVED.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl std::fmt::Debug for OutboundOauth2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundOauth2")
            .field("config", &self.inner.config)
            .finish()
    }
}

impl PartialEq for OutboundOauth2 {
    fn eq(&self, other: &Self) -> bool {
        self.inner.config == other.inner.config
    }
}

impl Eq for OutboundOauth2 {}

impl Hash for OutboundOauth2 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.config.hash(state);
    }
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
    refresh_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    /// Minimal real HTTP/1.1 token endpoint used by the tests. Serves the
    /// queued responses in order (looping the last one) and records every
    /// request body.
    struct FakeTokenServer {
        addr: SocketAddr,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
    }

    async fn start_fake_token_server(responses: Vec<(u16, String)>) -> FakeTokenServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let worker_requests = requests.clone();
        tokio::spawn(async move {
            let responses = Arc::new(responses);
            let counter = Arc::new(AtomicUsize::new(0));
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let counter = counter.clone();
                let responses = responses.clone();
                let requests = worker_requests.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, responses, counter, requests).await;
                });
            }
        });
        FakeTokenServer { addr, requests }
    }

    async fn handle_connection(
        mut stream: TcpStream,
        responses: Arc<Vec<(u16, String)>>,
        counter: Arc<AtomicUsize>,
        requests: Arc<std::sync::Mutex<Vec<String>>>,
    ) -> std::io::Result<()> {
        let mut buf = [0u8; 8192];
        let mut data = Vec::new();
        // Read the full request (headers + body) until the declared
        // content-length is satisfied.
        loop {
            let n = match stream.read(&mut buf).await {
                Ok(n) if n > 0 => n,
                _ => return Ok(()),
            };
            data.extend_from_slice(&buf[..n]);
            if let Some(header_end) = find_subslice(&data, b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&data[..header_end]).to_ascii_lowercase();
                let declared = headers
                    .split("\r\n")
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if data.len() >= header_end + 4 + declared {
                    break;
                }
            }
        }
        let body_start = find_subslice(&data, b"\r\n\r\n")
            .map(|p| p + 4)
            .unwrap_or(0);
        let body = String::from_utf8_lossy(&data[body_start..]).into_owned();
        requests.lock().unwrap().push(body);

        // Serve the queued response, or the last one for extra requests.
        let idx = counter
            .fetch_add(1, Ordering::SeqCst)
            .min(responses.len() - 1);
        let (status, payload) = &responses[idx];
        let response = format!(
            "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            status_reason(*status),
            payload.len(),
            payload,
        );
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await?;
        Ok(())
    }

    fn status_reason(status: u16) -> &'static str {
        match status {
            200 => "200 OK",
            301 => "301 Moved Permanently",
            400 => "400 Bad Request",
            401 => "401 Unauthorized",
            403 => "403 Forbidden",
            404 => "404 Not Found",
            429 => "429 Too Many Requests",
            500 => "500 Internal Server Error",
            _ => "000",
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn config() -> Oauth2Config {
        Oauth2Config {
            username: None,
            token: None,
            token_url: None,
            refresh_token: None,
            client_id: None,
            client_secret: None,
            scope: None,
        }
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let mut config = config();
        config.username = Some("user@example.org".into());
        config.token = Some("static-secret".into());
        config.refresh_token = Some("refresh-secret".into());
        config.client_secret = Some("client-secret".into());
        let provider = OutboundOauth2::try_new(&config).unwrap();
        let rendered = format!("{provider:?}");
        for secret in ["static-secret", "refresh-secret", "client-secret"] {
            assert!(!rendered.contains(secret), "{rendered} leaks {secret}");
        }
        assert!(rendered.contains("user@example.org"), "{rendered}");
    }

    #[tokio::test]
    async fn static_token_needs_no_endpoint() {
        let mut config = config();
        config.token = Some("static-token".into());
        let provider = OutboundOauth2::try_new(&config).unwrap();
        assert_eq!(provider.access_token().await.unwrap(), "static-token");
    }

    #[tokio::test]
    async fn no_token_and_no_endpoint_gives_no_provider() {
        let config = config();
        assert!(OutboundOauth2::try_new(&config).is_none());
    }

    #[tokio::test]
    async fn refresh_grant_fetches_and_caches_token() {
        let server = start_fake_token_server(vec![(
            200,
            r#"{"access_token":"tok-1","expires_in":3600}"#.into(),
        )])
        .await;
        let mut config = config();
        config.token_url = Some(format!("http://{}/token", server.addr));
        config.refresh_token = Some("refresh-1".into());
        config.client_id = Some("client-1".into());
        config.client_secret = Some("secret-1".into());
        config.scope = Some("https://mail.example.org/".into());
        let provider = OutboundOauth2::try_new(&config).unwrap();

        assert_eq!(provider.access_token().await.unwrap(), "tok-1");
        // Second call must be served from the cache: no new HTTP request.
        assert_eq!(provider.access_token().await.unwrap(), "tok-1");
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let sent = &requests[0];
        for expected in [
            "grant_type=refresh_token",
            "refresh_token=refresh-1",
            "client_id=client-1",
            "client_secret=secret-1",
            "scope=https%3A%2F%2Fmail.example.org%2F",
        ] {
            assert!(
                sent.contains(expected),
                "request {sent:?} missing {expected}"
            );
        }
    }

    #[tokio::test]
    async fn expired_token_is_refetched_with_rotated_refresh_token() {
        let server = start_fake_token_server(vec![
            (
                200,
                r#"{"access_token":"tok-1","expires_in":1,"refresh_token":"refresh-2"}"#.into(),
            ),
            (200, r#"{"access_token":"tok-2","expires_in":3600}"#.into()),
        ])
        .await;
        let mut config = config();
        config.token_url = Some(format!("http://{}/token", server.addr));
        config.refresh_token = Some("refresh-1".into());
        let provider = OutboundOauth2::try_new(&config).unwrap();

        assert_eq!(provider.access_token().await.unwrap(), "tok-1");
        // expires_in=1 means the token is already within the refresh skew.
        assert_eq!(provider.access_token().await.unwrap(), "tok-2");
        let requests = server.requests.lock().unwrap();
        // The second request must present the rotated refresh token.
        assert_eq!(requests.len(), 2);
        assert!(
            requests[1].contains("refresh_token=refresh-2"),
            "{:?}",
            requests[1]
        );
    }

    #[tokio::test]
    async fn client_credentials_grant_when_no_refresh_token() {
        let server = start_fake_token_server(vec![(
            200,
            r#"{"access_token":"ccb-tok","expires_in":1800}"#.into(),
        )])
        .await;
        let mut config = config();
        config.token_url = Some(format!("http://{}/token", server.addr));
        config.client_id = Some("client-1".into());
        config.client_secret = Some("secret-1".into());
        let provider = OutboundOauth2::try_new(&config).unwrap();

        assert_eq!(provider.access_token().await.unwrap(), "ccb-tok");
        let requests = server.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].contains("grant_type=client_credentials"),
            "{:?}",
            requests[0]
        );
        assert!(
            requests[0].contains("client_id=client-1"),
            "{:?}",
            requests[0]
        );
        assert!(
            requests[0].contains("client_secret=secret-1"),
            "{:?}",
            requests[0]
        );
    }

    #[tokio::test]
    async fn rejected_grant_is_permanent_error() {
        let server =
            start_fake_token_server(vec![(400, r#"{"error":"invalid_grant"}"#.into())]).await;
        let mut config = config();
        config.token_url = Some(format!("http://{}/token", server.addr));
        config.refresh_token = Some("bad-refresh".into());
        let provider = OutboundOauth2::try_new(&config).unwrap();

        let err = provider.access_token().await.unwrap_err();
        assert!(matches!(err, Oauth2Error::Permanent(_)), "{err:?}");
        let err = provider.access_token().await.unwrap_err();
        assert!(matches!(err, Oauth2Error::Permanent(_)), "{err:?}");
    }

    #[tokio::test]
    async fn server_failure_is_transient_error() {
        let server = start_fake_token_server(vec![(500, r#"{"error":"boom"}"#.into())]).await;
        let mut config = config();
        config.token_url = Some(format!("http://{}/token", server.addr));
        config.refresh_token = Some("refresh-1".into());
        let provider = OutboundOauth2::try_new(&config).unwrap();

        let err = provider.access_token().await.unwrap_err();
        assert!(matches!(err, Oauth2Error::Temporary(_)), "{err:?}");
    }
}
