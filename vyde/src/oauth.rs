//! Browser-based OAuth login.

use std::process::Command;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    time::{Duration, timeout},
};
use vyde_core::{CliError, Result, Session};

use crate::{ipc, platform::HttpPlatform, platform::keyring};
use vyde_core::channel::{Request, Response};

const CALLBACK_PORT: u16 = 8675;
const UI_PATH: &str = "/oauth2/authorize";

/// Open the browser and complete the OAuth authorization flow.
pub async fn login(platform: &HttpPlatform) -> std::process::ExitCode {
    match run_login(platform).await {
        Ok(session) => {
            if let Err(err) = keyring::store_session(&session) {
                eprintln!(
                    "vyde: authenticated, but could not store the session: {}",
                    err.short()
                );
                return std::process::ExitCode::FAILURE;
            }
            if let Err(err) = sync_service(platform, session).await {
                eprintln!("vyde: authenticated, but could not update the local service: {err}");
                return std::process::ExitCode::FAILURE;
            }
            println!("signed in; the session is stored for this user");
            std::process::ExitCode::SUCCESS
        }

        Err(err) => {
            eprintln!("vyde: {}", err.short());
            std::process::ExitCode::FAILURE
        }
    }
}

async fn sync_service(platform: &HttpPlatform, session: Session) -> std::io::Result<()> {
    let mut client = ipc::Client::connect(&ipc::socket_path(), Some(platform.base())).await?;
    match client.ask(&Request::InstallSession(session)).await? {
        Response::SessionLoaded => Ok(()),
        response => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("the service returned an unexpected response: {response:?}"),
        )),
    }
}

async fn run_login(platform: &HttpPlatform) -> Result<Session> {
    let listener = TcpListener::bind(("127.0.0.1", CALLBACK_PORT))
        .await
        .map_err(|err| CliError::missing(format!("could not bind OAuth callback: {err}")))?;
    let verifier = random_value();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_value();
    let redirect_uri = format!("http://127.0.0.1:{CALLBACK_PORT}/callback");
    let client_id = platform.oauth_client_id().await?;
    let mut url = reqwest::Url::parse(&format!("{}{}", platform.ui_base(), UI_PATH))
        .map_err(|err| CliError::malformed(format!("invalid interface URL: {err}")))?;
    url.query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid profile email offline_access")
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");

    open_browser(url.as_str())?;
    eprintln!("vyde: waiting for browser authorization...");

    let (stream, _) = timeout(Duration::from_secs(300), listener.accept())
        .await
        .map_err(|_| CliError::missing("timed out waiting for OAuth authorization"))?
        .map_err(CliError::from_io)?;
    let (reader, mut writer) = stream.into_split();
    let mut request_line = String::new();
    BufReader::new(reader)
        .read_line(&mut request_line)
        .await
        .map_err(CliError::from_io)?;
    let target = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| CliError::malformed("the OAuth callback was not an HTTP request"))?;
    let callback = reqwest::Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|err| CliError::malformed(format!("invalid OAuth callback: {err}")))?;
    if callback.path() != "/callback"
        || callback
            .query_pairs()
            .find(|(key, value)| key == "state" && value == &state)
            .is_none()
    {
        return Err(CliError::refused(
            400,
            "OAuth state did not match",
            Some("invalid_state".to_owned()),
        ));
    }

    if let Some(error) = callback.query_pairs().find(|(key, _)| key == "error") {
        return Err(CliError::refused(
            400,
            error.1.to_string(),
            Some("oauth_denied".to_owned()),
        ));
    }
    let code = callback
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .ok_or_else(|| CliError::malformed("the OAuth callback did not contain a code"))?;
    writer
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nAuthorization complete. You can close this window.",
        )
        .await
        .map_err(CliError::from_io)?;

    let response = platform
        .http()
        .post(format!("{}/oauth2/token", platform.base()))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .map_err(|err| CliError::Unreachable {
            base: platform.base().to_owned(),
            reason: err.to_string(),
        })?;
    let status = response.status();
    let body = response.text().await.map_err(|err| CliError::Unreachable {
        base: platform.base().to_owned(),
        reason: err.to_string(),
    })?;
    if !status.is_success() {
        return Err(CliError::refused(
            status.as_u16(),
            body,
            Some("oauth_token_failed".to_owned()),
        ));
    }
    let token: TokenResponse = serde_json::from_str(&body)
        .map_err(|err| CliError::malformed(format!("invalid OAuth token response: {err}")))?;
    Ok(Session {
        token: token.access_token,
        refresh_token: token.refresh_token,
        account_id: None,
        email: None,
        name: None,
        scope: Some(token.scope),
        expires_in: token.expires_in,
    })
}

fn random_value() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    let command = ("xdg-open", url);
    #[cfg(target_os = "macos")]
    let command = ("open", url);
    #[cfg(target_os = "windows")]
    let command = ("cmd", &format!("/C start {url}"));
    Command::new(command.0)
        .arg(command.1)
        .spawn()
        .map(|_| ())
        .map_err(|err| CliError::missing(format!("could not open the browser: {err}")))
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
    #[serde(default)]
    scope: String,
}
