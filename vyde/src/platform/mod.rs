//! The service side: the platform port, over HTTP.
//!
//! This is the half that has nothing to do with a terminal, and it is a separate concern from the
//! interface for a reason that shows up as soon as somebody scripts it: the flow is useful without
//! anyone watching.

pub mod dto;
pub mod keyring;
/// Local file helpers for the backend photo upload.
pub mod photos;

use std::time::Duration;

use async_trait::async_trait;

use vyde_core::{
    Account, Address, CliError, PlatformPort, Result, Session, port::ManagementOperation,
};

use self::dto::{AccountDto, AddressDto, EmailsDto, ErrorBody, OrganizationDto};
use vyde_core::{Organization, port::AccountPatch};

#[derive(serde::Deserialize)]
struct OAuthTokenDto {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
    #[serde(default)]
    scope: String,
}

impl From<OAuthTokenDto> for Session {
    fn from(value: OAuthTokenDto) -> Self {
        Self {
            token: value.access_token,
            refresh_token: value.refresh_token,
            account_id: None,
            email: None,
            name: None,
            scope: Some(value.scope),
            expires_in: value.expires_in,
        }
    }
}

/// Talks to the platform through the gateway.
#[derive(Clone)]
pub struct HttpPlatform {
    http: reqwest::Client,
    base: String,
}

const CLI_METADATA_URL: &str = "https://docs.vyde.dev/.well-known/vyde-cli.json";

#[derive(serde::Deserialize)]
struct CliMetadata {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
}

fn validate_cli_metadata(metadata: CliMetadata) -> Result<String> {
    if metadata.client_id.trim().is_empty()
        || metadata.redirect_uri != "http://127.0.0.1:8675/callback"
        || !metadata.scopes.iter().any(|scope| scope == "openid")
        || !metadata
            .scopes
            .iter()
            .any(|scope| scope == "offline_access")
    {
        return Err(CliError::malformed(
            "CLI OAuth metadata has an invalid client configuration",
        ));
    }
    Ok(metadata.client_id)
}

impl HttpPlatform {
    /// Build against `base`, which must include the scheme.
    ///
    /// # Errors
    ///
    /// [`CliError::Unreachable`] for a URL that cannot be parsed. Checked here so a typo in an
    /// argument is a message and not a panic on the first request.
    pub fn new(base: &str) -> Result<Self> {
        let base = base.trim_end_matches('/').to_owned();
        reqwest::Url::parse(&base).map_err(|err| CliError::Unreachable {
            base: base.clone(),
            reason: format!("`{base}` is not a URL: {err}"),
        })?;

        let mut builder = reqwest::Client::builder()
            // A TUI that hangs with no way to say so is worse than one that fails. Fifteen seconds is
            // longer than any of these calls should take and short enough to be worth reporting.
            .timeout(Duration::from_secs(15))
            .user_agent(concat!("vyde-cli/", env!("CARGO_PKG_VERSION")));
        if base.contains("vyde.test") {
            let ca_path = std::env::var_os("VYDE_CA_CERT_PATH")
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    Some(std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../../services/certs/ca.crt"
                    )))
                });
            if let Some(path) = ca_path.filter(|path| path.is_file()) {
                let pem = std::fs::read(&path).map_err(|err| CliError::Unreachable {
                    base: base.clone(),
                    reason: format!("could not read development CA {}: {err}", path.display()),
                })?;
                let certificate =
                    reqwest::Certificate::from_pem(&pem).map_err(|err| CliError::Unreachable {
                        base: base.clone(),
                        reason: format!("could not parse development CA {}: {err}", path.display()),
                    })?;
                builder = builder.add_root_certificate(certificate);
            }
        }
        let http = builder.build().map_err(|err| CliError::Unreachable {
            base: base.clone(),
            reason: err.to_string(),
        })?;

        // Read once, here, and never again: a client that re-reads its bucket on every upload could
        // be pointed at a different bucket halfway through a session, and the account would end up
        // holding a URL that the current configuration can no longer explain.
        Ok(Self { http, base })
    }

    /// Where this points, for a header line.
    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    pub(crate) fn http(&self) -> &reqwest::Client {
        &self.http
    }

    pub(crate) async fn oauth_client_id(&self) -> Result<String> {
        let metadata_url = if cfg!(debug_assertions) {
            std::env::var("VYDE_CLI_METADATA_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| CLI_METADATA_URL.to_owned())
        } else {
            CLI_METADATA_URL.to_owned()
        };
        let response =
            self.http
                .get(&metadata_url)
                .send()
                .await
                .map_err(|err| CliError::Unreachable {
                    base: metadata_url.clone(),
                    reason: err.to_string(),
                })?;
        let status = response.status();
        let body = response.text().await.map_err(|err| CliError::Unreachable {
            base: metadata_url.clone(),
            reason: err.to_string(),
        })?;
        if !status.is_success() {
            return Err(CliError::refused(
                status.as_u16(),
                format!("could not load CLI OAuth metadata from {metadata_url}"),
                Some("cli_metadata_failed".to_owned()),
            ));
        }
        let metadata: CliMetadata = serde_json::from_str(&body)
            .map_err(|err| CliError::malformed(format!("invalid CLI OAuth metadata: {err}")))?;
        validate_cli_metadata(metadata)
    }

    /// Return the configured web interface URL.
    pub fn ui_base(&self) -> String {
        std::env::var("VYDE_IDENTITY_UI_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| {
                if self.base.contains("vyde.test") {
                    "https://identity.vyde.test:5173".to_owned()
                } else {
                    "https://identity.vyde.dev".to_owned()
                }
            })
    }

    /// Whether an upload could work, which is what decides if the interface offers it.
    /// Whether an upload could work, for a caller outside the [`PlatformPort`] trait.
    #[must_use]
    pub fn can_upload_photos(&self) -> bool {
        true
    }

    /// Send a request and decode it.
    ///
    /// One place, because the difference between "unreachable" and "refused" is the difference between
    /// telling the user to check the URL and telling them their password is wrong.
    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T> {
        let response = request.send().await.map_err(|err| CliError::Unreachable {
            base: self.base.clone(),
            reason: err.to_string(),
        })?;

        let status = response.status();
        let text = response.text().await.map_err(|err| CliError::Unreachable {
            base: self.base.clone(),
            reason: err.to_string(),
        })?;

        if !status.is_success() {
            // The platform writes its refusals for the caller. Prefer that over the status line:
            // "that password is wrong" is more use than "400 Bad Request".
            let body: ErrorBody = serde_json::from_str(&text).unwrap_or(ErrorBody {
                message: None,
                code: None,
            });
            return Err(CliError::Refused {
                status: status.as_u16(),
                message: body
                    .message
                    .unwrap_or_else(|| format!("the platform answered {status}")),
                code: body.code,
            });
        }

        serde_json::from_str(&text).map_err(|err| CliError::Malformed(err.to_string()))
    }

    /// Send a request whose success carries nothing to decode.
    ///
    /// A `DELETE` that removes an address answers with an empty body, and asking `send` for a `()`
    /// would make an empty `200` a parse failure — the success would read as an error, which is the
    /// worst possible inversion for the one operation whose whole point is that nothing came back.
    async fn send_expecting_nothing(&self, request: reqwest::RequestBuilder) -> Result<()> {
        let response = request.send().await.map_err(|err| CliError::Unreachable {
            base: self.base.clone(),
            reason: err.to_string(),
        })?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let text = response.text().await.map_err(|err| CliError::Unreachable {
            base: self.base.clone(),
            reason: err.to_string(),
        })?;
        let body: ErrorBody = serde_json::from_str(&text).unwrap_or(ErrorBody {
            message: None,
            code: None,
        });

        Err(CliError::Refused {
            status: status.as_u16(),
            message: body
                .message
                .unwrap_or_else(|| format!("the platform answered {status}")),
            code: body.code,
        })
    }

    /// `GET {path}`, as a caller of `self`.
    ///
    /// Beside [`HttpPlatform::patch`] and [`HttpPlatform::post`] because the bearer token is the one thing
    /// all three must remember and the one thing that is invisible when it is missing: the request
    /// succeeds, the platform answers `401`, and the error says "not authorised" rather than "you forgot".
    fn get(&self, path: &str, token: &str) -> reqwest::RequestBuilder {
        self.http
            .get(format!("{}{path}", self.base))
            .bearer_auth(token)
    }

    /// `POST {path}` with a JSON body, as a caller of `self`.
    fn post(&self, path: &str, token: &str, body: &serde_json::Value) -> reqwest::RequestBuilder {
        self.http
            .post(format!("{}{path}", self.base))
            .bearer_auth(token)
            .json(body)
    }

    /// `PATCH {path}` with a JSON body, as a caller of `self`.
    ///
    /// Three methods share this shape — update account, change password, rename organization — and
    /// writing it three times is how one of them ends up missing the bearer token.
    fn patch(&self, path: &str, token: &str, body: serde_json::Value) -> reqwest::RequestBuilder {
        self.http
            .patch(format!("{}{path}", self.base))
            .bearer_auth(token)
            .json(&body)
    }
}

#[async_trait]
impl PlatformPort for HttpPlatform {
    fn base(&self) -> &str {
        // The field, not the inherent method of the same name, so there is one place that knows the
        // answer rather than an inherent method that happens to agree with it today.
        &self.base
    }

    async fn account(&self, token: &str) -> Result<Account> {
        let decoded: AccountDto = self
            .send(
                self.http
                    .get(format!("{}/v1/accounts/me", self.base))
                    .bearer_auth(token),
            )
            .await?;

        Ok(decoded.into())
    }

    async fn update_account(&self, token: &str, patch: &AccountPatch<'_>) -> Result<Account> {
        // Only the fields that are set are serialized, by hand rather than by `skip_serializing_if`
        // on the port type: a patch is built by a form and the fields it does not mention must be
        // *absent from the JSON*, not present as null. The platform reads absence as "leave it".
        let mut body = serde_json::Map::new();
        if let Some(name) = patch.name {
            body.insert("name".into(), name.into());
        }
        if let Some(country) = patch.country {
            body.insert("country".into(), country.into());
        }
        if let Some(language) = patch.language {
            body.insert("language".into(), language.into());
        }
        if let Some(birthday) = patch.birthday {
            body.insert("birthday".into(), birthday.into());
        }
        // Added after `birthday` and not with it, which is the only way to find out it was missing: the
        // photo flow builds a patch whose *only* field is this one, so an empty body was refused by the
        // platform as "change nothing" — a refusal that reads like the upload failed, when the upload had
        // already succeeded and the object was sitting in the bucket.
        if let Some(photo_url) = patch.photo_url {
            body.insert("photo_url".into(), photo_url.into());
        }

        let decoded: AccountDto = self
            .send(self.patch("/v1/accounts/me", token, serde_json::Value::Object(body)))
            .await?;

        Ok(decoded.into())
    }

    async fn change_password(&self, token: &str, current: &str, new: &str) -> Result<()> {
        self.send_expecting_nothing(self.patch(
            "/v1/accounts/me/password",
            token,
            serde_json::json!({ "current_password": current, "new_password": new }),
        ))
        .await
    }

    async fn list_emails(&self, token: &str) -> Result<Vec<Address>> {
        let decoded: EmailsDto = self
            .send(
                self.http
                    .get(format!("{}/v1/accounts/me/emails", self.base))
                    .bearer_auth(token),
            )
            .await?;

        Ok(decoded.emails.into_iter().map(Into::into).collect())
    }

    async fn add_email(&self, token: &str, email: &str) -> Result<Address> {
        let decoded: AddressDto = self
            .send(
                self.http
                    .post(format!("{}/v1/accounts/me/emails", self.base))
                    .bearer_auth(token)
                    .json(&serde_json::json!({ "email": email })),
            )
            .await?;

        Ok(decoded.into())
    }

    async fn set_primary_email(&self, token: &str, email_id: &str) -> Result<Address> {
        let decoded: AddressDto = self
            .send(
                self.http
                    .put(format!(
                        "{}/v1/accounts/me/emails/{email_id}/primary",
                        self.base
                    ))
                    .bearer_auth(token),
            )
            .await?;

        Ok(decoded.into())
    }

    async fn remove_email(&self, token: &str, email_id: &str) -> Result<()> {
        self.send_expecting_nothing(
            self.http
                .delete(format!("{}/v1/accounts/me/emails/{email_id}", self.base))
                .bearer_auth(token),
        )
        .await
    }

    async fn create_organization(
        &self,
        token: &str,
        name: &str,
        slug: Option<&str>,
    ) -> Result<Organization> {
        // The slug is left out entirely when there is none, rather than sent as `null`. On the wire
        // `{"slug":null}` reads as "set the slug to nothing", which is not what "you decide" means, and
        // it only works today because the other side is lenient about null.
        let mut body = serde_json::json!({ "name": name });
        if let Some(slug) = slug {
            body["slug"] = serde_json::Value::String(slug.to_owned());
        }

        let decoded: OrganizationDto = self
            .send(self.post("/v1/organizations", token, &body))
            .await?;

        Ok(decoded.into())
    }

    async fn list_organizations(&self, token: &str) -> Result<Vec<Organization>> {
        let decoded: Vec<OrganizationDto> = self.send(self.get("/v1/organizations", token)).await?;

        Ok(decoded.into_iter().map(Into::into).collect())
    }

    async fn get_organization(&self, token: &str, organization_id: &str) -> Result<Organization> {
        let decoded: OrganizationDto = self
            .send(self.get(&format!("/v1/organizations/{organization_id}"), token))
            .await?;

        Ok(decoded.into())
    }

    async fn rename_organization(
        &self,
        token: &str,
        organization_id: &str,
        name: &str,
    ) -> Result<Organization> {
        let decoded: OrganizationDto = self
            .send(self.patch(
                &format!("/v1/organizations/{organization_id}"),
                token,
                serde_json::json!({ "name": name }),
            ))
            .await?;

        Ok(decoded.into())
    }

    async fn refresh(&self, refresh_token: &str) -> Result<Session> {
        let client_id = self.oauth_client_id().await?;
        let decoded: OAuthTokenDto = self
            .send(
                self.http
                    .post(format!("{}/oauth2/token", self.base))
                    .form(&[
                        ("grant_type", "refresh_token"),
                        ("client_id", client_id.as_str()),
                        ("refresh_token", refresh_token),
                    ]),
            )
            .await?;

        Ok(decoded.into())
    }

    async fn end_session(&self, refresh_token: Option<&str>) -> Result<()> {
        let _: serde_json::Value = self
            .send(
                self.http
                    .post(format!("{}/v1/auth/logout", self.base))
                    .json(&serde_json::json!({ "refresh_token": refresh_token })),
            )
            .await?;

        Ok(())
    }

    async fn manage(
        &self,
        token: &str,
        operation: &ManagementOperation,
    ) -> Result<serde_json::Value> {
        let response = match operation {
            ManagementOperation::UsernameAvailability { username } => self.http
                .get(format!("{}/v1/accounts/username-availability?username={}", self.base, urlencoding::encode(username)))
                .bearer_auth(token),
            ManagementOperation::SetUsername { username } => self.patch("/v1/accounts/me", token, serde_json::json!({ "username": username })),
            ManagementOperation::VerifyEmail { account_id, email_id, code } => self.http
                .post(format!("{}/v1/accounts/{account_id}/emails/{email_id}/verify", self.base))
                .bearer_auth(token)
                .json(&serde_json::json!({ "code": code })),
            ManagementOperation::ResendEmail { account_id, email_id } => self.http
                .post(format!("{}/v1/accounts/{account_id}/emails/{email_id}/resend", self.base))
                .bearer_auth(token),
            ManagementOperation::ListGrants => self.get("/v1/grants", token),
            ManagementOperation::RevokeGrant { client_id } => self.http
                .delete(format!("{}/v1/grants/{client_id}", self.base))
                .bearer_auth(token),
            ManagementOperation::ListMembers { organization_id } => self.get(&format!("/v1/organizations/{organization_id}/members"), token),
            ManagementOperation::AddMember { organization_id, account_id, role } => self.http
                .post(format!("{}/v1/organizations/{organization_id}/members", self.base))
                .bearer_auth(token)
                .json(&serde_json::json!({ "account_id": account_id, "role": role })),
            ManagementOperation::RemoveMember { organization_id, account_id } => self.http
                .delete(format!("{}/v1/organizations/{organization_id}/members/{account_id}", self.base))
                .bearer_auth(token),
            ManagementOperation::ChangeMemberRole { organization_id, account_id, role } => self.patch(
                &format!("/v1/organizations/{organization_id}/members/{account_id}"),
                token,
                serde_json::json!({ "role": role }),
            ),
            ManagementOperation::LeaveOrganization { organization_id } => self.http
                .post(format!("{}/v1/organizations/{organization_id}/leave", self.base))
                .bearer_auth(token),
            ManagementOperation::CreateInvitation { organization_id, role, expires_in_seconds, max_uses } => self.http
                .post(format!("{}/v1/organizations/{organization_id}/invitations", self.base))
                .bearer_auth(token)
                .json(&serde_json::json!({ "role": role, "expires_in_seconds": expires_in_seconds, "max_uses": max_uses })),
            ManagementOperation::ListInvitations { organization_id } => self.get(&format!("/v1/organizations/{organization_id}/invitations"), token),
            ManagementOperation::RevokeInvitation { organization_id, invitation_id } => self.http
                .delete(format!("{}/v1/organizations/{organization_id}/invitations/{invitation_id}", self.base))
                .bearer_auth(token),
            ManagementOperation::RegenerateInvitation { organization_id, invitation_id } => self.http
                .post(format!("{}/v1/organizations/{organization_id}/invitations/{invitation_id}", self.base))
                .bearer_auth(token),
            ManagementOperation::PreviewInvitation { token: invite } => self.http
                .post(format!("{}/v1/organizations/invitations/preview", self.base))
                .json(&serde_json::json!({ "token": invite })),
            ManagementOperation::AcceptInvitation { token: invite } => self.http
                .post(format!("{}/v1/organizations/invitations/accept", self.base))
                .bearer_auth(token)
                .json(&serde_json::json!({ "token": invite })),
            ManagementOperation::ListApplications { organization_id } => self.get(&format!("/v1/organizations/{organization_id}/clients"), token),
            ManagementOperation::CreateApplication { organization_id, body } => self.http
                .post(format!("{}/v1/organizations/{organization_id}/clients", self.base))
                .bearer_auth(token)
                .json(body),
            ManagementOperation::UpdateApplication { organization_id, client_id, body } => self.patch(
                &format!("/v1/organizations/{organization_id}/clients/{client_id}"),
                token,
                body.clone(),
            ),
            ManagementOperation::DeleteApplication { organization_id, client_id } => self.http
                .delete(format!("{}/v1/organizations/{organization_id}/clients/{client_id}", self.base))
                .bearer_auth(token),
            ManagementOperation::RegenerateApplicationSecret { organization_id, client_id } => self.http
                .post(format!("{}/v1/organizations/{organization_id}/clients/{client_id}/secret", self.base))
                .bearer_auth(token),
        };
        if matches!(
            operation,
            ManagementOperation::RevokeGrant { .. }
                | ManagementOperation::RemoveMember { .. }
                | ManagementOperation::RevokeInvitation { .. }
                | ManagementOperation::LeaveOrganization { .. }
                | ManagementOperation::DeleteApplication { .. }
        ) {
            self.send_expecting_nothing(response).await?;
            Ok(serde_json::Value::Null)
        } else {
            self.send(response).await
        }
    }

    /// To R2, not through the gateway — the gateway routes identity, and a bucket is not an upstream.
    ///
    /// The URL it hands back is built from the *public* base rather than the S3 endpoint, because an
    /// account's `photo_url` is read by somebody else's `<img src>`: an S3 endpoint URL with a signature
    /// requirement on it is a URL that renders broken in every consumer that is not the uploader.
    async fn upload_profile_photo(
        &self,
        session: &Session,
        bytes: &[u8],
        filename: &str,
        content_type: &str,
    ) -> Result<Account> {
        let response = self
            .http
            .post(format!("{}/v1/accounts/me/photo", self.base))
            .bearer_auth(&session.token)
            .multipart(
                reqwest::multipart::Form::new().part(
                    "photo",
                    reqwest::multipart::Part::bytes(bytes.to_vec())
                        .file_name(filename.to_owned())
                        .mime_str(content_type)
                        .map_err(|error| CliError::Malformed(error.to_string()))?,
                ),
            );
        self.send(response).await
    }

    /// Whether a bucket was configured at construction.
    ///
    /// Free rather than a call on the field, so the interface reads it once on the ping and then holds a
    /// plain bool: the answer cannot change while the process runs, because the configuration is read
    /// once — for the same reason the credential is.
    fn can_upload_photos(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{CliMetadata, validate_cli_metadata};

    fn metadata() -> CliMetadata {
        CliMetadata {
            client_id: "cli-client".to_owned(),
            redirect_uri: "http://127.0.0.1:8675/callback".to_owned(),
            scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        }
    }

    #[test]
    fn accepts_valid_metadata() {
        assert_eq!(validate_cli_metadata(metadata()).unwrap(), "cli-client");
    }

    #[test]
    fn rejects_invalid_metadata_fields() {
        let mut invalid = metadata();
        invalid.client_id.clear();
        assert!(validate_cli_metadata(invalid).is_err());

        let mut invalid = metadata();
        invalid.redirect_uri = "http://localhost/callback".to_owned();
        assert!(validate_cli_metadata(invalid).is_err());

        let mut invalid = metadata();
        invalid.scopes = vec!["profile".to_owned()];
        assert!(validate_cli_metadata(invalid).is_err());
    }
}
