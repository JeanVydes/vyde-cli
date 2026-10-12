//! The HTTP adapter: the one place that knows the platform's wire shapes.
//!
//! Everything goes through the gateway, never straight to identity. Not a style choice — identity is
//! meant to be unreachable from outside, and a client that could bypass the gateway could also bypass
//! whatever the gateway strips.
//!
//! # Why the DTOs are here and not in `core`
//!
//! `core` speaks in [`Account`](vyde_core::Account) and [`Session`](vyde_core::Session). This file
//! is where those become JSON. The split is what lets the flow's tests run with a fake and no socket,
//! and it is also where a rename on the platform lands: one file, not the flow, the form and the
//! drawing.

use serde::Deserialize;

/// The account as the platform renders it.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct AccountDto {
    pub id: String,
    pub name: String,
    pub country: String,
    pub language: String,
    pub birthday: String,
    pub status: String,
    #[serde(default)]
    pub primary_email: Option<AddressDto>,
    /// Absent on a platform that has no photo column, and on any account without one — both are
    /// `None` here and the difference is not this client's business.
    #[serde(default)]
    pub photo_url: Option<String>,
}

/// One address.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct AddressDto {
    pub id: String,
    pub email: String,
    pub verified: bool,
    /// `primary`, not `is_primary`: this is the platform's spelling and getting it wrong would leave
    /// every address reading as secondary, which quietly hides the one that cannot be removed.
    #[serde(default)]
    pub primary: bool,
}

/// The platform's list of an account's addresses.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct EmailsDto {
    pub emails: Vec<AddressDto>,
}

/// An organization, as the platform reports it.
#[derive(Clone, Debug, Deserialize)]
pub(super) struct OrganizationDto {
    pub id: String,
    pub name: String,
    pub slug: String,
}

impl From<OrganizationDto> for vyde_core::Organization {
    fn from(dto: OrganizationDto) -> Self {
        Self {
            id: dto.id,
            name: dto.name,
            slug: dto.slug,
        }
    }
}

impl From<AddressDto> for vyde_core::Address {
    fn from(dto: AddressDto) -> Self {
        Self {
            id: dto.id,
            email: dto.email,
            verified: dto.verified,
            primary: dto.primary,
        }
    }
}

impl From<AccountDto> for vyde_core::Account {
    fn from(dto: AccountDto) -> Self {
        Self {
            id: dto.id,
            name: dto.name,
            country: dto.country,
            language: dto.language,
            birthday: dto.birthday,
            status: dto.status,
            photo_url: dto.photo_url,
            primary_email: dto.primary_email.map(Into::into),
        }
    }
}

/// An OAuth token response.
#[derive(Debug, Deserialize)]
pub(super) struct LoginDto {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub expires_in: u64,
}

impl From<LoginDto> for vyde_core::Session {
    fn from(dto: LoginDto) -> Self {
        Self {
            token: dto.access_token,
            refresh_token: dto.refresh_token,
            account_id: dto.account_id,
            email: dto.email,
            name: dto.name,
            scope: dto.scope,
            expires_in: dto.expires_in,
        }
    }
}

/// The envelope every error arrives in.
#[derive(Debug, Deserialize)]
pub(super) struct ErrorBody {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

#[cfg(all(test, feature = "legacy-auth-tests"))]
mod tests {
    use super::*;

    /// The shape this adapter was written against. A change on the platform fails here rather than at
    /// a form that cannot read the answer.
    #[test]
    fn a_registration_response_decodes() {
        let json = r#"{
            "account": {
                "id": "acct-1", "name": "Someone", "country": "UY", "language": "es",
                "birthday": "1990-04-17", "status": "active",
                "primary_email": {
                    "id": "addr-1", "account_id": "acct-1", "email": "a@example.test",
                    "primary": true, "verified": false, "verified_at": null,
                    "created_at": "2026-10-05T21:49:19Z"
                },
                "created_at": "2026-10-05T21:49:19Z", "updated_at": "2026-10-05T21:49:19Z"
            },
            "primary_email": {
                "id": "addr-1", "account_id": "acct-1", "email": "a@example.test",
                "primary": true, "verified": false, "verified_at": null,
                "created_at": "2026-10-05T21:49:19Z"
            },
            "email_verification_required": true,
            "access_token": null, "token_type": null, "expires_in": null, "refresh_token": null
        }"#;

        let decoded: RegistrationDto =
            serde_json::from_str(json).expect("the platform's shape decodes");

        let account: vyde_core::Account = decoded.account.into();
        assert_eq!(account.name, "Someone");
        assert!(!account.is_verified());
        assert_eq!(decoded.primary_email.expect("an address").id, "addr-1");
    }

    /// A client that required `id_token` would break on every third party login, where `openid` was
    /// never granted.
    #[test]
    fn a_login_without_an_id_token_decodes() {
        let json = r#"{
            "access_token": "eyJ", "token_type": "Bearer", "expires_in": 900,
            "refresh_token": "abc", "scope": "openid profile",
            "subject": "account:1", "account_id": "1", "email": "a@example.test",
            "name": null, "claims": ["openid", "profile"]
        }"#;

        let decoded: LoginDto = serde_json::from_str(json).expect("decodes");
        let session: vyde_core::Session = decoded.into();

        assert_eq!(session.expires_in, 900);
        assert_eq!(session.scope.as_deref(), Some("openid profile"));
    }

    /// Production carries no code, and the flow has to work without one.
    #[test]
    fn a_resend_without_a_dev_code_decodes() {
        let json = r#"{
            "email": {
                "id": "addr-1", "account_id": "acct-1", "email": "a@example.test",
                "primary": true, "verified": false, "verified_at": null,
                "created_at": "2026-10-05T21:49:19Z"
            },
            "expires_in": 900, "attempts_remaining": 3
        }"#;

        let decoded: ResendDto = serde_json::from_str(json).expect("decodes");
        assert!(decoded.dev_code.is_none());
        assert_eq!(decoded.attempts_remaining, 3);
    }

    #[test]
    fn an_error_body_decodes_to_a_message() {
        let json =
            r#"{"error":"Unauthorized","code":"unauthenticated","message":"invalid credentials"}"#;
        let decoded: ErrorBody = serde_json::from_str(json).expect("decodes");

        assert_eq!(decoded.message.as_deref(), Some("invalid credentials"));
    }

    /// What registration answers. Its own type because the interesting field is not the account but
    /// the fact that no credential came with it.
    #[derive(Debug, Deserialize)]
    struct RegistrationDto {
        account: AccountDto,
        #[serde(default)]
        primary_email: Option<AddressDto>,
    }
}
