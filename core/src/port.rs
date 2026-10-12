//! The port: everything the flow needs from the outside world, as five calls.
//!
//! `async_trait` rather than a native `async fn` in the trait, for `dyn` compatibility — the
//! composition root holds `Arc<dyn PlatformPort>` and a test holds a fake, and a generic service would
//! force that choice at every call site instead of once.
//!
//! The signatures are in terms of domain types, not wire shapes. That is what lets [`AuthService`]
//! and its tests exist without knowing that any of this is HTTP.

use async_trait::async_trait;

use crate::{
    account::{Account, Address, Session},
    error::Result,
    organization::Organization,
};

#[allow(missing_docs)]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ManagementOperation {
    UsernameAvailability {
        username: String,
    },
    SetUsername {
        username: String,
    },
    VerifyEmail {
        account_id: String,
        email_id: String,
        code: String,
    },
    ResendEmail {
        account_id: String,
        email_id: String,
    },
    ListGrants,
    RevokeGrant {
        client_id: String,
    },
    ListMembers {
        organization_id: String,
    },
    AddMember {
        organization_id: String,
        account_id: String,
        role: String,
    },
    RemoveMember {
        organization_id: String,
        account_id: String,
    },
    ChangeMemberRole {
        organization_id: String,
        account_id: String,
        role: String,
    },
    LeaveOrganization {
        organization_id: String,
    },
    CreateInvitation {
        organization_id: String,
        role: String,
        expires_in_seconds: i64,
        max_uses: i32,
    },
    ListInvitations {
        organization_id: String,
    },
    RevokeInvitation {
        organization_id: String,
        invitation_id: String,
    },
    RegenerateInvitation {
        organization_id: String,
        invitation_id: String,
    },
    PreviewInvitation {
        token: String,
    },
    AcceptInvitation {
        token: String,
    },
    ListApplications {
        organization_id: String,
    },
    CreateApplication {
        organization_id: String,
        body: serde_json::Value,
    },
    UpdateApplication {
        organization_id: String,
        client_id: String,
        body: serde_json::Value,
    },
    DeleteApplication {
        organization_id: String,
        client_id: String,
    },
    RegenerateApplicationSecret {
        organization_id: String,
        client_id: String,
    },
}

/// A partial change to an account's own fields.
///
/// One type rather than four arguments, because the whole point is that they are individually optional
/// and a signature of four `Option<String>`s gets read as "four required fields" by the next person who
/// touches it. `None` is a field to leave alone; it is never a field to blank.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AccountPatch<'a> {
    /// Display name.
    pub name: Option<&'a str>,
    /// ISO 3166-1 alpha-2.
    pub country: Option<&'a str>,
    /// ISO 639-1 alpha-2.
    pub language: Option<&'a str>,
    /// `YYYY-MM-DD`.
    pub birthday: Option<&'a str>,
    /// Where the avatar is, absolutely. `None` leaves it alone.
    pub photo_url: Option<&'a str>,
}

impl AccountPatch<'_> {
    /// Whether anything would change.
    ///
    /// Asked before sending, because a patch with nothing in it is refused by the platform — and
    /// "nothing in it" is the normal state of a form where the person changed their mind, which should
    /// be silence rather than an error.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.country.is_none()
            && self.language.is_none()
            && self.birthday.is_none()
            && self.photo_url.is_none()
    }
}

/// What the platform can be asked.
#[async_trait]
pub trait PlatformPort: Send + Sync {
    /// Where this port sends its requests.
    ///
    /// Part of the port rather than something the caller keeps alongside it, because "which platform is
    /// this" is a property of the connection and not of whoever is holding it. The service needs it to
    /// answer [`crate::channel::Request::Ping`]: an interface and the service it talks to are separate
    /// processes, and only the service knows which platform *it* is pointed at.
    fn base(&self) -> &str;

    /// Read the account this token belongs to.
    async fn account(&self, token: &str) -> Result<Account>;

    /// Apply a partial update to an account's own fields.
    ///
    /// The patch is a set of `Option`s and `None` means *leave it alone* — the difference between this
    /// and a method that takes every field. A caller with a form in front of it will send what it has,
    /// and a method that cannot tell "unchanged" from "blank" will overwrite a value somebody else
    /// changed in the meantime.
    async fn update_account(&self, token: &str, patch: &AccountPatch<'_>) -> Result<Account>;

    /// Replace a password, after the current one has been proven.
    async fn change_password(
        &self,
        token: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<()>;

    /// Every address attached to an account.
    async fn list_emails(&self, token: &str) -> Result<Vec<Address>>;

    /// Attach another address. It arrives unverified, and the platform mails a code.
    async fn add_email(&self, token: &str, address: &str) -> Result<Address>;

    /// Promote an address to primary. Only a verified one may be promoted.
    async fn set_primary_email(&self, token: &str, email_id: &str) -> Result<Address>;

    /// Detach an address. The primary one is refused by the platform, not by the interface.
    async fn remove_email(&self, token: &str, email_id: &str) -> Result<()>;

    /// Create an organization, owned by the caller.
    ///
    /// The slug is derived from the name when none is given, and the platform is the one that derives it:
    /// `Acme Cloud` becoming `acme-cloud` is a rule about what a tenant may be called, not a preference
    /// of this client.
    async fn create_organization(
        &self,
        token: &str,
        name: &str,
        slug: Option<&str>,
    ) -> Result<Organization>;

    /// The organizations this account belongs to.
    ///
    /// Not every organization there is, and not the ones it merely created: membership is what puts one
    /// here, and the platform owns that answer.
    async fn list_organizations(&self, token: &str) -> Result<Vec<Organization>>;

    /// Read one, for a member.
    async fn get_organization(&self, token: &str, organization_id: &str) -> Result<Organization>;

    /// Rename an organization.
    async fn rename_organization(
        &self,
        token: &str,
        organization_id: &str,
        name: &str,
    ) -> Result<Organization>;

    /// Trade a refresh token for a new access token.
    ///
    /// Answers with the same shape as a sign-in, because it *is* one as far as the client is concerned: a
    /// new bearer token, a new refresh token, and a new lifetime. The platform rotates the refresh token,
    /// so the old one is dead the moment this returns — a caller that keeps using it is refused rather
    /// than left with a working session that will quietly expire.
    async fn refresh(&self, refresh_token: &str) -> Result<Session>;

    /// End the session.
    async fn end_session(&self, refresh_token: Option<&str>) -> Result<()>;

    /// Execute an Identity management operation for the authenticated account.
    async fn manage(
        &self,
        token: &str,
        operation: &ManagementOperation,
    ) -> Result<serde_json::Value>;

    /// Put a profile photo in R2 and hand back the URL to point the account at.
    ///
    /// It does **not** touch the account — a photo that did not land on the record is a dangling URL in
    /// a bucket, which is harmless; a record that points at a URL that did not land is what blocks a
    /// screen. The caller that wants both calls [`update_account`](Self::update_account) with the URL.
    ///
    /// The filename and content type travel only as hints: the key is generated server-side and the
    /// bucket is the one configured for this client, so the caller cannot name an object it should not
    /// see.
    async fn upload_profile_photo(
        &self,
        session: &Session,
        bytes: &[u8],
        filename: &str,
        content_type: &str,
    ) -> Result<Account>;

    /// Whether [`Self::upload_profile_photo`] could succeed, decided without trying.
    ///
    /// `false` by default so a platform with no concept of a bucket needs no opinion about it. The
    /// point of asking up front is that an interface can then *not draw* the action: a key that is on
    /// screen and cannot work is worse than a key that is absent.
    fn can_upload_photos(&self) -> bool {
        false
    }
}
