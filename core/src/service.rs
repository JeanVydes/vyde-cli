//! The flow, as five use cases over one port.
//!
//! No screen, no cursor, no key. Each method is one thing a caller can ask for and gets a
//! [`Result`](crate::error::Result) back; deciding *when* to ask is the interface's job, and keeping
//! that out of here is what makes these testable without a terminal.
//!
//! What the flow does know is the one piece of sequencing that is not presentation: **registration
//! returns no credential**, so a client that wants to be signed in after registering has to sign in
//! separately. [`AuthService::register`] therefore returns the account and the pending address rather
//! than a session, and there is no `register_and_login` pretending otherwise.

use std::sync::Arc;

use crate::{
    account::{Account, Address, Session},
    error::Result,
    organization::Organization,
    port::{AccountPatch, ManagementOperation, PlatformPort},
};

/// The native auth flow.
pub struct AuthService {
    platform: Arc<dyn PlatformPort>,
}

impl AuthService {
    /// Build over a platform.
    pub fn new(platform: Arc<dyn PlatformPort>) -> Self {
        Self { platform }
    }

    /// Where this service sends its requests.
    ///
    /// Asked of the port rather than kept here, so there is one answer to "which platform is this" and
    /// not one per thing holding a port.
    #[must_use]
    pub fn base(&self) -> &str {
        self.platform.base()
    }

    /// Read the account behind a token.
    ///
    /// # Errors
    ///
    /// A refusal when the token is no longer accepted.
    pub async fn account(&self, session: &Session) -> Result<Account> {
        self.platform.account(&session.token).await
    }

    /// Apply a partial update to the account's own fields.
    ///
    /// The empty patch is refused here rather than sent. The platform refuses it too, but a form where
    /// the person changed their mind should be quiet, and the only way to know that is to ask before
    /// the round trip.
    ///
    /// # Errors
    ///
    /// [`crate::error::CliError::Missing`] when the patch changes nothing, and whatever the platform
    /// says about a field it refuses.
    pub async fn update_account(
        &self,
        session: &Session,
        patch: AccountPatch<'_>,
    ) -> Result<Account> {
        if patch.is_empty() {
            return Err(crate::error::CliError::missing("nothing to change"));
        }
        self.platform.update_account(&session.token, &patch).await
    }

    /// Change the password, proving the current one.
    ///
    /// # Errors
    ///
    /// [`crate::error::CliError::Refused`] when the current password is not the one in force. The
    /// platform does not say which of the two passwords was wrong, and neither does this.
    pub async fn change_password(
        &self,
        session: &Session,
        current_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let current_password =
            crate::error::CliError::require(current_password, "the current password")?;
        let new_password = crate::error::CliError::require(new_password, "the new password")?;

        if current_password == new_password {
            return Err(crate::error::CliError::missing(
                "the new password must differ from the current one",
            ));
        }

        self.platform
            .change_password(&session.token, current_password, new_password)
            .await
    }

    /// Every address on the account.
    pub async fn emails(&self, session: &Session) -> Result<Vec<Address>> {
        self.platform.list_emails(&session.token).await
    }

    /// Attach another address. It arrives unverified and the platform mails a code.
    pub async fn add_email(&self, session: &Session, address: &str) -> Result<Address> {
        let address = crate::error::CliError::require(address, "E-mail")?;
        self.platform.add_email(&session.token, address).await
    }

    /// Promote a verified address to primary.
    pub async fn set_primary_email(&self, session: &Session, email_id: &str) -> Result<Address> {
        let email_id = crate::error::CliError::require(email_id, "the address")?;
        self.platform
            .set_primary_email(&session.token, email_id)
            .await
    }

    /// Detach an address.
    ///
    /// The primary one is refused by the platform with a conflict. It is not checked here: this is a
    /// rule about the state of a resource this process cannot see, and a copy of it here would be a
    /// second thing to keep in step with the platform's answer.
    pub async fn remove_email(&self, session: &Session, email_id: &str) -> Result<()> {
        let email_id = crate::error::CliError::require(email_id, "the address")?;
        self.platform.remove_email(&session.token, email_id).await
    }

    /// Create an organization, owned by the caller.
    ///
    /// The name is checked here rather than left to the platform so an empty one does not become a
    /// request, but the slug is not checked: it is the platform's to derive, and a client that derived it
    /// too would have a second rule to keep in step with theirs.
    pub async fn create_organization(
        &self,
        session: &Session,
        name: &str,
        slug: Option<&str>,
    ) -> Result<Organization> {
        let name = crate::error::CliError::require(name, "the name")?;
        self.platform
            .create_organization(&session.token, name, slug)
            .await
    }

    /// The organizations this account belongs to.
    pub async fn list_organizations(&self, session: &Session) -> Result<Vec<Organization>> {
        self.platform.list_organizations(&session.token).await
    }

    /// Read one organization.
    pub async fn organization(
        &self,
        session: &Session,
        organization_id: &str,
    ) -> Result<Organization> {
        let organization_id = crate::error::CliError::require(organization_id, "the organization")?;
        self.platform
            .get_organization(&session.token, organization_id)
            .await
    }

    /// Rename an organization. The slug is not part of this and is not sent.
    ///
    /// The "is this actually a change" question is asked **here** rather than in each front end. It was in
    /// the form, and `vyde org rename --name <the same name>` went through to the platform: not wrong,
    /// since the platform accepts it, but a `200` for a write that changed nothing, from a command whose
    /// whole purpose is a write. One place means a script cannot skip it.
    pub async fn rename_organization(
        &self,
        session: &Session,
        organization_id: &str,
        name: &str,
    ) -> Result<Organization> {
        let organization_id = crate::error::CliError::require(organization_id, "the organization")?;
        let name = crate::error::CliError::require(name, "the name")?;

        let current = self
            .platform
            .get_organization(&session.token, organization_id)
            .await?;
        if !crate::organization::Organization::is_new_name(&current.name, name) {
            return Err(crate::error::CliError::missing(format!(
                "{} is already called {}",
                current.name, current.name
            )));
        }

        self.platform
            .rename_organization(&session.token, organization_id, name)
            .await
    }

    /// Trade a refresh token for a new session.
    ///
    /// The refresh token is required rather than optional, and that is what a caller holds: a refresh
    /// needs the thing that can be refreshed, and reading it out of the session it is about to replace
    /// would be using the expiring token as the credential for its own replacement.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Session> {
        let refresh_token = crate::error::CliError::require(refresh_token, "the refresh token")?;
        self.platform.refresh(refresh_token).await
    }

    /// End the session.
    ///
    /// A failure is swallowed. The caller has already forgotten the token by the time it gets here,
    /// so the state it wanted is the state it has, and reporting an error would make a sign-out look
    /// like it had not happened.
    pub async fn sign_out(&self, session: &Session) {
        let _ = self
            .platform
            .end_session(session.refresh_token.as_deref())
            .await;
    }

    /// Execute an Identity management operation using the active session.
    pub async fn manage(
        &self,
        session: &Session,
        operation: &ManagementOperation,
    ) -> Result<serde_json::Value> {
        self.platform.manage(&session.token, operation).await
    }

    /// Put a photo in R2 and hand back the URL to point the account at.
    ///
    /// It does not touch the account: the caller commits the URL with [`Self::update_account`] if it
    /// wants to. Splitting upload from commit keeps the port honest about what it can reach — a photo
    /// stored and a record that does not notice is a dangling URL in a bucket, which is harmless; a
    /// record that notices and a photo that did not land is what leaves a screen blank.
    pub async fn upload_profile_photo(
        &self,
        session: &Session,
        bytes: &[u8],
        filename: &str,
        content_type: &str,
    ) -> Result<Account> {
        self.platform
            .upload_profile_photo(session, bytes, filename, content_type)
            .await
    }

    /// Whether an upload could work here, without attempting one.
    ///
    /// Asked before the interface *offers* the action rather than when it is pressed. "Configured to
    /// fail" and "not configured" are the same answer at the keystroke, but not on screen: a key that
    /// leads to a form which cannot finish is worse than no key at all.
    #[must_use]
    pub fn can_upload_photos(&self) -> bool {
        self.platform.can_upload_photos()
    }
}

#[cfg(all(test, feature = "legacy-auth-tests"))]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// A platform that records what it was asked and answers from a script.
    ///
    /// This is the whole reason `core` is a separate crate: the flow's tests run with no terminal, no
    /// socket and no runtime of consequence.
    struct Fake {
        /// What the flow called, in order.
        calls: Mutex<Vec<String>>,
        /// The refresh tokens this double was handed, in order.
        ///
        /// Recorded rather than answered, so a test can say the refresh happened **once** and with the
        /// right token. A double that silently returned a session would let every test pass against a
        /// refresh that never ran.
        refreshes: Mutex<Vec<String>>,
        /// What to answer for `sign_in`. A flag rather than a `Result`, because `CliError` is not
        /// `Clone` and a test double that has to reproduce one would be building an error to throw it
        /// away.
        sign_in_fails: Mutex<bool>,
        /// What to answer for `account`.
        account: Mutex<Account>,
        /// What to answer for `request_code`.
        code: Mutex<CodeRequest>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                refreshes: Mutex::new(Vec::new()),
                sign_in_fails: Mutex::new(true),
                account: Mutex::new(account_fixture()),
                code: Mutex::new(CodeRequest {
                    expires_in: 900,
                    attempts_remaining: 3,
                    echoed: Some("123456".to_owned()),
                }),
            }
        }

        fn ok_sign_in(&self) {
            *self.sign_in_fails.lock().expect("the test's own lock") = false;
        }

        fn verified(&self) {
            let mut account = account_fixture();
            if let Some(address) = account.primary_email.as_mut() {
                address.verified = true;
            }
            *self.account.lock().expect("the test's own lock") = account;
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("the test's own lock").clone()
        }
    }

    /// The refusal every default fake answers with, so a test that does not care about an error gets
    /// one rather than a panic on an unwrapped `None`.
    struct CliErrorFixture;

    impl CliErrorFixture {
        fn refused() -> crate::error::CliError {
            crate::error::CliError::Refused {
                status: 401,
                message: "invalid credentials".to_owned(),
                code: Some("unauthenticated".to_owned()),
            }
        }
    }

    fn account_fixture() -> Account {
        Account {
            id: "acct-1".to_owned(),
            name: "Someone".to_owned(),
            country: "UY".to_owned(),
            language: "es".to_owned(),
            birthday: "1990-04-17".to_owned(),
            status: "active".to_owned(),
            photo_url: None,
            primary_email: Some(Address {
                id: "addr-1".to_owned(),
                email: "a@example.test".to_owned(),
                verified: false,
                primary: true,
            }),
        }
    }

    fn session_fixture() -> Session {
        Session {
            token: "eyJ".to_owned(),
            refresh_token: Some("refresh".to_owned()),
            account_id: Some("acct-1".to_owned()),
            email: Some("a@example.test".to_owned()),
            name: Some("Someone".to_owned()),
            scope: Some("openid profile".to_owned()),
            expires_in: 900,
        }
    }

    #[async_trait]
    impl PlatformPort for Fake {
        fn base(&self) -> &str {
            "test://nowhere"
        }

        async fn create_account(&self, new: &NewAccount<'_>) -> Result<(Account, Option<Address>)> {
            self.calls
                .lock()
                .expect("the test's own lock")
                .push(format!("register {}", new.email));
            Ok((
                self.account.lock().expect("the test's own lock").clone(),
                account_fixture().primary_email,
            ))
        }

        async fn sign_in(&self, email: &str, _password: &str) -> Result<Session> {
            self.calls
                .lock()
                .expect("the test's own lock")
                .push(format!("sign_in {email}"));
            if *self.sign_in_fails.lock().expect("the test's own lock") {
                return Err(CliErrorFixture::refused());
            }
            Ok(session_fixture())
        }

        async fn account(&self, _token: &str) -> Result<Account> {
            self.calls
                .lock()
                .expect("the test's own lock")
                .push("account".to_owned());
            Ok(self.account.lock().expect("the test's own lock").clone())
        }

        async fn request_code(
            &self,
            _token: &str,
            _account_id: &str,
            _address_id: &str,
        ) -> Result<CodeRequest> {
            self.calls
                .lock()
                .expect("the test's own lock")
                .push("request_code".to_owned());
            Ok(self.code.lock().expect("the test's own lock").clone())
        }

        async fn confirm_code(
            &self,
            _token: &str,
            _account_id: &str,
            _address_id: &str,
            _code: &str,
        ) -> Result<()> {
            self.calls
                .lock()
                .expect("the test's own lock")
                .push("confirm_code".to_owned());
            Ok(())
        }

        async fn update_account(
            &self,
            _: &str,
            _: &crate::port::AccountPatch<'_>,
        ) -> Result<crate::account::Account> {
            Err(crate::error::CliError::missing("not reached"))
        }
        async fn change_password(&self, _: &str, _: &str, _: &str) -> Result<()> {
            Err(crate::error::CliError::missing("not reached"))
        }
        async fn list_emails(&self, _: &str) -> Result<Vec<crate::account::Address>> {
            Err(crate::error::CliError::missing("not reached"))
        }
        async fn add_email(&self, _: &str, _: &str) -> Result<crate::account::Address> {
            Err(crate::error::CliError::missing("not reached"))
        }
        async fn set_primary_email(&self, _: &str, _: &str) -> Result<crate::account::Address> {
            Err(crate::error::CliError::missing("not reached"))
        }
        async fn remove_email(&self, _: &str, _: &str) -> Result<()> {
            Err(crate::error::CliError::missing("not reached"))
        }
        async fn create_organization(
            &self,
            _: &str,
            _: &str,
            _: Option<&str>,
        ) -> Result<crate::organization::Organization> {
            Err(crate::error::CliError::missing("not reached"))
        }
        async fn list_organizations(
            &self,
            _: &str,
        ) -> Result<Vec<crate::organization::Organization>> {
            Err(crate::error::CliError::missing("not reached"))
        }
        async fn get_organization(
            &self,
            _: &str,
            _: &str,
        ) -> Result<crate::organization::Organization> {
            Err(crate::error::CliError::missing("not reached"))
        }
        async fn rename_organization(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<crate::organization::Organization> {
            Err(crate::error::CliError::missing("not reached"))
        }

        async fn refresh(&self, refresh_token: &str) -> Result<Session> {
            let mut guard = self.refreshes.lock().expect("the test's own lock");
            guard.push(refresh_token.to_owned());

            Ok(Session {
                token: format!("eyJ-refreshed-{}", guard.len()),
                refresh_token: Some(format!("refresh-{}", guard.len())),
                account_id: Some("1".to_owned()),
                email: None,
                name: Some("Someone".to_owned()),
                scope: None,
                expires_in: 900,
            })
        }

        async fn end_session(&self, refresh: Option<&str>) -> Result<()> {
            self.calls
                .lock()
                .expect("the test's own lock")
                .push(format!("end_session {}", refresh.is_some()));
            Ok(())
        }

        async fn upload_profile_photo(
            &self,
            bytes: &[u8],
            filename: &str,
            _content_type: &str,
        ) -> Result<String> {
            self.calls
                .lock()
                .expect("the test's own lock")
                .push(format!(
                    "upload_profile_photo {}b {}",
                    bytes.len(),
                    filename
                ));
            // A stable fake URL, so a test can assert the account points at it without parsing a real key.
            Ok(format!("https://cdn.vyde.dev/photos/{filename}"))
        }
    }

    fn service() -> (AuthService, Arc<Fake>) {
        let fake = Arc::new(Fake::new());
        (AuthService::new(fake.clone()), fake)
    }

    fn new_account() -> NewAccount<'static> {
        NewAccount {
            name: "Someone",
            email: "a@example.test",
            password: "longenough",
            country: "UY",
            language: "es",
            birthday: "1990-04-17",
        }
    }

    /// Registration returns an account and a pending address, and deliberately no session. This is the
    /// fact that shapes the whole interface: there is nothing to be signed in with yet.
    #[tokio::test]
    async fn registering_yields_no_session() {
        let (service, fake) = service();

        let (account, address) = service
            .register(&new_account())
            .await
            .expect("the platform accepted it");

        assert_eq!(account.id, "acct-1");
        assert!(address.is_some(), "the address still needs confirming");
        assert_eq!(fake.calls(), vec!["register a@example.test"]);
    }

    /// A blank field never reaches the platform. A request that is going to be refused should not be
    /// sent.
    #[tokio::test]
    async fn a_blank_field_stops_before_the_platform() {
        let (service, fake) = service();
        let blank = NewAccount {
            name: "",
            ..new_account()
        };

        assert!(service.register(&blank).await.is_err());
        assert!(fake.calls().is_empty(), "nothing was sent");
    }

    #[tokio::test]
    async fn signing_in_returns_the_session_and_the_account() {
        let (service, fake) = service();
        fake.ok_sign_in();

        let (session, account) = service
            .sign_in_and_load("a@example.test", "longenough")
            .await
            .expect("signed in");

        assert_eq!(session.token, "eyJ");
        assert_eq!(account.expect("the account was read").id, "acct-1");
        assert_eq!(fake.calls(), vec!["sign_in a@example.test", "account"]);
    }

    /// The unverified account is what sends the flow to the mailbox, and reading it is how that
    /// happens.
    #[tokio::test]
    async fn an_unverified_account_needs_verification() {
        let (service, fake) = service();
        fake.ok_sign_in();

        assert!(
            service
                .needs_verification(&session_fixture())
                .await
                .expect("readable")
        );
    }

    #[tokio::test]
    async fn a_verified_account_does_not() {
        let (service, fake) = service();
        fake.ok_sign_in();
        fake.verified();

        assert!(
            !service
                .needs_verification(&session_fixture())
                .await
                .expect("readable")
        );
    }

    /// The account that comes back from a confirmation is verified. Returning `()` instead would
    /// leave the caller showing a stale unverified account on a screen that just confirmed one.
    #[tokio::test]
    async fn confirming_returns_the_verified_account() {
        let (service, fake) = service();
        fake.verified();
        let address = account_fixture().primary_email.expect("an address");

        let account = service
            .confirm_code(&session_fixture(), "acct-1", &address, "123456")
            .await
            .expect("confirmed");

        assert!(
            account.is_verified(),
            "and it is the fresh one, not the stale one"
        );
    }

    /// A blank code never reaches the platform.
    #[tokio::test]
    async fn a_blank_code_is_refused_locally() {
        let (service, fake) = service();
        let address = account_fixture().primary_address_or_panic();

        assert!(
            service
                .confirm_code(&session_fixture(), "acct-1", &address, "  ")
                .await
                .is_err()
        );
        assert!(fake.calls().is_empty());
    }

    /// A code the platform echoed is carried through; the interface is the only thing that decides to
    /// pre-fill it.
    #[tokio::test]
    async fn an_echoed_code_comes_through_the_port() {
        let (service, _fake) = service();
        let address = account_fixture().primary_address_or_panic();

        let request = service
            .request_code(&session_fixture(), "acct-1", &address)
            .await
            .expect("a code was sent");

        assert_eq!(request.echoed.as_deref(), Some("123456"));
        assert_eq!(request.attempts_remaining, 3);
    }

    /// A sign-out whose platform call fails still leaves the caller with no session, so the failure is
    /// not worth surfacing.
    #[tokio::test]
    async fn signing_out_swallows_a_failure() {
        struct Failing;
        #[async_trait]
        impl PlatformPort for Failing {
            fn base(&self) -> &str {
                "test://nowhere"
            }

            async fn create_account(
                &self,
                _: &NewAccount<'_>,
            ) -> Result<(Account, Option<Address>)> {
                unimplemented!("not reached");
            }
            async fn sign_in(&self, _: &str, _: &str) -> Result<Session> {
                unimplemented!("not reached");
            }
            async fn account(&self, _: &str) -> Result<Account> {
                unimplemented!("not reached");
            }
            async fn update_account(&self, _: &str, _: &AccountPatch<'_>) -> Result<Account> {
                unimplemented!("not reached");
            }
            async fn change_password(&self, _: &str, _: &str, _: &str) -> Result<()> {
                unimplemented!("not reached");
            }
            async fn list_emails(&self, _: &str) -> Result<Vec<Address>> {
                unimplemented!("not reached");
            }
            async fn add_email(&self, _: &str, _: &str) -> Result<Address> {
                unimplemented!("not reached");
            }
            async fn set_primary_email(&self, _: &str, _: &str) -> Result<Address> {
                unimplemented!("not reached");
            }
            async fn remove_email(&self, _: &str, _: &str) -> Result<()> {
                unimplemented!("not reached");
            }
            async fn create_organization(
                &self,
                _: &str,
                _: &str,
                _: Option<&str>,
            ) -> Result<crate::organization::Organization> {
                unimplemented!("not reached");
            }
            async fn list_organizations(
                &self,
                _: &str,
            ) -> Result<Vec<crate::organization::Organization>> {
                unimplemented!("not reached");
            }
            async fn get_organization(
                &self,
                _: &str,
                _: &str,
            ) -> Result<crate::organization::Organization> {
                unimplemented!("not reached");
            }
            async fn rename_organization(
                &self,
                _: &str,
                _: &str,
                _: &str,
            ) -> Result<crate::organization::Organization> {
                unimplemented!("not reached");
            }
            async fn request_code(&self, _: &str, _: &str, _: &str) -> Result<CodeRequest> {
                unimplemented!("not reached");
            }
            async fn confirm_code(&self, _: &str, _: &str, _: &str, _: &str) -> Result<()> {
                unimplemented!("not reached");
            }
            async fn refresh(&self, _: &str) -> Result<Session> {
                unimplemented!("not reached");
            }

            async fn end_session(&self, _: Option<&str>) -> Result<()> {
                Err(crate::error::CliError::Unreachable {
                    base: "http://test".into(),
                    reason: "gone".into(),
                })
            }

            async fn upload_profile_photo(
                &self,
                _: &Session,
                _: &[u8],
                _: &str,
                _: &str,
            ) -> Result<Account> {
                Err(crate::error::CliError::Unreachable {
                    base: "http://test".into(),
                    reason: "gone".into(),
                })
            }
        }

        let service = AuthService::new(Arc::new(Failing));
        service.sign_out(&session_fixture()).await;
    }

    /// A wrong password is a refusal, and the session is not created.
    #[tokio::test]
    async fn a_refused_sign_in_creates_nothing() {
        let (service, _fake) = service();

        assert!(service.sign_in("a@example.test", "wrong").await.is_err());
    }

    impl Account {
        fn primary_address_or_panic(&self) -> Address {
            self.primary_email
                .clone()
                .expect("the fixture has an address")
        }
    }
}
