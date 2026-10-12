//! The protocol between the interface and the service, and the dispatcher that implements it.
//!
//! # Why this exists
//!
//! The service must be able to run in the background and the interface must not: a terminal UI owns a
//! terminal, and a process that owns a terminal cannot be backgrounded. So they are two processes, and
//! two processes need a channel.
//!
//! Making that channel a *typed* one rather than a bag of JSON is the point of this module. Everything
//! the interface can ask for is a [`Request`] variant, everything it can be told is a [`Response`]
//! variant, and [`Dispatcher`] is the only code that touches [`AuthService`]. That closes the surface:
//! the interface cannot invent a call, cannot forget to validate a field before sending, and cannot
//! read a response shape that was never declared. Adding an operation means adding a variant to both
//! enums and one arm to the dispatcher — and the compiler points at the two arms nobody wrote.
//!
//! The alternative is the interface calling methods on a service object it happens to have a handle
//! to, which is only one process pretending to be two.
//!
//! # Why there is no transport here
//!
//! No socket, no framing, no serialisation. This module is the *meaning* of the conversation; the
//! bytes are [`crate::channel`]'s problem and the socket's problem. A test builds a `Dispatcher`, calls
//! [`Dispatcher::handle`], and asserts on the `Response` — no listener, no async runtime, no ports.
//!
//! # Events
//!
//! [`Event`] is for things the service decides without being asked. It is empty of interest today, and
//! that is deliberate rather than a placeholder: the variant that matters is "the grant you were
//! relying on was withdrawn", and adding it means one enum variant and one `send` in the dispatcher. The
//! channel is bidirectional from the first commit so that adding it is not a protocol change.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{
    account::{Account, Address, Session},
    error::{CliError, Result},
    organization::Organization,
    port::{AccountPatch, ManagementOperation},
    service::AuthService,
};

/// What the interface asks for.
///
/// Every operation the platform offers, and no others. This enum *is* the API surface: a caller
/// cannot reach past it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Execute an Identity management operation.
    Management(ManagementOperation),
    /// Install the session produced by the browser login.
    InstallSession(Session),

    /// Read the account for the stored token.
    Whoami,

    /// End the session.
    SignOut,

    /// Apply a partial change to the account's own fields.
    ///
    /// Every field is an `Option` and `None` means *leave it alone*. That is the difference between
    /// this and a request carrying four strings: a screen with a form in front of it sends what the
    /// person changed, and a request that cannot tell "unchanged" from "blank" overwrites whatever was
    /// there. `AccountPatch` is the type on the port; here the fields are spelled out because this enum
    /// is the wire.
    ///
    /// **The `skip_serializing_if` on every field is load-bearing.** Without it an absent field goes out
    /// as `null`, which reads on the wire as "set this to nothing" and only happens to work because the
    /// platform's deserialiser is lenient about `null`. That is two things to keep in step instead of
    /// one, and the failure when they drift is a country silently emptied by a rename. A field that is
    /// not in the message is not in the message.
    UpdateAccount {
        /// Display name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// ISO 3166-1 alpha-2.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        country: Option<String>,
        /// ISO 639-1 alpha-2.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        language: Option<String>,
        /// `YYYY-MM-DD`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        birthday: Option<String>,
        /// Where the avatar is, absolutely. `None` leaves it alone.
        ///
        /// It is produced by the upload flow, not typed by a user, so the only values seen on the wire
        /// are one that just came back from R2 and nothing else.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        photo_url: Option<String>,
    },

    /// Upload a profile photo to R2 and point the account at it.
    ///
    /// Two things at once, because the UI that offers it asks for one thing — "change my picture" — and
    /// a UI that asks for two cannot keep "upload" and "commit" straight when only one can go wrong.
    UploadProfilePhoto {
        /// The file, as bytes.
        bytes: Vec<u8>,
        /// A hint for the object key, so the stored name tracks the original.
        filename: String,
        /// The content type the file had, forwarded as the S3 content type.
        content_type: String,
    },

    /// Change the password for the authenticated account.
    ChangePassword {
        /// The password in force now.
        current_password: String,
        /// What to move to.
        new_password: String,
    },

    /// Every address on the account.
    ListEmails,

    /// Attach another address. It arrives unverified; the platform mails a code.
    AddEmail {
        /// The address to attach.
        email: String,
    },

    /// Promote a verified address to primary.
    SetPrimaryEmail {
        /// Which address.
        email_id: String,
    },

    /// Detach an address. The primary one is refused by the service, which owns that rule.
    RemoveEmail {
        /// Which address.
        email_id: String,
    },

    /// Create an organization, owned by the caller.
    CreateOrganization {
        /// The display name. The slug is derived from it when none is given.
        name: String,
        /// An explicit slug. Absent means "you decide", which is the usual case.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        slug: Option<String>,
    },

    /// Every organization this account belongs to.
    ListOrganizations,

    /// Read one organization.
    DescribeOrganization {
        /// Which organization.
        organization_id: String,
    },

    /// Rename an organization. The slug is not part of this.
    RenameOrganization {
        /// Which organization.
        organization_id: String,
        /// The new display name.
        name: String,
    },

    /// Say nothing and find out whether the service is there.
    ///
    /// Carries a nonce the answer must echo, because "the socket accepted a connection" is not the
    /// same claim as "the service is alive and understood me" — a stale socket file, or a process
    /// that inherited the path without listening, connects fine and answers nothing.
    Ping {
        /// Any string. Echoed back unchanged.
        nonce: String,
    },
}

impl Request {}

/// What the service says back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    /// JSON result from a management operation.
    Json(serde_json::Value),
    /// The service loaded the session persisted by the login process.
    SessionLoaded,

    /// The account behind the stored token.
    Account(Account),

    /// The session ended.
    SignedOut,

    /// The account's own fields were changed, and this is the re-read result.
    AccountUpdated(Account),

    /// The password was changed.
    PasswordChanged,

    /// A photo was uploaded and committed to the account; this is the re-read account.
    PhotoUploaded(Account),

    /// Every address on the account.
    ///
    /// A list rather than one `Response` per operation, because "show me my addresses" is the thing an
    /// interface asks before it can offer to add, promote or remove one — and asking per address would
    /// mean the interface already knew the set it is trying to show.
    Addresses(Vec<Address>),

    /// An address was attached.
    AddressAdded(Address),

    /// An address was promoted.
    AddressPromoted(Address),

    /// An address was detached.
    AddressRemoved {
        /// Which one, so the interface can drop it from the list it is holding.
        email_id: String,
    },

    /// An organization was created.
    OrganizationCreated(Organization),

    /// The organizations this account belongs to.
    ///
    /// A list, not one at a time: there is no screen or verb that wants a single organization without
    /// already knowing it is in this list.
    Organizations(Vec<Organization>),

    /// One organization, read.
    OrganizationRead(Organization),

    /// An organization was renamed.
    OrganizationRenamed(Organization),

    /// The service is alive, and this is the nonce it was given.
    ///
    /// `signed_in` and `platform` ride along because the service already knows both, and asking it
    /// twice would be two round trips to learn one thing.
    ///
    /// `platform` is the *service's* base URL, which is not necessarily the interface's: the two are
    /// separate processes and the interface can be started without the variable that points the service
    /// at a local stack. Reporting the interface's own value was worse than useless — it named
    /// `https://vyde.dev` while the service was pointed at `localhost`, which sends the reader to
    /// debug the wrong process.
    Pong {
        /// Exactly what was sent in [`Request::Ping`].
        nonce: String,
        /// Whether the service holds a token.
        signed_in: bool,
        /// Where the service sends its requests.
        platform: String,
        /// Whether this service can put a photo in a bucket.
        ///
        /// Reported on the ping rather than discovered by pressing a key, because the whole point is
        /// that a key which cannot work should not be drawn. `#[serde(default)]` so an older service
        /// talking to a newer interface answers `false` — the interface then simply does not show the
        /// key, which is the right thing to do with a service that predates the feature.
        #[serde(default)]
        can_upload_photos: bool,
    },

    /// It did not work.
    ///
    /// A failure is a response, not a transport error: the channel carries answers, and "your password
    /// is wrong" is an answer. Only a broken socket is a transport failure.
    Failed {
        /// What to show the user.
        message: String,
        /// Whether trying the same thing again could work. The interface says "try again" only when
        /// this is true, so a wrong password does not invite a retry loop.
        retryable: bool,
        /// The HTTP status the platform gave, or `0` when the failure was the service's own — "not
        /// signed in", say, which never reached the platform at all.
        ///
        /// Carried because the interface rebuilds a [`CliError`] out of this, and `CliError::Refused`
        /// keeps the status: it is the difference between "fix your input" and "you may not", and the
        /// two need different words on screen. Dropping it here would lose it.
        status: u16,
        /// The platform's machine-readable code, when it gave one.
        code: Option<String>,
    },
}

impl Response {
    /// A refusal, from any error.
    ///
    /// The status and code are read out of a [`CliError::Refused`] and defaulted to nothing otherwise,
    /// rather than invented here. A refusal the service raised itself — not signed in, no code
    /// requested — never had a status, and making one up would let a real `403` and a local refusal
    /// look the same to whatever reads this.
    #[must_use]
    pub fn failed(error: &CliError) -> Self {
        let (status, code) = match error {
            CliError::Refused { status, code, .. } => (*status, code.clone()),
            _ => (0, None),
        };

        Self::Failed {
            message: error.short(),
            retryable: error.is_retryable(),
            status,
            code,
        }
    }

    /// Whether this is a failure, for the interface's status line.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    /// Whether trying the same request again could work.
    ///
    /// Only meaningful on a failure; anything else is not worth retrying, so it is `false`.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Failed {
                retryable: true,
                ..
            }
        )
    }

    /// The message to show, for either a failure or a success.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Failed { message, .. } => message,
            _ => "",
        }
    }

    /// This response, or the refusal it carries.
    ///
    /// The bridge between the two ways of being wrong. On the wire a refusal is a `Response`, because
    /// the channel carries answers and "your password is wrong" is one. In the interface it has to
    /// come back as an `Err`, because that is what the flows above already handle — a failure path
    /// that forgets the password, and a status line that goes red. Without this, every call site would
    /// match on `Failed` itself, and the first one somebody forgot would carry on with a missing
    /// account.
    pub fn into_result(self) -> Result<Self> {
        match self {
            Self::Failed {
                message,
                status,
                code,
                ..
            } => Err(CliError::refused(status, message, code)),
            other => Ok(other),
        }
    }
}

/// Something the service decided without being asked.
///
/// Empty of interest, and that is the point. The variant that matters is a grant being withdrawn under
/// a caller who is mid-request, and today a caller finds out on their next request — which is correct,
/// just not immediate. The channel is bidirectional from the first commit so that adding it is not a
/// protocol change for either side.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    /// Nothing has been pushed yet.
    ///
    /// A real variant rather than an empty enum so the channel compiles and the plumbing is exercised
    /// end to end. When a real event arrives it replaces this, and no wire format changes.
    Ready,
}

/// Holds what the session needs between requests.
///
/// The service is stateless per request only in appearance: signing in has to leave a token somewhere
/// for the next request to use. This is that somewhere, and keeping it in the dispatcher rather than in
/// the interface is what lets the interface be a terminal that can be closed and reopened.
#[derive(Clone, Debug)]
pub struct State {
    /// The token from the last successful sign-in.
    pub token: Option<String>,
    /// Which account that token belongs to, needed by the confirmation call.
    pub account_id: Option<String>,
    /// The token that can replace `token` when it runs out.
    ///
    /// Was thrown away. A session was therefore good for exactly as long as the platform's clock said,
    /// and after fifteen minutes every command answered "not signed in; run `vyde login`" — for a session
    /// that was still perfectly refreshable and that the *service* was still holding.
    pub refresh_token: Option<String>,
    /// When `token` stops being accepted, as a countdown in seconds.
    ///
    /// A countdown rather than a deadline because it is what the platform reported, and re-reading it
    /// from the platform would mean a call every second. It is **not** decremented on a timer: see
    /// [`State::seconds_left`].
    pub expires_in: u64,
    /// When the lifetime was reported, so the countdown has something to count down from.
    pub issued_at: std::time::Instant,
}

impl State {
    /// A signed-out state, or one holding a token handed in from outside.
    ///
    /// A token from `VYDE_TOKEN` has no lifetime and no refresh token, so its countdown is zero and the
    /// refresh check fires on the first request — which is the right answer, because there is nothing to
    /// refresh it with and the message says exactly that instead of a bare `401`.
    #[must_use]
    pub fn new(token: Option<String>) -> Self {
        Self {
            token,
            account_id: None,
            refresh_token: None,
            expires_in: 0,
            issued_at: std::time::Instant::now(),
        }
    }

    fn from_session(session: Session) -> Self {
        Self {
            token: Some(session.token),
            account_id: session.account_id,
            refresh_token: session.refresh_token,
            expires_in: session.expires_in,
            issued_at: std::time::Instant::now(),
        }
    }
}

/// How many seconds of the token's life are actually left.
///
/// A wall clock would need the platform's and the machine's to agree, and a laptop that slept for a
/// minute would either think it has nine hundred seconds left or that it has none. Elapsed time on a
/// monotonic clock is the one number that cannot disagree with itself.
impl State {
    /// Seconds of life left, zero once spent.
    #[must_use]
    pub fn seconds_left(&self) -> u64 {
        let spent = self.issued_at.elapsed().as_secs();
        self.expires_in.saturating_sub(spent)
    }
}

/// Refresh when this few seconds are left, and not sooner.
///
/// **Sixty, not ten.** The threshold is not "how long until it hurts" but "how long can a refresh take",
/// because the refresh itself is a call: at ten seconds a request that takes twelve arrives with a token
/// that expired while it was in flight, and the one thing a refresh must never do is be the cause of the
/// expiry it was sent to avoid. Sixty covers a slow platform with room to spare and still renews once
/// every fourteen minutes on a fifteen-minute token.
pub const REFRESH_WITHIN: u64 = 60;

/// Where the token goes between requests.
///
/// A trait, and not a field, because *where* is the whole point: the service process is the only
/// process that should hold a bearer token, so the store it is given decides whether that survives the
/// service being killed. The kernel keyring does; a plain field does not.
///
/// The interface never implements this. An interface that kept the token would be an interface
/// holding a credential in a process that draws to a screen — one that gets logged, screenshotted or
/// core-dumped.
pub trait TokenStore: Send + Sync {
    /// The token from an earlier sign-in, if there is one.
    fn load(&self) -> Option<String>;

    /// Load the complete persisted session when available.
    fn load_session(&self) -> Option<Session> {
        self.load().map(|token| Session {
            token,
            refresh_token: None,
            account_id: None,
            email: None,
            name: None,
            scope: None,
            expires_in: 0,
        })
    }

    /// Keep it. Fails when the store refused, which the service reports rather than hiding: a
    /// successful sign-in whose token went nowhere is not a sign-in.
    fn save(&self, token: &str) -> Result<()>;

    /// Persist the complete session.
    fn save_session(&self, session: &Session) -> Result<()> {
        self.save(&session.token)
    }

    /// Drop it.
    fn forget(&self) -> Result<()>;
}

/// A store that is just a variable.
///
/// Not a testing convenience. It is what the service uses when there is nowhere better to put the
/// token, and it is honest about the consequence: the session ends when the process does. Better a
/// session that lasts one run than a token written somewhere unprotected.
#[derive(Clone, Debug, Default)]
pub struct Memory(Arc<std::sync::Mutex<Option<String>>>);

impl Memory {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenStore for Memory {
    fn load(&self) -> Option<String> {
        self.0.lock().ok().and_then(|held| held.clone())
    }

    fn save(&self, token: &str) -> Result<()> {
        let mut held = self
            .0
            .lock()
            .map_err(|_| CliError::missing("the token store is poisoned"))?;
        *held = Some(token.to_owned());
        Ok(())
    }

    fn forget(&self) -> Result<()> {
        if let Ok(mut held) = self.0.lock() {
            *held = None;
        }
        Ok(())
    }
}

/// The service: one method, one enum in, one enum out.
///
/// Not generic over the platform, unlike [`AuthService`]. This *is* the boundary the interface talks
/// to, and the interface never sees a port — so the indirection stops here rather than going one level
/// further.
pub struct Dispatcher {
    auth: Arc<AuthService>,
    store: Arc<dyn TokenStore>,
    state: State,
}

impl Dispatcher {
    /// Build over an authentication service and somewhere to keep the token.
    ///
    /// The store is read once here, not on every request. That is what makes a service that was
    /// started before the last `vyde login` still know about the session: the token is durable, so
    /// restarting the service does not sign everybody out.
    pub fn new(auth: Arc<AuthService>, store: Arc<dyn TokenStore>) -> Self {
        let session = store.load_session();
        let token = session
            .as_ref()
            .map(|session| session.token.clone())
            .or_else(|| {
                // A token in the environment is how CI and a script hand one over without a login step.
                // It is read here, in the service, and not by the interface: an interface that read it
                // would be carrying the credential again.
                std::env::var("VYDE_TOKEN")
                    .ok()
                    .filter(|token| !token.trim().is_empty())
            });

        Self {
            auth,
            store,
            state: session.map_or_else(|| State::new(token), State::from_session),
        }
    }

    /// The current session state, for a service that is asked what it has.
    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Carry out one request.
    ///
    /// Total: every `Request` produces a `Response` and no `Request` can fail in a way the caller
    /// cannot read. That is what makes the channel reliable — a rejected request is an answer, not a
    /// dropped connection, so the interface never has to distinguish "the service said no" from "the
    /// service died", which it cannot usefully do anyway.
    pub async fn handle(&mut self, request: Request) -> Response {
        match self.try_handle(request).await {
            Ok(response) => response,
            Err(error) => Response::failed(&error),
        }
    }

    async fn try_handle(&mut self, request: Request) -> Result<Response> {
        // Once, here, for every request that carries a token — before the match, so it cannot be
        // forgotten by an arm. Skipped for the three that need no session, because a refresh is a call
        // and `vyde ping` is the call somebody makes *because* something is not answering.
        if Self::needs_a_session(&request) {
            self.refresh_if_needed().await?;
        }

        match request {
            Request::Management(operation) => Ok(Response::Json(
                self.auth.manage(&self.session()?, &operation).await?,
            )),
            Request::InstallSession(session) => {
                self.store.save_session(&session)?;
                self.state = State::from_session(session);
                Ok(Response::SessionLoaded)
            }
            Request::Whoami => {
                let account = self.auth.account(&self.session()?).await?;
                Ok(Response::Account(account))
            }

            Request::SignOut => {
                // The token is forgotten even when the local state was already empty: `vyde logout`
                // is a request to make sure nothing is left, and "there was nothing here" is not a
                // reason to skip the check.
                self.store.forget()?;
                self.state = State::new(None);
                Ok(Response::SignedOut)
            }

            Request::UpdateAccount {
                name,
                country,
                language,
                birthday,
                photo_url,
            } => {
                let patch = AccountPatch {
                    name: name.as_deref(),
                    country: country.as_deref(),
                    language: language.as_deref(),
                    birthday: birthday.as_deref(),
                    photo_url: photo_url.as_deref(),
                };

                let updated = self.auth.update_account(&self.session()?, patch).await?;
                // The response is the account the platform re-read, not the fields that were sent. It
                // is the normalized answer — `br` stored as `BR` — and a screen that echoed its own
                // input would show something the database does not hold.
                Ok(Response::AccountUpdated(updated))
            }

            Request::ChangePassword {
                current_password,
                new_password,
            } => {
                self.auth
                    .change_password(&self.session()?, &current_password, &new_password)
                    .await?;
                Ok(Response::PasswordChanged)
            }

            Request::UploadProfilePhoto {
                bytes,
                filename,
                content_type,
            } => {
                // The upload is to R2 directly, and the account commit is a PATCH — the two are one user
                // action, so both happen before the loop draws anything. If the upload works and the
                // commit fails, the URL is in the world but the account is unchanged; that is the right
                // failure mode, because a stale photo attached to nobody is harmless, while a photo not
                // attached here makes the upload look like nothing happened.
                let token = self.session()?;
                let updated = self
                    .auth
                    .upload_profile_photo(&token, &bytes, &filename, &content_type)
                    .await?;
                Ok(Response::PhotoUploaded(updated))
            }

            Request::ListEmails => Ok(Response::Addresses(
                self.auth.emails(&self.session()?).await?,
            )),

            Request::AddEmail { email } => {
                let address = self.auth.add_email(&self.session()?, &email).await?;
                Ok(Response::AddressAdded(address))
            }

            Request::SetPrimaryEmail { email_id } => {
                let address = self
                    .auth
                    .set_primary_email(&self.session()?, &email_id)
                    .await?;
                Ok(Response::AddressPromoted(address))
            }

            Request::RemoveEmail { email_id } => {
                self.auth.remove_email(&self.session()?, &email_id).await?;
                // Echoed back so the interface can drop the row it is holding without keeping a
                // parallel list of what it thinks exists.
                Ok(Response::AddressRemoved { email_id })
            }

            Request::CreateOrganization { name, slug } => {
                let created = self
                    .auth
                    .create_organization(&self.session()?, &name, slug.as_deref())
                    .await?;
                Ok(Response::OrganizationCreated(created))
            }

            Request::ListOrganizations => {
                let organizations = self.auth.list_organizations(&self.session()?).await?;
                Ok(Response::Organizations(organizations))
            }

            Request::DescribeOrganization { organization_id } => {
                let organization = self
                    .auth
                    .organization(&self.session()?, &organization_id)
                    .await?;
                Ok(Response::OrganizationRead(organization))
            }

            Request::RenameOrganization {
                organization_id,
                name,
            } => {
                let renamed = self
                    .auth
                    .rename_organization(&self.session()?, &organization_id, &name)
                    .await?;
                Ok(Response::OrganizationRenamed(renamed))
            }

            Request::Ping { nonce } => Ok(Response::Pong {
                nonce,
                signed_in: self.state.token.is_some(),
                platform: self.auth.base().to_owned(),
                // The interface cannot know this by itself: the bucket is configured on the side that
                // talks to R2, and the interface is a separate process. Asking here is what lets a key
                // that cannot work be *absent* from the screen rather than present and refused.
                can_upload_photos: self.auth.can_upload_photos(),
            }),
        }
    }

    /// The stored token as a session, or a message saying to sign in.
    fn session(&self) -> Result<Session> {
        let token = self
            .state
            .token
            .clone()
            .ok_or_else(|| CliError::missing("not signed in; run `vyde login`"))?;

        Ok(Session {
            token,
            refresh_token: self.state.refresh_token.clone(),
            account_id: self.state.account_id.clone(),
            email: None,
            name: None,
            scope: None,
            expires_in: self.state.seconds_left(),
        })
    }

    /// Whether a request will need a session at all.
    ///
    /// An **allowlist of the three that do not**, and that is the direction on purpose. The first version
    /// was a denylist of the ones that did, and it was wrong in the worst way possible: `ConfirmCode` and
    /// `RequestCode` were on it, and both go through `self.auth.account(&session)` — so a person whose
    /// token had expired could not confirm their address, and the code they had just been mailed was the
    /// one thing that would have fixed it.
    ///
    /// A request added later is therefore assumed to need a session, and a new arm that does not need one
    /// has to be named here on purpose. Being wrong means one unnecessary refresh, not a refusal.
    fn needs_a_session(request: &Request) -> bool {
        !matches!(request, Request::Ping { .. })
    }

    /// Refresh the token if it is nearly spent, once per request.
    ///
    /// Here and not in the two front ends, and that placement is the point: both of them reach the
    /// platform only through the dispatcher, so one check covers every call and neither interface has to
    /// remember to do it. A check in the terminal front end would be a check the script front end does not
    /// have, and then scripts would silently need a new login every fifteen minutes while the terminal did
    /// not.
    async fn refresh_if_needed(&mut self) -> Result<()> {
        if self.state.token.is_none() || self.state.seconds_left() > REFRESH_WITHIN {
            return Ok(());
        }

        self.refresh_now().await
    }

    /// Trade the refresh token for a new one, and keep it.
    ///
    /// Fails loudly rather than carrying on with the old token: a refresh that failed and a request that
    /// then fails with `401` is two errors for one problem, and the second hides the first.
    async fn refresh_now(&mut self) -> Result<()> {
        let Some(refresh_token) = self.state.refresh_token.clone() else {
            return Err(CliError::missing(
                "the session expired and there is nothing to refresh it with; run `vyde login`",
            ));
        };

        let session = self.auth.refresh(&refresh_token).await?;

        // The store first. A new token that only reached memory is a session that dies with the process,
        // which is exactly what the keyring was added to prevent — and a `save` that fails here has to
        // fail the refresh, because the alternative is a service that believes it is signed in and is not.
        self.store.save_session(&session)?;

        self.state.token = Some(session.token);
        self.state.refresh_token = session.refresh_token;
        self.state.expires_in = session.expires_in;
        self.state.issued_at = std::time::Instant::now();
        if let Some(account_id) = session.account_id {
            self.state.account_id = Some(account_id);
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "legacy-auth-tests"))]
mod tests {
    use super::*;
    use crate::form::Field;

    /// A registration request survives the round trip through a form, which is what the interface
    /// relies on when the user goes back and forward. The order is the whole risk: a form is a list and
    /// a request is a struct, and nothing else keeps them aligned.
    #[test]
    fn a_registration_request_round_trips_through_a_form() {
        let mut form = Form::new(
            "Create",
            vec![
                Field::text("Name", ""),
                Field::text("E-mail", ""),
                Field::secret("Password"),
                Field::choice("Country", &[("UY", "Uruguay"), ("AR", "Argentina")]),
                Field::choice("Language", &[("es", "Español"), ("en", "English")]),
                Field::date("Birthday"),
            ],
        );
        let mut filled = Form::new(
            "Create",
            vec![
                Field::text("Name", ""),
                Field::text("E-mail", ""),
                Field::secret("Password"),
                Field::choice("Country", &[("UY", "Uruguay"), ("AR", "Argentina")]),
                Field::choice("Language", &[("es", "Español"), ("en", "English")]),
                Field::date("Birthday"),
            ],
        );
        filled.set_at(0, "Ada Lovelace");
        filled.set_at(1, "ada@example.test");
        filled.set_at(2, "a-long-password");
        filled.set_at(3, "AR");
        filled.set_at(4, "en");
        filled.set_date_at(5, "1815-12-10");

        let request = Request::from_form(&filled);
        let cloned = request.clone();
        cloned.into_form(&mut form);

        assert_eq!(
            Request::from_form(&form),
            request,
            "the form came back the same"
        );
    }

    /// A patch that names one field must not blank the others.
    ///
    /// This is the property the whole `AccountPatch` shape exists for, and it is invisible until it
    /// breaks: the platform takes `None` as "leave it" and `Some("")` as "blank it", so a client that
    /// sends the whole form would silently erase a country every time somebody changed their name. The
    /// assertion is on the wire form, because that is where the distinction has to survive — a JSON
    /// `null` would arrive as "blank" and fail at the far end rather than here.
    #[test]
    fn a_patch_carries_only_the_fields_it_names() {
        let request = Request::UpdateAccount {
            name: Some("New Name".into()),
            country: None,
            language: None,
            birthday: None,
            photo_url: None,
        };

        let json = serde_json::to_string(&request).expect("serialises");
        assert!(json.contains(r#""name":"New Name""#), "{json}");
        assert!(
            !json.contains("null"),
            "an absent field must be absent, not null: {json}"
        );

        // And the arms that read it back have to agree about which is which.
        assert!(matches!(
            request,
            Request::UpdateAccount {
                country: None,
                language: None,
                birthday: None,
                ..
            }
        ));
    }

    /// A change that changes nothing is refused before the round trip.
    ///
    /// The platform refuses it too — but a form where the person changed their mind should be quiet,
    /// and the only way to know that is to ask before sending.
    #[test]
    fn an_empty_patch_is_refused_rather_than_sent() {
        let patch = crate::port::AccountPatch::default();
        assert!(patch.is_empty());
        assert!(
            !crate::port::AccountPatch {
                name: Some("x"),
                ..Default::default()
            }
            .is_empty()
        );
    }

    /// The wire form, because this is the boundary and both sides will be deployed separately.
    #[test]
    fn the_protocol_serialises() {
        let request = Request::SignIn {
            email: "a@b.co".into(),
            password: "longenough".into(),
        };
        let json = serde_json::to_string(&request).expect("a request serialises");
        assert_eq!(
            serde_json::from_str::<Request>(&json).expect("and reads back"),
            request
        );

        let response = Response::Failed {
            message: "nope".into(),
            retryable: false,
            status: 403,
            code: Some("forbidden".into()),
        };
        let json = serde_json::to_string(&response).expect("a response serialises");
        assert_eq!(
            serde_json::from_str::<Response>(&json).expect("and reads back"),
            response
        );
    }

    /// Every failure carries whether a retry could work, because the interface says "try again" on that
    /// basis and a wrong password must not invite a loop.
    #[test]
    fn a_failure_says_whether_retrying_could_work() {
        let wrong_password = CliError::Refused {
            status: 401,
            message: "invalid credentials".into(),
            code: None,
        };
        assert!(!Response::failed(&wrong_password).is_retryable());

        let Response::Failed {
            message, status, ..
        } = Response::failed(&wrong_password)
        else {
            panic!("expected a failure");
        };
        assert_eq!(message, "invalid credentials");
        assert_eq!(status, 401, "the status survives the trip to the interface");
    }

    /// A refusal the platform gave and a refusal the service raised have to stay distinguishable: one is
    /// "you may not" and the other is "you have not signed in", and they get different words. The
    /// service's own carries no status, so zero stands for "there was none".
    #[test]
    fn a_refusal_the_service_raised_has_no_status() {
        let missing = CliError::missing("not signed in; run `vyde login`");
        assert_eq!(
            Response::failed(&missing),
            Response::Failed {
                message: "not signed in; run `vyde login`".into(),
                retryable: false,
                status: 0,
                code: None,
            }
        );
    }

    /// A refusal has to come back out the other side as an `Err`, because that is what the flows above
    /// already handle. This is the bridge, and it is what stops a caller from carrying on with a
    /// missing account after being told no.
    #[test]
    fn a_refusal_arrives_as_an_error() {
        let refused = Response::Failed {
            message: "invalid credentials".into(),
            retryable: false,
            status: 401,
            code: None,
        };

        let CliError::Refused {
            status, message, ..
        } = refused.into_result().expect_err("an error")
        else {
            panic!("expected a refusal");
        };
        assert_eq!(status, 401);
        assert_eq!(message, "invalid credentials");
    }

    /// Asking before signing in is answered, not fatal — every `Request` has to produce a `Response` or
    /// the channel has to carry errors as well as answers, and carrying only answers is what lets a
    /// broken request be a message rather than a dropped connection.
    #[tokio::test]
    async fn whoami_without_a_session_is_an_answer() {
        let mut dispatcher = Dispatcher::new(
            Arc::new(AuthService::new(Arc::new(NoPlatform))),
            Arc::new(Memory::new()),
        );

        let response = dispatcher.handle(Request::Whoami).await;

        assert!(response.is_failure());
        assert!(!matches!(response, Response::Account(_)));
    }

    struct NoPlatform;

    #[async_trait::async_trait]
    impl crate::PlatformPort for NoPlatform {
        fn base(&self) -> &str {
            "test://nowhere"
        }

        async fn create_account(
            &self,
            _: &NewAccount<'_>,
        ) -> Result<(Account, Option<crate::Address>)> {
            Err(CliError::missing("not reached"))
        }
        async fn sign_in(&self, _: &str, _: &str) -> Result<Session> {
            Err(CliError::missing("not reached"))
        }
        async fn account(&self, _: &str) -> Result<Account> {
            Err(CliError::missing("not reached"))
        }
        async fn request_code(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> Result<crate::port::CodeRequest> {
            Err(CliError::missing("not reached"))
        }
        async fn confirm_code(&self, _: &str, _: &str, _: &str, _: &str) -> Result<()> {
            Err(CliError::missing("not reached"))
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

        async fn refresh(&self, _: &str) -> Result<crate::Session> {
            Err(CliError::missing("not reached"))
        }

        async fn end_session(&self, _: Option<&str>) -> Result<()> {
            Err(CliError::missing("not reached"))
        }
        async fn upload_profile_photo(
            &self,
            _: &Session,
            _: &[u8],
            _: &str,
            _: &str,
        ) -> Result<Account> {
            Err(CliError::missing("not reached"))
        }
    }
}
