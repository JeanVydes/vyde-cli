//! The types the flow moves.
//!
//! Domain types, not wire shapes: a [`Session`] here is "signed in as somebody", and whether the
//! platform calls it `access_token` or a cookie or a header pair is the adapter's problem. The
//! difference shows up the moment the platform changes a field name — one file here, not the flow and
//! the form and the drawing.

/// An account, as this client knows it.
///
/// `Serialize`/`Deserialize` because this crosses the channel to the interface: it is the type that
/// travels, so the wire shape and the domain shape are the same type rather than a second one that has
/// to be kept in step.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Account {
    /// Platform id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// ISO 3166-1 alpha-2.
    pub country: String,
    /// ISO 639-1 alpha-2.
    pub language: String,
    /// `YYYY-MM-DD`.
    pub birthday: String,
    /// `active`, `suspended` or `closed`.
    pub status: String,
    /// Where the avatar is, absolutely. Absent means "no photo yet", and it is optional in the type
    /// because an account is created without one and most stay that way.
    pub photo_url: Option<String>,
    /// The primary address, when there is one.
    pub primary_email: Option<Address>,
}

impl Account {
    /// Whether the primary address has been confirmed.
    ///
    /// The one thing the interface asks an account, and it decides whether the next step is the
    /// mailbox. An account with no address at all is not "unverified" — there is nothing to verify —
    /// so this is false for it too, and the flow treats both the same way.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.primary_email
            .as_ref()
            .is_some_and(Address::is_verified)
    }
}

/// One address on an account.
///
/// Travels over the channel too, so it carries the same derives.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Address {
    /// Address id, which the confirmation call needs alongside the account's.
    pub id: String,
    /// The address itself.
    pub email: String,
    /// Whether the platform has confirmed it.
    pub verified: bool,
    /// Whether this is the address the account signs in with.
    ///
    /// Only one can be, and the platform refuses to remove it. Carried here so an interface can grey the
    /// row out rather than offering an action that always comes back refused — the rule is still
    /// enforced at the platform, which is the only place that knows the state.
    pub primary: bool,
}

impl Address {
    /// Whether the platform has confirmed this address.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.verified
    }

    /// Whether this address can be detached.
    ///
    /// The platform refuses to remove the primary one, so an interface that offers the action anyway is
    /// offering something that cannot succeed.
    #[must_use]
    pub fn can_be_removed(&self) -> bool {
        !self.primary
    }
}

/// What registration asks for.
///
/// Borrowed rather than owned because it is built from a form and used immediately; copying six
/// `String`s to hand them to one call would be noise.
#[derive(Debug)]
pub struct NewAccount<'a> {
    /// Display name.
    pub name: &'a str,
    /// The first address, which becomes the primary one.
    pub email: &'a str,
    /// At least ten characters, by the platform's rule.
    pub password: &'a str,
    /// ISO 3166-1 alpha-2. Not validated here: the platform validates it properly, and a second
    /// check would be a second rule to keep in step.
    pub country: &'a str,
    /// ISO 639-1 alpha-2.
    pub language: &'a str,
    /// `YYYY-MM-DD`.
    pub birthday: &'a str,
}

impl NewAccount<'_> {
    /// Check that nothing required is blank.
    ///
    /// # Errors
    ///
    /// [`CliError::Missing`](crate::error::CliError::Missing) naming the first blank field, in the
    /// order the form shows them — so the message matches what the user is looking at.
    pub fn validate(&self) -> crate::error::Result<()> {
        for (value, field) in [
            (self.name, "Name"),
            (self.email, "E-mail"),
            (self.password, "Password"),
            (self.country, "Country"),
            (self.language, "Language"),
            (self.birthday, "Birthday"),
        ] {
            crate::error::CliError::require(value, field)?;
        }
        Ok(())
    }
}

/// A signed-in session.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Session {
    /// The bearer credential. Held here and never rendered.
    pub token: String,
    /// Present when the session can be renewed. Absent for a grant without `offline_access`, and
    /// that is not a failure — it means there is nothing to renew.
    pub refresh_token: Option<String>,
    /// Which account this is for, when the platform said.
    pub account_id: Option<String>,
    /// The address that was used to sign in.
    pub email: Option<String>,
    /// The account's name, when the platform sent it.
    pub name: Option<String>,
    /// The granted names, space delimited.
    pub scope: Option<String>,
    /// Seconds the token has left, as the platform reported.
    pub expires_in: u64,
}

impl Session {
    /// Whether the platform told us the token is nearly spent.
    ///
    /// Two hundred seconds is a guess, and deliberately a small one: this is a warning that a
    /// re-login may be coming, not a countdown, and a client that treats it as an error would warn
    /// about a session that has twenty minutes left.
    #[must_use]
    pub fn is_about_to_expire(&self) -> bool {
        self.expires_in < 200
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(verified: bool) -> Account {
        Account {
            id: "1".to_owned(),
            name: "Someone".to_owned(),
            country: "UY".to_owned(),
            language: "es".to_owned(),
            birthday: "1990-04-17".to_owned(),
            status: "active".to_owned(),
            photo_url: None,
            primary_email: Some(Address {
                id: "e1".to_owned(),
                email: "a@example.test".to_owned(),
                verified,
                // It is the primary: that is the only place this fixture is used, and a fixture
                // that said otherwise would make every "can this be removed" question answer wrongly.
                primary: true,
            }),
        }
    }

    #[test]
    fn verification_is_read_off_the_address() {
        assert!(account(true).is_verified());
        assert!(!account(false).is_verified());
    }

    /// An account with no address is not verified, and not "cannot be verified" either — there is
    /// nothing to confirm, so the flow has no mailbox step to show.
    #[test]
    fn an_account_with_no_address_is_not_verified() {
        let mut bare = account(true);
        bare.primary_email = None;

        assert!(!bare.is_verified());
    }

    #[test]
    fn a_blank_required_field_is_named_in_form_order() {
        let blank = NewAccount {
            name: "Someone",
            email: "",
            password: "longenough",
            country: "UY",
            language: "es",
            birthday: "1990-04-17",
        };

        let err = blank.validate().expect_err("the e-mail is blank");
        assert!(matches!(err, crate::error::CliError::Missing { .. }));
        assert!(err.to_string().contains("E-mail"), "and it names the field");
    }

    #[test]
    fn a_fully_filled_new_account_validates() {
        NewAccount {
            name: "Someone",
            email: "a@example.test",
            password: "longenough",
            country: "UY",
            language: "es",
            birthday: "1990-04-17",
        }
        .validate()
        .expect("nothing blank");
    }

    #[test]
    fn a_token_with_under_two_minutes_is_flagged() {
        let session = |expires_in| Session {
            token: "t".to_owned(),
            refresh_token: None,
            account_id: None,
            email: None,
            name: None,
            scope: None,
            expires_in,
        };

        assert!(session(30).is_about_to_expire());
        assert!(
            !session(899).is_about_to_expire(),
            "fifteen minutes is not nearly spent"
        );
    }
}
