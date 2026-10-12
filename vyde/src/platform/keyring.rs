//! Where the session token lives between runs.
//!
//! # The kernel keyring, and why not a file
//!
//! The Linux kernel has a keyring: a per-user, per-session store of small secrets, reachable through
//! `keyctl`, with permissions and an expiry. It is the OS's own cryptographic space, and it is the
//! right answer for a token with the lifetime this one has.
//!
//! The alternatives and why each is wrong here:
//!
//! * **A file.** A token in `~/.config/vyde/credentials` is a token on disk, readable by every process
//!   running as that user and by anything that gets a backup. `0600` is a start and not an answer.
//! * **The Secret Service** (`gnome-keyring`, `libsecret`). Encrypted at rest under a login keyring,
//!   which is what a long-lived credential wants — a GitHub token, an API key. It needs a daemon, a
//!   D-Bus session, and an unlocked login keyring, so it does not work over ssh and does not work in
//!   a container. It is a desktop answer to a terminal question.
//! * **The kernel keyring.** No daemon, nothing written to disk in the clear, and the *session*
//!   keyring is destroyed when the session ends. A token left behind by an interrupted login is gone,
//!   which is the failure you actually want for a credential.
//!
//! So: the session keyring, under a name that says what it is. Two terminals signed in as different
//! users do not collide.
//!
//! # When there is no keyring
//!
//! Some containers are built without `CONFIG_KEYCTL`, and some sandboxes deny the syscall. Then
//! storing is refused, `login` prints the token once instead, and says so. Failing loudly is the
//! point: silently falling back to a file is how "we put it in the OS store" becomes "we put it in
//! your home directory".

use vyde_core::CliError;
use vyde_core::Session;

/// What happened to a token that was handed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stored {
    /// It is in the OS store. Nobody will see it again.
    InKeyring,
    /// There was no OS store, so it has to be printed once and is gone after that.
    Printed,
}

/// Owned by whoever holds it, so the key can be unlinked by handle as well as by name.
#[cfg(feature = "keyring")]
type Key = keyutils::Key;

#[cfg(feature = "keyring")]
fn keyring() -> Result<keyutils::Keyring, CliError> {
    // `attach`, not `attach_or_create`: a session keyring either exists — the login session made it —
    // or it does not, and inventing one would put the token in a ring that dies when *this process*
    // does rather than when the session does. That is not what was asked for.
    keyutils::Keyring::attach(keyutils::SpecialKeyring::Session)
        // `Missing`, not `Unreachable`. This was an `Unreachable` — "cannot reach the platform" — for a
        // keyring that is simply not there, which sent the reader to debug a platform that was working.
        // It belongs with the other "absent, and here is what to do" answers.
        .map_err(|err| {
            CliError::missing(format!(
                "this session has no kernel keyring, so there is nowhere to keep the token: {err}"
            ))
        })
}

/// Keep the token for this session.
///
/// # Errors
///
/// [`CliError::Unreachable`] when there is no keyring to put it in. There is deliberately no file
/// fallback.
#[cfg(feature = "keyring")]
pub fn store(token: &str) -> Result<Stored, CliError> {
    let mut ring = keyring()?;

    // `add_key` updates a key that already carries the description, so signing in twice replaces the
    // token rather than failing on a taken name — which is the behaviour wanted, and why there is no
    // `forget()` first.
    //
    // `keytypes::User` is the key type: "user"-owned data, readable by the user's processes and
    // gone when the session keyring is destroyed.
    ring.add_key::<keyutils::keytypes::User, _, _>("vyde:session", token.as_bytes())
        .map_err(|err| CliError::missing(format!("could not store the token: {err}")))?;

    Ok(Stored::InKeyring)
}

/// Store the complete OAuth session in the OS keyring.
pub fn store_session(session: &Session) -> Result<Stored, CliError> {
    let value = serde_json::to_string(session)
        .map_err(|err| CliError::malformed(format!("could not encode the session: {err}")))?;
    store(&value)
}

/// Keep the token, or report that it has to be printed instead.
#[cfg(all(not(feature = "keyring"), target_os = "macos"))]
pub fn store(token: &str) -> Result<Stored, CliError> {
    let account = std::env::var("USER").unwrap_or_else(|_| "vyde".to_owned());
    let status = std::process::Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-a",
            &account,
            "-s",
            "vyde:session",
            "-w",
            token,
            "-U",
        ])
        .status()
        .map_err(|err| CliError::missing(format!("could not access the macOS Keychain: {err}")))?;
    if status.success() {
        Ok(Stored::InKeyring)
    } else {
        Err(CliError::missing(
            "macOS Keychain rejected the session credential",
        ))
    }
}

#[cfg(all(not(feature = "keyring"), not(target_os = "macos")))]
/// Report that this platform has no configured credential store.
pub fn store(_token: &str) -> Result<Stored, CliError> {
    Ok(Stored::Printed)
}

/// Keep the token, or report that it has to be printed instead.
#[cfg(feature = "keyring")]
pub fn store_or_print(token: &str) -> Result<Stored, CliError> {
    store(token)
}

/// Keep the token, or report that it has to be printed instead.
#[cfg(not(feature = "keyring"))]
pub fn store_or_print(token: &str) -> Result<Stored, CliError> {
    store(token)
}

/// Read the token back, or `None` when there is none.
///
/// `None` is the ordinary answer — nobody has signed in — so it is not an error.
#[must_use]
pub fn load() -> Option<String> {
    #[cfg(feature = "keyring")]
    {
        let ring = keyring().ok()?;
        // Searched by description rather than read directly: a read needs a `Key` handle, and the
        // description is how the key is found again on the next run.
        let key: Key = ring
            .search_for_key::<keyutils::keytypes::User, _, Option<&mut keyutils::Keyring>>(
                "vyde:session",
                None,
            )
            .ok()?;
        let bytes: Vec<u8> = key.read().ok()?;
        String::from_utf8(bytes).ok()
    }

    #[cfg(not(feature = "keyring"))]
    {
        #[cfg(target_os = "macos")]
        {
            let account = std::env::var("USER").unwrap_or_else(|_| "vyde".to_owned());
            return std::process::Command::new("/usr/bin/security")
                .args([
                    "find-generic-password",
                    "-a",
                    &account,
                    "-s",
                    "vyde:session",
                    "-w",
                ])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|value| value.trim_end().to_owned());
        }

        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }
}

/// Read a persisted OAuth session, if one exists.
#[must_use]
pub fn load_session() -> Option<Session> {
    let value = load()?;
    serde_json::from_str(&value).ok()
}

/// Remove the stored token.
///
/// Called on sign-out, and whenever the platform refuses it — an expired token should not be left in
/// the keyring to fail again on the next run.
#[must_use]
pub fn forget() -> bool {
    #[cfg(feature = "keyring")]
    {
        let Ok(mut ring) = keyring() else {
            return false;
        };
        let Ok(key) = ring
            .search_for_key::<keyutils::keytypes::User, _, Option<&mut keyutils::Keyring>>(
                "vyde:session",
                None,
            )
        else {
            // Nothing stored is not a failure. A sign-out on a machine that never signed in should
            // not print a complaint.
            return true;
        };
        // `unlink_key` rather than `revoke`: revoking leaves the key in the ring in an unusable state
        // that still shows up in `/proc/keys`, and any descriptor that already had it stays readable.
        ring.unlink_key(&key).is_ok()
    }

    #[cfg(not(feature = "keyring"))]
    {
        #[cfg(target_os = "macos")]
        {
            let account = std::env::var("USER").unwrap_or_else(|_| "vyde".to_owned());
            return std::process::Command::new("/usr/bin/security")
                .args([
                    "delete-generic-password",
                    "-a",
                    &account,
                    "-s",
                    "vyde:session",
                ])
                .status()
                .map(|status| status.success())
                .unwrap_or(false);
        }

        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    }
}

/// The keyring as the service's [`TokenStore`].
///
/// This is the piece that makes the split worth having. The token lives in the *service*, in the
/// kernel's own store, so `vyde login` in one shell leaves `vyde whoami` working in another, in a
/// different process, with the interface holding nothing at all. When the interface held the token
/// instead, closing the terminal would sign you out.
pub struct Keyring;

impl vyde_core::channel::TokenStore for Keyring {
    fn load(&self) -> Option<String> {
        load()
    }

    fn load_session(&self) -> Option<Session> {
        load_session()
    }

    fn save(&self, token: &str) -> vyde_core::Result<()> {
        match store(token)? {
            Stored::InKeyring => Ok(()),
            // There was no keyring, so the token was printed once — the one case where the interface
            // has to be told, because whoever reads that line is the only one who can act on it.
            Stored::Printed => Err(vyde_core::CliError::missing(
                "no OS keyring on this machine: the token was printed once and this session cannot \
                 remember it",
            )),
        }
    }

    fn save_session(&self, session: &Session) -> vyde_core::Result<()> {
        match store_session(session)? {
            Stored::InKeyring => Ok(()),
            Stored::Printed => Err(vyde_core::CliError::missing(
                "no OS keyring on this machine: the session cannot be remembered",
            )),
        }
    }

    fn forget(&self) -> vyde_core::Result<()> {
        // The bool is "was there something to remove", which the old headless front end printed.
        // Nobody is printing it now: `vyde logout` says the session is gone either way, and a line
        // that distinguishes "removed a token" from "there was none" is noise for a person who
        // already knows they ran logout.
        let _ = forget();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The keyring is process-global state under one fixed name, so two tests touching it at once
    /// interleave into a state neither wrote — one stores a token while the other forgets it, and the
    /// failure lands on whichever ran second for reasons that have nothing to do with either.
    ///
    /// This is the same shape as the gateway's environment guard: shared process state needs a lock,
    /// and a lock held only by the tests is the right place for it because production has one caller.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct Guard(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

    impl Guard {
        fn take() -> Self {
            Self(
                LOCK.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
        }
    }

    /// The store is best effort *by design* on a machine that has no keyring, so every test here has
    /// to cope with that. Skipping silently is not an option: a test that always skips is
    /// indistinguishable from one that passes.
    fn have_keyring() -> bool {
        keyring().is_ok()
    }

    /// The whole point of the feature. Skipped-by-assertion rather than skipped, so a machine
    /// without a keyring reports that rather than passing in silence.
    #[test]
    fn a_token_survives_the_round_trip_and_forget_removes_it() {
        let _guard = Guard::take();

        if !have_keyring() {
            assert!(load().is_none(), "no keyring, so nothing can be stored");
            return;
        }

        let token = "vyde-test-token-not-a-real-credential";
        assert_eq!(
            store(token).expect("the keyring accepted it"),
            Stored::InKeyring
        );

        assert_eq!(
            load().as_deref(),
            Some(token),
            "the token did not come back"
        );

        assert!(forget(), "forget reported it could not remove it");
        assert!(load().is_none(), "and it is still readable");
    }

    /// Signing in twice must leave one key, not two. A keyring that accumulates credentials is a keyring
    /// that cannot be emptied by forgetting one of them.
    #[test]
    fn storing_twice_leaves_one_token() {
        let _guard = Guard::take();

        if !have_keyring() {
            return;
        }

        store("first-token").expect("stored");
        store("second-token").expect("stored again");

        assert_eq!(
            load().as_deref(),
            Some("second-token"),
            "the newer one wins"
        );
        let _ = forget();
    }

    /// Reading when nothing was stored is `None`, not an error. It is the state every first run is in,
    /// and making it a failure means every `whoami` before a `login` reports a problem that does not
    /// exist.
    #[test]
    fn reading_an_empty_keyring_is_not_an_error() {
        let _guard = Guard::take();
        let _ = forget();
        assert!(load().is_none());
    }

    /// Forgetting twice is fine.
    #[test]
    fn forgetting_twice_is_fine() {
        let _guard = Guard::take();
        let _ = forget();
        let _ = forget();
        assert!(load().is_none());
    }
}
