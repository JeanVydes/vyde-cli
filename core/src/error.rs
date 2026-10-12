//! What a call to the platform can fail with.
//!
//! Three cases because the interface has three things to do with a failure: show it, offer a retry,
//! or hold still. A refused request and an unreachable server both mean "the user has to do
//! something", but they read differently and only one is worth retrying unchanged.

/// Why a platform call failed.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// The platform could not be reached at all.
    #[error("cannot reach {base}: {reason}")]
    Unreachable {
        /// The base URL that was being called, which is the part worth reading.
        ///
        /// Its own field rather than something scraped out of `reason`. `reqwest` puts the URL in the
        /// middle of its message — `error sending request for url (http://host:8081/v1/accounts): …` —
        /// so parsing it means guessing at delimiters that are another library's formatting, and a
        /// wrong guess produces a message about the wrong host.
        base: String,
        /// The transport's own words.
        reason: String,
    },

    /// The local service could not be reached.
    ///
    /// **A separate variant from [`CliError::Unreachable`], and it has to be.** They have different
    /// fixes: one means `vyde serve` is not running, the other means the platform is down or the URL is
    /// wrong. Sharing a variant meant a broken socket reported "cannot reach the platform", which sends
    /// the reader to debug a service that was working perfectly — and the failure it actually describes,
    /// a socket that went away mid-conversation, is not even about either of those.
    #[error("the local service is not answering: {reason}")]
    ServiceUnreachable {
        /// The transport's own words.
        reason: String,
    },

    /// The platform answered, and the answer was a refusal.
    ///
    /// The status is kept because it is the difference between "fix your input" and "you may not",
    /// and the two need different words on screen.
    #[error("{message}")]
    Refused {
        /// HTTP status.
        status: u16,
        /// The platform's own message, written for the caller.
        message: String,
        /// The machine-readable code, when there is one.
        code: Option<String>,
    },

    /// The response was not the shape the port expected.
    #[error("unexpected response: {0}")]
    Malformed(String),

    /// A required value was absent.
    ///
    /// The message carries the consequence and the way out, not just what is missing: "no stored
    /// token" on its own leaves somebody reading a log with nothing to do about it, while "no stored
    /// token; run `vyde login` or pass --token" is a next command.
    #[error("{message}")]
    Missing {
        /// What is absent and what to do about it.
        message: String,
    },

    /// The invocation could not be parsed. Not a platform failure, so it carries its own variant
    /// rather than borrowing `Missing` with a `&'static str` that has to be leaked to hold a whole
    /// usage screen.
    #[error("{problem}")]
    Usage {
        /// What was wrong, in one line.
        problem: String,
        /// The usage text, printed under it.
        help: String,
    },

    /// `vyde help`, which prints and exits non-zero.
    #[error("{0}")]
    Help(String),
}

impl CliError {
    /// Whether retrying the same input could plausibly work.
    ///
    /// A wrong password is worth retrying; a malformed response is not, and retrying it forever is
    /// how a bug turns into a hang.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            // Retryable: the service is started on demand, so the next attempt may well find it, and a
            // dropped socket is not something the person did wrong.
            Self::Unreachable { .. } | Self::ServiceUnreachable { .. } => true,
            Self::Refused { status, .. } => *status >= 500,
            Self::Malformed(_) | Self::Missing { .. } | Self::Usage { .. } | Self::Help(_) => false,
        }
    }

    /// One line for a status bar, without the whole error chain.
    #[must_use]
    pub fn short(&self) -> String {
        match self {
            Self::Unreachable { base, reason } => {
                // The address, because "cannot reach the platform" sends the reader to look at the
                // platform while the actual mistake is nearly always the address. This was reported
                // live: a client pointed at a local stack refused every registration with no hint that
                // it was calling `https://vyde.dev`.
                format!("cannot reach {base}: {reason}")
            }
            Self::ServiceUnreachable { .. } => "the local service is not answering".to_owned(),
            Self::Refused { message, .. } => message.clone(),
            Self::Malformed(what) => format!("bad response: {what}"),
            Self::Missing { message } => message.clone(),
            // The whole usage screen would blow out a one-line status bar, so only the problem goes
            // there. `headless` prints the full text.
            Self::Usage { problem, .. } | Self::Help(problem) => problem.clone(),
        }
    }

    /// The usage screen, when this error carries one.
    ///
    /// Returning it rather than formatting it here is what keeps `core` free of any opinion about
    /// how a terminal should render help — the front end decides that.
    #[must_use]
    pub fn help(&self) -> Option<&str> {
        match self {
            Self::Usage { help, .. } | Self::Help(help) => Some(help),
            _ => None,
        }
    }

    /// A required thing is absent. The message says what to do about it.
    pub fn missing(message: impl Into<String>) -> Self {
        Self::Missing {
            message: message.into(),
        }
    }

    /// A socket that failed, as this crate's error.
    ///
    /// Its own variant, and deliberately not `Unreachable`: see the note there. `Unreachable` means the
    /// platform could not be reached and its reason is somebody else's words; this one means the tunnel
    /// broke, which is a different machine on a different host with a different fix.
    pub fn from_io(error: std::io::Error) -> Self {
        Self::ServiceUnreachable {
            reason: error.to_string(),
        }
    }

    /// A response that did not have the shape the caller needed.
    pub fn malformed(problem: impl Into<String>) -> Self {
        Self::Malformed(problem.into())
    }

    /// Borrow a required value out of a form field.
    pub fn require<'a>(value: &'a str, field: &'static str) -> Result<&'a str> {
        if value.trim().is_empty() {
            return Err(Self::missing(format!("{field} is required")));
        }
        Ok(value)
    }

    /// A refusal that arrived as words rather than as a response.
    ///
    /// For the channel, where a `401` from the platform and a "not signed in" raised by the service
    /// itself both come back the same way. `status` of `0` means the latter, and callers that branch
    /// on the status — "you may not" versus "fix your input" — must treat `0` as *nothing was
    /// refused by the platform at all*.
    pub fn refused(status: u16, message: impl Into<String>, code: Option<String>) -> Self {
        Self::Refused {
            status,
            message: message.into(),
            code,
        }
    }
}

/// The result every fallible thing in this crate returns.
pub type Result<T> = std::result::Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_transient_failures_are_worth_retrying() {
        assert!(
            CliError::Unreachable {
                base: "http://test".into(),
                reason: "refused".into()
            }
            .is_retryable()
        );
        assert!(
            CliError::Refused {
                status: 503,
                message: String::new(),
                code: None
            }
            .is_retryable()
        );
        // A 401 is the user's to fix, not a transient blip.
        assert!(
            !CliError::Refused {
                status: 401,
                message: String::new(),
                code: None
            }
            .is_retryable()
        );
        assert!(!CliError::missing("Name is required").is_retryable());
        assert!(!CliError::Malformed("no id".into()).is_retryable());
    }

    #[test]
    fn whitespace_is_not_a_value() {
        assert!(matches!(
            CliError::require("   ", "E-mail"),
            Err(CliError::Missing { .. })
        ));
        assert_eq!(
            CliError::require("a@b.co", "E-mail").expect("a value"),
            "a@b.co"
        );
    }

    /// The status line gets the short form; it must not get a socket error with a hostname in it.
    /// The short form names the address and drops the transport noise.
    ///
    /// Both halves matter. The address is the fix — "cannot reach the platform" sends the reader to the
    /// platform, and the actual mistake is nearly always the URL. The noise is dropped because
    /// `reqwest`'s version buries the useful part.
    #[test]
    fn the_short_form_names_the_address_and_drops_the_noise() {
        let short = CliError::Unreachable {
            base: "http://10.0.0.5:8081".into(),
            reason: "error sending request: dns error".into(),
        }
        .short();

        assert_eq!(
            short,
            "cannot reach http://10.0.0.5:8081: error sending request: dns error"
        );
        assert!(short.contains("dns error"), "{short}");
    }

    /// A socket that failed and a platform that could not be reached are different problems with
    /// different fixes, and the message has to say which one happened. Sharing a variant made a dead
    /// tunnel report "cannot reach the platform", which is how a working local stack looks broken.
    #[test]
    fn a_dead_tunnel_does_not_blame_the_platform() {
        let socket = CliError::from_io(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        assert_eq!(socket.short(), "the local service is not answering");

        let platform = CliError::Unreachable {
            base: "https://vyde.dev".into(),
            reason: "connection refused".into(),
        };
        assert_ne!(platform.short(), socket.short());
    }
}
