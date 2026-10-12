//! A terminal client for Vyde: native auth and account access, through the gateway.
//!
//! # The flow
//!
//! Register, confirm the address, sign in, see the account. Four screens and one status line, which
//! is the smallest thing that runs the flow end to end.
//!
//! ```text
//! choose ──▶ register ──┐
//!    │                  │  registration issues no credential, by design
//!    └──▶ login ◀───────┘
//!              │
//!              ├──▶ account
//!              │      │
//!              └──▶ verify ──▶ account
//! ```
//!
//! # What it talks to
//!
//! The gateway, never identity directly. Identity is meant to be unreachable from outside, and a
//! client that could bypass the gateway could also bypass whatever the gateway strips.
//!
//! # Where the base URL comes from
//!
//! `VYDE_GATEWAY_URL`, then `http://localhost:8081`. A flag beats both, because a flag is a
//! deliberate choice for one run and an environment variable is usually left over from another.

#![deny(missing_docs)]

pub mod api;
pub mod app;
pub mod error;
pub mod form;
pub mod terminal;
pub mod ui;

use std::process::ExitCode;

use error::Result;

/// Where the platform is, when nothing says otherwise.
pub const DEFAULT_GATEWAY_URL: &str = "http://localhost:8081";

/// Parse the base URL: flag, then environment, then the default.
///
/// A flag is split on `=` and the first `=` is the separator, so a URL with a query string survives
/// — which `split_once` gives and `split('=')` would not.
pub fn resolve_gateway_url(flag: Option<&str>) -> String {
    if let Some(value) = flag {
        return value.to_owned();
    }
    if let Ok(value) = std::env::var("VYDE_GATEWAY_URL") {
        if !value.trim().is_empty() {
            return value;
        }
    }
    DEFAULT_GATEWAY_URL.to_owned()
}

fn main() -> ExitCode {
    // The tracing subscriber goes in first and logs to a file rather than the screen: anything
    // written to stdout while the alternate screen is up corrupts the drawing, and a panic message
    // from the library would land in the middle of the form.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init()
        .ok();

    let url = resolve_gateway_url(std::env::args().nth(1).as_deref());

    let mut app = match app::App::new(&url) {
        Ok(app) => app,
        Err(err) => {
            eprintln!("vyde: {err}");
            return ExitCode::FAILURE;
        }
    };

    // A wrong URL is worth saying before taking over the screen, where the message would scroll away
    // with the drawing.
    if let Err(err) = reqwest::Url::parse(&url) {
        eprintln!("vyde: `{url}` is not a URL");
        return ExitCode::FAILURE;
    }

    match terminal::run(&mut app) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("vyde: the terminal stopped: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flag_and_no_environment_means_the_default() {
        // The environment variable is not read here: this asserts the constant, not the lookup, and
        // a test that set the environment would race every other test in this binary.
        assert_eq!(DEFAULT_GATEWAY_URL, "http://localhost:8081");
    }

    #[test]
    fn a_flag_wins() {
        assert_eq!(resolve_gateway_url(Some("http://elsewhere:9000")), "http://elsewhere:9000");
    }
}
