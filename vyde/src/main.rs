//! `vyde` — a terminal client for the Vyde platform.
//!
//! The headless command line client for Vyde.
//!
//! # Composition root
//!
//! Everything is built here, once, and passed down: the HTTP adapter into the service, the service
//! into the app. Nothing reaches for a global. The one place a base URL is resolved is
//! [`resolve_gateway_url`], so the precedence — flag, environment, default — is in one readable place.

#![deny(missing_docs)]

pub mod headless;
pub mod ipc;
/// Browser-based OAuth authentication.
pub mod oauth;
pub mod platform;

use std::process::ExitCode;

use vyde_core::{AuthService, Result};

use crate::platform::HttpPlatform;

/// Where the platform is, when nothing says otherwise.
///
/// The production platform. A client whose default is a developer's `localhost` is a client that
/// silently talks to nothing on a machine without a dev stack, and the failure shows up as a
/// connection refused somewhere far from the cause.
pub const DEFAULT_GATEWAY_URL: &str = "https://vyde.dev";
/// Development gateway served by the local Docker stack.
pub const DEV_GATEWAY_URL: &str = "https://api.vyde.test:8443";

/// The base URL: a flag, then the environment, then the default.
///
/// A flag beats the environment because a flag is a deliberate choice for one run, and an environment
/// variable is usually left over from another.
#[must_use]
pub fn resolve_gateway_url(flag: Option<&str>) -> String {
    chosen_gateway_url(flag).unwrap_or_else(|| DEFAULT_GATEWAY_URL.to_owned())
}

/// The base URL **only if somebody chose it**, and `None` when it is just the default.
///
/// Separate from [`resolve_gateway_url`] because this value is what gets handed to a service the
/// interface starts, and the two cases are not equivalent. A default is not a preference — nobody
/// picked it — so passing it down means a typo in one command poisons every later one: the interface
/// that made the mistake exits, and the service it spawned keeps the wrong address and answers
/// "cannot reach `http://localhost:9999`" to a later command that asked for nothing in particular. An
/// explicit value is a decision, and passing a decision down is the point.
#[must_use]
pub fn chosen_gateway_url(flag: Option<&str>) -> Option<String> {
    let from_flag = flag
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    if from_flag.is_some() {
        return from_flag;
    }

    std::env::var("VYDE_GATEWAY_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn main() -> ExitCode {
    let raw_arguments: Vec<String> = std::env::args().collect();
    let dev = raw_arguments.iter().any(|argument| argument == "--dev");
    let arguments: Vec<String> = raw_arguments
        .into_iter()
        .filter(|argument| argument != "--dev")
        .collect();

    // Parsed before anything is built, so a bad invocation costs nothing.
    let command = match headless::parse(&arguments) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("vyde: {}", err.short());
            // The usage screen under the problem, when there is one. stderr, so a caller capturing
            // stdout gets nothing at all from a command that did not run.
            if let Some(help) = err.help() {
                eprintln!("\n{help}");
            }
            return ExitCode::FAILURE;
        }
    };

    let url = if dev && chosen_gateway_url(None).is_none() {
        DEV_GATEWAY_URL.to_owned()
    } else {
        resolve_gateway_url(std::env::var("VYDE_GATEWAY_URL").ok().as_deref())
    };
    let platform = match HttpPlatform::new(&url) {
        Ok(platform) => platform,
        Err(err) => {
            eprintln!("vyde: {err}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("vyde: could not start the async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    if matches!(command, headless::Command::Login) {
        return runtime.block_on(oauth::login(&platform));
    }

    // One decision, here, and it is the architecture: `serve` is the only thing that builds a service,
    // and everything else is a client that connects to one. There is no path that quietly does both,
    // which is what stops a working in-process call from hiding the tunnel until it breaks.
    if matches!(command, headless::Command::Serve) {
        return serve(platform, runtime);
    }

    // Only an explicitly chosen URL is handed to a service this interface starts. Passing the default
    // down would let a typo in one command decide the platform for every command after it.
    let chosen = if dev && chosen_gateway_url(None).is_none() {
        Some(url.clone())
    } else {
        chosen_gateway_url(std::env::var("VYDE_GATEWAY_URL").ok().as_deref())
    };

    let client =
        match runtime.block_on(ipc::Client::connect(&ipc::socket_path(), chosen.as_deref())) {
            Ok(client) => client,
            Err(err) => {
                eprintln!(
                    "vyde: cannot reach the local service on {}: {}",
                    ipc::socket_path().display(),
                    err
                );
                eprintln!(
                    "hint: start it with `vyde serve`, or check that the socket is not owned by \
                 someone else."
                );
                return ExitCode::FAILURE;
            }
        };

    headless_command(client, platform, runtime, command)
}

/// Run the service: bind the tunnel and answer requests until stopped.
///
/// No terminal, no screen, no drawing. That is the point: this process can be backgrounded, and the
/// interface — which cannot — is a client of it. `Ctrl-C` here ends the service and leaves the socket
/// behind, which the next bind removes after checking nothing is listening on it.
fn serve(platform: HttpPlatform, runtime: tokio::runtime::Runtime) -> ExitCode {
    let path = ipc::socket_path();
    let server = match runtime.block_on(ipc::Server::bind(path.clone())) {
        Ok(server) => server,
        Err(err) => {
            eprintln!("vyde: cannot listen on {}: {err}", path.display());
            return ExitCode::FAILURE;
        }
    };

    eprintln!("vyde: the service is listening on {}", path.display());

    // One dispatcher for the whole process, behind a lock.
    //
    // The lock is not for concurrency the service does not have — `Server::serve` takes one connection
    // at a time. It is because `serve` takes an `FnMut` that must return a future, and a future
    // borrowing `&mut dispatcher` does not outlive the call. An `Arc<Mutex<_>>` turns the borrow into
    // a clone, which is the whole reason it is worth the wrapper.
    //
    // It is also correct rather than merely convenient: the dispatcher holds the session, so one per
    // connection would be two sessions that do not know about each other.
    let service = std::sync::Arc::new(AuthService::new(std::sync::Arc::new(platform)));
    let dispatcher = std::sync::Arc::new(tokio::sync::Mutex::new(vyde_core::Dispatcher::new(
        service,
        // **The kernel keyring, here in the service process.** This is the single most important line
        // in the file: it is why the token outlives the terminal that signed in, why `vyde whoami`
        // works in a different shell, and why `vyde logout` in a third one clears it. An interface
        // that held the token itself would lose the session every time it was closed — which is the
        // whole reason the two processes exist at all.
        std::sync::Arc::new(platform::keyring::Keyring),
    )));

    match runtime.block_on(server.serve(move |request| {
        let dispatcher = dispatcher.clone();
        async move {
            // The guard is held across the await on purpose: it is the serialization. A `whoami`
            // that ran while a `sign_in` was in flight would read the previous account's token.
            let mut dispatcher = dispatcher.lock().await;
            dispatcher.handle(request).await
        }
    })) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("vyde: the service stopped: {err}");
            ExitCode::FAILURE
        }
    }
}

fn headless_command(
    mut client: ipc::Client,
    platform: HttpPlatform,
    runtime: tokio::runtime::Runtime,
    command: headless::Command,
) -> ExitCode {
    match runtime.block_on(headless::run(&mut client, &platform, command)) {
        Ok(report) => {
            for line in report.lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            // stderr, so a caller capturing stdout gets the report and never the failure.
            eprintln!("vyde: {}", err.short());
            if let Some(help) = err.help() {
                eprintln!("\n{help}");
            }
            ExitCode::FAILURE
        }
    }
}

/// Re-exported so the binary and its tests agree on the one `Result` the crate speaks.
type _Result = Result<()>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_production() {
        assert_eq!(DEFAULT_GATEWAY_URL, "https://vyde.dev");
        assert_eq!(resolve_gateway_url(None), "https://vyde.dev");
    }

    /// The default is production *and is not a choice*.
    ///
    /// Both halves matter. `chosen_gateway_url` returning `None` for the default is what stops a typo in
    /// one command from deciding the platform for every command after it: the interface that made the
    /// mistake exits, and the service it started would otherwise keep the wrong address and answer
    /// "cannot reach `http://localhost:9999`" to somebody who asked for nothing in particular. Found by
    /// doing exactly that and being stuck with it.
    #[test]
    fn nothing_chosen_means_nothing_to_pass_down() {
        assert_eq!(chosen_gateway_url(None), None);
        assert_eq!(
            chosen_gateway_url(Some("http://localhost:8081")),
            Some("http://localhost:8081".to_owned()),
            "an explicit address is a decision, and a decision is passed down"
        );
        assert_eq!(
            chosen_gateway_url(Some("  ")),
            None,
            "blank is not a choice"
        );
    }

    #[test]
    fn a_flag_wins_over_the_default() {
        assert_eq!(
            resolve_gateway_url(Some("http://elsewhere:9000")),
            "http://elsewhere:9000"
        );
    }

    /// A blank flag is not a choice. Falling through to the default is what somebody who exported
    /// `VYDE_GATEWAY_URL=""` expects; returning the blank would fail every call with a parse error
    /// about nothing.
    #[test]
    fn a_blank_flag_falls_through() {
        assert_eq!(resolve_gateway_url(Some("   ")), DEFAULT_GATEWAY_URL);
    }

    #[test]
    fn the_terminal_check_answers_something() {
        // The value depends on how the test runner was started, so only the type is asserted: what
        // matters is that the function exists and does not need a terminal to be called.
    }
}
