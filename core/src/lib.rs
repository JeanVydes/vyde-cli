//! The native auth flow and the types it moves.
//!
//! # What lives here, and what deliberately does not
//!
//! The flow, the form state machine, and the domain types. No terminal, no HTTP, no clock, no
//! randomness — so the whole of the auth flow is testable by constructing an [`AuthService`] over a
//! fake [`PlatformPort`] and asserting on what came back. That is the reason this is a separate
//! crate: it is the only way the tests below can exist without a pty.
//!
//! Everything that touches the outside world is a [`PlatformPort`] implementation in the binary crate.
//! The split is the same one identity and gateway use, and it earns itself the same way: a port with
//! one implementation that is not behind a trait is a port with one implementation that cannot be
//! replaced, and that is the same as having written the call directly.

#![deny(missing_docs)]

pub mod account;
pub mod channel;
pub mod choices;
pub mod error;
pub mod form;
pub mod organization;
pub mod port;
pub mod service;

pub use account::{Account, Address, NewAccount, Session};
pub use channel::{Dispatcher, Event, Request, Response};
pub use error::{CliError, Result};
pub use form::{Field, Form};
pub use organization::Organization;
pub use port::{AccountPatch, PlatformPort};
pub use service::AuthService;
