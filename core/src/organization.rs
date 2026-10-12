//! Organizations: the tenant an account belongs to.
//!
//! Present for one reason — an organization can be renamed, and a client that cannot name it cannot ask.
//! Deliberately not modelled any further: membership, roles and applications are the platform's
//! business, and a client type that mirrored them would be a second description of them to keep in step.

use serde::{Deserialize, Serialize};

/// An organization, as the platform reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Organization {
    /// Stable identifier, the one a rename is addressed to.
    pub id: String,
    /// Display name. The only field a rename changes.
    pub name: String,
    /// URL-safe identifier.
    ///
    /// **Never editable.** It appears in every URL, every `client_id` and every grant issued against
    /// the organization, so it is reported so a client can show where a thing lives, and not sent on a
    /// rename because changing one is a migration rather than a field edit.
    pub slug: String,
}

impl Organization {
    /// A rename with nothing in it is not a rename.
    ///
    /// Asked before sending so the form can stay quiet rather than have the platform explain that
    /// `{name: "..."}` was never going to be accepted.
    #[must_use]
    pub fn is_new_name(current: &str, proposed: &str) -> bool {
        !proposed.trim().is_empty() && proposed.trim() != current.trim()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unchanged_name_is_not_a_rename() {
        assert!(!Organization::is_new_name("Acme Cloud", "Acme Cloud"));
        assert!(
            !Organization::is_new_name("Acme Cloud", "  Acme Cloud  "),
            "whitespace is not a change"
        );
        assert!(
            !Organization::is_new_name("Acme Cloud", "   "),
            "blank is not a change"
        );
        assert!(Organization::is_new_name("Acme Cloud", "Acme Cloud Ltd"));
    }
}
