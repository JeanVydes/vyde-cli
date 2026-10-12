//! The fixed sets the registration form offers.
//!
//! # Why these lists are here and not fetched
//!
//! A country code is one of about two hundred and fifty, and a language is one of about eight
//! hundred. Asking the platform for the list would be a network call on a form that has to work
//! offline and would then be a second thing that can fail before the user has typed anything.
//!
//! The cost is that a new country or language needs a new build of the client, which is acceptable
//! for a set that changes every few years, and would not be for one that changes weekly.
//!
//! The values are what the platform expects — `UY`, `es` — and the labels are for a person. Both are
//! `&'static str` because they are compile-time constants, which is the only reason this file is not
//! a data file the platform serves.

/// ISO 3166-1 alpha-2, the countries where the platform can be used.
pub const COUNTRIES: &[(&str, &str)] = &[
    ("AR", "Argentina"),
    ("AT", "Austria"),
    ("AU", "Australia"),
    ("BE", "Belgium"),
    ("BR", "Brasil"),
    ("CA", "Canada"),
    ("CH", "Switzerland"),
    ("CL", "Chile"),
    ("CO", "Colombia"),
    ("CZ", "Czechia"),
    ("DE", "Germany"),
    ("DK", "Denmark"),
    ("EE", "Estonia"),
    ("ES", "España"),
    ("FI", "Finland"),
    ("FR", "France"),
    ("GB", "United Kingdom"),
    ("GR", "Greece"),
    ("HU", "Hungary"),
    ("IE", "Ireland"),
    ("IN", "India"),
    ("IS", "Iceland"),
    ("IT", "Italy"),
    ("JP", "Japan"),
    ("KR", "South Korea"),
    ("LT", "Lithuania"),
    ("LU", "Luxembourg"),
    ("LV", "Latvia"),
    ("MX", "México"),
    ("MY", "Malaysia"),
    ("NL", "Netherlands"),
    ("NO", "Norway"),
    ("NZ", "New Zealand"),
    ("PE", "Perú"),
    ("PL", "Poland"),
    ("PT", "Portugal"),
    ("RO", "Romania"),
    ("SE", "Sweden"),
    ("SG", "Singapore"),
    ("SI", "Slovenia"),
    ("SK", "Slovakia"),
    ("US", "United States"),
    ("UY", "Uruguay"),
    ("ZA", "South Africa"),
];

/// ISO 639-1 alpha-2, the languages the interface offers.
///
/// Deliberately a subset. This list is for choosing the *account's* language, and a person who wants
/// a language that is not here is better served by the two-letter code than by scrolling a list of
/// forty.
pub const LANGUAGES: &[(&str, &str)] = &[
    ("de", "Deutsch"),
    ("en", "English"),
    ("es", "Español"),
    ("fr", "Français"),
    ("it", "Italiano"),
    ("ja", "日本語"),
    ("nl", "Nederlands"),
    ("pl", "Polski"),
    ("pt", "Português"),
    ("ru", "Русский"),
    ("sv", "Svenska"),
    ("tr", "Türkçe"),
    ("uk", "Українська"),
    ("zh", "中文"),
];

/// The option a select starts on, when one of these is in the list.
///
/// A field with no sensible default would open on whatever is alphabetically first, which for a
/// country is `AR Argentina` — wrong for most people and wrong in a way they may not notice. So the
/// form asks for a starting option and this is the only place that knows what the ones are.
#[must_use]
pub fn preferred<'a>(options: &[(&'a str, &'a str)], candidates: &[&'a str]) -> &'a str {
    let first = options.first().map_or("", |(value, _)| *value);
    candidates
        .iter()
        .find(|code| options.iter().any(|(value, _)| value == *code))
        .copied()
        .unwrap_or(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values are what the platform validates, so a label accidentally used as a value would be
    /// accepted by the form and refused by the server.
    #[test]
    fn every_country_value_is_an_alpha2_code() {
        for (code, label) in COUNTRIES {
            assert_eq!(code.len(), 2, "`{code}` ({label}) is not two letters");
            assert!(
                code.chars().all(|c| c.is_ascii_uppercase()),
                "`{code}` is not upper case"
            );
            assert!(!label.is_empty(), "`{code}` has no label");
        }
    }

    #[test]
    fn every_language_value_is_an_alpha2_code() {
        for (code, label) in LANGUAGES {
            assert_eq!(code.len(), 2, "`{code}` ({label}) is not two letters");
            assert!(
                code.chars().all(|c| c.is_ascii_lowercase()),
                "`{code}` is not lower case"
            );
        }
    }

    /// Duplicates would make the arrows land on the same option twice.
    #[test]
    fn no_option_appears_twice() {
        for (name, options) in [("country", COUNTRIES), ("language", LANGUAGES)] {
            let mut seen = std::collections::HashSet::new();
            for (value, _) in options.iter() {
                assert!(seen.insert(*value), "{name}: `{value}` appears twice");
            }
        }
    }

    #[test]
    fn the_lists_are_sorted_so_the_arrows_go_somewhere_sensible() {
        for (name, options) in [("country", COUNTRIES), ("language", LANGUAGES)] {
            let codes: Vec<&str> = options.iter().map(|(code, _)| *code).collect();
            let mut sorted = codes.clone();
            sorted.sort_unstable();
            assert_eq!(codes, sorted, "{name} is not in code order");
        }
    }

    /// Uruguay and Spanish are the defaults because that is where this started, and the test is what
    /// stops a refactor from quietly changing them.
    #[test]
    fn the_preferred_option_is_found() {
        assert_eq!(preferred(COUNTRIES, &["UY", "AR"]), "UY");
        assert_eq!(preferred(LANGUAGES, &["es"]), "es");
    }

    /// A preferred option that is not in the list falls back to the first rather than inventing a
    /// value the platform would refuse.
    #[test]
    fn a_missing_preference_falls_back_to_the_first() {
        assert_eq!(preferred(COUNTRIES, &["ZZ"]), "AR");
    }
}
