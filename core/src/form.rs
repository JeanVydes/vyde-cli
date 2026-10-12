//! The form: a list of fields, one of which has the cursor.
//!
//! Deliberately the smallest thing that can run the flow. No validation beyond "not empty", because
//! the platform validates everything properly and duplicating its rules here would mean two places to
//! keep in step and a second, weaker answer on screen.
//!
//! The cursor is an index rather than a position in a string, because the password fields render as
//! dots and a cursor offset into a masked value is a lie about where the character is.

/// How a field takes its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Anything goes.
    Text {
        /// Shown while empty, so the expected shape is visible before typing starts.
        placeholder: &'static str,
    },
    /// Rendered as dots.
    Secret,
    /// One of a fixed set. Not free text: a country code is one of about two hundred and a half, and
    /// typing `U` into a text field gets you `UY` by luck rather than by choosing.
    Choice {
        /// Every option, as `(value, label)`. The value goes on the wire; the label is what a person
        /// reads, so it can be `UY  Uruguay` without the platform ever seeing the second half.
        options: &'static [(&'static str, &'static str)],
        /// Which option is highlighted.
        selected: usize,
    },
    /// `YYYY-MM-DD`, which cannot be a free text field: `1990-4-7` and `19-04-1990` are both things
    /// somebody will type, and the platform will refuse both. The separators are supplied here, so
    /// the field can only ever produce the format the platform asked for.
    Date {
        /// The digits so far, and which half the caret is in.
        parts: DateParts,
    },
}

impl Default for Kind {
    fn default() -> Self {
        Self::Text { placeholder: "" }
    }
}

/// One input.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Field {
    /// Shown on the left of the row.
    pub label: &'static str,
    /// What is typed so far. For a `Choice` this is the selected option's value; for a `Date` it is
    /// what the parts render to.
    pub value: String,
    /// How this field takes input.
    pub kind: Kind,
}

impl Field {
    /// A plain visible field.
    #[must_use]
    pub fn text(label: &'static str, placeholder: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            kind: Kind::Text { placeholder },
        }
    }

    /// A field whose value must not appear on screen.
    #[must_use]
    pub fn secret(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            kind: Kind::Secret,
        }
    }

    /// A field whose value is one of a fixed set.
    #[must_use]
    pub fn choice(label: &'static str, options: &'static [(&'static str, &'static str)]) -> Self {
        Self {
            label,
            value: options
                .first()
                .map_or_else(String::new, |(value, _)| (*value).to_owned()),
            kind: Kind::Choice {
                options,
                selected: 0,
            },
        }
    }

    /// A `YYYY-MM-DD` field.
    #[must_use]
    pub fn date(label: &'static str) -> Self {
        Self {
            label,
            value: String::new(),
            kind: Kind::Date {
                parts: DateParts::default(),
            },
        }
    }

    /// Rendered as dots, whether this field is one or not. The question a drawing routine asks, kept
    /// here so it does not have to match on `Kind` and get it wrong for the secret case.
    #[must_use]
    pub fn is_secret(&self) -> bool {
        matches!(self.kind, Kind::Secret)
    }

    /// What the row shows: the value, or the placeholder when there is none.
    #[must_use]
    pub fn display(&self) -> String {
        if self.is_secret() {
            return "•".repeat(self.value.chars().count());
        }
        if self.value.is_empty() {
            return match self.kind {
                Kind::Text { placeholder } => placeholder.to_owned(),
                // A choice always has a value, so an empty one is a broken option list rather than
                // something to render as blank.
                _ => String::new(),
            };
        }
        self.value.clone()
    }

    /// Whether this row has anything in it.
    ///
    /// A `Choice` is never empty: the first option is selected from the start, so an unchosen country
    /// cannot be submitted as `""`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !matches!(self.kind, Kind::Choice { .. }) && self.value.trim().is_empty()
    }

    /// Whether this field holds something that could be sent.
    ///
    /// Distinct from `is_empty` only for the date, and the distinction is the whole point: `1990-01-`
    /// is not empty, and it is not an answer either.
    #[must_use]
    pub fn is_answered(&self) -> bool {
        match &self.kind {
            Kind::Date { parts } => {
                date_is_complete(&[parts.year.clone(), parts.month_day.clone()])
            }
            // A picker always has a selection — that is the point of defaulting it to something sensible rather
            // than to the first option alphabetically — so it is answered as soon as the option is named.
            Kind::Choice { .. } => !self.value.trim().is_empty(),
            Kind::Text { .. } | Kind::Secret => !self.value.trim().is_empty(),
        }
    }

    /// Why this field cannot be sent yet, in words meant for the person filling it in.
    #[must_use]
    pub fn wants(&self) -> String {
        match &self.kind {
            Kind::Date { parts } => match (parts.year.len(), parts.month_day.len()) {
                (0..=3, _) => format!("{} — the year needs four digits", self.label),
                (_, 0..=1) => format!("{} — the month needs two digits", self.label),
                (_, 2..=3) => format!("{} — the day needs two digits", self.label),
                _ => format!("{} — write it as YYYY-MM-DD", self.label),
            },
            _ => format!("{} needs something in it", self.label),
        }
    }

    /// Whether the placeholder is showing, which is what makes the row dim.
    #[must_use]
    pub fn showing_placeholder(&self) -> bool {
        self.value.is_empty() && matches!(self.kind, Kind::Text { .. })
    }

    /// Empty this field.
    pub fn clear(&mut self) {
        self.value.clear();
    }

    /// Select one option by value, leaving the selection alone if the value is not in the list.
    ///
    /// A picker has to start on *something*, and the first option alphabetically is `AR Argentina` and
    /// `de Deutsch` — which is wrong for most people in a way they may not notice, since the field looks
    /// filled in. So the caller names a starting option and this puts it there.
    pub fn select(&mut self, value: &str) {
        if let Kind::Choice { options, selected } = &mut self.kind
            && let Some(index) = options
                .iter()
                .position(|(candidate, _)| *candidate == value)
        {
            *selected = index;
            self.value = value.to_owned();
        }
    }

    /// Overwrite the value.
    pub fn set(&mut self, value: impl Into<String>) {
        self.value = value.into();
    }

    /// Put a date in from `YYYY-MM-DD`, as a stored session or a request would carry it.
    ///
    /// Takes the value apart rather than storing it as one string, because the parts are what the
    /// renderer and the cursor operate on. Anything that is not four-four digits leaves the field as
    /// it was rather than putting a shape the platform will refuse into the parts.
    pub fn set_date(&mut self, value: &str) {
        let Some((year, rest)) = value.split_once('-') else {
            return;
        };
        let Some((month, day)) = rest.split_once('-') else {
            return;
        };
        let parts = [year.to_owned(), format!("{month}{day}")];

        if !date_is_complete(&parts) {
            return;
        }

        self.value = render_date(&parts);
        if let Kind::Date { parts: stored } = &mut self.kind {
            stored.year = parts[0].clone();
            stored.month_day = parts[1].clone();
            // A restored date is finished, so the caret belongs after the day rather than in the year.
            stored.part = 1;
        }
    }

    /// Append one character.
    pub fn push(&mut self, character: char) {
        self.value.push(character);
    }

    /// Remove the last character.
    ///
    /// `String::pop` is a char-boundary operation, so a multi-byte character comes off whole. Indexing
    /// by byte and truncating would panic on the first accented name typed.
    pub fn pop(&mut self) {
        self.value.pop();
    }
}

/// An ordered set of fields with a focused one.
#[derive(Debug)]
pub struct Form {
    /// Shown in the panel's top border.
    pub title: &'static str,
    /// The inputs, in the order they are filled.
    pub fields: Vec<Field>,
    /// Which field takes the next keystroke.
    pub focus: usize,
}

impl Form {
    /// Set a choice field by index.
    pub fn select_at(&mut self, index: usize, value: &str) {
        if let Some(field) = self.fields.get_mut(index) {
            field.select(value);
        }
    }

    /// Set a date field by index.
    pub fn set_date_at(&mut self, index: usize, value: &str) {
        if let Some(field) = self.fields.get_mut(index) {
            field.set_date(value);
        }
    }
    /// Build a form from its fields.
    pub fn new(title: &'static str, fields: Vec<Field>) -> Self {
        Self {
            title,
            fields,
            focus: 0,
        }
    }

    /// The widest label, for a drawing routine that has to align the values into a column.
    #[must_use]
    pub fn label_width(&self) -> usize {
        self.fields
            .iter()
            .map(|field| field.label.len())
            .max()
            .unwrap_or(8)
            .max(12)
    }

    /// Move the focus down, wrapping.
    ///
    /// Wrapping because the fields are a ring: tabbing off the last one and back to the first beats
    /// reaching for the shift key.
    pub fn next(&mut self) {
        if !self.fields.is_empty() {
            self.focus = (self.focus + 1) % self.fields.len();
        }
    }

    /// Move the focus up, wrapping.
    pub fn previous(&mut self) {
        if !self.fields.is_empty() {
            self.focus = if self.focus == 0 {
                self.fields.len() - 1
            } else {
                self.focus - 1
            };
        }
    }

    /// One field's value, by index.
    #[must_use]
    pub fn value(&self, index: usize) -> &str {
        self.fields
            .get(index)
            .map_or("", |field| field.value.as_str())
    }

    /// Empty one field by index.
    ///
    /// Indexed rather than focused because the flow calling this is acting on a *specific* field — "the
    /// password was wrong, forget it" — and a form-level clear would empty whatever the cursor
    /// happened to be on.
    pub fn clear_at(&mut self, index: usize) {
        if let Some(field) = self.fields.get_mut(index) {
            field.clear();
        }
    }

    /// Overwrite one field by index, for pre-filling from what was typed elsewhere.
    pub fn set_at(&mut self, index: usize, value: impl Into<String>) {
        if let Some(field) = self.fields.get_mut(index) {
            field.set(value);
        }
    }

    /// Type into the focused field.
    ///
    /// A `Choice` ignores typing: its value moves with the arrows, not with the keyboard, and a
    /// keystroke that silently did nothing would read as a dropped key. A letter picks the option that
    /// starts with it, which is what somebody typing "uruguay" is actually trying to do.
    pub fn insert(&mut self, character: char) {
        let Some(field) = self.fields.get_mut(self.focus) else {
            return;
        };
        match &mut field.kind {
            Kind::Choice { options, selected } => {
                let lowered = character.to_ascii_lowercase();
                if let Some(index) = options
                    .iter()
                    .position(|(_, label)| label.to_ascii_lowercase().starts_with(lowered))
                {
                    *selected = index;
                    field.value = options[index].0.to_owned();
                }
            }
            Kind::Date { parts } => {
                // Digits only. `1990-4-7` cannot be produced this way because the separators are
                // supplied by `date_layout`, not typed.
                if !character.is_ascii_digit() {
                    return;
                }

                if parts.part == 0 {
                    if parts.year.len() < 4 {
                        parts.year.push(character);
                    }
                    // Four digits is a whole year, so the caret crosses on its own. Without this
                    // somebody types `1990` and then has to discover the arrow key, which is not
                    // something a date field should require.
                    if parts.year.len() == 4 {
                        parts.part = 1;
                    }
                } else if parts.month_day.len() < 4 {
                    parts.month_day.push(character);
                }

                field.value = render_date(&[parts.year.clone(), parts.month_day.clone()]);
            }
            Kind::Text { .. } | Kind::Secret => field.push(character),
        }
    }

    /// Backspace in the focused field.
    pub fn backspace(&mut self) {
        let Some(field) = self.fields.get_mut(self.focus) else {
            return;
        };
        match &mut field.kind {
            Kind::Choice { .. } => {
                // Nothing to delete: the value is a selection, not a string.
            }
            Kind::Date { parts } => {
                // Crosses *back* over the boundary when the month half is empty, so backspace walks
                // the whole date in one direction instead of stopping dead at the hyphen.
                if parts.part == 1 && parts.month_day.is_empty() {
                    parts.part = 0;
                } else if parts.part == 0 {
                    parts.year.pop();
                } else {
                    parts.month_day.pop();
                }

                field.value = render_date(&[parts.year.clone(), parts.month_day.clone()]);
            }
            Kind::Text { .. } | Kind::Secret => field.pop(),
        }
    }

    /// Move a `Choice` down, or advance a `Date` from the year to the month.
    ///
    /// A no-op on a text or secret field, where the up and down arrows belong to the interface rather
    /// than to the value.
    pub fn step_down(&mut self) {
        let Some(field) = self.fields.get_mut(self.focus) else {
            return;
        };
        match &mut field.kind {
            Kind::Choice { options, selected } => {
                *selected = (*selected + 1) % options.len().max(1);
                if let Some((value, _)) = options.get(*selected) {
                    field.value = (*value).to_owned();
                }
            }
            Kind::Date { parts, .. } => {
                // Forward only. Backwards belongs to backspace, which knows about the boundary;
                // letting the up arrow cross it too would give two keys the same meaning.
                if parts.year.len() == 4 {
                    parts.part = 1;
                }
            }
            Kind::Text { .. } | Kind::Secret => {}
        }
    }

    /// Move a `Choice` up. Wrapping, so a long list can be reached from anywhere.
    pub fn step_up(&mut self) {
        let Some(field) = self.fields.get_mut(self.focus) else {
            return;
        };
        match &mut field.kind {
            Kind::Choice { options, selected } if options.len() > 1 => {
                *selected = if *selected == 0 {
                    options.len() - 1
                } else {
                    *selected - 1
                };
                if let Some((value, _)) = options.get(*selected) {
                    field.value = (*value).to_owned();
                }
            }
            Kind::Date { parts, .. } => {
                // The down arrow is one-way on purpose. The up arrow crossing back would give it the
                // same meaning as backspace, and backspace already does it correctly.
                if parts.year.len() == 4 {
                    parts.part = 1;
                }
            }
            Kind::Choice { .. } | Kind::Text { .. } | Kind::Secret => {}
        }
    }

    /// Clear the focused field.
    pub fn clear(&mut self) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            field.clear();
        }
    }

    /// The first empty field, if any.
    #[must_use]
    pub fn first_empty(&self) -> Option<usize> {
        self.fields.iter().position(Field::is_empty)
    }

    /// The first field that has no answer yet, if any.
    ///
    /// **Not the same question as `first_empty`, and the difference is the birthday field.** While
    /// somebody is typing `1990-01-` the field is not empty, so the empty check passed it, the form
    /// submitted, and the platform answered with a date-format error nobody could act on — with the
    /// row already drawn red the whole time. A field is answered when it holds something that could
    /// be sent: text has characters, a picker has a selection, a date has eight digits.
    #[must_use]
    pub fn first_unanswered(&self) -> Option<usize> {
        self.fields.iter().position(|field| !field.is_answered())
    }

    /// Jump to the first empty field, so the cursor lands on what is missing rather than a message
    /// naming a field the user is not looking at.
    pub fn focus_first_empty(&mut self) {
        if let Some(index) = self.first_empty() {
            self.focus = index;
        }
    }

    /// Whether every field has something in it.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.first_empty().is_none()
    }
}

/// The parts of a `YYYY-MM-DD` field, with a cursor over them.
///
/// The two halves — the year, and the month-and-day — are separate because that is where the caret
/// goes: typing moves through digits and stops at four, and the cursor crosses from one half to the
/// other. Storing the whole string and indexing into it would make the hyphen a character you can
/// backspace over, which is how `1990-` becomes a thing somebody can produce.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DateParts {
    /// Up to four digits.
    pub year: String,
    /// Up to four digits: the first two are the month, the rest the day.
    pub month_day: String,
    /// Which half the caret is in. 0 is the year.
    pub part: usize,
}

/// The display for a date field, and where the caret goes in it.
///
/// **One function owns this layout**, because the first version built it twice — once in the renderer
/// and once in the tests — and they disagreed: in the year half it produced `1990▏-0310`, with the
/// month and day run together and the hyphen between them missing. Anything that has to stay in step
/// with a format belongs next to the format.
///
/// The separators appear only once the group before them is complete, so a field nobody has typed in
/// does not show a row of hyphens, and one that has a full year shows `1990-`.
#[must_use]
pub fn date_layout(parts: &DateParts) -> (String, usize) {
    let year = parts.year.as_str();
    let month = &parts.month_day[..parts.month_day.len().min(2)];
    let day = &parts.month_day[parts.month_day.len().min(2)..];

    if year.is_empty() {
        return (String::new(), 0);
    }

    let mut text = String::with_capacity(10);
    text.push_str(year);

    if year.len() < 4 {
        // Still typing the year: no separator yet, and the caret sits at the end of what is there.
        return (text.clone(), text.len());
    }

    text.push('-');
    text.push_str(month);
    let after_month = text.len();

    if parts.part == 0 {
        return (text, year.len());
    }

    if month.len() == 2 {
        text.push('-');
        text.push_str(day);
    }

    let caret = if month.len() < 2 {
        after_month
    } else {
        text.len()
    };
    (text, caret)
}

/// `YYYY-MM-DD` from the parts — the same function the display uses.
///
/// Deliberately not a second formatter. There was one, and it disagreed with the renderer: it
/// produced `1990--` when only the year was typed, because it emitted both separators
/// unconditionally. That string is not merely ugly — it is what a submit would have sent, and the
/// platform would have refused it for a reason nobody could see. One formatter, one answer.
#[must_use]
pub fn render_date(parts: &[String; 2]) -> String {
    let part = DateParts {
        year: parts[0].clone(),
        month_day: parts[1].clone(),
        part: 1,
    };
    date_layout(&part).0
}

/// Whether a date field holds something that could be a date.
///
/// Not a real date check — the platform owns that rule, and a second one here would be a second thing
/// to keep in step. This only refuses the shapes that cannot be right: a year that is not four digits,
/// and a month or day that is not two.
#[must_use]
pub fn date_is_complete(parts: &[String; 2]) -> bool {
    parts[0].len() == 4
        && parts[1].len() == 4
        && parts[0].chars().all(|c| c.is_ascii_digit())
        && parts[1].chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> Form {
        Form::new(
            "Test",
            vec![
                Field::text("E-mail", "you@example.test"),
                Field::secret("Password"),
            ],
        )
    }

    #[test]
    fn typing_goes_to_the_focused_field() {
        let mut form = form();
        for character in "abc".chars() {
            form.insert(character);
        }

        assert_eq!(form.value(0), "abc");
        assert!(form.value(1).is_empty(), "the password was not touched");
    }

    #[test]
    fn focus_wraps_in_both_directions() {
        let mut form = form();
        form.next();
        assert_eq!(form.focus, 1);

        form.next();
        assert_eq!(form.focus, 0, "past the last field comes back to the first");

        form.previous();
        assert_eq!(form.focus, 1, "and up from the first is the last");
    }

    /// A password must never appear on screen, and the row's width still has to match the number of
    /// characters typed — a mask of fixed width gives away the length.
    #[test]
    fn a_secret_renders_as_one_dot_per_character() {
        let mut form = form();
        form.next();
        for _ in 0..12 {
            form.insert('x');
        }

        assert_eq!(form.fields[1].display(), "•".repeat(12));
        assert!(!form.fields[1].display().contains('x'));
    }

    /// Backspace takes a whole character, not a byte. Truncating by byte would panic on the first
    /// accented character typed into any field.
    #[test]
    fn backspace_removes_a_whole_character() {
        let mut form = form();
        for character in "ñé".chars() {
            form.insert(character);
        }
        assert_eq!(form.value(0), "ñé");

        form.backspace();
        assert_eq!(form.value(0), "ñ");
        assert_eq!(form.value(0).chars().count(), 1);
    }

    #[test]
    fn the_placeholder_shows_only_while_the_field_is_empty() {
        let mut form = form();
        assert!(form.fields[0].showing_placeholder());

        form.insert('a');
        assert!(!form.fields[0].showing_placeholder());
        assert_eq!(form.fields[0].display(), "a");
    }

    #[test]
    fn focus_moves_to_the_first_empty_field() {
        let mut form = form();
        form.next();
        form.focus_first_empty();

        assert_eq!(form.focus, 0, "the e-mail is the missing one");
        assert!(!form.is_complete());
    }

    #[test]
    fn a_complete_form_is_complete() {
        let mut form = form();
        form.insert('a');
        form.next();
        form.insert('b');

        assert!(form.is_complete());
    }

    /// `set_at` and `clear_at` name the field rather than the cursor, because the flow clears a
    /// specific one — the password it just learned was wrong — and not whichever has the focus.
    #[test]
    fn a_named_field_is_edited_independently_of_the_cursor() {
        let mut form = form();
        form.set_at(1, "secret-value");
        form.focus = 0;

        form.clear_at(1);
        assert!(form.value(1).is_empty());
        assert_eq!(form.focus, 0, "and the cursor did not move");
    }
}

#[cfg(test)]
mod date_layout_tests {
    use super::{DateParts, Field, Form, Kind};

    /// Typing a date produces `YYYY-MM-DD`, and the caret crosses from the year by itself when the
    /// fourth digit lands. Requiring a separate key to move on is what a date field must not do.
    #[test]
    fn typing_a_date_crosses_into_the_month_by_itself() {
        let mut form = Form::new("d", vec![Field::date("Birthday")]);

        for digit in "19901231".chars() {
            form.insert(digit);
        }

        assert_eq!(form.value(0), "1990-12-31");
    }

    /// The display grows in the right order and the hyphens appear only once the group before them is
    /// done — the bug was `1990▏-0310` in the year half, with the month and day run together.
    #[test]
    fn the_layout_shows_a_partial_date_sensibly() {
        let partial = |year: &str, month_day: &str, part: usize| {
            super::date_layout(&DateParts {
                year: year.to_owned(),
                month_day: month_day.to_owned(),
                part,
            })
        };

        assert_eq!(partial("", "", 0).0, "", "an untouched field shows nothing");
        assert_eq!(
            partial("199", "", 0).0,
            "199",
            "no hyphen before the year is finished"
        );
        assert_eq!(
            partial("1990", "", 1).0,
            "1990-",
            "the hyphen appears after a whole year"
        );
        // Once the month is whole the second hyphen appears even with no day yet, because that is what makes
        // the day slot visible. The value is the display, so a field in this state carries a trailing hyphen
        // — which is why `first_unanswered` exists and why nothing submits a date from here.
        assert_eq!(
            partial("1990", "03", 1).0,
            "1990-03-",
            "the day slot is shown once the month is whole"
        );
        assert_eq!(partial("1990", "0310", 1).0, "1990-03-10", "the full thing");
    }

    #[test]
    fn the_caret_sits_where_the_next_digit_goes() {
        let at = |year: &str, month_day: &str, part: usize| {
            super::date_layout(&DateParts {
                year: year.to_owned(),
                month_day: month_day.to_owned(),
                part,
            })
            .1
        };

        assert_eq!(at("19", "", 0), 2, "in the year, after what is typed");
        // `"1990-"` is five characters, so the caret after the hyphen is 5 — not 6. The separator is
        // part of the text, and the caret is an index into the text.
        assert_eq!(at("1990", "", 1), 5, "after the first hyphen");
        // `"1990-03-"` is eight characters, so after the second hyphen the caret is 8 — past the day slot's
        // own hyphen, which is where the first day digit belongs.
        assert_eq!(at("1990", "03", 1), 8, "and past the day slot's hyphen");
        assert_eq!(at("1990", "031", 1), 9, "mid-day");
        assert_eq!(at("1990", "0310", 1), 10, "at the end");
    }

    /// Backspace crosses the hyphen instead of stopping dead on it, and crossing does not delete: the
    /// first backspace moves the caret back, the next removes a digit. Losing a digit to a caret move
    /// would make fixing a typo in the month cost the last digit of the year.
    #[test]
    fn backspace_crosses_back_over_the_hyphen() {
        let mut form = Form::new("d", vec![Field::date("Birthday")]);
        for digit in "199001".chars() {
            form.insert(digit);
        }
        assert_eq!(form.value(0), "1990-01-", "and the day slot is showing");

        for _ in 0..2 {
            form.backspace();
        }
        assert_eq!(form.value(0), "1990-", "the month is gone");

        form.backspace();
        assert_eq!(
            form.value(0),
            "1990-",
            "crossing moved the caret and deleted nothing"
        );

        form.backspace();
        assert_eq!(form.value(0), "199", "and now a digit goes");
    }

    /// A date the platform would refuse is one this field cannot produce: the separators are supplied,
    /// so `1990-4-7` has no way to exist.
    #[test]
    fn a_short_month_is_impossible() {
        let mut form = Form::new("d", vec![Field::date("Birthday")]);
        for digit in "1990".chars() {
            form.insert(digit);
        }
        form.insert('1');
        form.insert('2');

        assert!(
            form.value(0).contains("-12-") || form.value(0) == "1990-12",
            "{}",
            form.value(0)
        );
    }

    /// Restoring a stored date puts it back whole and leaves the caret at the end, not in the year.
    #[test]
    fn a_stored_date_is_restored_whole() {
        let mut field = Field::date("Birthday");
        field.set_date("1815-12-10");

        assert_eq!(field.value, "1815-12-10");
        let Kind::Date { parts } = &field.kind else {
            panic!("expected a date");
        };
        assert_eq!(parts.year, "1815");
        assert_eq!(parts.month_day, "1210");
        assert_eq!(parts.part, 1, "the caret is not back in the year");
    }

    /// Garbage in, no change out. A stored value that is not a date should leave the field alone
    /// rather than put a shape the platform will refuse into the parts.
    #[test]
    fn a_malformed_stored_date_is_refused() {
        let mut field = Field::date("Birthday");
        field.set_date("nonsense");

        assert_eq!(field.value, "", "nothing was accepted");
    }
}
