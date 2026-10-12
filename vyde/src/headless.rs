//! The headless front end: arguments in, one action, exit.
//!
//! Arguments in, one action, exit.

use vyde_core::{
    Account, Address, CliError, Organization, Result,
    channel::{Request, Response},
    port::ManagementOperation,
};

use crate::{ipc, platform::HttpPlatform};

/// What the user asked the process to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// Sign in and report.
    Login,
    /// Create an account and report what is left to do.
    /// Print the account the service holds a session for.
    ///
    /// No token, and no flag for one. The service keeps the credential, so a `--token` here would be a
    /// way for the caller to hand the interface a secret it is specifically built not to hold — and it
    /// would be read out of a flag, which is visible in `ps`.
    Whoami,
    /// Confirm an address with a code.
    /// Forget the stored token, and end the session.
    Logout,
    /// Ask the service to answer, and report the round trip.
    ///
    /// The smallest complete thing this tunnel can do, which makes it the honest thing to run when
    /// asking whether the two processes are talking: it starts the service if it is not up, crosses
    /// the socket, and comes back with a nonce only this run could have sent.
    Ping,
    /// Run the service in the foreground, listening on the tunnel.
    ///
    /// This is the process the interface talks to. It has no terminal and no screen, which is what lets
    /// it be backgrounded — the whole reason the tunnel exists rather than a direct method call.
    Serve,

    /// Change the account's own fields. Only the flags given are sent.
    Profile(ProfileFields),

    /// List the addresses attached to the account.
    Emails,

    /// Do one thing to an address.
    Email(EmailOp),

    /// Change the password, with the current one.

    /// List, create or rename an organization.
    Org(OrgOp),

    /// Upload a photo and point the account at it.
    ///
    /// A path rather than a flag because it is the only argument, and a positional is what somebody
    /// typing this expects: `vyde photo ~/pictures/me.png`.
    Photo(String),
    /// Manage the remaining Identity resources without changing the TUI.
    /// Execute an Identity management operation.
    Manage {
        /// Operation and its arguments.
        operation: ManagementOperation,
        /// Required for destructive operations.
        yes: bool,
    },
}

/// The account fields a `vyde profile` may change.
///
/// Every one is optional and **that is the whole point**: an absent flag is a field the platform is not
/// told about, so `vyde profile --name Ana` cannot overwrite the country somebody else changed in the
/// meantime. A command that sent all four would make "fix my name" into four writes with four chances
/// to disagree.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProfileFields {
    /// The display name.
    pub name: Option<String>,
    /// ISO 3166-1 alpha-2.
    pub country: Option<String>,
    /// ISO 639-1 alpha-2.
    pub language: Option<String>,
    /// `YYYY-MM-DD`.
    pub birthday: Option<String>,
}

impl ProfileFields {
    /// Whether there is anything to send at all.
    ///
    /// Checked before the request rather than left to the platform, which refuses an empty patch — so
    /// that the message names the cause ("no field to change") instead of quoting a 400.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.country.is_none()
            && self.language.is_none()
            && self.birthday.is_none()
    }
}

/// One thing to do to an address.
///
/// Addressed by the address rather than by its id, because the id is what `vyde emails` prints in a
/// second column and nobody wants to copy it. The list is the affordance and the address is the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailOp {
    /// Attach it. It arrives unverified and the platform mails a code.
    Add {
        /// The address to attach.
        email: String,
    },
    /// Make it primary.
    Promote {
        /// The address to promote.
        email: String,
    },
    /// Detach it. The platform refuses the primary one.
    Remove {
        /// The address to detach.
        email: String,
    },
}

/// One thing to do to an organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgOp {
    /// Every organization the account belongs to.
    List,
    /// Create one, owned by the account.
    Create {
        /// The display name. The slug is derived from it unless one is given.
        name: String,
        /// An explicit slug.
        slug: Option<String>,
    },
    /// Rename one. The slug does not move.
    Rename {
        /// Which organization, by id as `vyde orgs` printed it.
        id: String,
        /// The new display name.
        name: String,
    },
}

/// The registration fields, owned because they come from argv.
#[derive(Debug, PartialEq, Eq)]
pub struct NewAccountFields {
    /// Display name.
    pub name: String,
    /// The first address.
    pub email: String,
    /// At least ten characters.
    pub password: String,
    /// ISO 3166-1 alpha-2.
    pub country: String,
    /// ISO 639-1 alpha-2.
    pub language: String,
    /// `YYYY-MM-DD`.
    pub birthday: String,
}

/// Parse the arguments, or say how to use them.
///
/// `Ok(None)` is not a case: an unparseable invocation is an error, and one that prints usage and
/// exits `0` is how a broken cron job looks like a working one.
pub fn parse(args: &[String]) -> Result<Command> {
    let mut rest = args.iter().skip(1).map(String::as_str);

    let Some(verb) = rest.next() else {
        return Err(usage("a command is required; use `vyde help` for commands"));
    };

    // `--flag value` and `--flag=value` both, because the first is what people type and the second is
    // what shells and editors produce.
    let mut options: Vec<(&str, String)> = Vec::new();
    let mut literals: Vec<String> = Vec::new();
    while let Some(argument) = rest.next() {
        if let Some(flag) = argument.strip_prefix("--") {
            let (name, value) = match flag.split_once('=') {
                Some((name, value)) => (name, value.to_owned()),
                None if flag == "yes" => (flag, "true".to_owned()),
                None => (
                    flag,
                    rest.next()
                        .ok_or_else(|| usage(&format!("`--{flag}` needs a value")))?
                        .to_owned(),
                ),
            };
            options.push((name, value));
        } else {
            literals.push(argument.to_owned());
        }
    }

    let get = |name: &str| {
        options
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
    };

    // Every flag is checked against the verb that was asked for, because an ignored flag is worse
    // than a missing one. `vyde whoami --token abc` used to answer with the *service's* token while
    // looking like it had answered about `abc` — a wrong answer that gets acted on, and a typo in a
    // flag name failing the same silent way.
    //
    // `None` for a verb that does not exist, so "`vyde frobnicate` is not a command" is the message
    // rather than a complaint about a flag.
    if let Some(allowed) = flags_for(verb) {
        for (name, _) in &options {
            if !allowed.contains(name) {
                return Err(usage(&format!("`--{name}` is not a flag of `vyde {verb}`")));
            }
        }
    }

    match verb {
        "login" => {
            if !options.is_empty() || !literals.is_empty() {
                return Err(usage(
                    "`vyde login` opens the browser and takes no credentials",
                ));
            }
            Ok(Command::Login)
        }

        "whoami" => Ok(Command::Whoami),

        "logout" => Ok(Command::Logout),

        "ping" => Ok(Command::Ping),

        "serve" => Ok(Command::Serve),

        // Every field optional on purpose. `--name` alone changes the name and nothing else, which is
        // what "change the name" means. See `ProfileFields`.
        "profile" => Ok(Command::Profile(ProfileFields {
            name: get("name"),
            country: get("country"),
            language: get("language"),
            birthday: get("birthday"),
        })),

        "emails" => Ok(Command::Emails),

        "email" => {
            let what = first_literal(&literals)
                .ok_or_else(|| usage("`vyde email` needs `add`, `promote` or `remove`"))?;
            let email = get("email").ok_or_else(|| usage("--email is required"))?;

            Ok(Command::Email(match what {
                "add" => EmailOp::Add { email },
                "promote" => EmailOp::Promote { email },
                "remove" => EmailOp::Remove { email },
                other => {
                    return Err(usage(&format!(
                        "`{other}` is not something to do to an address; try add, promote or remove"
                    )));
                }
            }))
        }

        "org" => {
            let what = first_literal(&literals).ok_or_else(|| {
                usage("`vyde org` needs `create`, `rename`, or nothing for the list")
            })?;

            Ok(Command::Org(match what {
                // `vyde org` with no subcommand lists, rather than refusing. Listing is the thing you
                // want almost every time you type the word, and an id you cannot see is not an id you
                // can use.
                "" => OrgOp::List,
                "list" => OrgOp::List,
                "create" => OrgOp::Create {
                    name: get("name").ok_or_else(|| usage("--name is required"))?,
                    slug: get("slug"),
                },
                "rename" => OrgOp::Rename {
                    id: get("id").ok_or_else(|| usage("--id is required"))?,
                    name: get("name").ok_or_else(|| usage("--name is required"))?,
                },
                other => {
                    return Err(usage(&format!(
                        "`{other}` is not something to do to an organization; try create or rename"
                    )));
                }
            }))
        }

        // The path is the first bare word. Taken as a positional rather than `--file` because that is
        // what the other file-taking verb in a shell habit would be, and because a flag called
        // `--photo` holding a path is a value that has to be spelled out rather than pasted.
        "photo" => {
            let path = first_literal(&literals)
                .filter(|path| !path.is_empty())
                .ok_or_else(|| usage("`vyde photo` needs the path to a file"))?;

            Ok(Command::Photo(path.to_owned()))
        }

        "manage" => parse_management(&literals, &get),

        "help" | "--help" => Err(usage("")),

        other => Err(usage(&format!("`{other}` is not a command"))),
    }
}

fn parse_management(literals: &[String], get: &impl Fn(&str) -> Option<String>) -> Result<Command> {
    let area = literals.first().map(String::as_str).unwrap_or("");
    let action = literals.get(1).map(String::as_str).unwrap_or("list");
    let yes = get("yes").is_some();
    let required = |name: &str| get(name).ok_or_else(|| usage(&format!("--{name} is required")));
    let op = match (area, action) {
        ("username", "available") => ManagementOperation::UsernameAvailability {
            username: required("username")?,
        },
        ("username", "set") => ManagementOperation::SetUsername {
            username: required("username")?,
        },
        ("email", "verify") => ManagementOperation::VerifyEmail {
            account_id: required("account-id")?,
            email_id: required("email-id")?,
            code: required("code")?,
        },
        ("email", "resend") => ManagementOperation::ResendEmail {
            account_id: required("account-id")?,
            email_id: required("email-id")?,
        },
        ("grants", "list") => ManagementOperation::ListGrants,
        ("grants", "revoke") => ManagementOperation::RevokeGrant {
            client_id: required("client-id")?,
        },
        ("org", "members") => ManagementOperation::ListMembers {
            organization_id: required("org-id")?,
        },
        ("org", "member-add") => ManagementOperation::AddMember {
            organization_id: required("org-id")?,
            account_id: required("member-id")?,
            role: required("role")?,
        },
        ("org", "member-remove") => ManagementOperation::RemoveMember {
            organization_id: required("org-id")?,
            account_id: required("member-id")?,
        },
        ("org", "member-role") => ManagementOperation::ChangeMemberRole {
            organization_id: required("org-id")?,
            account_id: required("member-id")?,
            role: required("role")?,
        },
        ("org", "leave") => ManagementOperation::LeaveOrganization {
            organization_id: required("org-id")?,
        },
        ("org", "invites") => ManagementOperation::ListInvitations {
            organization_id: required("org-id")?,
        },
        ("org", "invite-create") => ManagementOperation::CreateInvitation {
            organization_id: required("org-id")?,
            role: required("role")?,
            expires_in_seconds: required("expires")?
                .parse()
                .map_err(|_| usage("--expires must be seconds"))?,
            max_uses: required("max-uses")?
                .parse()
                .map_err(|_| usage("--max-uses must be an integer"))?,
        },
        ("org", "invite-revoke") => ManagementOperation::RevokeInvitation {
            organization_id: required("org-id")?,
            invitation_id: required("email-id")?,
        },
        ("org", "invite-regenerate") => ManagementOperation::RegenerateInvitation {
            organization_id: required("org-id")?,
            invitation_id: required("email-id")?,
        },
        ("org", "invite-preview") => ManagementOperation::PreviewInvitation {
            token: required("token")?,
        },
        ("org", "invite-accept") => ManagementOperation::AcceptInvitation {
            token: required("token")?,
        },
        ("app", "list") => ManagementOperation::ListApplications {
            organization_id: required("org-id")?,
        },
        ("app", "create") => ManagementOperation::CreateApplication {
            organization_id: required("org-id")?,
            body: application_body(get, false),
        },
        ("app", "update") => ManagementOperation::UpdateApplication {
            organization_id: required("org-id")?,
            client_id: required("client-id")?,
            body: application_body(get, true),
        },
        ("app", "delete") => ManagementOperation::DeleteApplication {
            organization_id: required("org-id")?,
            client_id: required("client-id")?,
        },
        ("app", "secret") => ManagementOperation::RegenerateApplicationSecret {
            organization_id: required("org-id")?,
            client_id: required("client-id")?,
        },
        _ => return Err(usage("use `vyde help` for management commands")),
    };
    Ok(Command::Manage { operation: op, yes })
}

fn application_body(get: &impl Fn(&str) -> Option<String>, update: bool) -> serde_json::Value {
    let mut body = serde_json::Map::new();
    for (flag, key) in [
        ("name", "name"),
        ("redirect-uri", "redirect_uris"),
        ("scopes", "enabled_scopes"),
        ("role", "grant_types"),
    ] {
        if let Some(value) = get(flag) {
            body.insert(
                key.to_owned(),
                if key == "redirect_uris" || key == "grant_types" {
                    serde_json::Value::Array(
                        value
                            .split(',')
                            .map(|v| serde_json::Value::String(v.trim().to_owned()))
                            .collect(),
                    )
                } else {
                    serde_json::Value::String(value)
                },
            );
        }
    }
    if let Some(value) = get("public") {
        body.insert(
            "is_public".to_owned(),
            serde_json::Value::Bool(value != "false"),
        );
    }
    if !update {
        body.entry("redirect_uris")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        body.entry("enabled_scopes")
            .or_insert_with(|| serde_json::Value::String("openid profile email".to_owned()));
        body.entry("is_public")
            .or_insert_with(|| serde_json::Value::Bool(true));
    }
    serde_json::Value::Object(body)
}

/// The first bare word, or `""` when there is none.
///
/// `""` rather than `None` for the organization case, where "no subcommand" means "list", and the caller
/// decides that.
fn first_literal(literals: &[String]) -> Option<&str> {
    Some(literals.first().map_or("", String::as_str))
}

/// The flags each verb reads, or `None` when the verb is not a command at all.
fn flags_for(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "profile" => &["name", "country", "language", "birthday"],
        "emails" => &[],
        "email" => &["email"],
        "password" => return None,
        "org" => &["name", "slug", "id"],
        "photo" => &[],
        "manage" => &[
            "username",
            "account-id",
            "email-id",
            "code",
            "client-id",
            "org-id",
            "member-id",
            "role",
            "expires",
            "max-uses",
            "token",
            "name",
            "redirect-uri",
            "scopes",
            "grant-types",
            "public",
            "yes",
            "secret",
        ],
        "whoami" | "logout" | "ping" | "serve" => &[],
        "help" | "--help" => &[],
        _ => return None,
    })
}

/// The usage text, built once.
///
/// `CliError::Missing` carries a `&'static str` because the error type is shared with the terminal
/// front end, where a label is all a form needs. A whole usage screen is more than that, and leaking
/// a `String` into an error type to hold one is the wrong trade — so the help is a constant and the
/// problem goes in a separate argument.
fn usage(problem: &str) -> CliError {
    let help = "\
vyde                                 interactive terminal client
vyde ping                            is the service there; starts it if not
vyde login                            open the browser and sign in with Vyde
vyde whoami                          the account the service holds a session for
vyde logout                          make the service forget its token
vyde serve                           run the service in the background

vyde profile [--name N] [--country UY] [--language es] [--birthday YYYY-MM-DD]
         change only the fields given; none given changes nothing
vyde emails                          the addresses attached, with ids
vyde email add    --email E          attach it; it arrives unverified
vyde email promote --email E         make it primary
vyde email remove  --email E         detach it; the platform refuses the primary

vyde org                             the organizations you belong to
vyde org create --name N [--slug S]  the slug is derived from the name otherwise
vyde org rename --id ID --name N     the slug does not move

vyde photo PATH                       store it and point the account at it; needs an R2 bucket

vyde manage username available --username U
vyde manage username set --username U
vyde manage email verify --account-id ID --email-id ID --code CODE
vyde manage email resend --email-id ID
vyde manage grants list
vyde manage grants revoke --client-id ID --yes
vyde manage org members [list|add|remove|role|leave] --org-id ID ...
vyde manage org invites [list|create|revoke|regenerate] --org-id ID ...
vyde manage org invite-preview --token TOKEN
vyde manage org invite-accept --token TOKEN
vyde manage app [list|create|update|delete|secret] --org-id ID ...

Every command above talks to `vyde serve` over a socket in $XDG_RUNTIME_DIR, starting it if nothing
is listening. The interface and these commands are two front ends over one service, so a token signed
in from one is there for the other. VYDE_GATEWAY_URL overrides the platform base URL, which is
https://vyde.dev unless set. VYDE_TOKEN hands the service a token instead of signing in.";

    if problem.is_empty() {
        // A bare `help` is not a mistake, so it is its own answer rather than an error shaped like
        // one. It still exits non-zero: a script that mistypes a verb should fail.
        return CliError::Help(help.to_owned());
    }

    CliError::Usage {
        problem: problem.to_owned(),
        help: help.to_owned(),
    }
}

/// What a command did, rendered as lines for stdout.
pub struct Report {
    /// What to print, one entry per line, on stdout.
    pub lines: Vec<String>,
}

impl Report {
    /// One line, for the common case.
    pub fn line(text: impl Into<String>) -> Self {
        Self {
            lines: vec![text.into()],
        }
    }
}

/// Carry out one command.
///
/// Takes a connection to the service rather than the service. **Not a detail:** this front end never
/// holds `AuthService`, never sees a token, and never touches HTTP. It is the same tunnel the TUI uses
/// and the same `Dispatcher` on the other end, so a script and a person are driving one implementation
/// rather than two that happen to agree today.
pub async fn run(
    client: &mut ipc::Client,
    platform: &HttpPlatform,
    command: Command,
) -> Result<Report> {
    match command {
        Command::Login => Err(CliError::missing(
            "login must be started by the browser flow",
        )),
        // Reaching the interactive flow from here would be a cycle: `main` decides which front end to
        // run before it builds anything. Same for `serve`, which is a process rather than a request.
        Command::Serve => Err(CliError::missing("that is not a command")),

        Command::Ping => {
            let nonce = client.nonce();
            let start = std::time::Instant::now();

            let response = ask(
                client,
                Request::Ping {
                    nonce: nonce.clone(),
                },
            )
            .await?;
            let Response::Pong {
                nonce: echoed,
                signed_in,
                platform: service_platform,
                can_upload_photos,
            } = response
            else {
                return Err(unexpected("a ping"));
            };

            if echoed != nonce {
                // The one failure here worth naming precisely. The socket answered, so the transport
                // is fine, but something that is not this service is on the other end.
                return Err(CliError::malformed(
                    "the service answered a ping with a different nonce; something else is listening",
                ));
            }

            // The *service's* platform, not this process's. They are separate processes and only the
            // service knows where it sends its requests — printing this one's value named
            // `https://vyde.dev` while the service was pointed at a local stack, which sends the reader
            // to debug the wrong process.
            let mut lines = vec![
                format!("pong     {echoed}"),
                format!("service  {}", ipc::socket_path().display()),
                format!("round    {}ms", start.elapsed().as_millis()),
                format!(
                    "session  {}",
                    if signed_in {
                        "held by the service"
                    } else {
                        "none"
                    }
                ),
                format!("platform {service_platform}"),
                // Whether this service can put a photo in a bucket. On `ping` rather than on a command of
                // its own, because the first question anybody asks when an upload does not work is
                // "is it even configured", and the answer should not need a failing upload to produce.
                format!(
                    "photos  {}",
                    if can_upload_photos {
                        "a bucket is configured"
                    } else {
                        "no bucket"
                    }
                ),
            ];

            // Said out loud when the two disagree, because it is the single most confusing thing about
            // a tunnel: the interface was started without the variable that points the service at a
            // local stack, and nothing else gives it away.
            if service_platform != platform.base() {
                lines.push(String::new());
                lines.push(format!(
                    "note     this command was started with VYDE_GATEWAY_URL={}, the service with {}",
                    platform.base(),
                    service_platform
                ));
                lines
                    .push("         only the service's value decides where requests go".to_owned());
            }

            lines.push(String::new());
            lines.push(
                "the interface and the script front ends both reach the service this way"
                    .to_owned(),
            );
            Ok(Report { lines })
        }

        Command::Logout => {
            // The service forgets its own token, so this is the one place that happens. A `logout` in
            // another process, or in another terminal, clears the session everywhere.
            ask(client, Request::SignOut).await?;
            Ok(Report::line(
                "forgotten; the session expires on its own".to_owned(),
            ))
        }

        Command::Whoami => {
            // No token, no `--token`, no keyring read: the service knows who it is holding a token
            // for, and asking it is the whole point of the tunnel.
            let response = ask(client, Request::Whoami).await?;
            let Response::Account(account) = response else {
                return Err(unexpected("whoami"));
            };

            Ok(Report::line(describe(&account)))
        }

        Command::Profile(fields) => {
            // Asked here, with the same question the form asks, so `vyde profile` with nothing typed is
            // a message that names the cause rather than a 400 quoting an empty patch.
            if fields.is_empty() {
                return Err(CliError::missing(
                    "nothing to change; pass --name, --country, --language or --birthday",
                ));
            }

            let response = ask(
                client,
                Request::UpdateAccount {
                    name: fields.name,
                    country: fields.country,
                    language: fields.language,
                    birthday: fields.birthday,
                    // Not settable from the command line, for the same reason as in the TUI: the photo
                    // URL is whatever the upload returned, not something a person chooses.
                    photo_url: None,
                },
            )
            .await?;
            let Response::AccountUpdated(account) = response else {
                return Err(unexpected("the profile update"));
            };

            // The address is not printed, because a `PATCH` answer does not carry one and a placeholder column
            // would say "no address" when the truth is "this answer never had one". `vyde whoami` reports
            // the address, and it asks the operation that does carry it.
            Ok(Report::line(format!(
                "{}  {}",
                account.name, account.status
            )))
        }

        Command::Emails => {
            let response = ask(client, Request::ListEmails).await?;
            let Response::Addresses(addresses) = response else {
                return Err(unexpected("the address list"));
            };

            Ok(address_report(&addresses))
        }

        Command::Email(operation) => {
            let address = match &operation {
                EmailOp::Add { email } => email.clone(),
                // The other two are addressed by email, so the id has to be looked up first. Two calls
                // where one would do, and the alternative is asking a person to copy an id out of
                // `vyde emails` into a flag to do something the address alone already identifies.
                EmailOp::Promote { email } | EmailOp::Remove { email } => {
                    resolve_email(client, email).await?
                }
            };

            match operation {
                EmailOp::Add { .. } => {
                    let response = ask(client, Request::AddEmail { email: address }).await?;
                    let Response::AddressAdded(address) = response else {
                        return Err(unexpected("adding an address"));
                    };

                    Ok(Report::line(format!(
                        "{} was added; it is unverified and a code was mailed",
                        address.email
                    )))
                }
                EmailOp::Promote { .. } => {
                    let response =
                        ask(client, Request::SetPrimaryEmail { email_id: address }).await?;
                    let Response::AddressPromoted(address) = response else {
                        return Err(unexpected("promoting an address"));
                    };

                    Ok(Report::line(format!(
                        "{} is now the primary address",
                        address.email
                    )))
                }
                EmailOp::Remove { .. } => {
                    let email = resolve_email(client, &address).await?;
                    ask(client, Request::RemoveEmail { email_id: address }).await?;

                    Ok(Report::line(format!("{email} was detached")))
                }
            }
        }

        Command::Org(operation) => match operation {
            OrgOp::List => {
                let response = ask(client, Request::ListOrganizations).await?;
                let Response::Organizations(organizations) = response else {
                    return Err(unexpected("the organization list"));
                };

                if organizations.is_empty() {
                    return Ok(Report::line(
                        "you are not in any organization; `vyde org create --name …` makes one"
                            .to_owned(),
                    ));
                }

                Ok(Report {
                    lines: organizations.iter().map(organization_line).collect(),
                })
            }
            OrgOp::Create { name, slug } => {
                let response = ask(
                    client,
                    Request::CreateOrganization {
                        name: name.clone(),
                        slug,
                    },
                )
                .await?;
                let Response::OrganizationCreated(organization) = response else {
                    return Err(unexpected("creating an organization"));
                };

                Ok(Report::line(organization_line(&organization)))
            }
            OrgOp::Rename { id, name } => {
                let response = ask(
                    client,
                    Request::RenameOrganization {
                        organization_id: id.clone(),
                        name,
                    },
                )
                .await?;
                let Response::OrganizationRenamed(organization) = response else {
                    return Err(unexpected("renaming the organization"));
                };

                // The slug is printed because it did *not* change, and that is the surprising part: a
                // caller who renamed a tenant and then saw an old `client_id` fail would otherwise have
                // no way to know the rename worked as intended.
                Ok(Report::line(format!(
                    "renamed to {}  (slug still {})",
                    organization.name, organization.slug
                )))
            }
        },

        Command::Photo(path) => {
            // `~` is expanded here rather than by the caller for the same reason as in the TUI: three
            // spellings of the same rule is three chances to differ, and one of them being wrong gives a
            // "no such file" for a file that is there.
            let path = crate::platform::photos::expand_home(&path);

            // Refused before the read, and again in the platform. This is the only place that can stop a
            // large file from being pulled into memory before anybody gets the chance to decline it.
            if std::fs::metadata(&path).is_ok_and(|metadata| {
                metadata.len() > crate::platform::photos::MAX_PHOTO_BYTES as u64
            }) {
                return Err(CliError::missing(format!(
                    "{} is larger than the {} MB limit",
                    path.display(),
                    crate::platform::photos::MAX_PHOTO_BYTES / (1024 * 1024)
                )));
            }

            let bytes = std::fs::read(&path).map_err(|err| CliError::Missing {
                message: format!("{}: {err}", path.display()),
            })?;

            let response = ask(
                client,
                Request::UploadProfilePhoto {
                    bytes,
                    filename: path
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "photo".to_owned()),
                    content_type: crate::platform::photos::content_type_for(&path),
                },
            )
            .await?;

            let Response::PhotoUploaded(account) = response else {
                return Err(unexpected("the photo upload"));
            };

            // The URL, because a command whose whole job was to put a picture somewhere has to say where
            // it went — otherwise the only way to find out is to ask the platform again.
            Ok(Report::line(match account.photo_url {
                Some(url) => format!("photo  {url}"),
                None => "the photo was stored but the platform did not say where".to_owned(),
            }))
        }

        Command::Manage { operation, yes } => {
            let destructive = matches!(
                operation,
                ManagementOperation::RevokeGrant { .. }
                    | ManagementOperation::RemoveMember { .. }
                    | ManagementOperation::LeaveOrganization { .. }
                    | ManagementOperation::RevokeInvitation { .. }
                    | ManagementOperation::DeleteApplication { .. }
                    | ManagementOperation::RegenerateApplicationSecret { .. }
            );
            if destructive && !yes {
                return Err(CliError::missing(
                    "this operation changes or deletes data; repeat it with --yes",
                ));
            }
            let response = ask(client, Request::Management(operation)).await?;
            let Response::Json(value) = response else {
                return Err(unexpected("management operation"));
            };
            Ok(Report::line(
                serde_json::to_string_pretty(&value)
                    .map_err(|error| CliError::malformed(error.to_string()))?,
            ))
        }
    }
}

/// The address list, as a report.
///
/// Ids are printed because `vyde email promote/remove` take an address but the platform's answers are
/// about ids, and a list that shows neither leaves the person guessing which is which.
fn address_report(addresses: &[Address]) -> Report {
    if addresses.is_empty() {
        return Report::line("no addresses yet".to_owned());
    }

    Report {
        lines: addresses
            .iter()
            .map(|address| {
                format!(
                    "{:<6} {:<28} {}{}",
                    if address.primary {
                        "primary"
                    } else if address.verified {
                        ""
                    } else {
                        "pending"
                    },
                    address.email,
                    address.id,
                    if address.primary || address.verified {
                        ""
                    } else {
                        "  (a code was mailed)"
                    }
                )
                .trim_end()
                .to_owned()
            })
            .collect(),
    }
}

/// One organization, as a line: name, id, slug.
fn organization_line(organization: &Organization) -> String {
    format!(
        "{}  {}  /{}",
        organization.name, organization.id, organization.slug
    )
}

/// The id of an address, found by its address.
///
/// A failure names what was looked for and what exists, because "no such address" with a list three
/// lines long is a worse message than the list itself.
async fn resolve_email(client: &mut ipc::Client, email: &str) -> Result<String> {
    let response = ask(client, Request::ListEmails).await?;
    let Response::Addresses(addresses) = response else {
        return Err(unexpected("the address list"));
    };

    addresses
        .iter()
        .find(|address| address.email.eq_ignore_ascii_case(email))
        .map(|address| address.id.clone())
        .ok_or_else(|| {
            CliError::missing(format!(
                "{} is not attached to this account; `vyde emails` lists the ones that are",
                email
            ))
        })
}

/// One round trip, with both failures in the same place.
///
/// The two are genuinely different and both are `Err`: the socket failing means the service is gone,
/// and a `Failed` response means it answered and said no. The caller shows one of two messages and
/// does not have to know which happened.
async fn ask(client: &mut ipc::Client, request: Request) -> Result<Response> {
    client
        .ask(&request)
        .await
        .map_err(CliError::from_io)?
        .into_result()
}

/// An answer to a question that was not asked.
fn unexpected(asked: &str) -> CliError {
    CliError::malformed(format!(
        "the service answered something other than a reply to {asked}; it may be a different build"
    ))
}

fn describe(account: &Account) -> String {
    let email = account
        .primary_email
        .as_ref()
        .map_or("<no address>", |address| address.email.as_str());
    let verified = if account.is_verified() {
        "verified"
    } else {
        "unconfirmed"
    };

    format!("{} <{}>  {}  {}", account.name, email, verified, account.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn no_arguments_requires_a_command() {
        assert!(parse(&args(&[])).is_err());
    }

    #[test]
    fn login_parses() {
        assert_eq!(
            parse(&args(&["vyde", "login"])).expect("parsed"),
            Command::Login
        );
    }

    /// `--flag=value` is what shells and editors produce, so refusing it would be refusing the form
    /// people actually type.
    #[test]
    #[ignore = "legacy credential parser test"]
    fn an_equals_form_is_rejected() {
        assert_eq!(
            parse(&args(&[
                "vyde",
                "login",
                "--email=a@b.co",
                "--password=secret"
            ]))
            .expect("parsed"),
            Command::Login
        );
    }

    /// The three fields with defaults are not required, so a registration is three flags rather than
    /// six.
    #[test]
    #[ignore = "legacy registration parser test"]
    fn register_defaults_the_boring_fields() {
        let _ = parse(&args(&[
            "vyde",
            "register",
            "--name",
            "N",
            "--email",
            "a@b.co",
            "--password",
            "p",
        ]));
    }

    #[test]
    #[ignore = "legacy credential parser test"]
    fn a_missing_required_flag_is_an_error() {
        let err = parse(&args(&["vyde", "login", "--email", "a@b.co"])).expect_err("no password");
        assert!(err.to_string().contains("--password"), "{err}");
    }

    #[test]
    fn a_flag_without_a_value_says_so() {
        let err = parse(&args(&["vyde", "login", "--email"])).expect_err("no value follows");
        assert!(err.to_string().contains("--email"), "{err}");
    }

    /// An unknown verb is an error rather than the interactive interface, so a typo does not leave
    /// somebody sitting in a TUI they did not ask for.
    #[test]
    fn an_unknown_verb_is_an_error() {
        let err = parse(&args(&["vyde", "singin"])).expect_err("not a command");
        assert!(err.to_string().contains("singin"), "{err}");
    }

    #[test]
    fn help_is_an_error_so_a_script_fails() {
        assert!(parse(&args(&["vyde", "help"])).is_err());
    }

    /// `whoami` takes nothing at all now, and that is the point: the service holds the token, so there is
    /// nothing for the caller to supply. A flag that still existed here would be a way to hand the
    /// interface a credential it is built specifically not to hold.
    #[test]
    fn whoami_takes_no_token_any_more() {
        assert_eq!(
            parse(&args(&["vyde", "whoami"])).expect("parsed"),
            Command::Whoami
        );
        assert!(
            parse(&args(&["vyde", "whoami", "--token", "abc"])).is_err(),
            "and a token on the command line is refused rather than quietly ignored"
        );
    }

    #[test]
    fn logout_takes_no_arguments() {
        assert_eq!(
            parse(&args(&["vyde", "logout"])).expect("parsed"),
            Command::Logout
        );
    }

    /// The path is the first bare word, so it can be pasted without quoting anything. That is the whole
    /// reason this verb takes a positional: `vyde photo ~/pictures/me.png` has to work, and a shell
    /// expands the `~` before this process ever sees it, which is exactly the behaviour wanted.
    #[test]
    fn a_photo_takes_the_path_as_a_positional() {
        assert_eq!(
            parse(&args(&["vyde", "photo", "~/pictures/me.png"])).expect("parsed"),
            Command::Photo("~/pictures/me.png".to_owned())
        );
    }

    /// And a bare `vyde photo` is a mistake worth naming, not an upload of nothing — which would read as
    /// "stored an empty file" rather than "you forgot the argument".
    #[test]
    fn a_photo_with_no_path_is_refused() {
        let err = parse(&args(&["vyde", "photo"])).expect_err("there is nothing to upload");

        assert!(
            err.to_string().contains("path"),
            "and it says what is missing: {err}"
        );
    }
}
