//! The tunnel between the interface and the service.
//!
//! # What this is for
//!
//! The service runs in the background; the interface owns a terminal and cannot. Two processes, so a
//! channel — and the channel is the *only* thing they share. `core::channel` holds what they say to
//! each other, and this file is how the bytes get there.
//!
//! # A unix socket, not a WebSocket
//!
//! The user asked for "a websocket", and this is deliberately not one. Both processes are on the same
//! machine, so there is no proxy to traverse, no TLS to negotiate and no third party to interpose, and
//! an HTTP upgrade buys nothing: the payload is JSON either way, and the handshake is bytes that have
//! to be produced and parsed for no capability gained.
//!
//! What length-prefixed JSON gives instead is a channel that can become a WebSocket by changing this
//! file and nothing else — the protocol in `core::channel` already carries the serialisation, and the
//! split is only meaningful because the two are separate. Framing is `u32` big-endian length, then
//! that many bytes of JSON.
//!
//! If this ever needs to cross a machine, that is the day the transport changes, and it will be a
//! deliberate decision about authentication rather than a surprise.
//!
//! # The rule for when to reach for a real WebSocket
//!
//! Hand-rolled framing is right here and would be wrong anywhere that has to traverse a network. The
//! line is whether there is an intermediary: a unix socket between two processes of one user has
//! nothing in the middle, and everything a WebSocket provides — a handshake a proxy cannot mangle,
//! client masking, ping/pong, automatic reconnection — exists to survive exactly the intermediaries a
//! local socket does not have.
//!
//! So: this file stays hand-rolled for the interface talking to its own service. **A service talking to
//! another service behind the gateway uses `tungstenite`** — that crosses a network, sits behind a
//! proxy, and carries a credential rather than relying on filesystem permissions. The protocol in
//! `core::channel` is the same either way; only this file changes, which is the reason it is a file of
//! its own and not spread through the dispatcher.
//!
//! # Where the socket lives
//!
//! `$XDG_RUNTIME_DIR` when set, which is where a session's own files belong and where the sticky bit
//! means only its owner can read it. Otherwise `/tmp` under a name carrying the user's uid, which is
//! the fallback for a session with no XDG directory — a container, or a bare `su`.
//!
//! `0700` on the socket's directory either way. A control socket that another user can connect to is
//! a way to act as the person who owns it, so the permissions are part of the authentication and not
//! a tidiness detail.

use std::path::{Path, PathBuf};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

use vyde_core::channel::{Event, Request, Response};

/// The longest message accepted, in bytes.
///
/// A cap rather than a `usize` read, because a length is attacker-controlled here: whoever can reach
/// the socket can claim a four gigabyte frame. 16 MiB is far more than any request here and small
/// enough that a bad length fails fast instead of allocating.
const MAX_FRAME: u32 = 16 * 1024 * 1024;

/// The socket's path for this user and this platform.
#[must_use]
pub fn socket_path() -> PathBuf {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "vyde".to_owned());

    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR")
        && !runtime.trim().is_empty()
    {
        // `$XDG_RUNTIME_DIR` is per-session and already `0700`, which is exactly the property wanted.
        return Path::new(&runtime).join("vyde.sock");
    }

    // No XDG directory: a container, or a shell with no session bus. The uid is in the name because
    // `/tmp` is shared and a predictable name would be a squatting target — an attacker who creates
    // it first would be the one the interface connects to.
    let uid = current_uid();
    PathBuf::from("/tmp").join(format!("vyde-{user}-{uid}.sock"))
}

/// The uid, without pulling in `libc` for one number.
///
/// `/proc/self/status` rather than a syscall: reading a file the kernel already wrote is portable
/// across the environments this runs in, and a uid has no business being a library dependency.
fn current_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let value = line.strip_prefix("Uid:")?;
                value.split_whitespace().next()?.parse().ok()
            })
        })
        .unwrap_or(0)
}

/// Write one length-prefixed frame.
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let length = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the message is too long to send",
        )
    })?;

    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

/// Read one length-prefixed frame, or `None` at a clean end of stream.
///
/// `None` for EOF and `Err` for a bad length are different answers on purpose: the first is a peer
/// that closed, the second is something that is not speaking this protocol, and a caller that conflates
/// them turns a malformed frame into a normal disconnect.
pub async fn read_frame<R>(reader: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncReadExt + Unpin,
{
    let mut length_bytes = [0u8; 4];
    match reader.read_exact(&mut length_bytes).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }

    let length = u32::from_be_bytes(length_bytes);
    if length > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("a frame of {length} bytes is over the {MAX_FRAME} limit"),
        ));
    }

    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload).await?;
    Ok(Some(payload))
}

/// The service end: accepts connections and carries requests to a dispatcher.
pub struct Server {
    listener: UnixListener,
    path: PathBuf,
}

impl Server {
    /// Bind the socket, replacing a stale one.
    ///
    /// A socket left behind by a service that was killed rather than stopped would make every
    /// subsequent bind fail with `AddrInUse`, so an existing path is removed first — but only after
    /// checking that something is *not* already listening on it, because removing a live socket
    /// orphans the service behind it.
    ///
    /// # Errors
    ///
    /// An `io::Error` from binding, or from the probe.
    pub async fn bind(path: PathBuf) -> std::io::Result<Self> {
        if path.exists() {
            // A connect that succeeds means a service is alive and this is a second one.
            if UnixStream::connect(&path).await.is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("a service is already listening on {}", path.display()),
                ));
            }
            std::fs::remove_file(&path)?;
        }

        if let Some(parent) = path.parent() {
            // `0700` on the directory: a control socket another user can reach is a way to act as the
            // person who owns it, so the permissions are the authentication.
            std::fs::create_dir_all(parent)?;
            set_owner_only(parent);
        }

        let listener = UnixListener::bind(&path)?;
        set_owner_only(&path);

        Ok(Self { listener, path })
    }

    /// Where this is listening.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serve until the process is stopped.
    ///
    /// One connection at a time. The interface is one process talking to one service, so concurrency
    /// here would be a way to have two interfaces share one session — which is exactly the state the
    /// dispatcher holds and cannot be held twice.
    ///
    /// # Errors
    ///
    /// The accept error. A per-connection error is logged and the loop continues: one interface
    /// closing mid-message is not a reason to take the service down for the next one.
    pub async fn serve<F, Fut>(self, mut handle: F) -> std::io::Result<()>
    where
        F: FnMut(Request) -> Fut,
        Fut: std::future::Future<Output = Response>,
    {
        loop {
            let (stream, _) = self.listener.accept().await?;
            converse(stream, &mut handle).await?;
        }
    }
}

/// Answer requests on one already-connected stream, until the other end closes.
///
/// Its own function rather than a block inside `serve`, because that is what lets a test drive the
/// real protocol over a socket pair: no listener, no path, no name to collide with the next test, and
/// no port left bound after it. The framing and the dispatch are the production ones, which is the
/// point — a test that used a stub socket would be testing the stub.
pub async fn converse<F, Fut>(stream: UnixStream, mut handle: F) -> std::io::Result<()>
where
    F: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    // One handle, read and written. `UnixStream` is not `Copy`, so splitting it into a reader and a
    // writer would need `tokio::io::split`, which returns two halves of one socket — what the loop
    // below wants anyway, and what the writer's `flush` would not reach through.
    let (mut reader, mut writer) = tokio::io::split(stream);

    loop {
        match read_frame(&mut reader).await {
            // A closed connection is how a conversation ends, not a failure: the interface quit.
            Ok(None) => return Ok(()),
            Ok(Some(payload)) => {
                // A frame that is not a request is a broken peer, not a broken service.
                let request = match serde_json::from_slice::<Request>(&payload) {
                    Ok(request) => request,
                    Err(err) => {
                        let response = Response::Failed {
                            message: format!("the request could not be read: {err}"),
                            retryable: false,
                            status: 0,
                            code: None,
                        };
                        let body = serde_json::to_vec(&response).unwrap_or_default();
                        let _ = write_frame(&mut writer, &body).await;
                        return Ok(());
                    }
                };

                let response = handle(request).await;
                let body = serde_json::to_vec(&response).unwrap_or_default();
                if write_frame(&mut writer, &body).await.is_err() {
                    return Ok(());
                }
            }
            Err(err) => {
                eprintln!("vyde service: {err}");
                return Ok(());
            }
        }
    }
}

/// A service and a client on one socket, for tests.
///
/// The pair is created with `UnixStream::pair`, so nothing is bound to a path and nothing is left
/// behind: two tests can do this at the same time without racing for one socket name, which is the
/// failure that makes a test suite flaky for reasons that have nothing to do with what it tests.
///
/// Everything between the two ends is the production path — the framing, the `Request`, the
/// `Dispatcher` — so a test that passes here has proved the wire format, not just the screen state.
#[cfg(all(test, feature = "legacy-auth-tests"))]
pub mod test {
    use std::sync::Arc;

    use vyde_core::{
        AuthService, PlatformPort,
        channel::{Dispatcher, Memory},
    };

    use super::Client;

    /// A client whose service is backed by `platform`.
    pub async fn pair(platform: Arc<dyn PlatformPort>) -> Client {
        let (ours, theirs) = tokio::net::UnixStream::pair().expect("a socket pair");

        let dispatcher = Arc::new(tokio::sync::Mutex::new(Dispatcher::new(
            Arc::new(AuthService::new(platform)),
            // `Memory`, never the keyring: the keyring is process-global state under one fixed name,
            // so two tests signing in at once would interleave into a session neither wrote.
            Arc::new(Memory::new()),
        )));

        tokio::spawn(async move {
            super::converse(theirs, move |request| {
                let dispatcher = dispatcher.clone();
                async move { dispatcher.lock().await.handle(request).await }
            })
            .await
        });

        Client::over(ours)
    }
}

/// The interface end: a connection to the service.
///
/// Not `Clone`. One connection is one conversation, and cloning the handle would let two owners read
/// each other's replies — a request and its answer have to stay on the same stream, so the type says
/// so rather than the protocol.
pub struct Client {
    reader: tokio::io::ReadHalf<UnixStream>,
    writer: tokio::io::WriteHalf<UnixStream>,
    /// Counts the nonces handed out, so two pings on one connection are not the same string.
    nonce: u64,
}

impl Client {
    /// Wrap an already-connected stream, rather than connecting to a path.
    ///
    /// For tests, which pair two streams and hand one to [`converse`] and one here. That keeps them off
    /// the filesystem entirely, which matters because two tests running at once would otherwise race for
    /// one socket name — and the loser would fail for a reason that has nothing to do with what it is
    /// testing.
    pub fn over(stream: UnixStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader,
            writer,
            nonce: 0,
        }
    }

    /// A string nobody else will guess, for proving a round trip came back.
    ///
    /// Not a random number generator — the nonce only has to be distinguishable from the empty
    /// string and from whatever a previous request used, and time is enough for that while being one
    /// fewer dependency in a program whose whole point is being small and always installed.
    pub fn nonce(&mut self) -> String {
        self.nonce += 1;
        format!("{}-{}", std::process::id(), self.nonce)
    }

    /// Connect, starting the service first if it is not already there.
    ///
    /// `gateway_url` is what a service started *by this call* is pointed at; see [`ensure_service`].
    /// A service that is already running keeps whatever URL it was started with.
    ///
    /// # Errors
    ///
    /// An `io::Error` from connecting, or from starting the service.
    pub async fn connect(path: &Path, gateway_url: Option<&str>) -> std::io::Result<Self> {
        if let Ok(stream) = UnixStream::connect(path).await {
            let (reader, writer) = tokio::io::split(stream);
            return Ok(Self {
                reader,
                writer,
                nonce: 0,
            });
        }

        ensure_service(gateway_url)?;

        // **Waiting is the whole fix.** The first version spawned the service and reconnected
        // immediately, which failed every time: a freshly spawned process has not run `Server::bind`
        // yet, so the connect arrives first and finds nothing. It looked intermittent because a
        // second `vyde` command a moment later found the service already up.
        //
        // Bounded, because "not coming" has to be an answer too. A service that cannot start — a
        // socket path owned by someone else, a machine with no `$XDG_RUNTIME_DIR` — must fail in
        // about a second rather than hang the interface that asked for it.
        let deadline = std::time::Instant::now() + STARTUP_GRACE;
        let mut waited = std::time::Duration::ZERO;

        loop {
            if let Ok(stream) = UnixStream::connect(path).await {
                let (reader, writer) = tokio::io::split(stream);
                return Ok(Self {
                    reader,
                    writer,
                    nonce: 0,
                });
            }

            if std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!(
                        "no service on {} after waiting {STARTUP_GRACE:?}",
                        path.display()
                    ),
                ));
            }

            tokio::time::sleep(waited.max(std::time::Duration::from_millis(20))).await;
            waited += std::time::Duration::from_millis(10);
        }
    }

    /// Send a request and wait for the answer.
    ///
    /// # Errors
    ///
    /// An `io::Error` from the socket, or a serialisation failure.
    pub async fn ask(&mut self, request: &Request) -> std::io::Result<Response> {
        let payload = serde_json::to_vec(request)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))?;

        write_frame(&mut self.writer, &payload).await?;

        let Some(frame) = read_frame(&mut self.reader).await? else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the service closed the connection",
            ));
        };

        serde_json::from_slice(&frame)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
    }

    /// Take whatever event the service pushed without being asked.
    ///
    /// `None` when there is none *yet*, which is the ordinary answer for every poll and is why this
    /// returns `Option` rather than blocking. Blocking here would mean the interface could not read a
    /// key while an event was outstanding, and a key is the whole point of the interface.
    ///
    /// # Errors
    ///
    /// An `io::Error` from the socket.
    pub async fn poll_event(&mut self) -> std::io::Result<Option<Event>> {
        let Some(frame) = read_frame(&mut self.reader).await? else {
            return Ok(None);
        };

        serde_json::from_slice(&frame)
            .map(Some)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
    }
}

/// How long to wait for a service that was just spawned.
///
/// A second is generous for a process that only has to bind a socket, and short enough that a
/// service which is never going to appear does not look like a hang.
const STARTUP_GRACE: std::time::Duration = std::time::Duration::from_secs(1);

/// Start the service in the background if nothing is listening.
fn ensure_service(gateway_url: Option<&str>) -> std::io::Result<()> {
    // The socket path is not named here: `Client::connect` already has it and retries, so computing
    // it again would be a second answer to "where is the socket" and could disagree if the environment
    // changed in between.
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command.arg("serve");

    // **The platform URL is passed down explicitly, and this is not a convenience.**
    //
    // The service inherits the environment by default, so it usually works — until the interface is
    // started without `VYDE_GATEWAY_URL` while a developer's shell had it, or with it cleared. Then the
    // service it spawns silently points at production, and every request fails with "cannot reach the
    // platform" while the interface looks correctly configured. That is exactly what happened: a TUI
    // pointed at a local stack reported a platform error caused by a *second process* being pointed
    // somewhere else.
    //
    // Naming it makes the interface's choice the service's choice. A service that was already running
    // keeps its own URL — this only applies to one this call starts — and `Ping` reports which is which,
    // so a disagreement is visible rather than inferred from a failure.
    if let Some(url) = gateway_url {
        command.env("VYDE_GATEWAY_URL", url);
    }

    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    // The bind is the readiness signal, and the interface's connect is what waits for it. Polling
    // here as well would be a second thing that has to know how long that takes.
    Ok(())
}

/// `0700` on a socket or its directory, best effort.
///
/// `set_permissions` can fail on a filesystem that does not carry unix modes — some network mounts, and
/// some container overlays. That is reported by the connect failing rather than by this call, so it
/// is not worth turning into an error of its own.
fn set_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}

#[cfg(all(test, feature = "legacy-auth-tests"))]
mod tests {
    use super::*;

    /// A frame survives the round trip byte for byte. Everything above this depends on it, and the
    /// failure mode of getting it wrong is a silent truncation rather than an error.
    #[tokio::test]
    async fn a_frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(64);

        write_frame(&mut a, b"hello").await.expect("written");
        assert_eq!(
            read_frame(&mut b).await.expect("read"),
            Some(b"hello".to_vec())
        );
    }

    /// Two frames in a row, because the length prefix is what separates them and a test that sends one
    /// proves nothing about it.
    #[tokio::test]
    async fn two_frames_stay_separate() {
        let (mut a, mut b) = tokio::io::duplex(256);

        write_frame(&mut a, b"first").await.expect("written");
        write_frame(&mut a, b"second frame, longer")
            .await
            .expect("written");

        assert_eq!(
            read_frame(&mut b).await.expect("read"),
            Some(b"first".to_vec())
        );
        assert_eq!(
            read_frame(&mut b).await.expect("read"),
            Some(b"second frame, longer".to_vec())
        );
    }

    /// EOF is `None`, not an error. Every sign-out closes the connection, and a test that reports that
    /// as a failure makes a normal exit look broken.
    #[tokio::test]
    async fn a_closed_connection_is_not_an_error() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);

        assert_eq!(read_frame(&mut b).await.expect("a clean end"), None);
    }

    /// A length over the cap is refused rather than allocated. The length comes from the peer, so this
    /// is the difference between "someone sent a bad frame" and "someone asked for four gigabytes".
    #[tokio::test]
    async fn an_oversized_length_is_refused() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(MAX_FRAME + 1).to_be_bytes())
            .await
            .expect("written");

        let err = read_frame(&mut b).await.expect_err("refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// The whole conversation, over a real socket, with the dispatcher answering. This is the tunnel
    /// working, not a mock of it.
    #[tokio::test]
    async fn a_request_gets_its_answer_over_a_socket() {
        let dir = std::env::temp_dir().join(format!("vyde-ipc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");

        let server = Server::bind(dir.join("t.sock")).await.expect("bound");
        let address = server.path().to_owned();

        let serving = tokio::spawn(server.serve(|request| async move {
            match request {
                Request::SignIn { email, .. } => Response::Account(vyde_core::Account {
                    id: "1".into(),
                    name: email,
                    country: "UY".into(),
                    language: "es".into(),
                    birthday: "1990-01-01".into(),
                    status: "active".into(),
                    photo_url: None,
                    primary_email: None,
                }),
                other => Response::Failed {
                    message: format!("no: {other:?}"),
                    retryable: false,
                    status: 0,
                    code: None,
                },
            }
        }));

        let mut client = Client::connect(&address, None).await.expect("connected");
        let answer = client
            .ask(&Request::SignIn {
                email: "a@b.co".into(),
                password: "x".into(),
            })
            .await
            .expect("answered");

        let Response::Account(account) = answer else {
            panic!("expected an account, got {answer:?}");
        };
        assert_eq!(account.name, "a@b.co");

        drop(client);
        serving.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A frame that is not a request gets a refusal, and the connection closes rather than the service
    /// trying to interpret it. Anything else is how one bad peer becomes a service that answers
    /// nonsense.
    #[tokio::test]
    async fn a_frame_that_is_not_a_request_is_refused() {
        let dir = std::env::temp_dir().join(format!("vyde-ipc-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("t.sock");

        let server = Server::bind(path.clone()).await.expect("bound");
        let address = server.path().to_owned();
        let serving = tokio::spawn(server.serve(|_request| async {
            Response::Failed {
                message: "unreachable".into(),
                retryable: false,
                status: 0,
                code: None,
            }
        }));

        let mut stream = UnixStream::connect(&address).await.expect("connected");
        write_frame(&mut stream, b"{not json")
            .await
            .expect("written");

        let answer = read_frame(&mut stream)
            .await
            .expect("read")
            .expect("a frame");
        let response: Response = serde_json::from_slice(&answer).expect("a response");
        assert!(response.is_failure());

        drop(stream);
        serving.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two interfaces cannot share one service silently: the second bind is refused while the first is
    /// alive, because the dispatcher holds a session and there is one of it.
    #[tokio::test]
    async fn a_second_service_is_refused_while_one_is_alive() {
        let dir = std::env::temp_dir().join(format!("vyde-ipc-dup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        let path = dir.join("t.sock");

        let _first = Server::bind(path.clone()).await.expect("bound");
        // Not `expect_err`: that needs `Server: Debug`, and a listener holding a socket has no useful
        // `Debug`. The `let Err(..) = .. else` says what is being asserted without asking for one.
        let Err(err) = Server::bind(path.clone()).await else {
            panic!("a second service bound the same socket");
        };

        assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
        drop(_first);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
