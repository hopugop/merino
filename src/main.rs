#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), deny(warnings))]
#![warn(clippy::all)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#[macro_use]
extern crate log;

use actix::Actor;
use clap::{ArgGroup, Parser};
use merino::*;
use std::env;
use std::error::Error;
use std::io;
use std::net::ToSocketAddrs;
use std::os::unix::prelude::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Logo to be printed at when merino is run
const LOGO: &str = r"
                      _
  _ __ ___   ___ _ __(_)_ __   ___
 | '_ ` _ \ / _ \ '__| | '_ \ / _ \
 | | | | | |  __/ |  | | | | | (_) |
 |_| |_| |_|\___|_|  |_|_| |_|\___/

 A SOCKS5 Proxy server written in Rust
";

#[derive(Parser, Debug)]
#[command(version)]
#[command(group(
    ArgGroup::new("auth")
        .args(["no_auth", "users"]),
), group(
    ArgGroup::new("log")
        .args(["verbosity", "quiet"]),
))]
struct Opt {
    #[arg(short, long, default_value_t = 1080)]
    /// Set port to listen on
    port: u16,

    #[arg(short, long, default_value = "127.0.0.1")]
    /// Set ip to listen on
    ip: String,

    #[arg(long)]
    /// Allow insecure configuration
    allow_insecure: bool,

    #[arg(long)]
    /// Allow unauthenticated connections
    no_auth: bool,

    #[arg(short, long)]
    /// CSV File with username/password pairs
    users: Option<PathBuf>,

    /// Maximum number of simultaneous client connections
    #[arg(long, default_value_t = merino::DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,

    /// Cache successfully resolved domain names for this many seconds.
    /// 0 (the default) disables the cache, keeping a fresh lookup per request.
    #[arg(long, value_name = "SECONDS", default_value_t = 0)]
    dns_cache_ttl: u64,

    /// Cap simultaneous connections from one source IP. 0 (the default)
    /// leaves one host able to occupy every --max-connections slot.
    #[arg(long, value_name = "N", default_value_t = 0)]
    max_connections_per_ip: usize,

    /// Maximum number of names held in the DNS cache
    #[arg(long, value_name = "ENTRIES", default_value_t = merino::DEFAULT_DNS_CACHE_ENTRIES)]
    dns_cache_entries: usize,

    /// Serve real-time statistics over HTTP (off by default).
    /// Example: 127.0.0.1:9090. A hostname (e.g. a Tailscale DNS name) is
    /// resolved once at startup, like --ip. Endpoints: /, /stats, /clients, /healthz.
    #[arg(long, value_name = "ADDR:PORT")]
    stats_addr: Option<String>,

    /// Require this bearer token on every statistics request.
    /// Recommended whenever --stats-addr binds a non-loopback address.
    #[arg(long, value_name = "TOKEN")]
    stats_token: Option<String>,

    /// Log verbosity level. -vv for more verbosity.
    /// Environmental variable `RUST_LOG` overrides this flag!
    #[arg(short, action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Do not output any logs (even errors!). Overrides `RUST_LOG`
    #[arg(short)]
    quiet: bool,
}

/// Map the `-v`/`-vv` verbosity flags to a `RUST_LOG` filter.
fn log_level_for(verbosity: u8) -> &'static str {
    match verbosity {
        1 => "merino=DEBUG",
        2 => "merino=TRACE",
        _ => "merino=INFO",
    }
}

/// Decide which authentication methods to advertise.
///
/// A users file enables `USERPASS`, `--no-auth` enables `NOAUTH`, and when
/// neither is configured `NOAUTH` is used so a plain `merino` invocation still
/// starts a working proxy.
fn select_auth_methods(no_auth: bool, users_file: Option<&Path>) -> Vec<u8> {
    let mut methods = Vec::new();
    if no_auth {
        methods.push(merino::AuthMethods::NoAuth as u8);
    }
    if users_file.is_some() {
        methods.push(merino::AuthMethods::UserPass as u8);
    }
    if methods.is_empty() {
        methods.push(merino::AuthMethods::NoAuth as u8);
    }
    methods
}

/// Load users from a CSV file, rejecting files that group or others can access
/// unless `allow_insecure` is set.
fn load_users(users_file: &Path, allow_insecure: bool) -> Result<Vec<User>, Box<dyn Error>> {
    let file = std::fs::File::open(users_file)?;

    let metadata = file.metadata()?;
    // 0o077 is (S_IRWXG | S_IRWXO) or the group **and** "others" permission
    // bits in Unix. The users file must not be readable, writable, or
    // executable by anyone but the owner.
    if (metadata.mode() & 0o077) > 0 && !allow_insecure {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "Permissions {:o} for {:?} are too open. It is recommended that \
                your users file is NOT accessible by group or others. To override \
                this check, set --allow-insecure",
                metadata.mode() & 0o777,
                users_file
            ),
        )
        .into());
    }

    let mut users: Vec<User> = Vec::new();
    let mut rdr = csv::Reader::from_reader(file);
    for result in rdr.deserialize() {
        let record: User = result?;
        trace!("Loaded user: {}", record.username);
        users.push(record);
    }

    if users.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("No users loaded from {users_file:?}. Check configuration."),
        )
        .into());
    }

    Ok(users)
}

/// Resolve a `--stats-addr` value into the address to bind.
///
/// Accepts an IP literal (`127.0.0.1:9090`, `[::1]:9090`) or a hostname
/// (e.g. a Tailscale DNS name such as `host.ts.net:9090`), mirroring how
/// `--ip` may name the bind address. A hostname is resolved once at startup;
/// the first resolved address is used.
fn resolve_stats_addr(addr: &str) -> Result<std::net::SocketAddr, Box<dyn Error>> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("no addresses resolved for {addr}"),
            )
        })
        .map_err(Into::into)
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", LOGO);

    let opt = Opt::parse();

    // Setup logging
    let log_env = env::var("RUST_LOG");

    if !opt.quiet {
        let mut builder = pretty_env_logger::formatted_timed_builder();
        match &log_env {
            // An explicit RUST_LOG takes precedence over the verbosity flags.
            Ok(filter) => {
                builder.parse_filters(filter);
            }
            Err(_) => {
                builder.parse_filters(log_level_for(opt.verbosity));
            }
        }
        builder.init();
    }

    if let (Ok(filter), true) = (&log_env, opt.verbosity != 0) {
        warn!(
            "Log level is overriden by environmental variable to `{}`",
            filter
        );
    }

    // Setup Proxy settings

    let auth_methods = select_auth_methods(opt.no_auth, opt.users.as_deref());

    // Fall back to NOAUTH when no authentication method was configured so a
    // plain `merino` invocation starts a working proxy instead of failing.
    if !opt.no_auth && opt.users.is_none() {
        warn!(
            "No authentication method configured, defaulting to NOAUTH. \
            Use --users <FILE> to require username/password authentication."
        );
    }

    let authed_users: Vec<User> = match opt.users.as_deref() {
        Some(users_file) => load_users(users_file, opt.allow_insecure)?,
        None => Vec::new(),
    };

    // Start the actix system and the proxy server actor. The actor must be
    // created from inside the system's runtime context.
    let sys = actix::System::new();
    let mut server = sys.block_on(SocksServer::bind(
        opt.port,
        &opt.ip,
        auth_methods,
        authed_users,
        None,
    ))?;
    server.set_max_connections(opt.max_connections);
    server.set_max_connections_per_ip(opt.max_connections_per_ip);

    // Statistics are always collected; only the HTTP listener is opt-in.
    // The addr may be an IP literal or a hostname; hostnames are resolved to
    // an address here so the listener uses a plain SocketAddr below.
    let stats_addr: Option<std::net::SocketAddr> = opt
        .stats_addr
        .as_deref()
        .map(resolve_stats_addr)
        .transpose()?;
    let stats = Arc::new(merino::Stats::new());
    stats.note_listeners(server.local_addrs());
    server.set_stats(stats.clone());
    if opt.dns_cache_ttl > 0 {
        server.set_dns_cache(
            Duration::from_secs(opt.dns_cache_ttl),
            opt.dns_cache_entries,
        );
    }
    let stats_token: Option<Arc<str>> = opt.stats_token.as_deref().map(Arc::from);

    sys.block_on(async move {
        server.start();

        if let Some(addr) = stats_addr {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => listener,
                Err(e) => {
                    error!("Failed to bind stats listener on {addr}: {e}");
                    return Err(e);
                }
            };
            info!("Stats HTTP service listening on {addr}");
            if !addr.ip().is_loopback() && stats_token.is_none() {
                warn!(
                    "Stats HTTP service is exposed on a non-loopback address \
                    without --stats-token"
                );
            }
            let stats = stats.clone();
            let token = stats_token.clone();
            actix::spawn(async move {
                merino::serve_stats(listener, stats, token).await;
            });
        }

        actix::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("Shutdown signal received, stopping accept loops");
            actix::System::current().stop();
        });
        #[cfg(unix)]
        actix::spawn(async move {
            if let Ok(mut signal) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                && signal.recv().await.is_some()
            {
                info!("Shutdown signal received, stopping accept loops");
                actix::System::current().stop();
            }
        });
        Ok(())
    })?;
    sys.run()?;

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::os::unix::fs::PermissionsExt;

    fn write_temp_csv(name: &str, contents: &str, mode: u32) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("merino-test-{}-{name}.csv", std::process::id()));
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn defaults_when_no_auth() {
        let opt = Opt::try_parse_from(["merino", "--no-auth"]).unwrap();
        assert_eq!(opt.port, 1080);
        assert_eq!(opt.ip, "127.0.0.1");
        assert!(opt.no_auth);
        assert!(!opt.allow_insecure);
        assert_eq!(opt.max_connections, merino::DEFAULT_MAX_CONNECTIONS);
        assert!(opt.users.is_none());
    }

    #[test]
    fn no_auth_and_users_are_mutually_exclusive() {
        assert!(Opt::try_parse_from(["merino", "--no-auth", "--users", "u.csv"]).is_err());
    }

    #[test]
    fn verbosity_and_quiet_are_mutually_exclusive() {
        assert!(Opt::try_parse_from(["merino", "--no-auth", "-v", "-q"]).is_err());
    }

    #[test]
    fn parses_full_configuration() {
        let opt = Opt::try_parse_from([
            "merino",
            "--ip",
            "0.0.0.0",
            "--port",
            "9000",
            "--users",
            "u.csv",
            "--allow-insecure",
            "--max-connections",
            "7",
            "-vv",
        ])
        .unwrap();
        assert_eq!(opt.ip, "0.0.0.0");
        assert_eq!(opt.port, 9000);
        assert_eq!(opt.max_connections, 7);
        assert_eq!(opt.verbosity, 2);
        assert!(opt.allow_insecure);
        assert_eq!(opt.users.as_deref(), Some(Path::new("u.csv")));
    }

    #[test]
    fn log_level_maps_verbosity() {
        assert_eq!(log_level_for(0), "merino=INFO");
        assert_eq!(log_level_for(1), "merino=DEBUG");
        assert_eq!(log_level_for(2), "merino=TRACE");
        assert_eq!(log_level_for(9), "merino=INFO");
    }

    #[test]
    fn auth_methods_selection() {
        assert_eq!(
            select_auth_methods(true, None),
            vec![AuthMethods::NoAuth as u8]
        );
        assert_eq!(
            select_auth_methods(true, Some(Path::new("u.csv"))),
            vec![AuthMethods::NoAuth as u8, AuthMethods::UserPass as u8]
        );
        assert_eq!(
            select_auth_methods(false, Some(Path::new("u.csv"))),
            vec![AuthMethods::UserPass as u8]
        );
        assert_eq!(
            select_auth_methods(false, None),
            vec![AuthMethods::NoAuth as u8]
        );
    }

    #[test]
    fn load_users_reads_private_file() {
        let path = write_temp_csv(
            "ok",
            "username,password\nalice,secret\nbob,hunter2\n",
            0o600,
        );
        let users = load_users(&path, false).unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0], User::new("alice", "secret"));
        assert_eq!(users[1], User::new("bob", "hunter2"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_users_rejects_world_readable_file() {
        let path = write_temp_csv("open", "username,password\nalice,secret\n", 0o644);
        assert!(load_users(&path, false).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_users_rejects_group_readable_file() {
        let path = write_temp_csv("group", "username,password\nalice,secret\n", 0o640);
        assert!(load_users(&path, false).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_users_rejects_group_writable_file() {
        let path = write_temp_csv("group-write", "username,password\nalice,secret\n", 0o620);
        assert!(load_users(&path, false).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_users_allows_world_readable_with_insecure_flag() {
        let path = write_temp_csv("insecure", "username,password\nalice,secret\n", 0o644);
        assert!(load_users(&path, true).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_users_allows_group_readable_with_insecure_flag() {
        let path = write_temp_csv("insecure-group", "username,password\nalice,secret\n", 0o640);
        assert!(load_users(&path, true).is_ok());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_users_errors_on_missing_file() {
        let path = std::env::temp_dir().join("merino-test-missing-xyz.csv");
        assert!(load_users(&path, false).is_err());
    }

    #[test]
    fn load_users_errors_on_malformed_csv() {
        let path = write_temp_csv("malformed", "username,password\nalice\n", 0o600);
        assert!(load_users(&path, false).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_users_errors_on_empty_list() {
        let path = write_temp_csv("empty", "username,password\n", 0o600);
        assert!(load_users(&path, false).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_stats_addr_accepts_ip_literal() {
        assert_eq!(
            resolve_stats_addr("127.0.0.1:9090").unwrap(),
            "127.0.0.1:9090".parse().unwrap()
        );
        assert_eq!(
            resolve_stats_addr("[::1]:9090").unwrap(),
            "[::1]:9090".parse().unwrap()
        );
    }

    #[test]
    fn resolve_stats_addr_resolves_a_hostname() {
        // localhost resolves to a loopback address on every supported host.
        let addr = resolve_stats_addr("localhost:9090").unwrap();
        assert!(addr.ip().is_loopback());
        assert_eq!(addr.port(), 9090);
    }

    #[test]
    fn resolve_stats_addr_rejects_garbage() {
        assert!(resolve_stats_addr("no-port-here").is_err());
        assert!(resolve_stats_addr(":notaport").is_err());
    }
}
