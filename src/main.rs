#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), deny(warnings))]
#![warn(clippy::all)]
#[macro_use]
extern crate log;

use actix::Actor;
use clap::{ArgGroup, Parser};
use merino::*;
use std::env;
use std::error::Error;
use std::os::unix::prelude::MetadataExt;
use std::path::PathBuf;

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

    /// Log verbosity level. -vv for more verbosity.
    /// Environmental variable `RUST_LOG` overrides this flag!
    #[arg(short, action = clap::ArgAction::Count)]
    verbosity: u8,

    /// Do not output any logs (even errors!). Overrides `RUST_LOG`
    #[arg(short)]
    quiet: bool,
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
                let level = match opt.verbosity {
                    1 => "merino=DEBUG",
                    2 => "merino=TRACE",
                    _ => "merino=INFO",
                };
                builder.parse_filters(level);
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

    let mut auth_methods: Vec<u8> = Vec::new();

    // Allow unauthenticated connections
    if opt.no_auth {
        auth_methods.push(merino::AuthMethods::NoAuth as u8);
    }

    // Enable username/password auth
    let authed_users: Result<Vec<User>, Box<dyn Error>> = match opt.users {
        Some(users_file) => {
            auth_methods.push(AuthMethods::UserPass as u8);
            let file = std::fs::File::open(&users_file).unwrap_or_else(|e| {
                error!("Can't open file {:?}: {}", users_file, e);
                std::process::exit(1);
            });

            let metadata = file.metadata()?;
            // 7 is (S_IROTH | S_IWOTH | S_IXOTH) or the "permisions for others" in unix
            if (metadata.mode() & 7) > 0 && !opt.allow_insecure {
                error!(
                    "Permissions {:o} for {:?} are too open. \
                    It is recommended that your users file is NOT accessible by others. \
                    To override this check, set --allow-insecure",
                    metadata.mode() & 0o777,
                    users_file
                );
                std::process::exit(1);
            }

            let mut users: Vec<User> = Vec::new();

            let mut rdr = csv::Reader::from_reader(file);
            for result in rdr.deserialize() {
                let record: User = match result {
                    Ok(r) => r,
                    Err(e) => {
                        error!("{}", e);
                        std::process::exit(1);
                    }
                };

                trace!("Loaded user: {}", record.username);
                users.push(record);
            }

            if users.is_empty() {
                error!(
                    "No users loaded from {:?}. Check configuration.",
                    users_file
                );
                std::process::exit(1);
            }

            Ok(users)
        }
        _ => Ok(Vec::new()),
    };

    // Fall back to NOAUTH when no authentication method was configured so a
    // plain `merino` invocation starts a working proxy instead of failing.
    if auth_methods.is_empty() {
        warn!(
            "No authentication method configured, defaulting to NOAUTH. \
            Use --users <FILE> to require username/password authentication."
        );
        auth_methods.push(merino::AuthMethods::NoAuth as u8);
    }

    let authed_users = authed_users?;

    // Start the actix system and the proxy server actor. The actor must be
    // created from inside the system's runtime context.
    let sys = actix::System::new();
    let server = sys.block_on(SocksServer::bind(
        opt.port,
        &opt.ip,
        auth_methods,
        authed_users,
        None,
    ))?;
    sys.block_on(async move {
        server.start();
    });
    sys.run()?;

    Ok(())
}
