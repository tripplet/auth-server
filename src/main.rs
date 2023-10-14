mod auth;
mod http;
mod listen;

// Logging
use log::LevelFilter;
use simple_logger::SimpleLogger;

// Command line parsing
use clap::{ArgGroup, Parser};

// Allocator
//use mimalloc::MiMalloc;

//#[global_allocator]
//static GLOBAL: MiMalloc = MiMalloc;

// The main config
#[derive(Debug, Parser)]
#[clap(version)]
#[clap(group(ArgGroup::new("secrets").required(true)))]
pub struct Config {
    /// Address to listen on like 127.0.0.1:14314, can also be a unix socket (e.g. unix:/tmp/auth-server.sock)
    #[clap(long, env, default_value = "127.0.0.1:14314")]
    listen: listen::Socket,

    /// Timeout after which the programs waits for new requests afterwards it exists
    /// (used for systemd socket activation)
    //#[cfg(feature = "systemd_socket_activation")]
    #[clap(long, env)]
    systemd_activation_idle: Option<u16>,

    /// Set the group of the unix socket file to the given group
    #[clap(long, env)]
    socket_group: Option<String>,

    /// Secret to use
    #[clap(long, env, group = "secrets", hide_env_values = true)]
    secret: Option<String>,

    /// Read secret from file
    #[clap(long, env, group = "secrets")]
    secret_file: Option<String>,

    /// The name of the cookie
    #[clap(long, env, default_value = "REQUEST_AUTHORIZATION_TOKEN")]
    cookie_name: String,

    /// Verbose mode
    #[clap(short, long)]
    verbose: bool,
}

#[actix_web::main]
async fn main() {
    // Parse arguments
    let cfg = Config::parse();

    // Initialize logger
    SimpleLogger::new().init().unwrap();
    if cfg.verbose {
        log::set_max_level(LevelFilter::Info);
    } else {
        log::set_max_level(LevelFilter::Warn);
    }

    http::run_server(&cfg).await;
}
