mod auth;
mod http;

// Logging
use log::LevelFilter;
use simple_logger::SimpleLogger;

// Commandline parsing
use clap::Parser;

// The main config
#[derive(Debug, Parser)]
#[clap(version, about = "Service for authenticating requests from nginx (ngx_http_auth_request_module).")]
pub struct Config {
    /// Address to listen on, can also be a unix socket (unix:/tmp/auth-server.sock)
    #[clap(long, default_value = "127.0.0.1:14314", env)]
    listen: String,

    /// Set the group of the unix socket file to the given group
    #[clap(long, env)]
    socket_group: Option<String>,

    /// Secret secret to use
    #[clap(long, env, hide_env_values = true)]
    secret: Option<String>,

    /// Read secret from file
    #[clap(long, env, hide_env_values = true)]
    secret_file: Option<String>,

    /// The name of the cookie
    #[clap(long, env, default_value = "REQUEST_AUTHORIZATION_TOKEN")]
    cookie_name: String,

    /// Verbose mode
    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
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
