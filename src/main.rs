mod auth;
mod http;

use std::fs;
use std::process;

// Logging
use log::{error, LevelFilter};
use simple_logger::SimpleLogger;

// Time management
use time::Duration;
extern crate time;

// Commandline parsing
use structopt::StructOpt;

// Web related stuff
use warp::{self, filters, Filter};

// The main config
#[derive(Debug, StructOpt)]
#[structopt(about = "Service for authenticating requests from nginx (ngx_http_auth_request_module).")]
pub struct Config {
    /// Address to listen on, can also be a unix socket (unix:/tmp/auth-server.sock)
    #[structopt(long, default_value = "127.0.0.1:14314", env)]
    listen: String,

    /// Set the group of the unix socket file to the given group
    #[structopt(long, env)]
    socket_group: Option<String>,

    /// Secret secret to use
    #[structopt(long, env, hide_env_values = true)]
    secret: Option<String>,

    /// Read secret from file
    #[structopt(long, env, hide_env_values = true)]
    secret_file: Option<String>,

    /// The name of the cookie
    #[structopt(long, env, default_value = "REQUEST_AUTHORIZATION_TOKEN")]
    cookie_name: String,

    /// Verbose mode
    #[structopt(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    let cfg = Config::from_args(); // Parse arguments

    // Initialize logger
    SimpleLogger::new().init().unwrap();
    if cfg.verbose {
        log::set_max_level(LevelFilter::Info);
    } else {
        log::set_max_level(LevelFilter::Warn);
    }

    let secret_key: &'static str;

    // Get the secret and 'leak' it, otherwise it can not easily be used in the warp:: expressions
    if cfg.secret.is_some() && cfg.secret_file.is_some() {
        error!("Do not specify both secret and secret_file");
        process::exit(-1);
    } else if let Some(secret) = cfg.secret.clone() {
        secret_key = Box::leak(secret.into_boxed_str());
    } else if let Some(secret_file) = cfg.secret_file.clone() {
        secret_key = Box::leak(
            fs::read_to_string(secret_file)
                .expect("file 'secret' not found, exiting")
                .trim()
                .to_string()
                .into_boxed_str(),
        );
    } else {
        error!("No secret defined");
        process::exit(-1);
    }

    let cookie_name: &'static str = Box::leak(cfg.cookie_name.clone().into_boxed_str());

    let check_request = warp::path!("check" / String)
        .and(filters::cookie::cookie(cookie_name))
        .map(move |sub: String, cookie: String| {
            match auth::check_token(&cookie, &sub, &secret_key).is_ok() {
                false => warp::http::StatusCode::UNAUTHORIZED,
                true => warp::http::StatusCode::OK,
            }
        });

    let generate_request = warp::path!("generate")
        .and(warp::query::<auth::AuthParameter>())
        .map(move |param: auth::AuthParameter| {
            let duration = Duration::seconds(param.duration as i64);
            let cookie = http::generate_cookie(
                cookie_name,
                &param,
                &secret_key,
            )
            .unwrap();

            let valid_util =
                (time::OffsetDateTime::now_utc() + duration).format("%Y-%m-%d %H:%M:%S UTC");

            let reply = warp::reply::Response::new(
                format!(
                    "sub: {}\ndomain: {}\nauthorized until: {}",
                    &param.sub, &param.domain, valid_util
                )
                .into(),
            );
            warp::reply::with_header(reply, "Set-Cookie", cookie)
        })
        .with(warp::reply::with::header("Content-Type", "text/plain"));

    let services = check_request.or(generate_request);

    http::run_server(&cfg, services).await;
}