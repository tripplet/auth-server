use std::error::Error;
use std::fs;
use std::process;

// Serialization
use serde::{Deserialize, Serialize};

// Logging
use log::{error, LevelFilter};
use simple_logger::SimpleLogger;

// Time management
use time::Duration;
extern crate time;

// Commandline parsing
use structopt::StructOpt;

// Web related stuff
use cookie::Cookie;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use warp::{self, Filter, filters};
use tokio::{signal, select};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct CookieParameter {
    domain: String,
    duration: u64,
    sub: String,
}

// The main config
#[derive(Debug, StructOpt)]
#[structopt(about = "Service for authenticating requests from nginx (ngx_http_auth_request_module).")]
struct Config {
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
    }
    else if let Some(secret) = cfg.secret {
        secret_key = Box::leak(secret.into_boxed_str());
    }
    else if let Some(secret_file) = cfg.secret_file {
        secret_key = Box::leak(
            fs::read_to_string(secret_file)
                .expect("file 'secret' not found, exiting")
                .trim()
                .to_string()
                .into_boxed_str(),
        );
    }
    else {
        error!("No secret defined");
        process::exit(-1);
    }

    let cookie_name: &'static str = Box::leak(cfg.cookie_name.into_boxed_str());

    let check_request = warp::path!("check" / String)
        .and(filters::cookie::cookie(cookie_name))
        .map(move |sub: String, cookie: String| {
            match check_token(&cookie, &sub, &secret_key).is_ok() {
                false => warp::http::StatusCode::UNAUTHORIZED,
                true => warp::http::StatusCode::OK,
            }
        });

    let generate_request = warp::path!("generate")
        .and(warp::query::<CookieParameter>())
        .map(move |param: CookieParameter| {
            let duration = Duration::seconds(param.duration as i64);
            let cookie = generate_cookie(
                cookie_name,
                &param.sub,
                duration,
                &param.domain,
                &secret_key,
            ).unwrap();

            let valid_util = (time::OffsetDateTime::now_utc() + duration).format("%Y-%m-%d %H:%M:%S UTC");

            let reply = warp::reply::Response::new(format!("sub: {}\ndomain: {}\nauthorized until: {}", &param.sub, &param.domain, valid_util).into());
            warp::reply::with_header(reply, "Set-Cookie", cookie)
        })
        .with(warp::reply::with::header("Content-Type", "text/plain"));

    let services = check_request.or(generate_request);

    if cfg.listen.starts_with("unix:") {
        if cfg!(windows) {
            error!("Unix sockets are not supported on windows");
            process::exit(-1);
        }
        else {
            let socket_path = cfg.listen.strip_prefix("unix:").unwrap();
            let incoming = create_socket_file(socket_path, cfg.socket_group).unwrap();

            select! {
                _ = warp::serve(services).run_incoming(incoming) => (),
                _ = signal::ctrl_c() => (),
            }

            // Cleanup socket file
            let _ = fs::remove_file(socket_path);
        }
    }
    else {
        let server = warp::serve(services)
            .run(cfg.listen.parse::<std::net::SocketAddr>().unwrap());

        select! {
            _ = server => (),
            _ = signal::ctrl_c() => (),
        }
    }
}

#[cfg(any(unix, doc))]
fn create_socket_file(socket_path: &str, group: Option<String>) -> Result<tokio_stream::wrappers::UnixListenerStream, Box<dyn Error>> {
    use nix::unistd::{Group};
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    // Try removing an old existing socket file
    let _ = fs::remove_file(socket_path);

    // Set umask to o=rw,g=rw,o= before creating the socket file
    let old_umask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o117).expect("Invalid umask"));
    let listener = UnixListener::bind(socket_path).unwrap();

    // Restore the umask
    nix::sys::stat::umask(old_umask);

    // Set socket group owner and permissions
    if let Some(socket_group) = group {
        let group = Group::from_name(&socket_group)?.ok_or("group not found")?;
        let _ = nix::unistd::chown(socket_path, None, Some(group.gid))?;
    }

    Ok(UnixListenerStream::new(listener))
}

fn generate_cookie(name: &str, sub: &str, duration: Duration, domain: &str, key: &str) -> Result<String, Box<dyn Error>> {
    Ok(Cookie::build(name, generate_token(sub, duration, key)?)
        .domain(domain)
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(duration)
        .finish()
        .to_string())
}

fn generate_token(sub: &str, duration: Duration, key: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: sub.into(),
        exp: (time::OffsetDateTime::now_utc() + duration).unix_timestamp(),
    };

    Ok(encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(key.as_ref()),
    )?)
}

fn check_token(token: &str, sub: &str, key: &str) -> Result<Claims, Box<dyn Error>> {
    let jwt_validation = Validation {
        algorithms: vec![Algorithm::HS256],
        validate_exp: true,
        sub: Some(sub.to_string()),
        ..Validation::default()
    };

    Ok(decode::<Claims>(
        &token,
        &DecodingKey::from_secret(key.as_ref()),
        &jwt_validation,
    )?
    .claims)
}

