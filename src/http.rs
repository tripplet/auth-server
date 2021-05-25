use crate::auth;
use crate::Config;
use crate::http;

use std::convert::Infallible;
use std::error::Error;
use std::fs;
use std::process;

use cookie::{Cookie, SameSite};
use log::{error};
use time::Duration;
use tokio::{select, signal};

use warp::{self, filters, Filter, Rejection, Reply};
use warp::http::StatusCode;

/// Generate a cookie with the given authorization
pub fn generate_cookie(
    name: &str,
    param: &auth::AuthParameter,
    key: &str,
) -> Result<String, Box<dyn Error>> {
    Ok(Cookie::build(name, auth::generate_token(param, key)?)
        .domain(param.domain.clone())
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::seconds(param.duration as i64))
        .finish()
        .to_string())
}

/// Create a unix socket file with access allowed for the given group
#[cfg(any(unix, doc))]
pub fn create_socket_file(
    socket_path: &str,
    group: Option<&str>,
) -> Result<tokio_stream::wrappers::UnixListenerStream, Box<dyn Error>> {
    use nix::unistd::Group;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    // Try removing an old existing socket file
    let _ = fs::remove_file(socket_path);

    // Set umask to o=rw,g=rw,o= before creating the socket file
    let old_umask =
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o117).expect("Invalid umask"));
    let listener = UnixListener::bind(socket_path).unwrap();

    // Restore the umask
    nix::sys::stat::umask(old_umask);

    // Set socket group owner and permissions
    if let Some(socket_group) = group {
        let group = Group::from_name(socket_group)?.ok_or("group not found")?;
        let _ = nix::unistd::chown(socket_path, None, Some(group.gid))?;
    }

    Ok(UnixListenerStream::new(listener))
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let code;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
    }
    else if let Some(e) = err.find::<warp::reject::MissingCookie>() {
        code = StatusCode::UNAUTHORIZED;
    }
    else {
        code = StatusCode::INTERNAL_SERVER_ERROR;
    }

    Ok(code)
}

pub async fn run_server(cfg: &Config)
{
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

    let services = check_request.or(generate_request).recover(handle_rejection);

    if cfg.listen.starts_with("unix:") {
        if cfg!(windows) {
            error!("Unix sockets are not supported on windows");
            process::exit(-1);
        } else {
            let socket_path = cfg.listen.strip_prefix("unix:").unwrap();
            let incoming = http::create_socket_file(socket_path, cfg.socket_group.as_deref()).unwrap();

            select! {
                _ = warp::serve(services).run_incoming(incoming) => (),
                _ = signal::ctrl_c() => (),
            }

            // Cleanup socket file
            let _ = fs::remove_file(socket_path);
        }
    } else {
        let server = warp::serve(services).run(cfg.listen.parse::<std::net::SocketAddr>().unwrap());

        select! {
            _ = server => (),
            _ = signal::ctrl_c() => (),
        }
    }
}