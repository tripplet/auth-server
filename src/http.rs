use crate::auth;
use crate::Config;
use crate::http;

use std::error::Error;
use std::fs;
use std::process;

use cookie::Cookie;
use log::{error};
use time::Duration;
use tokio::{select, signal};


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

pub async fn run_server<F>(cfg: &Config, services: F)
where
    F: warp::Filter + Clone + Send + Sync + 'static,
    F::Extract: warp::Reply
{
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