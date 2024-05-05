use crate::auth;
use crate::http;
use crate::listen;
use crate::Config;

use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};
use std::{error::Error, fmt, fs, process};

use actix_web::cookie::{Cookie, SameSite};
use actix_web::middleware::{Condition, Logger};
use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};

use log::error;
use time::macros::format_description;
use tokio::{select, signal};

use crate::auth::seconds_saturating;

struct AppState {
    cookie_name: String,
    secret_key: String,
    request_received: Arc<AtomicBool>,
}

#[get("/check/{sub}")]
async fn check(
    req: HttpRequest,
    path: web::Path<String>,
    data: web::Data<AppState>,
) -> impl Responder {
    data.request_received.store(true, Ordering::Relaxed);

    match req.cookie(&data.cookie_name) {
        None => HttpResponse::Unauthorized(),
        Some(cookie) => {
            if auth::check_token(cookie.value(), &path.into_inner(), &data.secret_key).is_ok() {
                HttpResponse::Ok()
            } else {
                HttpResponse::Unauthorized()
            }
        }
    }
}

#[get("/generate")]
async fn generate(
    web::Query(param): web::Query<auth::Parameter>,
    data: web::Data<AppState>,
) -> impl Responder {
    data.request_received.store(true, Ordering::Relaxed);

    let duration = seconds_saturating(param.duration);
    let cookie = http::generate_cookie(&data.cookie_name, &param, &data.secret_key).unwrap();

    let valid_until = (time::OffsetDateTime::now_utc() + duration).format(format_description!(
        "[year]-[month]-[day] [hour]:[minute] UTC"
    ));

    match valid_until {
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
        Ok(valid_until) => HttpResponse::Ok()
            .insert_header(("Content-Type", "text/plain"))
            .insert_header(("Set-Cookie", cookie))
            .body(format!(
                "sub: {}\ndomain: {}\nauthorized until: {}",
                &param.sub, &param.domain, valid_until
            )),
    }
}

pub async fn run_server(cfg: &Config) {
    let secret_key = match load_secret_key(cfg) {
        Err(err) => {
            error!("{}", err);
            process::exit(-1);
        }
        Ok(key) => key,
    };

    // Avoid capturing cfg
    let cookie_name = cfg.cookie_name.clone();
    let verbose = cfg.verbose;

    // Create boolean handle idle timeout
    let request_received = Arc::new(AtomicBool::new(false));
    let request_received_setter = request_received.clone();

    let server = HttpServer::new(move || {
        App::new()
            .wrap(Condition::new(verbose, Logger::default()))
            .app_data(web::Data::new(AppState {
                cookie_name: cookie_name.to_string(),
                secret_key: secret_key.to_string(),
                request_received: request_received_setter.clone(),
            }))
            .service(check)
            .service(generate)
    })
    .workers(1)
    .keep_alive(std::time::Duration::from_secs(5));

    match &cfg.listen {
        #[cfg(feature = "systemd_socket_activation")]
        listen::Socket::Systemd => {
            use std::{future::Future, pin::Pin};

            let incoming = match socket_from_systemd_activation() {
                Ok(Some(socket)) => socket,
                Ok(None) => {
                    error!("No systemd socket activation provided");
                    process::exit(-2);
                }
                Err(err) => {
                    error!("Error determining socket activation: {err}");
                    process::exit(-3);
                }
            };

            let mut tasks: Vec<Pin<Box<dyn Future<Output = Result<(), &str>>>>> = vec![];

            // Add the http server to the task list
            tasks.push(Box::pin(async move {
                _ = server.listen_uds(incoming).unwrap().run().await;
                Ok(())
            }));

            // Add the Ctrl+C handler to the task list
            tasks.push(Box::pin(async move {
                _ = signal::ctrl_c().await;
                Ok(())
            }));

            // If a idle timeout is set, create a new timeout task and add it to the task list
            if let Some(idle_time) = cfg.systemd_activation_idle {
                if idle_time > 0 {
                    let timeout = tokio::time::Duration::from_secs(idle_time as u64);
                    let request_received_check = request_received.clone();

                    let idle_timeout = tokio::task::spawn(async move {
                        loop {
                            tokio::time::sleep(timeout).await;

                            // If the request_received has not been set to true in the timeout period => exit
                            if request_received_check
                                .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
                                .is_err()
                            {
                                break;
                            }
                        }
                    });

                    tasks.push(Box::pin(async move {
                        _ = idle_timeout.await;
                        Err("Idle timeout")
                    }));
                }
            }

            select! {
                result = futures::future::select_all(tasks) =>
                    match result {
                        (Err(err), ..) => error!("Closing server: {err}"),
                        _ => (),
                    }
            }
        }

        listen::Socket::File(path) => {
            if cfg!(windows) {
                _ = path;
                error!("Unix sockets are not supported on windows");
                process::exit(-1);
            }

            #[cfg(any(unix, doc))]
            {
                let incoming = http::create_socket_file(path, cfg.socket_group.as_deref()).unwrap();

                select! {
                    _ = server.listen_uds(incoming).unwrap().run() => (),
                    _ = signal::ctrl_c() => (),
                }

                // Try to cleanup socket file
                let _ = std::fs::remove_file(path);
            }
        }
        listen::Socket::Address(addr) => {
            let server = server.bind(addr).unwrap().run();

            select! {
                _ = server => (),
                _ = signal::ctrl_c() => (),
            }
        }
    }
}

#[derive(Debug)]
enum KeyError {
    NoKeyFound,
    KeyToShort,
    UnableToReadKeyFile(std::io::Error),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NoKeyFound => write!(f, "No secret defined"),
            Self::KeyToShort => write!(
                f,
                "The secret key is too short and should be at least 16 characters long"
            ),
            Self::UnableToReadKeyFile(err) => write!(f, "Unable to read secret file: {err}"),
        }
    }
}

impl Error for KeyError {}

fn load_secret_key(cfg: &Config) -> Result<String, KeyError> {
    let secret_key = if let Some(secret) = &cfg.secret {
        Ok(secret.clone())
    } else if let Some(secret_file) = &cfg.secret_file {
        match fs::read_to_string(secret_file) {
            Ok(secret) => Ok(secret),
            Err(err) => Err(KeyError::UnableToReadKeyFile(err)),
        }
    } else {
        Err(KeyError::NoKeyFound)
    };

    // Basic sanity check
    if secret_key.as_ref().is_ok_and(|k| k.len() < 16) {
        return Err(KeyError::KeyToShort);
    }

    secret_key
}

/// Generate a cookie with the given authorization
fn generate_cookie(
    name: &str,
    param: &auth::Parameter,
    key: &str,
) -> Result<String, Box<dyn Error>> {
    Ok(Cookie::build(name, param.generate_token(key)?)
        .domain(param.domain.clone())
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Strict)
        .max_age(seconds_saturating(param.duration))
        .finish()
        .to_string())
}

/// Create a unix socket file with access allowed for the given group
#[cfg(any(unix, doc))]
fn create_socket_file(
    socket_path: &str,
    group: Option<&str>,
) -> Result<std::os::unix::net::UnixListener, Box<dyn Error>> {
    use nix::unistd::Group;
    use std::os::unix::net::UnixListener;

    // Try removing an old existing socket file
    let _ = std::fs::remove_file(socket_path);

    // Set umask to o=rw,g=rw,o= before creating the socket file
    let old_umask =
        nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o117).expect("Invalid umask"));
    let listener = UnixListener::bind(socket_path)?;

    // Restore the umask
    nix::sys::stat::umask(old_umask);

    // Set socket group owner and permissions
    if let Some(socket_group) = group {
        let group = Group::from_name(socket_group)?.ok_or("group not found")?;
        nix::unistd::chown(socket_path, None, Some(group.gid))?;
    }

    Ok(listener)
}

#[cfg(feature = "systemd_socket_activation")]
pub fn socket_from_systemd_activation(
) -> Result<Option<std::os::unix::net::UnixListener>, Box<dyn Error>> {
    use libsystemd::activation;
    use std::os::unix::io::{FromRawFd, IntoRawFd};
    use std::os::unix::net::UnixListener;

    let mut fds = activation::receive_descriptors(true)?;
    if fds.is_empty() {
        Ok(None)
    } else if fds.len() == 1 {
        unsafe { Ok(Some(UnixListener::from_raw_fd(fds.remove(0).into_raw_fd()))) }
    } else {
        Err("Not supported".into())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    impl Default for Config {
        fn default() -> Self {
            Self {
                listen: "0.0.0.0:1234".parse().unwrap(),
                systemd_activation_idle: Default::default(),
                socket_group: Default::default(),
                secret: Default::default(),
                secret_file: Default::default(),
                cookie_name: Default::default(),
                verbose: Default::default(),
            }
        }
    }

    impl PartialEq for KeyError {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::UnableToReadKeyFile(_), Self::UnableToReadKeyFile(_)) => true,
                (Self::KeyToShort, Self::KeyToShort) => true,
                (Self::NoKeyFound, Self::NoKeyFound) => true,
                _ => false,
            }
        }
    }

    #[test]
    fn test_key_to_short_cli() {
        let cfg = Config {
            secret: Some("test".into()),
            ..Default::default()
        };

        assert_eq!(load_secret_key(&cfg), Err(KeyError::KeyToShort));
    }

    #[test]
    fn test_key_to_short_file() {
        let mut tempfile = tempfile::NamedTempFile::new().unwrap();
        write!(tempfile, "secret123").unwrap();

        let cfg = Config {
            secret_file: Some(tempfile.path().to_str().unwrap().into()),
            ..Default::default()
        };

        assert_eq!(load_secret_key(&cfg), Err(KeyError::KeyToShort));
    }

    #[test]
    fn test_key_cli() {
        let cfg = Config {
            secret: Some("1234567890123456".into()),
            ..Default::default()
        };

        assert_eq!(load_secret_key(&cfg), Ok("1234567890123456".into()));
    }

    #[test]
    fn test_key_from_file() {
        let mut tempfile = tempfile::NamedTempFile::new().unwrap();
        write!(tempfile, "1234567890123456").unwrap();

        let cfg = Config {
            secret_file: Some(tempfile.path().to_str().unwrap().into()),
            ..Default::default()
        };

        assert_eq!(load_secret_key(&cfg), Ok("1234567890123456".into()));
    }
}
