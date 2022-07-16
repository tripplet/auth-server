use crate::auth;
use crate::http;
use crate::listen;
use crate::Config;

use std::error::Error;
use std::process;

use actix_web::cookie::{Cookie, SameSite};
use actix_web::middleware::{Condition, Logger};
use actix_web::{get, web, App, HttpRequest, HttpResponse, HttpServer, Responder};

use log::error;
use time::{macros::format_description, Duration};
use tokio::{select, signal};

struct AppState {
    cookie_name: String,
    secret_key: String,
}

#[get("/check/{sub}")]
async fn check(
    req: HttpRequest,
    path: web::Path<String>,
    data: web::Data<AppState>,
) -> impl Responder {
    match req.cookie(&data.cookie_name) {
        None => HttpResponse::Unauthorized(),
        Some(cookie) => {
            match auth::check_token(cookie.value(), &path.into_inner(), &data.secret_key).is_ok() {
                false => HttpResponse::Unauthorized(),
                true => HttpResponse::Ok(),
            }
        }
    }
}

#[get("/generate")]
async fn generate(
    param: web::Query<auth::AuthParameter>,
    data: web::Data<AppState>,
) -> impl Responder {
    let duration = Duration::seconds(param.duration as i64);
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
    let secret_key = if let Some(secret) = &cfg.secret {
        secret.clone()
    } else if let Some(secret_file) = &cfg.secret_file {
        secret_file.clone()
    } else {
        error!("No secret defined");
        process::exit(-1);
    };

    // Avoid capturing cfg
    let cookie_name = cfg.cookie_name.clone();
    let verbose = cfg.verbose;

    let server = HttpServer::new(move || {
        App::new()
            .wrap(Condition::new(verbose, Logger::default()))
            .app_data(web::Data::new(AppState {
                cookie_name: cookie_name.to_string(),
                secret_key: secret_key.to_string(),
            }))
            .service(check)
            .service(generate)
    })
    .workers(1);

    match &cfg.listen {
        #[cfg(feature = "systemd_socket_activation")]
        listen::Socket::Systemd => {
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

            select! {
                _ = server.listen_uds(incoming).unwrap().run() => (),
                _ = signal::ctrl_c() => (),
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

                // Cleanup socket file
                let _ = std::fs::remove_file(&path);
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

/// Generate a cookie with the given authorization
fn generate_cookie(
    name: &str,
    param: &auth::AuthParameter,
    key: &str,
) -> Result<String, Box<dyn Error>> {
    Ok(Cookie::build(name, param.generate_token(key)?)
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
