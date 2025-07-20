use crate::auth;
use crate::http;
use crate::listen;
use crate::Config;

use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};
use std::{error::Error, process};

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
    let secret_key = match cfg.get_secret() {
        Err(err) => {
            error!("{err}");
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
            type Tasks = Pin<Box<dyn Future<Output = Result<(), &'static str>>>>;

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

            let mut tasks: Vec<Tasks> = vec![];

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
            if let Some(idle_time) = cfg.systemd_activation_idle
                && idle_time > 0
            {
                tasks.push(create_idle_timeout_task(
                    request_received.clone(),
                    tokio::time::Duration::from_secs(u64::from(idle_time)),
                ));
            }

            select! {
                result = futures::future::select_all(tasks) =>
                    if let (Err(err), ..) = result { error!("Closing server: {err}") }
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

#[cfg(feature = "systemd_socket_activation")]
fn create_idle_timeout_task(
    activity: Arc<AtomicBool>,
    idle_timeout: tokio::time::Duration,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), &'static str>>>> {
    let timeout_task = tokio::task::spawn(async move {
        loop {
            tokio::time::sleep(idle_timeout).await;

            // If the request_received has not been set to true in the timeout period => exit
            if activity
                .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                break;
            }
        }
    });

    Box::pin(async move {
        _ = timeout_task.await;
        Err("Idle timeout")
    })
}
