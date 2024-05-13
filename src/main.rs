mod auth;
mod config;
mod http;
mod listen;

use clap::Parser;
use log::LevelFilter;
use simple_logger::SimpleLogger;

use config::Config;

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
