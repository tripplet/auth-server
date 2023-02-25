use std::net::SocketAddr;

/// The different options for listening
#[derive(Debug, Clone, PartialEq)]
pub enum Socket {
    File(String),
    Address(SocketAddr),

    #[cfg(feature = "systemd_socket_activation")]
    Systemd,
}

impl std::str::FromStr for Socket {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        #[cfg(feature = "systemd_socket_activation")]
        if input == "systemd" {
            return Ok(Socket::Systemd);
        }

        if input.starts_with("unix:") {
            Ok(Socket::File(input.strip_prefix("unix:").unwrap().into()))
        } else {
            Ok(Socket::Address(
                input
                    .parse::<std::net::SocketAddr>()
                    .map_err(|_| String::from("Invalid socket address"))?,
            ))
        }
    }
}
