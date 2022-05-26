use std::net::SocketAddr;

#[derive(Debug, PartialEq)]
pub enum Socket {
    File(String),
    Address(SocketAddr),
    Systemd,
}

impl std::str::FromStr for Socket {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input == "systemd" {
            Ok(Socket::Systemd)
        }
        else if input.starts_with("unix:") {
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
