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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    use super::*;

    #[test]
    fn test_parse_v4() {
        assert_eq!(
            "0.0.0.0:1234".parse::<Socket>().unwrap(),
            Socket::Address(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                1234
            )))
        );
    }

    #[test]
    fn test_parse_v6() {
        assert_eq!(
            "[::]:1234".parse::<Socket>().unwrap(),
            Socket::Address(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                1234,
                0,
                0
            )))
        );
    }
}
