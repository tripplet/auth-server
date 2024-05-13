use std::{fmt, fs};

use clap::{ArgGroup, Parser};

use crate::listen;

// The main config
#[derive(Debug, Parser)]
#[clap(version)]
#[clap(group(ArgGroup::new("secrets").required(true)))]
pub struct Config {
    /// Address to listen on like 127.0.0.1:14314, can also be a unix socket (e.g. unix:/tmp/auth-server.sock)
    #[clap(long, env, default_value = "127.0.0.1:14314")]
    pub listen: listen::Socket,

    /// Timeout after which the programs waits for new requests afterwards it exists
    /// (used for systemd socket activation)
    #[cfg(feature = "systemd_socket_activation")]
    #[clap(long, env)]
    pub systemd_activation_idle: Option<u16>,

    /// Set the group of the unix socket file to the given group
    #[clap(long, env)]
    pub socket_group: Option<String>,

    /// Secret to use
    #[clap(long, env, group = "secrets", hide_env_values = true)]
    secret: Option<String>,

    /// Read secret from file
    #[clap(long, env, group = "secrets")]
    secret_file: Option<String>,

    /// The name of the cookie
    #[clap(long, env, default_value = "REQUEST_AUTHORIZATION_TOKEN")]
    pub cookie_name: String,

    /// Verbose mode
    #[clap(short, long)]
    pub verbose: bool,
}

impl Config {
    /// Get the secret
    pub fn get_secret(&self) -> Result<String, KeyError> {
        let secret_key = if let Some(secret) = &self.secret {
            Ok(secret.clone())
        } else if let Some(secret_file) = &self.secret_file {
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
}

#[derive(Debug)]
pub enum KeyError {
    NoKeyFound,
    KeyToShort,
    UnableToReadKeyFile(std::io::Error),
}

impl std::error::Error for KeyError {}

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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    impl Default for Config {
        fn default() -> Self {
            Self {
                listen: "0.0.0.0:1234".parse().unwrap(),

                #[cfg(feature = "systemd_socket_activation")]
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

        assert_eq!(cfg.get_secret(), Err(KeyError::KeyToShort));
    }

    #[test]
    fn test_key_to_short_file() {
        let mut tempfile = tempfile::NamedTempFile::new().unwrap();
        write!(tempfile, "secret123").unwrap();

        let cfg = Config {
            secret_file: Some(tempfile.path().to_str().unwrap().into()),
            ..Default::default()
        };

        assert_eq!(cfg.get_secret(), Err(KeyError::KeyToShort));
    }

    #[test]
    fn test_key_cli() {
        let cfg = Config {
            secret: Some("1234567890123456".into()),
            ..Default::default()
        };

        assert_eq!(cfg.get_secret(), Ok("1234567890123456".into()));
    }

    #[test]
    fn test_key_from_file() {
        let mut tempfile = tempfile::NamedTempFile::new().unwrap();
        write!(tempfile, "1234567890123456").unwrap();

        let cfg = Config {
            secret_file: Some(tempfile.path().to_str().unwrap().into()),
            ..Default::default()
        };

        assert_eq!(cfg.get_secret(), Ok("1234567890123456".into()));
    }
}
