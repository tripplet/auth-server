use std::error::Error;

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthParameter {
    pub domain: String,
    pub duration: u64,
    pub sub: String,
}

impl AuthParameter {
    /// Generate an authorization token
    pub fn generate_token(&self, key: &str) -> Result<String, jsonwebtoken::errors::Error> {
        self.generate_token_at_moment(key, time::OffsetDateTime::now_utc())
    }

    fn generate_token_at_moment(
        &self,
        key: &str,
        now: time::OffsetDateTime,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let claims = Claims {
            sub: self.sub.clone(),
            exp: (now + Duration::seconds(self.duration as i64)).unix_timestamp(),
        };

        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(key.as_ref()),
        )
    }
}

/// Check an authorization token
pub fn check_token(token: &str, sub: &str, key: &str) -> Result<Claims, Box<dyn Error>> {
    let mut jwt_validation = Validation::new(Algorithm::HS256);
    jwt_validation.leeway = 30;
    jwt_validation.sub = Some(sub.to_string());

    Ok(decode::<Claims>(
        token,
        &DecodingKey::from_secret(key.as_ref()),
        &jwt_validation,
    )?
    .claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::encode;

    #[test]
    fn generate_token() {
        let key = "secretkey";
        let param = AuthParameter {
            domain: "unused-here".to_string(),
            duration: 4242,
            sub: "service1".to_string(),
        };

        let token = param
            .generate_token_at_moment(key, time::OffsetDateTime::UNIX_EPOCH)
            .unwrap();

        assert_eq!(
            [
                encode(r#"{"typ":"JWT","alg":"HS256"}"#),
                encode(format!(
                    r#"{{"sub":"{}","exp":{}}}"#,
                    param.sub, param.duration
                ))
                .trim_end_matches("=")
                .to_owned(),
                "6cTcqIk7IHq_J_qmOsbQcXOLjAZMPqIlJUAOyEgVDhk".to_owned()
            ]
            .join("."),
            token
        );
    }

    #[test]
    fn check_expired_token() {
        let key = "secretkey";
        let param = AuthParameter {
            domain: "unused-here".to_string(),
            duration: 4242,
            sub: "service1".to_string(),
        };

        let token = param
            .generate_token_at_moment(key, time::OffsetDateTime::UNIX_EPOCH)
            .unwrap();

        let claims = super::check_token(&token, &param.sub, key);

        assert!(matches!(
            claims
                .unwrap_err()
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .unwrap()
                .kind(),
            jsonwebtoken::errors::ErrorKind::ExpiredSignature
        ));
    }

    #[test]
    fn check_valid_token() {
        let key = "secretkey";
        let param = AuthParameter {
            domain: "unused-here".to_string(),
            duration: 60 * 60 * 24 * 365 * 1000, // valid for ~1000 years should be enough
            sub: "service1".to_string(),
        };

        let token = param
            .generate_token_at_moment(key, time::OffsetDateTime::UNIX_EPOCH)
            .unwrap();

        assert!(super::check_token(&token, &param.sub, key).is_ok());
    }

    #[test]
    fn check_invalid_token() {
        let key = "secretkey";
        let param = AuthParameter {
            domain: "unused-here".to_string(),
            duration: 60 * 60 * 24 * 365 * 1000, // valid for ~1000 years should be enough
            sub: "service1".to_string(),
        };

        let token = param
            .generate_token_at_moment(key, time::OffsetDateTime::UNIX_EPOCH)
            .unwrap();

        assert!(matches!(
            super::check_token(&token, &param.sub, &(key.to_owned() + "invalid"))
                .unwrap_err()
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .unwrap()
                .kind(),
            jsonwebtoken::errors::ErrorKind::InvalidSignature
        ));
    }

    #[test]
    fn invalid_token() {
        assert!(matches!(
            dbg!(super::check_token("", "some-service", "secret"))
                .unwrap_err()
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .unwrap()
                .kind(),
            jsonwebtoken::errors::ErrorKind::InvalidToken
        ));

        assert!(matches!(
            dbg!(super::check_token("a.b.c", "some-service", "secret"))
                .unwrap_err()
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .unwrap()
                .kind(),
            jsonwebtoken::errors::ErrorKind::Base64(..)
        ));
    }
}
