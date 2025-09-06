use std::error::Error;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Parameter {
    pub domain: String,
    pub duration: u64,
    pub sub: String,
}

impl Parameter {
    /// Generate an authorization token
    pub fn generate_token(&self, key: &str) -> Result<String, jsonwebtoken::errors::Error> {
        self.generate_token_at_moment(key, time::OffsetDateTime::now_utc())
    }

    fn generate_token_at_moment(
        &self,
        key: &str,
        moment: time::OffsetDateTime,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let claims = Claims {
            sub: self.sub.clone(),
            exp: (moment + seconds_saturating(self.duration)).unix_timestamp(),
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

pub fn seconds_saturating(duration: u64) -> Duration {
    Duration::seconds(i64::try_from(duration).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose};

    #[test]
    fn generate_token_now() {
        let key = "secretkey";
        let param = Parameter {
            domain: "unused-here".to_string(),
            duration: 4242,
            sub: "service1".to_string(),
        };

        let token = param.generate_token(key).unwrap();
        let parts: Vec<_> = token.split('.').collect();

        assert_eq!(parts.len(), 3);

        assert_eq!(
            general_purpose::STANDARD_NO_PAD.encode(r#"{"typ":"JWT","alg":"HS256"}"#),
            parts[0]
        );

        let part1: serde_json::Value =
            serde_json::from_slice(&general_purpose::STANDARD_NO_PAD.decode(parts[1]).unwrap())
                .unwrap();

        assert_eq!(
            part1
                .as_object()
                .unwrap()
                .get("sub")
                .unwrap()
                .as_str()
                .unwrap(),
            param.sub
        );

        let exp = part1
            .as_object()
            .unwrap()
            .get("exp")
            .unwrap()
            .as_i64()
            .unwrap();
        let exp_truth =
            (time::OffsetDateTime::now_utc() + seconds_saturating(param.duration)).unix_timestamp();

        assert!((exp_truth..exp_truth + 10).contains(&exp));
    }

    #[test]
    fn generate_token() {
        let key = "secretkey";
        let param = Parameter {
            domain: "unused-here".to_string(),
            duration: 4242,
            sub: "service1".to_string(),
        };

        let token = param
            .generate_token_at_moment(key, time::OffsetDateTime::UNIX_EPOCH)
            .unwrap();

        assert_eq!(
            [
                general_purpose::STANDARD_NO_PAD.encode(r#"{"typ":"JWT","alg":"HS256"}"#),
                general_purpose::STANDARD_NO_PAD
                    .encode(format!(
                        r#"{{"sub":"{}","exp":{}}}"#,
                        param.sub, param.duration
                    ))
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
        let param = Parameter {
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
        let param = Parameter {
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
        let param = Parameter {
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
            super::check_token("", "some-service", "secret")
                .unwrap_err()
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .unwrap()
                .kind(),
            jsonwebtoken::errors::ErrorKind::InvalidToken
        ));

        assert!(matches!(
            super::check_token("a.b.c", "some-service", "secret")
                .unwrap_err()
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .unwrap()
                .kind(),
            jsonwebtoken::errors::ErrorKind::Base64(..)
        ));
    }

    #[test]
    fn changed_sub_should_be_invalid() {
        let key = "secretkey";
        let param = Parameter {
            domain: "unused-here".to_string(),
            duration: 60 * 60 * 24 * 365 * 1000, // valid for ~1000 years should be enough
            sub: "service1".to_string(),
        };

        let token = param
            .generate_token_at_moment(key, time::OffsetDateTime::UNIX_EPOCH)
            .unwrap();

        assert!(matches!(
            super::check_token(&token, "invalid-other-service", key)
                .unwrap_err()
                .downcast_ref::<jsonwebtoken::errors::Error>()
                .unwrap()
                .kind(),
            jsonwebtoken::errors::ErrorKind::InvalidSubject
        ));
    }

    #[test]
    fn missing_sub_should_be_invalid() {
        #[derive(Debug, Serialize, Deserialize)]
        struct TestClaims {
            exp: usize,
        }

        let key = "secretkey";
        let claims = TestClaims {
            exp: 60 * 60 * 24 * 365 * 1000,
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(key.as_ref()),
        )
        .unwrap();

        let err = super::check_token(&token, "valid-service", key).unwrap_err();
        let err_kind = err
            .downcast_ref::<jsonwebtoken::errors::Error>()
            .unwrap()
            .kind();

        assert!(matches!(
            err_kind, jsonwebtoken::errors::ErrorKind::Json(serde_err)
                if serde_err.to_string().contains("missing field `sub`")
        ));
    }
}
