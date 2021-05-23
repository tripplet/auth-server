use std::error::Error;

use time::Duration;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

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

/// Check an authorization token
pub fn check_token(token: &str, sub: &str, key: &str) -> Result<Claims, Box<dyn Error>> {
    let jwt_validation = Validation {
        algorithms: vec![Algorithm::HS256],
        validate_exp: true,
        sub: Some(sub.to_string()),
        ..Validation::default()
    };

    Ok(decode::<Claims>(
        &token,
        &DecodingKey::from_secret(key.as_ref()),
        &jwt_validation,
    )?
    .claims)
}

/// Generate an autthorization token
pub fn generate_token(
    param: &AuthParameter,
    key: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        sub: param.sub.clone().into(),
        exp: (time::OffsetDateTime::now_utc() + Duration::seconds(param.duration as i64)).unix_timestamp(),
    };

    Ok(encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(key.as_ref()),
    )?)
}