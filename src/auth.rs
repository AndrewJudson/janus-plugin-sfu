use janus_plugin::{janus_info};
use jsonwebtoken::{decode, Algorithm, Validation, dangerous_unsafe_decode};
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedToken {
    pub join_hub: bool,
    pub kick_users: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserClaims {
    join_hub: bool,
    kick_users: bool,
}

impl ValidatedToken {
    pub fn from_str(value: &str, key: &[u8]) -> Result<ValidatedToken, Box<dyn Error>> {
        let validation = Validation::new(Algorithm::RS512);
	janus_info!("Value is {:?}", value);
	janus_info!("Key is: {:?}", std::str::from_utf8(&key).unwrap());
	let unvalidated = dangerous_unsafe_decode::<UserClaims>(value);
	janus_info!("Claims are: {:?}", unvalidated);
        let token_data = decode::<UserClaims>(value, key, &validation)?;
        Ok(ValidatedToken {
            join_hub: token_data.claims.join_hub,
            kick_users: token_data.claims.kick_users,
        })
    }
}
