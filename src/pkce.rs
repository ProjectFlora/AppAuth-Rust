use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{AuthError, Result};

pub(crate) struct PkcePair {
    verifier: String,
    challenge: String,
}

impl PkcePair {
    pub(crate) fn generate() -> Result<Self> {
        let verifier = random_token()?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        Ok(Self {
            verifier,
            challenge,
        })
    }

    pub(crate) fn verifier(&self) -> &str {
        &self.verifier
    }

    pub(crate) fn challenge(&self) -> &str {
        &self.challenge
    }
}

pub(crate) fn random_token() -> Result<String> {
    let mut bytes = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| AuthError::Randomness)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_has_rfc7636_minimum_length_and_s256_challenge() {
        let pair = PkcePair::generate().unwrap();
        let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(pair.verifier().as_bytes()));

        assert_eq!(pair.verifier().len(), 43);
        assert_eq!(pair.challenge(), expected);
        assert!(pair
            .verifier()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)));
    }
}
