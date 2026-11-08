use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::{header, HeaderMap, HeaderValue, Method};
use jsonwebtoken::{
    decode, decode_header,
    jwk::{
        AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse,
    },
    Algorithm, DecodingKey, Validation,
};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::{AuthError, CancellationHandle, HttpRequest, HttpTransport, Result};

const JWKS_CACHE_MAX_AGE: Duration = Duration::from_secs(300);
const CLOCK_SKEW_LEEWAY_SECONDS: u64 = 60;

#[derive(Clone, Default)]
pub(crate) struct JwksCache(Arc<Mutex<Option<CachedJwks>>>);

pub(crate) struct IdTokenValidation<'a> {
    pub(crate) token: &'a str,
    pub(crate) issuer: &'a Url,
    pub(crate) jwks_uri: &'a Url,
    pub(crate) client_id: &'a str,
    pub(crate) expected_nonce: Option<&'a str>,
    pub(crate) require_nonce: bool,
}

struct CachedJwks {
    expires_at: Instant,
    jwks: JwkSet,
}

impl JwksCache {
    fn get(&self) -> Result<Option<JwkSet>> {
        let cached = self
            .0
            .lock()
            .map_err(|_| AuthError::InvalidJwks("JWKS cache is unavailable"))?;
        Ok(cached
            .as_ref()
            .filter(|cached| cached.expires_at > Instant::now())
            .map(|cached| cached.jwks.clone()))
    }

    fn store(&self, jwks: JwkSet, max_age: Duration) -> Result<()> {
        let mut cached = self
            .0
            .lock()
            .map_err(|_| AuthError::InvalidJwks("JWKS cache is unavailable"))?;
        *cached = if max_age.is_zero() {
            None
        } else {
            Some(CachedJwks {
                expires_at: Instant::now() + max_age,
                jwks,
            })
        };
        Ok(())
    }
}

#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    nonce: Option<String>,
    azp: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    fn contains(&self, value: &str) -> bool {
        match self {
            Self::Single(audience) => audience == value,
            Self::Multiple(audiences) => audiences.iter().any(|audience| audience == value),
        }
    }

    fn is_multiple(&self) -> bool {
        matches!(self, Self::Multiple(audiences) if audiences.len() > 1)
    }
}

pub(crate) async fn validate_id_token(
    validation: IdTokenValidation<'_>,
    jwks_cache: &JwksCache,
    transport: &dyn HttpTransport,
    cancellation: CancellationHandle,
) -> Result<()> {
    let IdTokenValidation {
        token,
        issuer,
        jwks_uri,
        client_id,
        expected_nonce,
        require_nonce,
    } = validation;
    let header = decode_header(token)
        .map_err(|_| AuthError::InvalidIdToken("JWT header is malformed or unsupported"))?;
    if header.jku.is_some() || header.jwk.is_some() {
        return Err(AuthError::InvalidIdToken(
            "JWT must not supply its own verification key",
        ));
    }
    let encoded_header = token
        .split('.')
        .next()
        .ok_or(AuthError::InvalidIdToken("JWT header is malformed"))?;
    let header_json = URL_SAFE_NO_PAD
        .decode(encoded_header)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .ok_or(AuthError::InvalidIdToken("JWT header is malformed"))?;
    if header_json.get("crit").is_some() {
        return Err(AuthError::InvalidIdToken(
            "JWT uses unsupported critical header parameters",
        ));
    }

    let algorithm = match header.alg {
        Algorithm::RS256 | Algorithm::ES256 => header.alg,
        _ => {
            return Err(AuthError::InvalidIdToken(
                "JWT signing algorithm is not allowed",
            ))
        }
    };

    let (mut jwks, was_cached) =
        load_jwks(jwks_uri, jwks_cache, transport, cancellation.clone()).await?;
    let mut jwk = find_jwk(&jwks, header.kid.as_deref(), algorithm);
    if jwk.is_none() && was_cached && header.kid.is_some() {
        let (fresh_jwks, max_age) = fetch_jwks(jwks_uri, transport, cancellation).await?;
        jwks_cache.store(fresh_jwks.clone(), max_age)?;
        jwks = fresh_jwks;
        jwk = find_jwk(&jwks, header.kid.as_deref(), algorithm);
    }
    let jwk = jwk.ok_or(AuthError::InvalidIdToken(
        "no matching trusted signing key was found",
    ))?;
    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|_| AuthError::InvalidJwks("signing key is malformed or unsupported"))?;

    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[issuer.as_str()]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["iss", "aud", "exp", "sub"]);
    validation.algorithms = vec![algorithm];
    validation.validate_nbf = true;
    validation.leeway = CLOCK_SKEW_LEEWAY_SECONDS;
    let claims = decode::<IdTokenClaims>(token, &decoding_key, &validation)
        .map_err(|_| AuthError::InvalidIdToken("signature or required claims are invalid"))?
        .claims;

    if claims.iss != issuer.as_str() || !claims.aud.contains(client_id) {
        return Err(AuthError::InvalidIdToken(
            "issuer or audience does not match the request",
        ));
    }
    if claims.sub.trim().is_empty() {
        return Err(AuthError::InvalidIdToken("subject must not be empty"));
    }
    if claims.aud.is_multiple() && claims.azp.as_deref() != Some(client_id) {
        return Err(AuthError::InvalidIdToken(
            "authorized party is missing or does not match the client",
        ));
    }
    if claims
        .azp
        .as_deref()
        .is_some_and(|authorized_party| authorized_party != client_id)
    {
        return Err(AuthError::InvalidIdToken(
            "authorized party does not match the client",
        ));
    }
    if let Some(expected_nonce) = expected_nonce {
        if claims
            .nonce
            .as_deref()
            .is_some_and(|nonce| nonce != expected_nonce)
            || (require_nonce && claims.nonce.is_none())
        {
            return Err(AuthError::InvalidIdToken(
                "nonce does not match the request",
            ));
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AuthError::Clock)?
        .as_secs();
    if claims.iat > now.saturating_add(CLOCK_SKEW_LEEWAY_SECONDS) {
        return Err(AuthError::InvalidIdToken("issued-at time is in the future"));
    }
    if claims.exp.saturating_add(CLOCK_SKEW_LEEWAY_SECONDS) < now {
        return Err(AuthError::InvalidIdToken("ID Token has expired"));
    }
    Ok(())
}

async fn load_jwks(
    jwks_uri: &Url,
    cache: &JwksCache,
    transport: &dyn HttpTransport,
    cancellation: CancellationHandle,
) -> Result<(JwkSet, bool)> {
    if let Some(jwks) = cache.get()? {
        return Ok((jwks, true));
    }
    let (jwks, max_age) = fetch_jwks(jwks_uri, transport, cancellation).await?;
    cache.store(jwks.clone(), max_age)?;
    Ok((jwks, false))
}

async fn fetch_jwks(
    jwks_uri: &Url,
    transport: &dyn HttpTransport,
    cancellation: CancellationHandle,
) -> Result<(JwkSet, Duration)> {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    let response = transport
        .execute(
            HttpRequest {
                method: Method::GET,
                url: jwks_uri.clone(),
                headers,
                body: Vec::new(),
            },
            cancellation,
        )
        .await?;
    if !response.status.is_success() {
        return Err(AuthError::HttpStatus(response.status));
    }
    let jwks: JwkSet = serde_json::from_slice(&response.body)
        .map_err(|_| AuthError::InvalidJwks("response is not a valid JWKS"))?;
    if jwks.keys.is_empty() {
        return Err(AuthError::InvalidJwks("JWKS contains no keys"));
    }
    let max_age = jwks_cache_max_age(&response.headers);
    Ok((jwks, max_age))
}

fn jwks_cache_max_age(headers: &HeaderMap) -> Duration {
    let Some(cache_control) = headers
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok())
    else {
        return JWKS_CACHE_MAX_AGE;
    };

    let mut max_age = None;
    for directive in cache_control.split(',').map(str::trim) {
        if directive.eq_ignore_ascii_case("no-cache") || directive.eq_ignore_ascii_case("no-store")
        {
            return Duration::ZERO;
        }
        if let Some((name, value)) = directive.split_once('=') {
            if name.trim().eq_ignore_ascii_case("max-age") {
                max_age = value.trim().trim_matches('"').parse::<u64>().ok();
            }
        }
    }
    Duration::from_secs(
        max_age
            .unwrap_or(JWKS_CACHE_MAX_AGE.as_secs())
            .min(JWKS_CACHE_MAX_AGE.as_secs()),
    )
}

fn find_jwk<'a>(jwks: &'a JwkSet, kid: Option<&str>, algorithm: Algorithm) -> Option<&'a Jwk> {
    let mut matches = jwks.keys.iter().filter(|jwk| {
        kid.is_none_or(|kid| jwk.common.key_id.as_deref() == Some(kid))
            && jwk
                .common
                .public_key_use
                .as_ref()
                .is_none_or(|key_use| matches!(key_use, PublicKeyUse::Signature))
            && jwk
                .common
                .key_operations
                .as_ref()
                .is_none_or(|operations| operations.contains(&KeyOperations::Verify))
            && jwk
                .common
                .key_algorithm
                .as_ref()
                .is_none_or(|key_algorithm| {
                    matches!(
                        (algorithm, key_algorithm),
                        (Algorithm::RS256, KeyAlgorithm::RS256)
                            | (Algorithm::ES256, KeyAlgorithm::ES256)
                    )
                })
            && matches!(
                (algorithm, &jwk.algorithm),
                (Algorithm::RS256, AlgorithmParameters::RSA(_))
                    | (
                        Algorithm::ES256,
                        AlgorithmParameters::EllipticCurve(
                            jsonwebtoken::jwk::EllipticCurveKeyParameters {
                                curve: EllipticCurve::P256,
                                ..
                            }
                        )
                    )
            )
    });
    let jwk = matches.next()?;
    matches.next().is_none().then_some(jwk)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use http::StatusCode;
    use ring::{
        rand::SystemRandom,
        signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
    };
    use rsa::{
        pkcs1v15::SigningKey,
        signature::{SignatureEncoding, Signer},
        traits::PublicKeyParts,
        RsaPrivateKey,
    };
    use serde_json::json;
    use sha2::Sha256;

    use super::*;
    use crate::HttpResponse;

    enum TestSigningKey {
        Rsa(RsaPrivateKey),
        Ec(EcdsaKeyPair),
    }

    struct TestKey {
        kid: &'static str,
        algorithm: &'static str,
        jwk: Value,
        signing_key: TestSigningKey,
    }

    impl TestKey {
        fn rs256() -> Self {
            let private_key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
            let jwk = json!({
                "kty": "RSA",
                "kid": "test-key",
                "use": "sig",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(private_key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(private_key.e().to_bytes_be()),
            });
            Self {
                kid: "test-key",
                algorithm: "RS256",
                jwk,
                signing_key: TestSigningKey::Rsa(private_key),
            }
        }

        fn es256(kid: &'static str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let signing_key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let public_key = signing_key.public_key().as_ref();
            let jwk = json!({
                "kty": "EC",
                "kid": kid,
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(&public_key[1..33]),
                "y": URL_SAFE_NO_PAD.encode(&public_key[33..65]),
            });
            Self {
                kid,
                algorithm: "ES256",
                jwk,
                signing_key: TestSigningKey::Ec(signing_key),
            }
        }

        fn sign(&self, claims: Value) -> String {
            let protected = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({"alg": self.algorithm, "kid": self.kid})).unwrap(),
            );
            let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
            let message = format!("{protected}.{payload}");
            let signature = match &self.signing_key {
                TestSigningKey::Rsa(private_key) => SigningKey::<Sha256>::new(private_key.clone())
                    .sign(message.as_bytes())
                    .to_vec(),
                TestSigningKey::Ec(private_key) => private_key
                    .sign(&SystemRandom::new(), message.as_bytes())
                    .unwrap()
                    .as_ref()
                    .to_vec(),
            };
            format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature))
        }
    }

    struct TestTransport {
        jwks_responses: Mutex<VecDeque<Value>>,
        requests: AtomicUsize,
    }

    impl TestTransport {
        fn new(jwks_responses: impl IntoIterator<Item = Value>) -> Self {
            Self {
                jwks_responses: Mutex::new(jwks_responses.into_iter().collect()),
                requests: AtomicUsize::new(0),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl HttpTransport for TestTransport {
        async fn execute(
            &self,
            _request: HttpRequest,
            _cancellation: CancellationHandle,
        ) -> Result<crate::HttpResponse> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            let jwks = self
                .jwks_responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(AuthError::Transport)?;
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("max-age=300"),
            );
            Ok(HttpResponse {
                status: StatusCode::OK,
                headers,
                body: serde_json::to_vec(&jwks).unwrap(),
            })
        }
    }

    fn claims(issuer: &str, audience: Value, nonce: Option<&str>) -> Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut claims = json!({
            "iss": issuer,
            "sub": "user-123",
            "aud": audience,
            "exp": now + 300,
            "iat": now,
        });
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }
        claims
    }

    fn jwks(keys: &[&TestKey]) -> Value {
        json!({"keys": keys.iter().map(|key| key.jwk.clone()).collect::<Vec<_>>()})
    }

    fn endpoints() -> (Url, Url) {
        (
            Url::parse("https://issuer.example").unwrap(),
            Url::parse("https://issuer.example/keys").unwrap(),
        )
    }

    async fn validate(
        token: &str,
        jwks_cache: &JwksCache,
        transport: &TestTransport,
        expected_nonce: Option<&str>,
        require_nonce: bool,
    ) -> Result<()> {
        let (issuer, jwks_uri) = endpoints();
        validate_id_token(
            IdTokenValidation {
                token,
                issuer: &issuer,
                jwks_uri: &jwks_uri,
                client_id: "native-client",
                expected_nonce,
                require_nonce,
            },
            jwks_cache,
            transport,
            CancellationHandle::new(),
        )
        .await
    }

    #[tokio::test]
    async fn validates_rs256_and_es256_signatures_and_claims() {
        for key in [TestKey::rs256(), TestKey::es256("test-key")] {
            let token = key.sign(claims(
                "https://issuer.example/",
                json!("native-client"),
                Some("expected-nonce"),
            ));
            let transport = TestTransport::new([jwks(&[&key])]);

            validate(
                &token,
                &JwksCache::default(),
                &transport,
                Some("expected-nonce"),
                true,
            )
            .await
            .unwrap();
            assert_eq!(transport.request_count(), 1);
        }
    }

    #[tokio::test]
    async fn rejects_invalid_claims_and_signatures() {
        let key = TestKey::rs256();
        let jwks_cache = JwksCache::default();
        let transport = TestTransport::new([jwks(&[&key])]);
        let valid_claims = claims(
            "https://issuer.example/",
            json!("native-client"),
            Some("expected-nonce"),
        );

        let wrong_nonce = key.sign(valid_claims.clone());
        assert!(matches!(
            validate(
                &wrong_nonce,
                &jwks_cache,
                &transport,
                Some("different-nonce"),
                true
            )
            .await,
            Err(AuthError::InvalidIdToken(
                "nonce does not match the request"
            ))
        ));

        let missing_nonce = key.sign(claims(
            "https://issuer.example/",
            json!("native-client"),
            None,
        ));
        assert!(matches!(
            validate(
                &missing_nonce,
                &jwks_cache,
                &transport,
                Some("expected-nonce"),
                true
            )
            .await,
            Err(AuthError::InvalidIdToken(
                "nonce does not match the request"
            ))
        ));

        let wrong_audience = key.sign(claims(
            "https://issuer.example/",
            json!("another-client"),
            Some("expected-nonce"),
        ));
        assert!(matches!(
            validate(
                &wrong_audience,
                &jwks_cache,
                &transport,
                Some("expected-nonce"),
                true
            )
            .await,
            Err(AuthError::InvalidIdToken(
                "signature or required claims are invalid"
            ))
        ));

        let wrong_issuer = key.sign(claims(
            "https://other.example/",
            json!("native-client"),
            Some("expected-nonce"),
        ));
        assert!(matches!(
            validate(
                &wrong_issuer,
                &jwks_cache,
                &transport,
                Some("expected-nonce"),
                true
            )
            .await,
            Err(AuthError::InvalidIdToken(
                "signature or required claims are invalid"
            ))
        ));

        let mut expired_claims = claims(
            "https://issuer.example/",
            json!("native-client"),
            Some("expected-nonce"),
        );
        expired_claims["exp"] = json!(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(120));
        let expired = key.sign(expired_claims);
        assert!(matches!(
            validate(
                &expired,
                &jwks_cache,
                &transport,
                Some("expected-nonce"),
                true
            )
            .await,
            Err(AuthError::InvalidIdToken(
                "signature or required claims are invalid"
            ))
        ));

        let mut future_issued_claims = claims(
            "https://issuer.example/",
            json!("native-client"),
            Some("expected-nonce"),
        );
        future_issued_claims["iat"] = json!(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_add(CLOCK_SKEW_LEEWAY_SECONDS + 1));
        let future_issued = key.sign(future_issued_claims);
        assert!(matches!(
            validate(
                &future_issued,
                &jwks_cache,
                &transport,
                Some("expected-nonce"),
                true
            )
            .await,
            Err(AuthError::InvalidIdToken("issued-at time is in the future"))
        ));

        let valid = key.sign(valid_claims);
        let mut altered_signature = valid.clone();
        let last = altered_signature.pop().unwrap();
        altered_signature.push(if last == 'a' { 'b' } else { 'a' });
        assert!(matches!(
            validate(
                &altered_signature,
                &jwks_cache,
                &transport,
                Some("expected-nonce"),
                true
            )
            .await,
            Err(AuthError::InvalidIdToken(
                "signature or required claims are invalid"
            ))
        ));
    }

    #[tokio::test]
    async fn refreshes_cached_jwks_for_an_unknown_key_id() {
        let old_key = TestKey::es256("old-key");
        let new_key = TestKey::es256("new-key");
        let cache = JwksCache::default();
        let transport = TestTransport::new([jwks(&[&old_key]), jwks(&[&new_key])]);

        let old_token = old_key.sign(claims(
            "https://issuer.example/",
            json!("native-client"),
            None,
        ));
        validate(&old_token, &cache, &transport, None, false)
            .await
            .unwrap();
        assert_eq!(transport.request_count(), 1);

        let new_token = new_key.sign(claims(
            "https://issuer.example/",
            json!("native-client"),
            None,
        ));
        validate(&new_token, &cache, &transport, None, false)
            .await
            .unwrap();
        assert_eq!(transport.request_count(), 2);

        validate(&new_token, &cache, &transport, None, false)
            .await
            .unwrap();
        assert_eq!(transport.request_count(), 2);
    }

    #[tokio::test]
    async fn requires_authorized_party_for_multiple_audiences() {
        let key = TestKey::es256("test-key");
        let transport = TestTransport::new([jwks(&[&key])]);
        let cache = JwksCache::default();
        let mut token_claims = claims(
            "https://issuer.example/",
            json!(["native-client", "another-client"]),
            None,
        );

        let missing_authorized_party = key.sign(token_claims.clone());
        assert!(matches!(
            validate(&missing_authorized_party, &cache, &transport, None, false).await,
            Err(AuthError::InvalidIdToken(
                "authorized party is missing or does not match the client"
            ))
        ));

        token_claims["azp"] = json!("native-client");
        let correct_authorized_party = key.sign(token_claims);
        validate(&correct_authorized_party, &cache, &transport, None, false)
            .await
            .unwrap();
    }

    #[test]
    fn honors_jwks_cache_control_and_caps_cache_lifetime() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=30"),
        );
        assert_eq!(jwks_cache_max_age(&headers), Duration::from_secs(30));

        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=3600"),
        );
        assert_eq!(jwks_cache_max_age(&headers), JWKS_CACHE_MAX_AGE);

        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        assert_eq!(jwks_cache_max_age(&headers), Duration::ZERO);
    }
}
