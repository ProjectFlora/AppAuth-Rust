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
pub(crate) struct JwksCache(Arc<JwksCacheState>);

#[derive(Default)]
struct JwksCacheState {
    value: Mutex<Option<Arc<CachedJwks>>>,
    fetch: tokio::sync::Mutex<()>,
}

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
    fn get(&self) -> Result<Option<Arc<CachedJwks>>> {
        let cached = self
            .0
            .value
            .lock()
            .map_err(|_| AuthError::InvalidJwks("JWKS cache is unavailable"))?;
        Ok(cached
            .as_ref()
            .filter(|cached| cached.expires_at > Instant::now())
            .cloned())
    }

    fn store(&self, jwks: JwkSet, max_age: Duration) -> Result<Arc<CachedJwks>> {
        let value = Arc::new(CachedJwks {
            expires_at: Instant::now() + max_age,
            jwks,
        });
        let mut cached = self
            .0
            .value
            .lock()
            .map_err(|_| AuthError::InvalidJwks("JWKS cache is unavailable"))?;
        *cached = (!max_age.is_zero()).then(|| value.clone());
        Ok(value)
    }
}

#[derive(Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
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
    validate_id_token_with_clock(validation, jwks_cache, transport, cancellation, || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| AuthError::Clock)
    })
    .await
}

// Read the clock after signature verification and any JWKS fetch. Keeping the
// clock injectable lets tests exercise the complete validation path without sleep.
async fn validate_id_token_with_clock(
    validation: IdTokenValidation<'_>,
    jwks_cache: &JwksCache,
    transport: &dyn HttpTransport,
    cancellation: CancellationHandle,
    clock: impl FnOnce() -> Result<u64>,
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

    let keys = load_jwks(
        jwks_uri,
        jwks_cache,
        transport,
        cancellation,
        header.kid.as_deref(),
        algorithm,
    )
    .await?;
    let jwk = find_jwk(&keys.jwks, header.kid.as_deref(), algorithm);
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
    // Validate all time claims below against one clock reading. The JWT library
    // still verifies the signature, algorithm, issuer, audience and required claims.
    validation.validate_exp = false;
    validation.validate_nbf = false;
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

    let now = clock()?;
    if claims.iat > now.saturating_add(CLOCK_SKEW_LEEWAY_SECONDS) {
        return Err(AuthError::InvalidIdToken("issued-at time is in the future"));
    }
    if claims.exp.saturating_add(CLOCK_SKEW_LEEWAY_SECONDS) < now {
        return Err(AuthError::InvalidIdToken("ID Token has expired"));
    }
    if claims
        .nbf
        .is_some_and(|nbf| nbf > now.saturating_add(CLOCK_SKEW_LEEWAY_SECONDS))
    {
        return Err(AuthError::InvalidIdToken("ID Token is not yet valid"));
    }
    Ok(())
}

async fn load_jwks(
    jwks_uri: &Url,
    cache: &JwksCache,
    transport: &dyn HttpTransport,
    cancellation: CancellationHandle,
    kid: Option<&str>,
    algorithm: Algorithm,
) -> Result<Arc<CachedJwks>> {
    if cancellation.is_cancelled() {
        return Err(AuthError::Cancelled);
    }
    let observed = cache.get()?;
    if let Some(keys) = &observed {
        if kid.is_none() || find_jwk(&keys.jwks, kid, algorithm).is_some() {
            return Ok(keys.clone());
        }
    }

    // Serialize retrieval per configuration, then recheck the cache: another
    // operation may already have fetched the set while this operation waited.
    let _fetch = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(AuthError::Cancelled),
        guard = cache.0.fetch.lock() => guard,
    };
    if let Some(current) = cache.get()? {
        if observed
            .as_ref()
            .is_none_or(|old| !Arc::ptr_eq(old, &current))
        {
            return Ok(current);
        }
    }
    let (jwks, max_age) = fetch_jwks(jwks_uri, transport, cancellation).await?;
    cache.store(jwks, max_age)
}

async fn fetch_jwks(
    jwks_uri: &Url,
    transport: &dyn HttpTransport,
    cancellation: CancellationHandle,
) -> Result<(JwkSet, Duration)> {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    let request = HttpRequest {
        method: Method::GET,
        url: jwks_uri.clone(),
        headers,
        body: Vec::new(),
    };
    let response = tokio::select! {
        biased;
        _ = cancellation.cancelled() => return Err(AuthError::Cancelled),
        response = transport.execute(request, cancellation.clone()) => response?,
    };
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
    let mut max_age = None;
    for value in headers.get_all(header::CACHE_CONTROL) {
        let Ok(value) = value.to_str() else {
            return Duration::ZERO;
        };
        for directive in value.split(',').map(str::trim) {
            let (name, value) = directive
                .split_once('=')
                .map_or((directive, None), |(name, value)| {
                    (name.trim(), Some(value.trim()))
                });
            if name.eq_ignore_ascii_case("no-cache") || name.eq_ignore_ascii_case("no-store") {
                return Duration::ZERO;
            }
            if name.eq_ignore_ascii_case("max-age") {
                // Ambiguous or invalid freshness must never extend key trust.
                if max_age.is_some() {
                    return Duration::ZERO;
                }
                let Some(value) = value else {
                    return Duration::ZERO;
                };
                let value = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value);
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Duration::ZERO;
                }
                let Ok(seconds) = value.parse::<u64>() else {
                    return Duration::ZERO;
                };
                max_age = Some(seconds);
            }
        }
    }
    // Do not infer a lifetime from Expires without parsing Date and cache age.
    if max_age.is_none() && headers.contains_key(header::EXPIRES) {
        return Duration::ZERO;
    }
    let mut ages = headers.get_all(header::AGE).iter();
    let age = if let Some(value) = ages.next() {
        if ages.next().is_some() {
            return Duration::ZERO;
        }
        let Some(age) = value
            .to_str()
            .ok()
            .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return Duration::ZERO;
        };
        age
    } else {
        0
    };
    Duration::from_secs(
        max_age
            .unwrap_or(JWKS_CACHE_MAX_AGE.as_secs())
            .saturating_sub(age)
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

    struct ScriptedTransport {
        responses: Mutex<VecDeque<Result<HttpResponse>>>,
        requests: AtomicUsize,
        started: tokio::sync::Notify,
        release: tokio::sync::Semaphore,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<Result<HttpResponse>>, blocked: bool) -> Self {
            let permits = if blocked { 0 } else { responses.len() };
            Self {
                responses: Mutex::new(responses.into()),
                requests: AtomicUsize::new(0),
                started: tokio::sync::Notify::new(),
                release: tokio::sync::Semaphore::new(permits),
            }
        }
    }

    #[async_trait]
    impl HttpTransport for ScriptedTransport {
        async fn execute(&self, _: HttpRequest, _: CancellationHandle) -> Result<HttpResponse> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            // Intentionally ignores cancellation: core must drop a cancelled fetch.
            self.release.acquire().await.unwrap().forget();
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected JWKS fetch")
        }
    }

    fn key_response(keys: &[&TestKey], cache_control: &str) -> HttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_str(cache_control).unwrap(),
        );
        HttpResponse {
            status: StatusCode::OK,
            headers,
            body: serde_json::to_vec(&jwks(keys)).unwrap(),
        }
    }

    fn seed_cache(cache: &JwksCache, key: &TestKey) {
        cache
            .store(
                serde_json::from_value(jwks(&[key])).unwrap(),
                JWKS_CACHE_MAX_AGE,
            )
            .unwrap();
    }

    // Poll once to prove that the second operation is actually waiting while
    // the first retrieval is held. No sleep or scheduler timing assumptions.
    async fn assert_pending<F: std::future::Future>(mut future: std::pin::Pin<&mut F>) {
        std::future::poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
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
        transport: &dyn HttpTransport,
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

    async fn validate_at(
        token: &str,
        cache: &JwksCache,
        transport: &dyn HttpTransport,
        now: u64,
    ) -> Result<()> {
        let (issuer, jwks_uri) = endpoints();
        validate_id_token_with_clock(
            IdTokenValidation {
                token,
                issuer: &issuer,
                jwks_uri: &jwks_uri,
                client_id: "native-client",
                expected_nonce: Some("expected-nonce"),
                require_nonce: true,
            },
            cache,
            transport,
            CancellationHandle::new(),
            || Ok(now),
        )
        .await
    }

    fn claims_at(now: u64) -> Value {
        json!({
            "iss": "https://issuer.example/",
            "sub": "user-123",
            "aud": "native-client",
            "exp": now.saturating_add(300),
            "iat": now,
            "nonce": "expected-nonce",
        })
    }

    #[tokio::test]
    async fn time_claims_allow_exactly_sixty_seconds_of_clock_skew() {
        // Deliberately unrelated to wall time: even expired-in-real-time signed
        // tokens must be evaluated solely against the injected validation clock.
        let now = 1_000_000;
        for key in [TestKey::rs256(), TestKey::es256("time-key")] {
            let cache = JwksCache::default();
            let transport = TestTransport::new([jwks(&[&key])]);
            for (claim, error) in [
                ("exp", "ID Token has expired"),
                ("iat", "issued-at time is in the future"),
                ("nbf", "ID Token is not yet valid"),
            ] {
                for offset in [0, 59, 60, 61] {
                    let mut claims = claims_at(now);
                    claims[claim] = json!(if claim == "exp" {
                        now - offset
                    } else {
                        now + offset
                    });
                    let result = validate_at(&key.sign(claims), &cache, &transport, now).await;
                    if offset <= 60 {
                        assert!(result.is_ok(), "{claim} offset {offset}: {result:?}");
                    } else {
                        assert!(
                            matches!(result, Err(AuthError::InvalidIdToken(message)) if message == error),
                            "{claim} offset {offset}"
                        );
                    }
                }
            }
            assert_eq!(transport.request_count(), 1);
        }
    }

    #[tokio::test]
    async fn time_claims_reject_missing_required_and_malformed_values() {
        let now = 1_000_000;
        let key = TestKey::es256("time-key");
        let cache = JwksCache::default();
        let transport = TestTransport::new([jwks(&[&key])]);
        for claim in ["exp", "iat", "nbf"] {
            for value in [
                json!("1000000"),
                json!(-1),
                json!(1000000.5),
                json!(true),
                json!({}),
                json!([]),
            ] {
                let mut claims = claims_at(now);
                claims[claim] = value;
                assert!(
                    matches!(
                        validate_at(&key.sign(claims), &cache, &transport, now).await,
                        Err(AuthError::InvalidIdToken(_))
                    ),
                    "accepted malformed {claim}"
                );
            }
        }
        for claim in ["exp", "iat"] {
            for null in [false, true] {
                let mut claims = claims_at(now);
                if null {
                    claims[claim] = Value::Null;
                } else {
                    claims.as_object_mut().unwrap().remove(claim);
                }
                assert!(
                    matches!(
                        validate_at(&key.sign(claims), &cache, &transport, now).await,
                        Err(AuthError::InvalidIdToken(_))
                    ),
                    "accepted missing/null {claim}"
                );
            }
        }
        // nbf is optional; serde treats an explicit null like an absent value.
        for null in [false, true] {
            let mut claims = claims_at(now);
            if null {
                claims["nbf"] = Value::Null;
            }
            validate_at(&key.sign(claims), &cache, &transport, now)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn time_claim_arithmetic_does_not_overflow() {
        let key = TestKey::es256("time-key");
        let cache = JwksCache::default();
        let transport = TestTransport::new([jwks(&[&key])]);
        for now in [0, u64::MAX] {
            let mut claims = claims_at(now);
            claims["nbf"] = json!(now);
            validate_at(&key.sign(claims), &cache, &transport, now)
                .await
                .unwrap();
        }
        let mut claims = claims_at(0);
        claims["exp"] = json!(0);
        assert!(matches!(
            validate_at(&key.sign(claims), &cache, &transport, u64::MAX).await,
            Err(AuthError::InvalidIdToken("ID Token has expired"))
        ));
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
    async fn rejects_none_and_hmac_signing_algorithms_before_fetching_keys() {
        let valid_claims = claims("https://issuer.example/", json!("native-client"), None);
        let none_header =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"alg": "none"})).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&valid_claims).unwrap());
        let none_token = format!("{none_header}.{payload}.");
        let hmac_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(Algorithm::HS256),
            &valid_claims,
            &jsonwebtoken::EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap();

        for token in [none_token, hmac_token] {
            let transport = TestTransport::new([]);
            assert!(matches!(
                validate(&token, &JwksCache::default(), &transport, None, false).await,
                Err(AuthError::InvalidIdToken(_))
            ));
            assert_eq!(transport.request_count(), 0);
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
            Err(AuthError::InvalidIdToken("ID Token has expired"))
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
            .saturating_add(CLOCK_SKEW_LEEWAY_SECONDS + 120));
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

    #[tokio::test]
    async fn failed_refresh_preserves_valid_cache_and_allows_later_retry() {
        let old = TestKey::es256("old");
        let new = TestKey::es256("new");
        let old_token = old.sign(claims_at(1_000_000));
        let new_token = new.sign(claims_at(1_000_000));
        let mut malformed = key_response(&[&new], "max-age=300");
        malformed.body = b"not json".to_vec();
        let mut unavailable = key_response(&[&new], "max-age=300");
        unavailable.status = StatusCode::SERVICE_UNAVAILABLE;
        for failure in [
            Err(AuthError::Transport),
            Ok(unavailable),
            Ok(malformed),
            Ok(key_response(&[], "max-age=300")),
        ] {
            let cache = JwksCache::default();
            seed_cache(&cache, &old);
            let transport = ScriptedTransport::new(
                vec![failure, Ok(key_response(&[&new], "max-age=300"))],
                false,
            );
            assert!(matches!(
                validate_at(&new_token, &cache, &transport, 1_000_000).await,
                Err(AuthError::Transport | AuthError::HttpStatus(_) | AuthError::InvalidJwks(_))
            ));
            // The failed refresh neither validates the unknown key nor discards
            // an unexpired trusted key. No stale fallback for the new token.
            validate_at(&old_token, &cache, &transport, 1_000_000)
                .await
                .unwrap();
            assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
            validate_at(&new_token, &cache, &transport, 1_000_000)
                .await
                .unwrap();
            assert_eq!(transport.requests.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn expired_cache_is_not_used_when_retrieval_fails() {
        let key = TestKey::es256("old");
        let cache = JwksCache::default();
        seed_cache(&cache, &key);
        {
            let mut value = cache.0.value.lock().unwrap();
            Arc::get_mut(value.as_mut().unwrap()).unwrap().expires_at =
                Instant::now() - Duration::from_secs(1);
        }
        let transport = ScriptedTransport::new(
            vec![
                Err(AuthError::Transport),
                Ok(key_response(&[&key], "max-age=300")),
            ],
            false,
        );
        let token = key.sign(claims_at(1_000_000));
        assert!(matches!(
            validate_at(&token, &cache, &transport, 1_000_000).await,
            Err(AuthError::Transport)
        ));
        validate_at(&token, &cache, &transport, 1_000_000)
            .await
            .unwrap();
        assert_eq!(transport.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn concurrent_cold_loads_and_rotations_fetch_only_once() {
        let old = TestKey::es256("old");
        let new = TestKey::es256("new");
        let token = new.sign(claims_at(1_000_000));
        // Also cover a refreshed set that still lacks the requested kid: queued
        // validators must not each issue another refresh for the same snapshot.
        for seeded in [false, true] {
            for found in [false, true] {
                let cache = JwksCache::default();
                if seeded {
                    seed_cache(&cache, &old);
                }
                let cloned_cache = cache.clone();
                let transport = ScriptedTransport::new(
                    vec![Ok(key_response(
                        &[if found { &new } else { &old }],
                        "max-age=300",
                    ))],
                    true,
                );
                let first = validate_at(&token, &cache, &transport, 1_000_000);
                tokio::pin!(first);
                tokio::select! {
                    _ = transport.started.notified() => {},
                    result = &mut first => panic!("fetch should block: {result:?}"),
                }
                let second = validate_at(&token, &cloned_cache, &transport, 1_000_000);
                tokio::pin!(second);
                assert_pending(second.as_mut()).await;
                assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
                transport.release.add_permits(1);
                let (first, second) = tokio::join!(first, second);
                for result in [first, second] {
                    if found {
                        result.unwrap();
                    } else {
                        assert!(matches!(
                            result,
                            Err(AuthError::InvalidIdToken(
                                "no matching trusted signing key was found"
                            ))
                        ));
                    }
                }
                assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
                // New set remains cached, so an older in-flight load cannot
                // overwrite it after publication.
                assert!(find_jwk(
                    &cache.get().unwrap().unwrap().jwks,
                    Some(if found { "new" } else { "old" }),
                    Algorithm::ES256
                )
                .is_some());
            }
        }
    }

    #[tokio::test]
    async fn cancelling_a_waiter_does_not_cancel_the_active_fetch() {
        let key = TestKey::es256("key");
        let cache = JwksCache::default();
        let transport =
            ScriptedTransport::new(vec![Ok(key_response(&[&key], "max-age=300"))], true);
        let (_, uri) = endpoints();
        let first = load_jwks(
            &uri,
            &cache,
            &transport,
            CancellationHandle::new(),
            Some("key"),
            Algorithm::ES256,
        );
        tokio::pin!(first);
        tokio::select! {
            _ = transport.started.notified() => {},
            result = &mut first => panic!("fetch should block: {:?}", result.err()),
        }
        let cancellation = CancellationHandle::new();
        let second = load_jwks(
            &uri,
            &cache,
            &transport,
            cancellation.clone(),
            Some("key"),
            Algorithm::ES256,
        );
        tokio::pin!(second);
        assert_pending(second.as_mut()).await;
        cancellation.cancel();
        assert!(matches!(second.await, Err(AuthError::Cancelled)));
        assert_eq!(transport.requests.load(Ordering::SeqCst), 1);
        transport.release.add_permits(1);
        first.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_fetch_releases_the_lock_for_another_operation() {
        let key = TestKey::es256("key");
        let cache = JwksCache::default();
        let transport =
            ScriptedTransport::new(vec![Ok(key_response(&[&key], "max-age=300"))], true);
        let (_, uri) = endpoints();
        let cancellation = CancellationHandle::new();
        let first = load_jwks(
            &uri,
            &cache,
            &transport,
            cancellation.clone(),
            Some("key"),
            Algorithm::ES256,
        );
        tokio::pin!(first);
        tokio::select! {
            _ = transport.started.notified() => {},
            result = &mut first => panic!("fetch should block: {:?}", result.err()),
        }
        cancellation.cancel();
        assert!(matches!(first.await, Err(AuthError::Cancelled)));
        assert!(cache.get().unwrap().is_none());
        transport.release.add_permits(1);
        load_jwks(
            &uri,
            &cache,
            &transport,
            CancellationHandle::new(),
            Some("key"),
            Algorithm::ES256,
        )
        .await
        .unwrap();
        assert_eq!(transport.requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn already_cancelled_operation_does_not_use_cached_keys_or_fetch() {
        let key = TestKey::es256("key");
        let cache = JwksCache::default();
        seed_cache(&cache, &key);
        let transport = ScriptedTransport::new(vec![], false);
        let (_, uri) = endpoints();
        let cancellation = CancellationHandle::new();
        cancellation.cancel();
        assert!(matches!(
            load_jwks(
                &uri,
                &cache,
                &transport,
                cancellation,
                Some("key"),
                Algorithm::ES256
            )
            .await,
            Err(AuthError::Cancelled)
        ));
        assert_eq!(transport.requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn noncacheable_keys_are_refetched_for_each_validation() {
        let key = TestKey::es256("key");
        let token = key.sign(claims_at(1_000_000));
        for directive in ["no-store", "no-cache", "max-age=0", "max-age=invalid"] {
            let cache = JwksCache::default();
            let transport = ScriptedTransport::new(
                vec![
                    Ok(key_response(&[&key], directive)),
                    Ok(key_response(&[&key], directive)),
                ],
                false,
            );
            for _ in 0..2 {
                validate_at(&token, &cache, &transport, 1_000_000)
                    .await
                    .unwrap();
                assert!(cache.get().unwrap().is_none());
            }
            assert_eq!(transport.requests.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn jwks_cache_directives_cannot_extend_trust_ambiguously() {
        for (directives, expected) in [
            (vec![], 300),
            (vec!["public"], 300),
            (vec!["MAX-AGE = \"30\""], 30),
            (vec!["max-age=18446744073709551615"], 300),
            (vec!["max-age=0"], 0),
            (vec!["max-age"], 0),
            (vec!["max-age=-1"], 0),
            (vec!["max-age=+1"], 0),
            (vec!["max-age=1.5"], 0),
            (vec!["max-age="], 0),
            (vec!["max-age=18446744073709551616"], 0),
            (vec!["max-age=\"30"], 0),
            (vec!["max-age=30,max-age=300"], 0),
            (vec!["max-age=30", "max-age=300"], 0),
            (vec!["max-age=300", "NO-STORE"], 0),
            (vec!["max-age=300", "no-cache=\"keys\""], 0),
        ] {
            let mut headers = HeaderMap::new();
            for directive in &directives {
                headers.append(
                    header::CACHE_CONTROL,
                    HeaderValue::from_str(directive).unwrap(),
                );
            }
            assert_eq!(
                jwks_cache_max_age(&headers),
                Duration::from_secs(expected),
                "{directives:?}"
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        assert_eq!(jwks_cache_max_age(&headers), Duration::ZERO);
    }

    #[test]
    fn jwks_cache_accounts_for_age_and_unsupported_expires() {
        for (age, expected) in [
            ("10", 20),
            ("30", 0),
            ("1000", 0),
            ("18446744073709551615", 0),
            ("invalid", 0),
            ("-1", 0),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("max-age=30"),
            );
            headers.insert(header::AGE, HeaderValue::from_str(age).unwrap());
            assert_eq!(jwks_cache_max_age(&headers), Duration::from_secs(expected));
        }
        let mut headers = HeaderMap::new();
        headers.append(header::AGE, HeaderValue::from_static("1"));
        headers.append(header::AGE, HeaderValue::from_static("2"));
        assert_eq!(jwks_cache_max_age(&headers), Duration::ZERO);
        headers.clear();
        headers.insert(
            header::EXPIRES,
            HeaderValue::from_static("Wed, 01 Jan 2031 00:00:00 GMT"),
        );
        assert_eq!(jwks_cache_max_age(&headers), Duration::ZERO);
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
