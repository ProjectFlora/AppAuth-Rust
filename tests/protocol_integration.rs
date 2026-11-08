use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use appauth_rust::{
    AuthError, AuthenticationState, AuthorizationRequest, CancellationHandle,
    ClientRegistrationRequest, EndSessionRequest, HttpRequest, HttpResponse, HttpTransport,
    ServiceConfiguration,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http::{HeaderMap, Method, StatusCode};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde_json::{json, Value};
use tokio::sync::oneshot;
use url::Url;

struct RecordedRequest {
    method: Method,
    url: Url,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Default)]
struct ScriptedTransport {
    responses: Mutex<VecDeque<HttpResponse>>,
    requests: Mutex<Vec<RecordedRequest>>,
}

impl ScriptedTransport {
    fn push_json(&self, status: StatusCode, body: Value) {
        self.responses.lock().unwrap().push_back(HttpResponse {
            status,
            headers: HeaderMap::new(),
            body: serde_json::to_vec(&body).unwrap(),
        });
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}

#[async_trait]
impl HttpTransport for ScriptedTransport {
    async fn execute(
        &self,
        request: HttpRequest,
        _cancellation: CancellationHandle,
    ) -> appauth_rust::Result<HttpResponse> {
        self.requests.lock().unwrap().push(RecordedRequest {
            method: request.method,
            url: request.url,
            headers: request.headers,
            body: request.body,
        });
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(AuthError::Transport)
    }
}

struct Es256TestKey {
    key_pair: EcdsaKeyPair,
}

impl Es256TestKey {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        Self { key_pair }
    }

    fn jwk(&self) -> Value {
        let public_key = self.key_pair.public_key().as_ref();
        json!({
            "kty": "EC",
            "kid": "integration-key",
            "use": "sig",
            "alg": "ES256",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&public_key[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&public_key[33..65]),
        })
    }

    fn sign_id_token(&self, issuer: &str, client_id: &str, nonce: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"alg": "ES256", "kid": "integration-key"})).unwrap(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({
                "iss": issuer,
                "sub": "integration-user",
                "aud": client_id,
                "exp": now + 300,
                "iat": now,
                "nonce": nonce,
            }))
            .unwrap(),
        );
        let message = format!("{header}.{claims}");
        let signature = self
            .key_pair
            .sign(&SystemRandom::new(), message.as_bytes())
            .unwrap();
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
}

fn response_parameters(url: &Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

#[tokio::test]
async fn discovery_authorization_oidc_and_refresh_form_one_public_api_flow() {
    let issuer = Url::parse("https://issuer.example/tenant").unwrap();
    let client_id = "integration-client";
    let redirect_uri = Url::parse("com.example.app:/oauth/callback").unwrap();
    let key = Es256TestKey::new();
    let transport = ScriptedTransport::default();
    transport.push_json(
        StatusCode::OK,
        json!({
            "issuer": issuer.as_str(),
            "authorization_endpoint": "https://issuer.example/tenant/authorize",
            "token_endpoint": "https://issuer.example/tenant/token",
            "jwks_uri": "https://issuer.example/tenant/keys",
        }),
    );

    let configuration =
        ServiceConfiguration::discover(issuer.clone(), &transport, CancellationHandle::new())
            .await
            .unwrap();
    let session = AuthorizationRequest::new(
        configuration.clone(),
        client_id,
        redirect_uri.clone(),
        vec!["openid".to_owned(), "profile".to_owned()],
    )
    .unwrap()
    .begin()
    .unwrap();
    let authorization_parameters = response_parameters(session.authorization_url());
    let state = authorization_parameters
        .iter()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .clone();
    let nonce = session.nonce().unwrap().to_owned();
    assert!(authorization_parameters
        .iter()
        .any(|(name, value)| name == "code_challenge_method" && value == "S256"));

    let id_token = key.sign_id_token(issuer.as_str(), client_id, &nonce);
    transport.push_json(
        StatusCode::OK,
        json!({
            "access_token": "initial-access",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "initial-refresh",
            "scope": "openid profile",
            "id_token": id_token,
            "provider_extension": {"enabled": true},
        }),
    );
    transport.push_json(StatusCode::OK, json!({"keys": [key.jwk()]}));

    let callback = Url::parse(&format!(
        "{}?code=integration-code&state={state}",
        redirect_uri
    ))
    .unwrap();
    let authorization_response = session.parse_redirect(&callback).unwrap();
    let token_response = session
        .exchange_code(
            &transport,
            &authorization_response,
            CancellationHandle::new(),
        )
        .await
        .unwrap();
    assert_eq!(token_response.access_token, "initial-access");
    assert_eq!(
        token_response.additional_parameters["provider_extension"],
        json!({"enabled": true})
    );

    let state_json =
        serde_json::to_value(session.authentication_state(token_response).unwrap()).unwrap();
    assert_eq!(state_json["oidc_nonce"], nonce);
    let mut authentication_state: AuthenticationState = serde_json::from_value(state_json).unwrap();
    transport.push_json(
        StatusCode::OK,
        json!({
            "access_token": "refreshed-access",
            "token_type": "Bearer",
            "expires_in": 1800,
        }),
    );
    authentication_state
        .refresh(
            &configuration,
            client_id,
            &transport,
            CancellationHandle::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        authentication_state.token_response().access_token,
        "refreshed-access"
    );
    assert_eq!(
        authentication_state
            .token_response()
            .refresh_token
            .as_deref(),
        Some("initial-refresh")
    );

    let requests = transport.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(
        requests[0].url.path(),
        "/tenant/.well-known/openid-configuration"
    );
    assert_eq!(requests[1].method, Method::POST);
    let code_exchange: Vec<_> = url::form_urlencoded::parse(&requests[1].body)
        .into_owned()
        .collect();
    assert!(code_exchange
        .iter()
        .any(|(name, value)| name == "code" && value == "integration-code"));
    assert!(code_exchange
        .iter()
        .any(|(name, value)| name == "code_verifier" && !value.is_empty()));
    assert_eq!(requests[2].url.path(), "/tenant/keys");
    let refresh: Vec<_> = url::form_urlencoded::parse(&requests[3].body)
        .into_owned()
        .collect();
    assert!(refresh
        .iter()
        .any(|(name, value)| name == "grant_type" && value == "refresh_token"));
}

#[tokio::test]
async fn public_registration_and_end_session_use_the_configured_protocol_endpoints() {
    let redirect_uri = Url::parse("com.example.app:/oauth/callback").unwrap();
    let mut configuration = ServiceConfiguration::new(
        Url::parse("https://issuer.example/authorize").unwrap(),
        Url::parse("https://issuer.example/token").unwrap(),
    )
    .unwrap()
    .with_registration_endpoint(Url::parse("https://issuer.example/register").unwrap())
    .unwrap();
    configuration = configuration
        .with_end_session_endpoint(Url::parse("https://issuer.example/logout").unwrap())
        .unwrap();
    let transport = ScriptedTransport::default();
    transport.push_json(
        StatusCode::CREATED,
        json!({
            "client_id": "registered-client",
            "application_type": "native",
            "token_endpoint_auth_method": "none",
        }),
    );

    let registration = ClientRegistrationRequest::new(&configuration, vec![redirect_uri.clone()])
        .unwrap()
        .with_client_name("integration app")
        .unwrap()
        .with_initial_access_token("registration-token")
        .unwrap()
        .register(&transport, CancellationHandle::new())
        .await
        .unwrap();
    assert_eq!(registration.client_id(), "registered-client");

    let end_session = EndSessionRequest::new(&configuration, registration.client_id())
        .unwrap()
        .with_id_token_hint("signed-id-token")
        .unwrap()
        .with_post_logout_redirect_uri(redirect_uri.clone())
        .unwrap()
        .begin()
        .unwrap();
    let logout_parameters = response_parameters(end_session.end_session_url());
    let logout_state = logout_parameters
        .iter()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .clone();
    let callback = Url::parse(&format!("{redirect_uri}?state={logout_state}&status=done")).unwrap();
    let response = end_session.parse_redirect(&callback).unwrap();
    assert_eq!(response.state(), logout_state);
    assert_eq!(response.additional_parameters()["status"], "done");

    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::POST);
    assert_eq!(
        requests[0].headers[http::header::AUTHORIZATION],
        "Bearer registration-token"
    );
    let metadata: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(metadata["application_type"], "native");
    assert_eq!(metadata["token_endpoint_auth_method"], "none");
    assert!(metadata.get("client_secret").is_none());
}

struct BlockingTransport {
    started: Mutex<Option<oneshot::Sender<()>>>,
}

#[async_trait]
impl HttpTransport for BlockingTransport {
    async fn execute(
        &self,
        _request: HttpRequest,
        cancellation: CancellationHandle,
    ) -> appauth_rust::Result<HttpResponse> {
        if let Some(started) = self.started.lock().unwrap().take() {
            started.send(()).unwrap();
        }
        cancellation.cancelled().await;
        Err(AuthError::Cancelled)
    }
}

#[tokio::test]
async fn cancellation_interrupts_public_discovery_operation() {
    let (started_sender, started_receiver) = oneshot::channel();
    let transport = BlockingTransport {
        started: Mutex::new(Some(started_sender)),
    };
    let cancellation = CancellationHandle::new();
    let request_cancellation = cancellation.clone();
    let operation = tokio::spawn(async move {
        ServiceConfiguration::discover(
            Url::parse("https://issuer.example").unwrap(),
            &transport,
            request_cancellation,
        )
        .await
    });

    started_receiver.await.unwrap();
    cancellation.cancel();
    assert!(matches!(
        operation.await.unwrap(),
        Err(AuthError::Cancelled)
    ));
}
