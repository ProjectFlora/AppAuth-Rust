use std::collections::{BTreeMap, HashSet};

use http::{header, HeaderMap, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::{form_urlencoded, Host, Url};

use crate::{
    pkce::{random_token, PkcePair},
    AuthError, CancellationHandle, HttpRequest, HttpTransport, Result,
};

const RESERVED_AUTHORIZATION_PARAMETERS: &[&str] = &[
    "client_id",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
];

#[derive(Clone)]
pub struct ServiceConfiguration {
    authorization_endpoint: Url,
    token_endpoint: Url,
}

impl ServiceConfiguration {
    pub fn new(authorization_endpoint: Url, token_endpoint: Url) -> Result<Self> {
        validate_endpoint(&authorization_endpoint)?;
        validate_endpoint(&token_endpoint)?;

        Ok(Self {
            authorization_endpoint,
            token_endpoint,
        })
    }

    pub fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }
}

pub struct AuthorizationRequest {
    configuration: ServiceConfiguration,
    client_id: String,
    redirect_uri: Url,
    scopes: Vec<String>,
    additional_parameters: BTreeMap<String, String>,
}

impl AuthorizationRequest {
    pub fn new(
        configuration: ServiceConfiguration,
        client_id: impl Into<String>,
        redirect_uri: Url,
        scopes: Vec<String>,
    ) -> Result<Self> {
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "client ID must not be empty",
            ));
        }

        validate_redirect_uri(&redirect_uri)?;
        for scope in &scopes {
            validate_scope(scope)?;
        }

        Ok(Self {
            configuration,
            client_id,
            redirect_uri,
            scopes,
            additional_parameters: BTreeMap::new(),
        })
    }

    pub fn with_additional_parameter(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self> {
        let name = name.into();
        if name.is_empty() || RESERVED_AUTHORIZATION_PARAMETERS.contains(&name.as_str()) {
            return Err(AuthError::InvalidConfiguration(
                "additional parameter has an empty or reserved name",
            ));
        }

        self.additional_parameters.insert(name, value.into());
        Ok(self)
    }

    pub fn begin(self) -> Result<AuthorizationSession> {
        let mut authorization_url = self.configuration.authorization_endpoint.clone();
        reject_reserved_endpoint_parameters(&authorization_url)?;

        let state = random_token()?;
        let nonce = if self.scopes.iter().any(|scope| scope == "openid") {
            Some(random_token()?)
        } else {
            None
        };
        let pkce = PkcePair::generate()?;

        {
            let mut query = authorization_url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.client_id);
            query.append_pair("redirect_uri", self.redirect_uri.as_str());
            if !self.scopes.is_empty() {
                query.append_pair("scope", &self.scopes.join(" "));
            }
            query.append_pair("state", &state);
            if let Some(nonce) = &nonce {
                query.append_pair("nonce", nonce);
            }
            query.append_pair("code_challenge", pkce.challenge());
            query.append_pair("code_challenge_method", "S256");
            for (name, value) in self.additional_parameters {
                query.append_pair(&name, &value);
            }
        }

        Ok(AuthorizationSession {
            authorization_url,
            redirect_uri: self.redirect_uri,
            token_endpoint: self.configuration.token_endpoint,
            client_id: self.client_id,
            state,
            nonce,
            pkce,
        })
    }
}

pub struct AuthorizationSession {
    authorization_url: Url,
    redirect_uri: Url,
    token_endpoint: Url,
    client_id: String,
    state: String,
    nonce: Option<String>,
    pkce: PkcePair,
}

impl AuthorizationSession {
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    pub fn parse_redirect(&self, redirect: &Url) -> Result<AuthorizationResponse> {
        validate_redirect_uri_match(&self.redirect_uri, redirect)?;

        let mut parameters = BTreeMap::new();
        let mut names = HashSet::new();
        for (name, value) in redirect.query_pairs() {
            if !names.insert(name.to_string()) {
                return Err(AuthError::InvalidAuthorizationResponse(
                    "response contains a duplicate parameter",
                ));
            }
            parameters.insert(name.into_owned(), value.into_owned());
        }

        for (name, expected_value) in self.redirect_uri.query_pairs() {
            if parameters.get(name.as_ref()) != Some(&expected_value.into_owned()) {
                return Err(AuthError::InvalidAuthorizationResponse(
                    "redirect URI query does not match",
                ));
            }
            parameters.remove(name.as_ref());
        }

        if parameters.get("state").map(String::as_str) != Some(self.state.as_str()) {
            return Err(AuthError::InvalidAuthorizationResponse("state mismatch"));
        }
        parameters.remove("state");

        let code = parameters.remove("code");
        let error = parameters.remove("error");
        if code.is_some() && error.is_some() {
            return Err(AuthError::InvalidAuthorizationResponse(
                "response contains both code and error",
            ));
        }
        if let Some(code) = code {
            if code.is_empty() {
                return Err(AuthError::InvalidAuthorizationResponse(
                    "authorization code must not be empty",
                ));
            }
            return Ok(AuthorizationResponse {
                code,
                state: self.state.clone(),
                additional_parameters: parameters,
            });
        }
        if let Some(code) = error {
            return Err(AuthError::AuthorizationServer {
                code,
                description: parameters.remove("error_description"),
            });
        }

        Err(AuthError::InvalidAuthorizationResponse(
            "response contains neither code nor error",
        ))
    }

    pub async fn exchange_code(
        &self,
        transport: &dyn HttpTransport,
        response: &AuthorizationResponse,
        cancellation: CancellationHandle,
    ) -> Result<TokenResponse> {
        if response.state != self.state {
            return Err(AuthError::InvalidAuthorizationResponse(
                "authorization response belongs to a different session",
            ));
        }

        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &response.code)
            .append_pair("redirect_uri", self.redirect_uri.as_str())
            .append_pair("client_id", &self.client_id)
            .append_pair("code_verifier", self.pkce.verifier())
            .finish()
            .into_bytes();
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );

        let token_response = transport
            .execute(
                HttpRequest {
                    method: Method::POST,
                    url: self.token_endpoint.clone(),
                    headers,
                    body,
                },
                cancellation,
            )
            .await?;

        if !token_response.status.is_success() {
            if let Ok(value) = serde_json::from_slice::<Value>(&token_response.body) {
                if let Some(code) = value.get("error").and_then(Value::as_str) {
                    return Err(AuthError::AuthorizationServer {
                        code: code.to_owned(),
                        description: value
                            .get("error_description")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    });
                }
            }
            return Err(AuthError::HttpStatus(token_response.status));
        }

        parse_token_response(&token_response.body)
    }
}

pub struct AuthorizationResponse {
    code: String,
    state: String,
    additional_parameters: BTreeMap<String, String>,
}

impl AuthorizationResponse {
    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn additional_parameters(&self) -> &BTreeMap<String, String> {
        &self.additional_parameters
    }
}

#[derive(Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    /// Raw ID Token value. This version does not validate its signature or claims.
    pub id_token: Option<String>,
    #[serde(default)]
    pub additional_parameters: BTreeMap<String, Value>,
}

fn parse_token_response(body: &[u8]) -> Result<TokenResponse> {
    let mut object: Map<String, Value> = serde_json::from_slice(body)
        .map_err(|_| AuthError::InvalidTokenResponse("response is not a JSON object"))?;

    let access_token = take_required_string(&mut object, "access_token")?;
    let token_type = take_required_string(&mut object, "token_type")?;
    if access_token.is_empty() || token_type.is_empty() {
        return Err(AuthError::InvalidTokenResponse(
            "access_token and token_type must not be empty",
        ));
    }

    let expires_in = take_optional_u64(&mut object, "expires_in")?;
    let refresh_token = take_optional_string(&mut object, "refresh_token")?;
    let scope = take_optional_string(&mut object, "scope")?;
    let id_token = take_optional_string(&mut object, "id_token")?;

    Ok(TokenResponse {
        access_token,
        token_type,
        expires_in,
        refresh_token,
        scope,
        id_token,
        additional_parameters: object.into_iter().collect(),
    })
}

fn take_required_string(object: &mut Map<String, Value>, key: &str) -> Result<String> {
    object
        .remove(key)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(AuthError::InvalidTokenResponse(
            "required string field is missing or invalid",
        ))
}

fn take_optional_string(object: &mut Map<String, Value>, key: &str) -> Result<Option<String>> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(AuthError::InvalidTokenResponse(
            "optional string field has an invalid value",
        )),
    }
}

fn take_optional_u64(object: &mut Map<String, Value>, key: &str) -> Result<Option<u64>> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => {
            value
                .as_u64()
                .map(Some)
                .ok_or(AuthError::InvalidTokenResponse(
                    "expires_in must be a non-negative integer",
                ))
        }
        Some(_) => Err(AuthError::InvalidTokenResponse(
            "expires_in must be a non-negative integer",
        )),
    }
}

fn validate_endpoint(endpoint: &Url) -> Result<()> {
    let is_https = endpoint.scheme() == "https";
    let is_loopback_host = match endpoint.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    let is_loopback_http = endpoint.scheme() == "http" && is_loopback_host;
    if (!is_https && !is_loopback_http)
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(AuthError::InvalidConfiguration(
            "endpoints must use HTTPS or loopback HTTP without user info or fragments",
        ));
    }
    Ok(())
}

fn validate_redirect_uri(redirect_uri: &Url) -> Result<()> {
    if redirect_uri.scheme().is_empty()
        || redirect_uri.fragment().is_some()
        || !redirect_uri.username().is_empty()
        || redirect_uri.password().is_some()
    {
        return Err(AuthError::InvalidConfiguration(
            "redirect URI must have a scheme and must not contain credentials or a fragment",
        ));
    }
    if redirect_uri.query_pairs().any(|(name, _)| {
        matches!(
            name.as_ref(),
            "code" | "state" | "error" | "error_description" | "error_uri" | "iss"
        )
    }) {
        return Err(AuthError::InvalidConfiguration(
            "redirect URI query contains an authorization response parameter",
        ));
    }
    Ok(())
}

fn validate_scope(scope: &str) -> Result<()> {
    if scope.is_empty()
        || !scope.bytes().all(|byte| {
            byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
        })
    {
        return Err(AuthError::InvalidConfiguration(
            "scope values must be non-empty RFC 6749 scope tokens",
        ));
    }
    Ok(())
}

fn reject_reserved_endpoint_parameters(endpoint: &Url) -> Result<()> {
    if endpoint
        .query_pairs()
        .any(|(name, _)| RESERVED_AUTHORIZATION_PARAMETERS.contains(&name.as_ref()))
    {
        return Err(AuthError::InvalidConfiguration(
            "authorization endpoint query contains a reserved parameter",
        ));
    }
    Ok(())
}

fn validate_redirect_uri_match(expected: &Url, received: &Url) -> Result<()> {
    if received.fragment().is_some()
        || expected.scheme() != received.scheme()
        || expected.username() != received.username()
        || expected.password() != received.password()
        || expected.host_str() != received.host_str()
        || expected.port() != received.port()
        || expected.path() != received.path()
    {
        return Err(AuthError::InvalidAuthorizationResponse(
            "redirect URI does not match the request",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use http::StatusCode;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{HttpRequest, HttpResponse};

    struct TestTransport {
        request: Mutex<Option<HttpRequest>>,
        response: Mutex<Option<HttpResponse>>,
    }

    #[async_trait]
    impl HttpTransport for TestTransport {
        async fn execute(
            &self,
            request: HttpRequest,
            _cancellation: CancellationHandle,
        ) -> Result<HttpResponse> {
            *self.request.lock().unwrap() = Some(request);
            Ok(self.response.lock().unwrap().take().unwrap())
        }
    }

    fn test_transport(status: StatusCode, body: &'static [u8]) -> TestTransport {
        TestTransport {
            request: Mutex::new(None),
            response: Mutex::new(Some(HttpResponse {
                status,
                headers: HeaderMap::new(),
                body: body.to_vec(),
            })),
        }
    }

    fn request(scopes: &[&str]) -> AuthorizationRequest {
        let configuration = ServiceConfiguration::new(
            Url::parse("https://issuer.example/authorize").unwrap(),
            Url::parse("https://issuer.example/token").unwrap(),
        )
        .unwrap();
        AuthorizationRequest::new(
            configuration,
            "native-client",
            Url::parse("com.example.app:/oauth2redirect").unwrap(),
            scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        )
        .unwrap()
    }

    #[test]
    fn authorization_request_uses_code_and_s256_pkce() {
        let session = request(&["openid", "profile"]).begin().unwrap();
        let parameters: BTreeMap<_, _> = session
            .authorization_url()
            .query_pairs()
            .into_owned()
            .collect();

        assert_eq!(
            parameters.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            parameters.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(parameters.get("nonce").map(String::as_str), session.nonce());
        assert_eq!(
            parameters.get("scope").map(String::as_str),
            Some("openid profile")
        );
        assert_eq!(
            parameters.get("redirect_uri").map(String::as_str),
            Some("com.example.app:/oauth2redirect")
        );
    }

    #[test]
    fn authorization_response_requires_matching_redirect_and_state() {
        let session = request(&["openid"]).begin().unwrap();
        let state = &session.state;
        let redirect = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=auth-code&state={state}&provider_hint=tenant"
        ))
        .unwrap();

        let response = session.parse_redirect(&redirect).unwrap();
        assert_eq!(response.code(), "auth-code");
        assert_eq!(
            response
                .additional_parameters
                .get("provider_hint")
                .map(String::as_str),
            Some("tenant")
        );
    }

    #[test]
    fn authorization_response_rejects_mismatched_state_and_redirect_uri() {
        let session = request(&["openid"]).begin().unwrap();
        let wrong_state =
            Url::parse("com.example.app:/oauth2redirect?code=auth-code&state=wrong").unwrap();
        assert!(matches!(
            session.parse_redirect(&wrong_state),
            Err(AuthError::InvalidAuthorizationResponse("state mismatch"))
        ));

        let wrong_path =
            Url::parse("com.example.app:/different?code=auth-code&state=state").unwrap();
        assert!(matches!(
            session.parse_redirect(&wrong_path),
            Err(AuthError::InvalidAuthorizationResponse(
                "redirect URI does not match the request"
            ))
        ));
    }

    #[test]
    fn rejects_duplicate_and_conflicting_authorization_parameters() {
        let session = request(&[]).begin().unwrap();
        let state = &session.state;
        let duplicate = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=one&code=two&state={state}"
        ))
        .unwrap();
        assert!(matches!(
            session.parse_redirect(&duplicate),
            Err(AuthError::InvalidAuthorizationResponse(
                "response contains a duplicate parameter"
            ))
        ));

        let conflict = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=one&error=denied&state={state}"
        ))
        .unwrap();
        assert!(matches!(
            session.parse_redirect(&conflict),
            Err(AuthError::InvalidAuthorizationResponse(
                "response contains both code and error"
            ))
        ));
    }

    #[test]
    fn additional_parameters_cannot_override_protocol_fields() {
        let result = request(&[]).with_additional_parameter("state", "attacker-controlled");
        assert!(matches!(
            result,
            Err(AuthError::InvalidConfiguration(
                "additional parameter has an empty or reserved name"
            ))
        ));
    }

    #[tokio::test]
    async fn code_exchange_sends_verifier_and_preserves_unknown_token_fields() {
        let session = request(&["openid"]).begin().unwrap();
        let redirect = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=auth-code&state={}",
            session.state
        ))
        .unwrap();
        let authorization_response = session.parse_redirect(&redirect).unwrap();
        let transport = test_transport(
            StatusCode::OK,
            br#"{
                "access_token":"access",
                "token_type":"Bearer",
                "expires_in":3600,
                "refresh_token":"refresh",
                "id_token":"unverified-id-token",
                "provider_data":{"key":"value"}
            }"#,
        );

        let token_response = session
            .exchange_code(
                &transport,
                &authorization_response,
                CancellationHandle::new(),
            )
            .await
            .unwrap();
        let sent_request = transport.request.lock().unwrap().take().unwrap();
        let form: BTreeMap<_, _> = form_urlencoded::parse(&sent_request.body)
            .into_owned()
            .collect();
        let challenge = session
            .authorization_url()
            .query_pairs()
            .find(|(name, _)| name == "code_challenge")
            .unwrap()
            .1;
        let verifier = form.get("code_verifier").unwrap();

        assert_eq!(sent_request.method, Method::POST);
        assert_eq!(sent_request.url.as_str(), "https://issuer.example/token");
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(form.get("code").map(String::as_str), Some("auth-code"));
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            challenge
        );
        assert_eq!(token_response.access_token, "access");
        assert_eq!(
            token_response.id_token.as_deref(),
            Some("unverified-id-token")
        );
        assert_eq!(
            token_response.additional_parameters["provider_data"]["key"],
            "value"
        );
    }

    #[tokio::test]
    async fn code_exchange_surfaces_oauth_errors() {
        let session = request(&[]).begin().unwrap();
        let redirect = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=auth-code&state={}",
            session.state
        ))
        .unwrap();
        let authorization_response = session.parse_redirect(&redirect).unwrap();
        let transport = test_transport(
            StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant","error_description":"expired code"}"#,
        );

        assert!(matches!(
            session
                .exchange_code(
                    &transport,
                    &authorization_response,
                    CancellationHandle::new()
                )
                .await,
            Err(AuthError::AuthorizationServer { code, .. }) if code == "invalid_grant"
        ));
    }

    #[tokio::test]
    async fn code_exchange_rejects_response_from_another_session() {
        let first_session = request(&[]).begin().unwrap();
        let second_session = request(&[]).begin().unwrap();
        let redirect = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=auth-code&state={}",
            first_session.state
        ))
        .unwrap();
        let authorization_response = first_session.parse_redirect(&redirect).unwrap();
        let transport = test_transport(
            StatusCode::OK,
            br#"{"access_token":"access","token_type":"Bearer"}"#,
        );

        assert!(matches!(
            second_session
                .exchange_code(
                    &transport,
                    &authorization_response,
                    CancellationHandle::new()
                )
                .await,
            Err(AuthError::InvalidAuthorizationResponse(
                "authorization response belongs to a different session"
            ))
        ));
        assert!(transport.request.lock().unwrap().is_none());
    }

    #[test]
    fn rejects_insecure_remote_endpoints_and_response_parameters_in_redirect_uri() {
        let insecure_endpoint = ServiceConfiguration::new(
            Url::parse("http://issuer.example/authorize").unwrap(),
            Url::parse("https://issuer.example/token").unwrap(),
        );
        assert!(matches!(
            insecure_endpoint,
            Err(AuthError::InvalidConfiguration(_))
        ));

        let configuration = ServiceConfiguration::new(
            Url::parse("https://issuer.example/authorize").unwrap(),
            Url::parse("https://issuer.example/token").unwrap(),
        )
        .unwrap();
        assert!(matches!(
            AuthorizationRequest::new(
                configuration,
                "native-client",
                Url::parse("com.example.app:/callback?state=static").unwrap(),
                vec![],
            ),
            Err(AuthError::InvalidConfiguration(
                "redirect URI query contains an authorization response parameter"
            ))
        ));
    }
}
