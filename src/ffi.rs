use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use http::{header::HeaderName, HeaderMap, HeaderValue, StatusCode};
use url::Url;

use crate::{
    revoke_token, AuthError, AuthenticationState, AuthorizationRequest, AuthorizationResponse,
    AuthorizationSession, CancellationHandle, ClientRegistrationRequest, EndSessionRequest,
    HttpRequest, HttpResponse, HttpTransport, Result, RevocationTokenType, ServiceConfiguration,
    TokenResponse,
};

/// Errors exposed to Swift and Kotlin callers.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// A caller-provided request or configuration value was invalid.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The server response was malformed or failed validation.
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    /// The authorization server rejected the request.
    #[error("authorization server returned error: {code}")]
    AuthorizationServer {
        /// OAuth error code.
        code: String,
        /// Optional human-readable error description.
        description: Option<String>,
    },
    /// The client registration server rejected the request.
    #[error("client registration server returned error: {code}")]
    ClientRegistrationServer {
        /// Registration error code.
        code: String,
        /// Optional human-readable error description.
        description: Option<String>,
    },
    /// An endpoint returned an unexpected status or an unusable OAuth error body.
    #[error("HTTP endpoint returned status {status}")]
    HttpStatus {
        /// HTTP status code.
        status: u16,
    },
    /// The HTTP transport failed without additional detail.
    #[error("HTTP transport failed")]
    Transport,
    /// The HTTP transport failed and provided a diagnostic message.
    #[error("HTTP transport failed: {0}")]
    TransportFailure(String),
    /// The operation was cancelled by the caller or platform.
    #[error("operation was cancelled")]
    Cancelled,
    /// The system clock is earlier than the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    Clock,
    /// Secure random value generation failed.
    #[error("secure random number generation failed")]
    Randomness,
    /// An unexpected internal or serialization error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

impl From<AuthError> for FfiError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::InvalidConfiguration(message) => Self::InvalidRequest(message.to_owned()),
            AuthError::InvalidAuthorizationResponse(message)
            | AuthError::InvalidEndSessionResponse(message)
            | AuthError::InvalidTokenResponse(message)
            | AuthError::InvalidClientRegistrationResponse(message)
            | AuthError::InvalidIdToken(message)
            | AuthError::InvalidJwks(message)
            | AuthError::InvalidDiscoveryMetadata(message) => {
                Self::InvalidResponse(message.to_owned())
            }
            AuthError::AuthorizationServer { code, description } => {
                Self::AuthorizationServer { code, description }
            }
            AuthError::ClientRegistrationServer { code, description } => {
                Self::ClientRegistrationServer { code, description }
            }
            AuthError::Transport => Self::Transport,
            AuthError::TransportFailure(message) => Self::TransportFailure(message),
            AuthError::HttpStatus(status) => Self::HttpStatus {
                status: status.as_u16(),
            },
            AuthError::Cancelled => Self::Cancelled,
            AuthError::Clock => Self::Clock,
            AuthError::Randomness => Self::Randomness,
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for FfiError {
    fn from(_: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Transport
    }
}

#[derive(uniffi::Object)]
/// Cloneable cancellation signal for native operations and HTTP requests.
pub struct FfiCancellationHandle {
    inner: CancellationHandle,
}

#[uniffi::export]
impl FfiCancellationHandle {
    #[uniffi::constructor]
    /// Creates a cancellation handle that is not cancelled.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: CancellationHandle::new(),
        })
    }

    /// Cancels the operation; repeated calls have no additional effect.
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    /// Returns whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// Suspends until cancellation is requested.
    pub async fn cancelled(&self) {
        self.inner.cancelled().await;
    }
}

#[derive(uniffi::Record)]
/// An HTTP header passed between the core and a native transport.
pub struct FfiHttpHeader {
    /// Header name.
    pub name: String,
    /// Header value as raw bytes.
    pub value: Vec<u8>,
}

#[derive(uniffi::Record)]
/// An HTTP request passed to a native transport.
pub struct FfiHttpRequest {
    /// HTTP method, such as `GET` or `POST`.
    pub method: String,
    /// Absolute endpoint URL.
    pub url: String,
    /// Request headers.
    pub headers: Vec<FfiHttpHeader>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

#[derive(uniffi::Record)]
/// An HTTP response returned by a native transport.
pub struct FfiHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<FfiHttpHeader>,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Native HTTP transport used by the shared OAuth/OIDC core.
///
/// Implementations must not follow redirects. They must propagate cancellation
/// and return redirect responses to the core without forwarding credentials.
#[uniffi::export(foreign)]
#[async_trait]
pub trait NativeHttpTransport: Send + Sync {
    /// Executes one request and returns its response or transport error.
    async fn execute(
        &self,
        request: FfiHttpRequest,
        cancellation: Arc<FfiCancellationHandle>,
    ) -> std::result::Result<FfiHttpResponse, FfiError>;
}

struct NativeTransport {
    inner: Arc<dyn NativeHttpTransport>,
}

#[async_trait]
impl HttpTransport for NativeTransport {
    async fn execute(
        &self,
        request: HttpRequest,
        cancellation: CancellationHandle,
    ) -> Result<HttpResponse> {
        let response = self
            .inner
            .execute(
                FfiHttpRequest {
                    method: request.method.to_string(),
                    url: request.url.to_string(),
                    headers: headers_to_ffi(request.headers),
                    body: request.body,
                },
                Arc::new(FfiCancellationHandle {
                    inner: cancellation.clone(),
                }),
            )
            .await
            .map_err(|error| match error {
                FfiError::Cancelled => AuthError::Cancelled,
                other => AuthError::TransportFailure(other.to_string()),
            })?;

        let status = StatusCode::from_u16(response.status).map_err(|error| {
            AuthError::TransportFailure(format!("invalid HTTP status: {error}"))
        })?;
        let headers = headers_from_ffi(response.headers)
            .map_err(|error| AuthError::TransportFailure(error.to_string()))?;
        Ok(HttpResponse {
            status,
            headers,
            body: response.body,
        })
    }
}

fn headers_to_ffi(headers: HeaderMap) -> Vec<FfiHttpHeader> {
    headers
        .iter()
        .map(|(name, value)| FfiHttpHeader {
            name: name.to_string(),
            value: value.as_bytes().to_vec(),
        })
        .collect()
}

fn headers_from_ffi(headers: Vec<FfiHttpHeader>) -> std::result::Result<HeaderMap, FfiError> {
    let mut result = HeaderMap::new();
    for header in headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| FfiError::InvalidResponse("invalid HTTP header name".to_owned()))?;
        let value = HeaderValue::from_bytes(&header.value)
            .map_err(|_| FfiError::InvalidResponse("invalid HTTP header value".to_owned()))?;
        result.append(name, value);
    }
    Ok(result)
}

#[derive(uniffi::Object)]
/// OAuth endpoint configuration shared by native authorization operations.
pub struct FfiServiceConfiguration {
    inner: ServiceConfiguration,
}

#[uniffi::export]
impl FfiServiceConfiguration {
    #[uniffi::constructor]
    /// Creates a configuration from explicit authorization and token endpoints.
    pub fn new(
        authorization_endpoint: String,
        token_endpoint: String,
    ) -> std::result::Result<Arc<Self>, FfiError> {
        let authorization_endpoint = parse_url(&authorization_endpoint, "authorization endpoint")?;
        let token_endpoint = parse_url(&token_endpoint, "token endpoint")?;
        let inner = ServiceConfiguration::new(authorization_endpoint, token_endpoint)?;
        Ok(Arc::new(Self { inner }))
    }

    #[uniffi::constructor]
    /// Discovers and validates OpenID Provider metadata for an issuer.
    pub async fn discover(
        issuer: String,
        transport: Arc<dyn NativeHttpTransport>,
        cancellation: Arc<FfiCancellationHandle>,
    ) -> std::result::Result<Arc<Self>, FfiError> {
        let issuer = parse_url(&issuer, "issuer")?;
        let transport = NativeTransport { inner: transport };
        let inner =
            ServiceConfiguration::discover(issuer, &transport, cancellation.inner.clone()).await?;
        Ok(Arc::new(Self { inner }))
    }

    /// Configures the issuer and JWKS endpoint used to validate ID Tokens.
    pub fn with_oidc_validation_endpoints(
        &self,
        issuer: String,
        jwks_uri: String,
    ) -> std::result::Result<Arc<Self>, FfiError> {
        let issuer = parse_url(&issuer, "issuer")?;
        let jwks_uri = parse_url(&jwks_uri, "JWKS endpoint")?;
        let inner = self
            .inner
            .clone()
            .with_oidc_validation_endpoints(issuer, jwks_uri)?;
        Ok(Arc::new(Self { inner }))
    }

    /// Adds an HTTPS end-session endpoint.
    pub fn with_end_session_endpoint(
        &self,
        endpoint: String,
    ) -> std::result::Result<Arc<Self>, FfiError> {
        let endpoint = parse_url(&endpoint, "end-session endpoint")?;
        let inner = self.inner.clone().with_end_session_endpoint(endpoint)?;
        Ok(Arc::new(Self { inner }))
    }

    /// Adds an HTTPS OAuth 2.0 token revocation endpoint.
    pub fn with_revocation_endpoint(
        &self,
        endpoint: String,
    ) -> std::result::Result<Arc<Self>, FfiError> {
        let endpoint = parse_url(&endpoint, "token revocation endpoint")?;
        let inner = self.inner.clone().with_revocation_endpoint(endpoint)?;
        Ok(Arc::new(Self { inner }))
    }

    /// Adds an HTTPS dynamic client registration endpoint.
    pub fn with_registration_endpoint(
        &self,
        endpoint: String,
    ) -> std::result::Result<Arc<Self>, FfiError> {
        let endpoint = parse_url(&endpoint, "registration endpoint")?;
        let inner = self.inner.clone().with_registration_endpoint(endpoint)?;
        Ok(Arc::new(Self { inner }))
    }

    /// Returns the authorization endpoint URL.
    pub fn authorization_endpoint(&self) -> String {
        self.inner.authorization_endpoint().to_string()
    }

    /// Returns the token endpoint URL.
    pub fn token_endpoint(&self) -> String {
        self.inner.token_endpoint().to_string()
    }

    /// Returns the configured token revocation endpoint URL, if any.
    pub fn revocation_endpoint(&self) -> Option<String> {
        self.inner.revocation_endpoint().map(ToString::to_string)
    }

    /// Returns the configured issuer URL, if any.
    pub fn issuer(&self) -> Option<String> {
        self.inner.issuer().map(ToString::to_string)
    }

    /// Returns the configured JWKS URL, if any.
    pub fn jwks_uri(&self) -> Option<String> {
        self.inner.jwks_uri().map(ToString::to_string)
    }
}

/// Requests invalidation of an access token or refresh token under RFC 7009.
///
/// This does not delete local authentication state. The host application must
/// delete state regardless of whether the network operation succeeds.
#[uniffi::export]
pub async fn revoke(
    configuration: Arc<FfiServiceConfiguration>,
    client_id: String,
    token: String,
    token_type_hint: Option<String>,
    transport: Arc<dyn NativeHttpTransport>,
    cancellation: Arc<FfiCancellationHandle>,
) -> std::result::Result<(), FfiError> {
    let token_type_hint = match token_type_hint.as_deref() {
        None => None,
        Some("access_token") => Some(RevocationTokenType::AccessToken),
        Some("refresh_token") => Some(RevocationTokenType::RefreshToken),
        Some(_) => {
            return Err(FfiError::InvalidRequest(
                "token type hint must be access_token or refresh_token".to_owned(),
            ));
        }
    };
    let transport = NativeTransport { inner: transport };
    revoke_token(
        &configuration.inner,
        &client_id,
        &token,
        token_type_hint,
        &transport,
        cancellation.inner.clone(),
    )
    .await?;
    Ok(())
}

/// A string-valued OAuth parameter.
#[derive(uniffi::Record)]
pub struct FfiParameter {
    /// Parameter name.
    pub name: String,
    /// Parameter value.
    pub value: String,
}

/// A JSON-valued token response parameter.
#[derive(uniffi::Record)]
pub struct FfiJsonParameter {
    /// Parameter name.
    pub name: String,
    /// Parameter value encoded as JSON text.
    pub value_json: String,
}

/// Inputs for creating an Authorization Code + PKCE request.
#[derive(uniffi::Record)]
pub struct FfiAuthorizationOptions {
    /// Public client identifier.
    pub client_id: String,
    /// Registered callback URI.
    pub redirect_uri: String,
    /// OAuth scopes requested from the authorization server.
    pub scopes: Vec<String>,
    /// Additional authorization request parameters.
    pub additional_parameters: Vec<FfiParameter>,
    /// Additional token exchange parameters.
    pub additional_token_parameters: Vec<FfiParameter>,
}

#[uniffi::export]
/// Creates a prepared authorization session for a native browser adapter.
pub fn begin_authorization(
    configuration: Arc<FfiServiceConfiguration>,
    options: FfiAuthorizationOptions,
    transport: Arc<dyn NativeHttpTransport>,
) -> std::result::Result<Arc<FfiAuthorizationSession>, FfiError> {
    let redirect_uri = parse_url(&options.redirect_uri, "redirect URI")?;
    let mut request = AuthorizationRequest::new(
        configuration.inner.clone(),
        options.client_id,
        redirect_uri,
        options.scopes,
    )?;
    request = apply_parameters(request, options.additional_parameters, false)?;
    request = apply_parameters(request, options.additional_token_parameters, true)?;
    let inner = request.begin()?;
    Ok(Arc::new(FfiAuthorizationSession { inner, transport }))
}

fn apply_parameters(
    mut request: AuthorizationRequest,
    parameters: Vec<FfiParameter>,
    token_parameters: bool,
) -> std::result::Result<AuthorizationRequest, FfiError> {
    ensure_unique_parameter_names(&parameters)?;
    for parameter in parameters {
        request = if token_parameters {
            request.with_additional_token_parameter(parameter.name, parameter.value)?
        } else {
            request.with_additional_parameter(parameter.name, parameter.value)?
        };
    }
    Ok(request)
}

fn ensure_unique_parameter_names(parameters: &[FfiParameter]) -> std::result::Result<(), FfiError> {
    let mut names = BTreeSet::new();
    if parameters
        .iter()
        .any(|parameter| !names.insert(parameter.name.as_str()))
    {
        return Err(FfiError::InvalidRequest(
            "parameter names must be unique".to_owned(),
        ));
    }
    Ok(())
}

/// A validated authorization response received from the redirect URI.
#[derive(uniffi::Object)]
pub struct FfiAuthorizationResponse {
    inner: AuthorizationResponse,
}

#[uniffi::export]
impl FfiAuthorizationResponse {
    /// Returns the authorization code.
    pub fn code(&self) -> String {
        self.inner.code().to_owned()
    }

    /// Returns the state matched against the originating session.
    pub fn state(&self) -> String {
        self.inner.state().to_owned()
    }

    /// Returns unrecognized response parameters.
    pub fn additional_parameters(&self) -> Vec<FfiParameter> {
        self.inner
            .additional_parameters()
            .iter()
            .map(|(name, value)| FfiParameter {
                name: name.clone(),
                value: value.clone(),
            })
            .collect()
    }
}

/// Prepared authorization URL and state for parsing a callback and exchanging its code.
#[derive(uniffi::Object)]
pub struct FfiAuthorizationSession {
    inner: AuthorizationSession,
    transport: Arc<dyn NativeHttpTransport>,
}

#[uniffi::export]
impl FfiAuthorizationSession {
    /// Returns the URL to open in an external user agent.
    pub fn authorization_url(&self) -> String {
        self.inner.authorization_url().to_string()
    }

    /// Returns the generated OIDC nonce, if `openid` was requested.
    pub fn nonce(&self) -> Option<String> {
        self.inner.nonce().map(str::to_owned)
    }

    /// Validates a callback URI and extracts its authorization response.
    pub fn parse_redirect(
        &self,
        redirect_uri: String,
    ) -> std::result::Result<Arc<FfiAuthorizationResponse>, FfiError> {
        let redirect_uri = parse_url(&redirect_uri, "authorization redirect")?;
        let inner = self.inner.parse_redirect(&redirect_uri)?;
        Ok(Arc::new(FfiAuthorizationResponse { inner }))
    }

    /// Exchanges the validated code, verifies any ID Token, and returns token state.
    pub async fn exchange_code(
        &self,
        response: Arc<FfiAuthorizationResponse>,
        cancellation: Arc<FfiCancellationHandle>,
    ) -> std::result::Result<Arc<FfiAuthenticationState>, FfiError> {
        let transport = NativeTransport {
            inner: self.transport.clone(),
        };
        let token_response = self
            .inner
            .exchange_code(&transport, &response.inner, cancellation.inner.clone())
            .await?;
        let inner = self.inner.authentication_state(token_response)?;
        Ok(Arc::new(FfiAuthenticationState {
            inner: tokio::sync::Mutex::new(inner),
        }))
    }
}

/// Token values returned by an OAuth token endpoint.
#[derive(uniffi::Record)]
pub struct FfiTokenResponse {
    /// The bearer access token.
    pub access_token: String,
    /// The token type, typically `Bearer`.
    pub token_type: String,
    /// Access-token lifetime in seconds, if supplied.
    pub expires_in: Option<u64>,
    /// Refresh token, if supplied.
    pub refresh_token: Option<String>,
    /// Granted scopes, if supplied.
    pub scope: Option<String>,
    /// Raw ID Token value, verified before return when present.
    pub id_token: Option<String>,
    /// Unrecognized token response values serialized as JSON text.
    pub additional_parameters: Vec<FfiJsonParameter>,
}

impl From<&TokenResponse> for FfiTokenResponse {
    fn from(response: &TokenResponse) -> Self {
        Self {
            access_token: response.access_token.clone(),
            token_type: response.token_type.clone(),
            expires_in: response.expires_in,
            refresh_token: response.refresh_token.clone(),
            scope: response.scope.clone(),
            id_token: response.id_token.clone(),
            additional_parameters: response
                .additional_parameters
                .iter()
                .map(|(name, value)| FfiJsonParameter {
                    name: name.clone(),
                    value_json: value.to_string(),
                })
                .collect(),
        }
    }
}

/// Serializable token state. The host application is responsible for secure storage.
#[derive(uniffi::Object)]
pub struct FfiAuthenticationState {
    inner: tokio::sync::Mutex<AuthenticationState>,
}

#[uniffi::export]
impl FfiAuthenticationState {
    #[uniffi::constructor]
    /// Restores authentication state from JSON previously produced by [`Self::to_json`].
    pub fn from_json(serialized: String) -> std::result::Result<Arc<Self>, FfiError> {
        let inner = serde_json::from_str(&serialized).map_err(|_| {
            FfiError::InvalidRequest("invalid authentication state JSON".to_owned())
        })?;
        Ok(Arc::new(Self {
            inner: tokio::sync::Mutex::new(inner),
        }))
    }

    /// Serializes this sensitive state for host-managed secure storage.
    pub async fn to_json(&self) -> std::result::Result<String, FfiError> {
        serde_json::to_string(&*self.inner.lock().await)
            .map_err(|error| FfiError::Internal(error.to_string()))
    }

    /// Returns the current token response.
    pub async fn token_response(&self) -> FfiTokenResponse {
        FfiTokenResponse::from(self.inner.lock().await.token_response())
    }

    /// Returns access-token expiration as Unix time, if known.
    pub async fn expires_at(&self) -> Option<u64> {
        self.inner.lock().await.expires_at()
    }

    /// Returns whether the access token has expired at the supplied Unix time.
    pub async fn is_expired_at(&self, unix_time_seconds: u64) -> Option<bool> {
        self.inner.lock().await.is_expired_at(unix_time_seconds)
    }

    /// Refreshes tokens explicitly and updates state only after a successful response.
    pub async fn refresh(
        &self,
        configuration: Arc<FfiServiceConfiguration>,
        client_id: String,
        additional_parameters: Vec<FfiParameter>,
        transport: Arc<dyn NativeHttpTransport>,
        cancellation: Arc<FfiCancellationHandle>,
    ) -> std::result::Result<(), FfiError> {
        ensure_unique_parameter_names(&additional_parameters)?;
        let additional_parameters = additional_parameters
            .into_iter()
            .map(|parameter| (parameter.name, parameter.value))
            .collect();
        let transport = NativeTransport { inner: transport };
        self.inner
            .lock()
            .await
            .refresh_with_additional_parameters(
                &configuration.inner,
                &client_id,
                &additional_parameters,
                &transport,
                cancellation.inner.clone(),
            )
            .await?;
        Ok(())
    }
}

/// Inputs for dynamic registration of a native public client.
#[derive(uniffi::Record)]
pub struct FfiRegistrationOptions {
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Optional display name sent to the registration endpoint.
    pub client_name: Option<String>,
    /// Optional per-request bearer token for a protected registration endpoint.
    pub initial_access_token: Option<String>,
}

/// Public client identifier returned by dynamic registration.
#[derive(uniffi::Record)]
pub struct FfiClientRegistrationResponse {
    /// Registered client ID.
    pub client_id: String,
}

#[uniffi::export]
/// Registers and returns the client ID for a native public client.
pub async fn register_public_client(
    configuration: Arc<FfiServiceConfiguration>,
    options: FfiRegistrationOptions,
    transport: Arc<dyn NativeHttpTransport>,
    cancellation: Arc<FfiCancellationHandle>,
) -> std::result::Result<FfiClientRegistrationResponse, FfiError> {
    let redirect_uris = options
        .redirect_uris
        .iter()
        .map(|uri| parse_url(uri, "redirect URI"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut request = ClientRegistrationRequest::new(&configuration.inner, redirect_uris)?;
    if let Some(client_name) = options.client_name {
        request = request.with_client_name(client_name)?;
    }
    if let Some(initial_access_token) = options.initial_access_token {
        request = request.with_initial_access_token(initial_access_token)?;
    }
    let transport = NativeTransport { inner: transport };
    let response = request
        .register(&transport, cancellation.inner.clone())
        .await?;
    Ok(FfiClientRegistrationResponse {
        client_id: response.client_id().to_owned(),
    })
}

/// Inputs for an OpenID Connect RP-Initiated Logout request.
#[derive(uniffi::Record)]
pub struct FfiEndSessionOptions {
    /// Public client identifier.
    pub client_id: String,
    /// Optional ID Token hint.
    pub id_token_hint: Option<String>,
    /// Optional callback URI; when set, a random state is validated on return.
    pub post_logout_redirect_uri: Option<String>,
}

/// A validated end-session callback.
#[derive(uniffi::Record)]
pub struct FfiEndSessionResponse {
    /// Validated state value.
    pub state: String,
    /// Unrecognized response parameters.
    pub additional_parameters: Vec<FfiParameter>,
}

/// Logout URL and state used to validate an optional post-logout callback.
#[derive(uniffi::Object)]
pub struct FfiEndSessionSession {
    inner: crate::EndSessionSession,
}

#[uniffi::export]
impl FfiEndSessionSession {
    /// Returns the URL to open in an external user agent.
    pub fn end_session_url(&self) -> String {
        self.inner.end_session_url().to_string()
    }

    /// Validates the post-logout callback URI and returns its response.
    pub fn parse_redirect(
        &self,
        redirect_uri: String,
    ) -> std::result::Result<FfiEndSessionResponse, FfiError> {
        let redirect_uri = parse_url(&redirect_uri, "end-session redirect")?;
        let response = self.inner.parse_redirect(&redirect_uri)?;
        Ok(FfiEndSessionResponse {
            state: response.state().to_owned(),
            additional_parameters: response
                .additional_parameters()
                .iter()
                .map(|(name, value)| FfiParameter {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect(),
        })
    }
}

#[uniffi::export]
/// Creates a logout session for a configured end-session endpoint.
pub fn begin_end_session(
    configuration: Arc<FfiServiceConfiguration>,
    options: FfiEndSessionOptions,
) -> std::result::Result<Arc<FfiEndSessionSession>, FfiError> {
    let mut request = EndSessionRequest::new(&configuration.inner, options.client_id)?;
    if let Some(id_token_hint) = options.id_token_hint {
        request = request.with_id_token_hint(id_token_hint)?;
    }
    if let Some(redirect_uri) = options.post_logout_redirect_uri {
        request = request
            .with_post_logout_redirect_uri(parse_url(&redirect_uri, "post-logout redirect URI")?)?;
    }
    Ok(Arc::new(FfiEndSessionSession {
        inner: request.begin()?,
    }))
}

fn parse_url(value: &str, description: &str) -> std::result::Result<Url, FfiError> {
    Url::parse(value)
        .map_err(|_| FfiError::InvalidRequest(format!("{description} is not a valid URL")))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use http::Method;

    use super::*;

    struct RecordingTransport {
        request: Mutex<Option<FfiHttpRequest>>,
        response: std::result::Result<FfiHttpResponse, FfiError>,
    }

    #[async_trait]
    impl NativeHttpTransport for RecordingTransport {
        async fn execute(
            &self,
            request: FfiHttpRequest,
            _cancellation: Arc<FfiCancellationHandle>,
        ) -> std::result::Result<FfiHttpResponse, FfiError> {
            *self.request.lock().unwrap() = Some(request);
            match &self.response {
                Ok(response) => Ok(FfiHttpResponse {
                    status: response.status,
                    headers: response
                        .headers
                        .iter()
                        .map(|header| FfiHttpHeader {
                            name: header.name.clone(),
                            value: header.value.clone(),
                        })
                        .collect(),
                    body: response.body.clone(),
                }),
                Err(FfiError::Cancelled) => Err(FfiError::Cancelled),
                Err(_) => Err(FfiError::Transport),
            }
        }
    }

    fn authorization_options() -> FfiAuthorizationOptions {
        FfiAuthorizationOptions {
            client_id: "native-client".into(),
            redirect_uri: "com.example.app:/callback".into(),
            scopes: vec![],
            additional_parameters: vec![],
            additional_token_parameters: vec![],
        }
    }

    #[test]
    fn native_authorization_rejects_reserved_and_duplicate_additional_parameters() {
        let configuration = FfiServiceConfiguration::new(
            "https://issuer.example/authorize".into(),
            "https://issuer.example/token".into(),
        )
        .unwrap();
        let transport = Arc::new(RecordingTransport {
            request: Mutex::new(None),
            response: Err(FfiError::Transport),
        });
        for (token, names) in [
            (
                false,
                vec![
                    "",
                    "client_id",
                    "code_challenge",
                    "code_challenge_method",
                    "nonce",
                    "redirect_uri",
                    "response_type",
                    "scope",
                    "state",
                ],
            ),
            (
                true,
                vec![
                    "",
                    "client_assertion",
                    "client_assertion_type",
                    "client_id",
                    "client_secret",
                    "code",
                    "code_verifier",
                    "grant_type",
                    "redirect_uri",
                    "refresh_token",
                    "scope",
                ],
            ),
        ] {
            for name in names {
                let mut options = authorization_options();
                let parameters = if token {
                    &mut options.additional_token_parameters
                } else {
                    &mut options.additional_parameters
                };
                parameters.push(FfiParameter {
                    name: name.into(),
                    value: "override".into(),
                });
                assert!(
                    matches!(
                        begin_authorization(configuration.clone(), options, transport.clone()),
                        Err(FfiError::InvalidRequest(_))
                    ),
                    "accepted {name}, token={token}"
                );
            }
            let mut options = authorization_options();
            let parameters = if token {
                &mut options.additional_token_parameters
            } else {
                &mut options.additional_parameters
            };
            for value in ["first", "second"] {
                parameters.push(FfiParameter {
                    name: "audience".into(),
                    value: value.into(),
                });
            }
            assert!(matches!(
                begin_authorization(configuration.clone(), options, transport.clone()),
                Err(FfiError::InvalidRequest(_))
            ));
        }
        assert!(transport.request.lock().unwrap().is_none());
    }

    #[test]
    fn native_callback_uses_core_encoding_and_session_validation() {
        let configuration = FfiServiceConfiguration::new(
            "https://issuer.example/authorize".into(),
            "https://issuer.example/token".into(),
        )
        .unwrap();
        let transport = Arc::new(RecordingTransport {
            request: Mutex::new(None),
            response: Err(FfiError::Transport),
        });
        let session =
            begin_authorization(configuration, authorization_options(), transport.clone()).unwrap();
        let url = Url::parse(&session.authorization_url()).unwrap();
        let state = url
            .query_pairs()
            .find(|(name, _)| name == "state")
            .unwrap()
            .1
            .into_owned();
        for query in [
            format!("code=%FF&state={state}"),
            format!("code=value&state={state}&%73tate={state}"),
            "code=value&state=another-operation".into(),
        ] {
            assert!(matches!(
                session.parse_redirect(format!("com.example.app:/callback?{query}")),
                Err(FfiError::InvalidResponse(_))
            ));
        }
        let response = session
            .parse_redirect(format!(
                "com.example.app:/callback?code=a%2Bb&state={state}"
            ))
            .unwrap();
        assert_eq!(response.code(), "a+b");
        assert!(transport.request.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn native_revocation_preserves_status_and_oauth_error_classification() {
        let configuration = FfiServiceConfiguration::new(
            "https://issuer.example/authorize".into(),
            "https://issuer.example/token".into(),
        )
        .unwrap()
        .with_revocation_endpoint("https://issuer.example/revoke".into())
        .unwrap();
        for (status, body) in [
            (200, "not JSON"),
            (204, ""),
            (400, r#"{"error":"unsupported_token_type"}"#),
            (400, r#"{"error":"one","error":"two"}"#),
            (503, r#"{"error":"temporarily_unavailable"}"#),
        ] {
            let transport = Arc::new(RecordingTransport {
                request: Mutex::new(None),
                response: Ok(FfiHttpResponse {
                    status,
                    headers: vec![],
                    body: body.as_bytes().to_vec(),
                }),
            });
            let result = revoke(
                configuration.clone(),
                "client".into(),
                "token".into(),
                Some("refresh_token".into()),
                transport.clone(),
                FfiCancellationHandle::new(),
            )
            .await;
            match status {
                200 => result.unwrap(),
                400 if body.contains("unsupported_token_type") => assert!(
                    matches!(result, Err(FfiError::AuthorizationServer { code, .. }) if code == "unsupported_token_type")
                ),
                _ => assert!(
                    matches!(result, Err(FfiError::HttpStatus { status: actual }) if actual == status)
                ),
            }
            assert!(transport.request.lock().unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn native_revocation_rejects_unknown_hint_and_precancelled_requests() {
        let configuration = FfiServiceConfiguration::new(
            "https://issuer.example/authorize".into(),
            "https://issuer.example/token".into(),
        )
        .unwrap()
        .with_revocation_endpoint("https://issuer.example/revoke".into())
        .unwrap();
        let transport = Arc::new(RecordingTransport {
            request: Mutex::new(None),
            response: Err(FfiError::Transport),
        });
        assert!(matches!(
            revoke(
                configuration.clone(),
                "client".into(),
                "token".into(),
                Some("unknown_hint".into()),
                transport.clone(),
                FfiCancellationHandle::new()
            )
            .await,
            Err(FfiError::InvalidRequest(_))
        ));
        let cancellation = FfiCancellationHandle::new();
        cancellation.cancel();
        assert!(matches!(
            revoke(
                configuration,
                "client".into(),
                "token".into(),
                None,
                transport.clone(),
                cancellation
            )
            .await,
            Err(FfiError::Cancelled)
        ));
        assert!(transport.request.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn native_transport_preserves_http_data_and_cancellation() {
        let recording = Arc::new(RecordingTransport {
            request: Mutex::new(None),
            response: Ok(FfiHttpResponse {
                status: 201,
                headers: vec![FfiHttpHeader {
                    name: "x-response".to_owned(),
                    value: b"ok".to_vec(),
                }],
                body: b"response".to_vec(),
            }),
        });
        let transport = NativeTransport {
            inner: recording.clone(),
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-request", HeaderValue::from_static("value"));
        let response = transport
            .execute(
                HttpRequest {
                    method: Method::POST,
                    url: Url::parse("https://issuer.example/token").unwrap(),
                    headers,
                    body: b"request".to_vec(),
                },
                CancellationHandle::new(),
            )
            .await
            .unwrap();

        let request = recording.request.lock().unwrap().take().unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.url, "https://issuer.example/token");
        assert_eq!(request.headers[0].name, "x-request");
        assert_eq!(request.headers[0].value, b"value");
        assert_eq!(request.body, b"request");
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.headers["x-response"], "ok");
        assert_eq!(response.body, b"response");

        let cancelled = NativeTransport {
            inner: Arc::new(RecordingTransport {
                request: Mutex::new(None),
                response: Err(FfiError::Cancelled),
            }),
        };
        assert!(matches!(
            cancelled
                .execute(
                    HttpRequest {
                        method: Method::GET,
                        url: Url::parse("https://issuer.example/keys").unwrap(),
                        headers: HeaderMap::new(),
                        body: Vec::new(),
                    },
                    CancellationHandle::new(),
                )
                .await,
            Err(AuthError::Cancelled)
        ));
    }
}
