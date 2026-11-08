use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use http::{header::HeaderName, HeaderMap, HeaderValue, StatusCode};
use url::Url;

use crate::{
    AuthError, AuthenticationState, AuthorizationRequest, AuthorizationResponse,
    AuthorizationSession, CancellationHandle, ClientRegistrationRequest, EndSessionRequest,
    HttpRequest, HttpResponse, HttpTransport, Result, ServiceConfiguration, TokenResponse,
};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("authorization server returned error: {code}")]
    AuthorizationServer {
        code: String,
        description: Option<String>,
    },
    #[error("client registration server returned error: {code}")]
    ClientRegistrationServer {
        code: String,
        description: Option<String>,
    },
    #[error("HTTP endpoint returned status {status}")]
    HttpStatus { status: u16 },
    #[error("HTTP transport failed")]
    Transport,
    #[error("HTTP transport failed: {0}")]
    TransportFailure(String),
    #[error("operation was cancelled")]
    Cancelled,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("secure random number generation failed")]
    Randomness,
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
pub struct FfiCancellationHandle {
    inner: CancellationHandle,
}

#[uniffi::export]
impl FfiCancellationHandle {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: CancellationHandle::new(),
        })
    }

    pub fn cancel(&self) {
        self.inner.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    pub async fn cancelled(&self) {
        self.inner.cancelled().await;
    }
}

#[derive(uniffi::Record)]
pub struct FfiHttpHeader {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct FfiHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<FfiHttpHeader>,
    pub body: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct FfiHttpResponse {
    pub status: u16,
    pub headers: Vec<FfiHttpHeader>,
    pub body: Vec<u8>,
}

/// Native transports must not follow redirects for OAuth requests.
#[uniffi::export(foreign)]
#[async_trait]
pub trait NativeHttpTransport: Send + Sync {
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
pub struct FfiServiceConfiguration {
    inner: ServiceConfiguration,
}

#[uniffi::export]
impl FfiServiceConfiguration {
    #[uniffi::constructor]
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

    pub fn with_end_session_endpoint(
        &self,
        endpoint: String,
    ) -> std::result::Result<Arc<Self>, FfiError> {
        let endpoint = parse_url(&endpoint, "end-session endpoint")?;
        let inner = self.inner.clone().with_end_session_endpoint(endpoint)?;
        Ok(Arc::new(Self { inner }))
    }

    pub fn with_registration_endpoint(
        &self,
        endpoint: String,
    ) -> std::result::Result<Arc<Self>, FfiError> {
        let endpoint = parse_url(&endpoint, "registration endpoint")?;
        let inner = self.inner.clone().with_registration_endpoint(endpoint)?;
        Ok(Arc::new(Self { inner }))
    }

    pub fn authorization_endpoint(&self) -> String {
        self.inner.authorization_endpoint().to_string()
    }

    pub fn token_endpoint(&self) -> String {
        self.inner.token_endpoint().to_string()
    }

    pub fn issuer(&self) -> Option<String> {
        self.inner.issuer().map(ToString::to_string)
    }

    pub fn jwks_uri(&self) -> Option<String> {
        self.inner.jwks_uri().map(ToString::to_string)
    }
}

#[derive(uniffi::Record)]
pub struct FfiParameter {
    pub name: String,
    pub value: String,
}

#[derive(uniffi::Record)]
pub struct FfiJsonParameter {
    pub name: String,
    pub value_json: String,
}

#[derive(uniffi::Record)]
pub struct FfiAuthorizationOptions {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub additional_parameters: Vec<FfiParameter>,
    pub additional_token_parameters: Vec<FfiParameter>,
}

#[uniffi::export]
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

#[derive(uniffi::Object)]
pub struct FfiAuthorizationResponse {
    inner: AuthorizationResponse,
}

#[uniffi::export]
impl FfiAuthorizationResponse {
    pub fn code(&self) -> String {
        self.inner.code().to_owned()
    }

    pub fn state(&self) -> String {
        self.inner.state().to_owned()
    }

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

#[derive(uniffi::Object)]
pub struct FfiAuthorizationSession {
    inner: AuthorizationSession,
    transport: Arc<dyn NativeHttpTransport>,
}

#[uniffi::export]
impl FfiAuthorizationSession {
    pub fn authorization_url(&self) -> String {
        self.inner.authorization_url().to_string()
    }

    pub fn nonce(&self) -> Option<String> {
        self.inner.nonce().map(str::to_owned)
    }

    pub fn parse_redirect(
        &self,
        redirect_uri: String,
    ) -> std::result::Result<Arc<FfiAuthorizationResponse>, FfiError> {
        let redirect_uri = parse_url(&redirect_uri, "authorization redirect")?;
        let inner = self.inner.parse_redirect(&redirect_uri)?;
        Ok(Arc::new(FfiAuthorizationResponse { inner }))
    }

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

#[derive(uniffi::Record)]
pub struct FfiTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
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

#[derive(uniffi::Object)]
pub struct FfiAuthenticationState {
    inner: tokio::sync::Mutex<AuthenticationState>,
}

#[uniffi::export]
impl FfiAuthenticationState {
    #[uniffi::constructor]
    pub fn from_json(serialized: String) -> std::result::Result<Arc<Self>, FfiError> {
        let inner = serde_json::from_str(&serialized).map_err(|_| {
            FfiError::InvalidRequest("invalid authentication state JSON".to_owned())
        })?;
        Ok(Arc::new(Self {
            inner: tokio::sync::Mutex::new(inner),
        }))
    }

    pub async fn to_json(&self) -> std::result::Result<String, FfiError> {
        serde_json::to_string(&*self.inner.lock().await)
            .map_err(|error| FfiError::Internal(error.to_string()))
    }

    pub async fn token_response(&self) -> FfiTokenResponse {
        FfiTokenResponse::from(self.inner.lock().await.token_response())
    }

    pub async fn expires_at(&self) -> Option<u64> {
        self.inner.lock().await.expires_at()
    }

    pub async fn is_expired_at(&self, unix_time_seconds: u64) -> Option<bool> {
        self.inner.lock().await.is_expired_at(unix_time_seconds)
    }

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

#[derive(uniffi::Record)]
pub struct FfiRegistrationOptions {
    pub redirect_uris: Vec<String>,
    pub client_name: Option<String>,
    pub initial_access_token: Option<String>,
}

#[derive(uniffi::Record)]
pub struct FfiClientRegistrationResponse {
    pub client_id: String,
}

#[uniffi::export]
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

#[derive(uniffi::Record)]
pub struct FfiEndSessionOptions {
    pub client_id: String,
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
}

#[derive(uniffi::Record)]
pub struct FfiEndSessionResponse {
    pub state: String,
    pub additional_parameters: Vec<FfiParameter>,
}

#[derive(uniffi::Object)]
pub struct FfiEndSessionSession {
    inner: crate::EndSessionSession,
}

#[uniffi::export]
impl FfiEndSessionSession {
    pub fn end_session_url(&self) -> String {
        self.inner.end_session_url().to_string()
    }

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
