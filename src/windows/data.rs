#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
struct WindowsAuthorizationRequest {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    #[serde(default)]
    additional_parameters: Vec<WindowsParameter>,
    #[serde(default)]
    additional_token_parameters: Vec<WindowsParameter>,
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
struct WindowsRevocationRequest {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    client_id: String,
    token: String,
    #[serde(default)]
    token_type_hint: Option<String>,
}

#[cfg(any(windows, test))]
#[derive(Deserialize)]
struct WindowsRefreshRequest {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
    client_id: String,
    state: crate::AuthenticationState,
    #[serde(default)]
    additional_parameters: Vec<WindowsParameter>,
}

#[cfg(any(windows, test))]
#[derive(Debug, Deserialize)]
struct WindowsEndSessionRequest {
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    end_session_endpoint: Option<String>,
    client_id: String,
    #[serde(default)]
    id_token_hint: Option<String>,
    #[serde(default)]
    post_logout_redirect_uri: Option<String>,
}

#[cfg(any(windows, test))]
#[derive(Debug, Serialize)]
struct WindowsEndSessionResponse {
    state: String,
    additional_parameters: Vec<WindowsParameter>,
}

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct WindowsParameter {
    name: String,
    value: String,
}

#[cfg(any(windows, test))]
#[derive(Debug, thiserror::Error)]
enum WindowsAuthorizationError {
    #[error(transparent)]
    Core(#[from] crate::AuthError),
    #[error("issuer URL is invalid")]
    InvalidIssuer,
    #[error("authorization or token endpoint URL is invalid")]
    InvalidEndpoint,
    #[error("redirect URI must be an unported http://127.0.0.1 loopback URI")]
    InvalidRedirectUri,
    #[error("parameter names must be unique")]
    DuplicateParameter,
    #[cfg(windows)]
    #[error("the system browser could not be opened")]
    BrowserCouldNotBeOpened,
    #[cfg(windows)]
    #[error("could not initialize the async runtime: {0}")]
    RuntimeInitialization(String),
    #[error("loopback server failed: {0}")]
    Loopback(#[from] std::io::Error),
}

/// The endpoint attachment performed while building a service configuration.
#[cfg(any(windows, test))]
#[derive(Debug, Copy, Clone)]
enum ConfigurationKind {
    /// Authorization and token refresh: attach OIDC validation endpoints.
    Oidc,
    /// Token revocation: attach the revocation endpoint.
    Revocation,
    /// End-session: attach the end-session endpoint.
    EndSession,
}

/// Endpoint strings selected by a request, shared by all blocking operations.
#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy)]
struct EndpointSelection<'a> {
    /// Issuer for discovery; used with discovery or with explicit endpoints for OIDC validation.
    issuer: Option<&'a str>,
    /// Authorization endpoint; required with explicit endpoints.
    authorization_endpoint: Option<&'a str>,
    /// Token endpoint; required with explicit endpoints.
    token_endpoint: Option<&'a str>,
    /// JWKS URI for ID Token validation; only used by `Oidc` operations.
    jwks_uri: Option<&'a str>,
    /// Revocation or end-session endpoint; required with explicit endpoints for those operations.
    named_endpoint: Option<&'a str>,
}

