use http::StatusCode;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid authorization response: {0}")]
    InvalidAuthorizationResponse(&'static str),
    #[error("invalid end-session response: {0}")]
    InvalidEndSessionResponse(&'static str),
    #[error("invalid token response: {0}")]
    InvalidTokenResponse(&'static str),
    #[error("invalid OIDC discovery metadata: {0}")]
    InvalidDiscoveryMetadata(&'static str),
    #[error("authorization server returned error: {code}")]
    AuthorizationServer {
        code: String,
        description: Option<String>,
    },
    #[error("HTTP transport failed")]
    Transport,
    #[error("HTTP endpoint returned status {0}")]
    HttpStatus(StatusCode),
    #[error("operation was cancelled")]
    Cancelled,
    #[error("system clock is before the Unix epoch")]
    Clock,
    #[error("secure random number generation failed")]
    Randomness,
}

pub type Result<T> = std::result::Result<T, AuthError>;
