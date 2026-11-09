use http::StatusCode;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// Errors produced while configuring or running an OAuth/OIDC operation.
pub enum AuthError {
    /// A client-supplied configuration value is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// The authorization redirect is malformed, mismatched, or belongs to another session.
    #[error("invalid authorization response: {0}")]
    InvalidAuthorizationResponse(&'static str),
    /// The end-session redirect is malformed or has an invalid state.
    #[error("invalid end-session response: {0}")]
    InvalidEndSessionResponse(&'static str),
    /// The token endpoint returned a malformed token response.
    #[error("invalid token response: {0}")]
    InvalidTokenResponse(&'static str),
    /// The registration endpoint returned an invalid public-client response.
    #[error("invalid client registration response: {0}")]
    InvalidClientRegistrationResponse(&'static str),
    /// An ID Token failed signature or claim validation.
    #[error("invalid ID Token: {0}")]
    InvalidIdToken(&'static str),
    /// The JWKS response could not be used to validate an ID Token.
    #[error("invalid JWKS: {0}")]
    InvalidJwks(&'static str),
    /// The discovery response was invalid or did not match the requested issuer.
    #[error("invalid OIDC discovery metadata: {0}")]
    InvalidDiscoveryMetadata(&'static str),
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
    /// The HTTP transport failed without additional detail.
    #[error("HTTP transport failed")]
    Transport,
    /// The HTTP transport failed and provided a diagnostic message.
    #[error("HTTP transport failed: {0}")]
    TransportFailure(String),
    /// An HTTP endpoint returned an unsuccessful status without an OAuth error body.
    #[error("HTTP endpoint returned status {0}")]
    HttpStatus(StatusCode),
    /// The operation was cancelled by the caller or platform.
    #[error("operation was cancelled")]
    Cancelled,
    /// The system clock is earlier than the Unix epoch.
    #[error("system clock is before the Unix epoch")]
    Clock,
    /// Secure random value generation failed.
    #[error("secure random number generation failed")]
    Randomness,
}

/// Result type used by the OAuth/OIDC core.
pub type Result<T> = std::result::Result<T, AuthError>;
