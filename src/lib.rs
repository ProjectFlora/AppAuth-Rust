//! OAuth 2.0 and OpenID Connect client support for native applications.
//!
//! The crate provides a shared Rust protocol core and a UniFFI surface for
//! platform-specific browser and HTTP adapters. Authorization uses the
//! external browser with Authorization Code + PKCE. The host application is
//! responsible for securely persisting serialized authentication state.
//!
//! Rust applications can use [`AuthorizationRequest`] with an implementation
//! of [`HttpTransport`]. Native applications should use the types in
//! [`ffi`] together with the platform adapters in this repository.
#![warn(missing_docs)]

mod authorization;
mod cancellation;
mod error;
mod id_token;
mod pkce;
mod transport;

/// UniFFI types and functions shared by the Swift and Kotlin adapters.
pub mod ffi;

uniffi::setup_scaffolding!();

pub use authorization::{
    AuthenticationState, AuthorizationRequest, AuthorizationResponse, AuthorizationSession,
    ClientRegistrationRequest, ClientRegistrationResponse, EndSessionRequest, EndSessionResponse,
    EndSessionSession, ServiceConfiguration, TokenResponse,
};
pub use cancellation::CancellationHandle;
pub use error::{AuthError, Result};
pub use transport::{HttpRequest, HttpResponse, HttpTransport, ReqwestTransport};
