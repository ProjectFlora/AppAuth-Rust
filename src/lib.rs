//! OAuth 2.0 and OpenID Connect client support for native applications.
//!
//! The crate provides a shared Rust protocol core, UniFFI bindings for Swift
//! and Kotlin adapters, and a Windows C ABI. Authorization uses the external
//! browser with Authorization Code + PKCE. The host application is responsible
//! for securely persisting serialized authentication state.
//!
//! Rust applications can use [`AuthorizationRequest`] with an implementation
//! of [`HttpTransport`]. Apple and Android applications use [`ffi`] with the
//! platform adapters; Windows C++ and .NET applications use the Windows
//! adapter's C ABI.
#![warn(missing_docs)]

mod authorization;
mod cancellation;
mod error;
mod id_token;
mod pkce;
mod transport;

/// UniFFI types and functions shared by the Swift and Kotlin adapters.
pub mod ffi;

/// Windows desktop authorization through the external browser and loopback redirect.
#[cfg(any(windows, test))]
pub mod windows;

uniffi::setup_scaffolding!();

pub use authorization::{
    revoke_token, AuthenticationState, AuthorizationRequest, AuthorizationResponse,
    AuthorizationSession, ClientRegistrationRequest, ClientRegistrationResponse, EndSessionRequest,
    EndSessionResponse, EndSessionSession, RevocationTokenType, ServiceConfiguration,
    TokenResponse,
};
pub use cancellation::CancellationHandle;
pub use error::{AuthError, Result};
pub use transport::{HttpRequest, HttpResponse, HttpTransport, ReqwestTransport};
