//! Windows desktop C ABI for authorization, token refresh, end-session, and
//! token revocation through the external browser and loopback redirects.
//!
//! The module is split by layer: `data` holds the request, response, and
//! error types shared by the operations; `loopback` implements the loopback
//! callback listener; `ops` runs the blocking operations; and `abi` exposes
//! the Windows C ABI.
#[cfg(windows)]
mod abi;
mod data;
mod loopback;
mod ops;

#[cfg(windows)]
pub use abi::{
    native_oidc_windows_authorization_result_free,
    native_oidc_windows_authorization_result_status,
    native_oidc_windows_authorization_result_value,
    native_oidc_windows_authorize,
    native_oidc_windows_cancellation_cancel,
    native_oidc_windows_cancellation_free,
    native_oidc_windows_cancellation_new,
    native_oidc_windows_end_session,
    native_oidc_windows_refresh,
    native_oidc_windows_revoke,
    NativeOidcWindowsAuthorizationResult,
    NativeOidcWindowsCancellationHandle,
    NativeOidcWindowsEndSessionResult,
    NativeOidcWindowsRefreshResult,
    NativeOidcWindowsRevocationResult,
};
