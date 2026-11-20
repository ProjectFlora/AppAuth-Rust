/// Windows desktop C ABI for authorization, token refresh, end-session, and
/// token revocation through the external browser and loopback redirects.
#[cfg(any(windows, test))]
pub mod abi;
#[cfg(any(windows, test))]
pub mod data;
#[cfg(any(windows, test))]
pub mod ops;
#[cfg(any(windows, test))]
pub mod loopback;

#[cfg(any(windows, test))]
pub use abi::{
    NativeOidcWindowsAuthorizationResult, NativeOidcWindowsCancellationHandle,
    NativeOidcWindowsRefreshResult, NativeOidcWindowsEndSessionResult,
    NativeOidcWindowsRevocationResult, copy_utf8_string,
};

#[cfg(windows)]
pub use abi::{
    native_oidc_windows_authorize, native_oidc_windows_refresh,
    native_oidc_windows_end_session, native_oidc_windows_revoke,
    native_oidc_windows_authorization_result_status,
    native_oidc_windows_authorization_result_value,
    native_oidc_windows_authorization_result_free,
};

#[cfg(test)]
pub use abi::{
    native_oidc_windows_cancellation_new,
    native_oidc_windows_cancellation_cancel,
    native_oidc_windows_cancellation_free,
};

#[cfg(any(windows, test))]
pub use abi::native_oidc_windows_authorize;

}
