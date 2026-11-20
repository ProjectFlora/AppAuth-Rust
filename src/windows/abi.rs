use std::ffi::{c_char, CStr, CString};
use std::ptr;

use url::Url;

use crate::{AuthError, AuthenticationState, CancellationHandle};

use super::data::{
    WindowsAuthorizationError, WindowsAuthorizationRequest, WindowsEndSessionRequest,
    WindowsEndSessionResponse, WindowsRefreshRequest, WindowsRevocationRequest,
};
use super::ops::{
    authorize_with_browser, end_session_with_browser, refresh_with_windows_request,
    revoke_with_windows_request,
};

const STATUS_SUCCESS: i32 = 0;
const STATUS_ERROR: i32 = 1;
const STATUS_CANCELLED: i32 = 2;

/// Opaque cancellation handle for a blocking Windows authorization call.
pub struct NativeOidcWindowsCancellationHandle {
    cancellation: CancellationHandle,
}

/// Opaque result returned by [`native_oidc_windows_authorize`].
pub struct NativeOidcWindowsAuthorizationResult {
    status: i32,
    value: CString,
}

/// Opaque result returned by [`native_oidc_windows_refresh`].
pub type NativeOidcWindowsRefreshResult = NativeOidcWindowsAuthorizationResult;

/// Opaque result returned by [`native_oidc_windows_end_session`].
pub type NativeOidcWindowsEndSessionResult = NativeOidcWindowsAuthorizationResult;

/// Opaque result returned by [`native_oidc_windows_revoke`].
pub type NativeOidcWindowsRevocationResult = NativeOidcWindowsAuthorizationResult;

impl NativeOidcWindowsAuthorizationResult {
    fn new(status: i32, value: impl Into<String>) -> *mut Self {
        let value = value.into().replace('\0', "\\u0000");
        let value = CString::new(value).expect("NUL characters were escaped");
        Box::into_raw(Box::new(Self { status, value }))
    }
}

fn open_system_browser(url: &Url) -> std::result::Result<(), WindowsAuthorizationError> {
    use windows_sys::Win32::UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL};

    let operation: Vec<u16> = "open".encode_utf16().chain([0]).collect();
    let url: Vec<u16> = url.as_str().encode_utf16().chain([0]).collect();
    let result = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            url.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if result as isize <= 32 {
        return Err(WindowsAuthorizationError::BrowserCouldNotBeOpened);
    }
    Ok(())
}

fn authorize(
    request: WindowsAuthorizationRequest,
    cancellation: CancellationHandle,
) -> std::result::Result<AuthenticationState, WindowsAuthorizationError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| WindowsAuthorizationError::RuntimeInitialization(error.to_string()))?
        .block_on(authorize_with_browser(
            request,
            cancellation,
            open_system_browser,
        ))
}

fn refresh(
    request: WindowsRefreshRequest,
    cancellation: CancellationHandle,
) -> std::result::Result<AuthenticationState, WindowsAuthorizationError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| WindowsAuthorizationError::RuntimeInitialization(error.to_string()))?
        .block_on(refresh_with_windows_request(request, cancellation))
}

fn end_session(
    request: WindowsEndSessionRequest,
    cancellation: CancellationHandle,
) -> std::result::Result<Option<WindowsEndSessionResponse>, WindowsAuthorizationError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| WindowsAuthorizationError::RuntimeInitialization(error.to_string()))?
        .block_on(end_session_with_browser(
            request,
            cancellation,
            open_system_browser,
        ))
}

fn revoke(
    request: WindowsRevocationRequest,
    cancellation: CancellationHandle,
) -> std::result::Result<(), WindowsAuthorizationError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| WindowsAuthorizationError::RuntimeInitialization(error.to_string()))?
        .block_on(revoke_with_windows_request(request, cancellation))
}

fn result(status: i32, value: impl Into<String>) -> *mut NativeOidcWindowsAuthorizationResult {
    NativeOidcWindowsAuthorizationResult::new(status, value)
}

fn run_authorize(
    request_json: &str,
    cancellation: CancellationHandle,
) -> *mut NativeOidcWindowsAuthorizationResult {
    let request = match serde_json::from_str::<WindowsAuthorizationRequest>(request_json) {
        Ok(request) => request,
        Err(error) => return result(STATUS_ERROR, error.to_string()),
    };
    match authorize(request, cancellation) {
        Ok(state) => match serde_json::to_string(&state) {
            Ok(state) => result(STATUS_SUCCESS, state),
            Err(error) => result(STATUS_ERROR, error.to_string()),
        },
        Err(WindowsAuthorizationError::Core(AuthError::Cancelled)) => {
            result(STATUS_CANCELLED, AuthError::Cancelled.to_string())
        }
        Err(error) => result(STATUS_ERROR, error.to_string()),
    }
}

fn run_refresh(
    request_json: &str,
    cancellation: CancellationHandle,
) -> *mut NativeOidcWindowsRefreshResult {
    let request = match serde_json::from_str::<WindowsRefreshRequest>(request_json) {
        Ok(request) => request,
        Err(error) => return result(STATUS_ERROR, error.to_string()),
    };
    match refresh(request, cancellation) {
        Ok(state) => match serde_json::to_string(&state) {
            Ok(state) => result(STATUS_SUCCESS, state),
            Err(error) => result(STATUS_ERROR, error.to_string()),
        },
        Err(WindowsAuthorizationError::Core(AuthError::Cancelled)) => {
            result(STATUS_CANCELLED, AuthError::Cancelled.to_string())
        }
        Err(error) => result(STATUS_ERROR, error.to_string()),
    }
}

fn run_end_session(
    request_json: &str,
    cancellation: CancellationHandle,
) -> *mut NativeOidcWindowsEndSessionResult {
    let request = match serde_json::from_str::<WindowsEndSessionRequest>(request_json) {
        Ok(request) => request,
        Err(error) => return result(STATUS_ERROR, error.to_string()),
    };
    match end_session(request, cancellation) {
        Ok(response) => match response {
            Some(response) => match serde_json::to_string(&response) {
                Ok(response) => result(STATUS_SUCCESS, response),
                Err(error) => result(STATUS_ERROR, error.to_string()),
            },
            None => result(STATUS_SUCCESS, ""),
        },
        Err(WindowsAuthorizationError::Core(AuthError::Cancelled)) => {
            result(STATUS_CANCELLED, AuthError::Cancelled.to_string())
        }
        Err(error) => result(STATUS_ERROR, error.to_string()),
    }
}

fn run_revoke(
    request_json: &str,
    cancellation: CancellationHandle,
) -> *mut NativeOidcWindowsRevocationResult {
    let request = match serde_json::from_str::<WindowsRevocationRequest>(request_json) {
        Ok(request) => request,
        Err(error) => return result(STATUS_ERROR, error.to_string()),
    };
    match revoke(request, cancellation) {
        Ok(()) => result(STATUS_SUCCESS, ""),
        Err(WindowsAuthorizationError::Core(AuthError::Cancelled)) => {
            result(STATUS_CANCELLED, AuthError::Cancelled.to_string())
        }
        Err(error) => result(STATUS_ERROR, error.to_string()),
    }
}

unsafe fn copy_utf8_string(value: *const c_char) -> std::result::Result<String, &'static str> {
    if value.is_null() {
        return Err("input string must not be null");
    }
    // The C ABI requires a valid, NUL-terminated UTF-8 string.
    CStr::from_ptr(value)
        .to_str()
        .map(str::to_owned)
        .map_err(|_| "input string must be valid UTF-8")
}

/// Creates a cancellation handle for [`native_oidc_windows_authorize`].
///
/// The returned handle must be freed with
/// [`native_oidc_windows_cancellation_free`].
#[no_mangle]
pub extern "C" fn native_oidc_windows_cancellation_new() -> *mut NativeOidcWindowsCancellationHandle
{
    Box::into_raw(Box::new(NativeOidcWindowsCancellationHandle {
        cancellation: CancellationHandle::new(),
    }))
}

/// Requests cancellation of an active Windows authorization.
///
/// A null handle is ignored. Do not free the handle until the authorization
/// call has returned.
///
/// # Safety
///
/// `handle` must be null or a live handle returned by
/// [`native_oidc_windows_cancellation_new`].
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_cancellation_cancel(
    handle: *const NativeOidcWindowsCancellationHandle,
) {
    if let Some(handle) = handle.as_ref() {
        handle.cancellation.cancel();
    }
}

/// Frees a cancellation handle.
///
/// # Safety
///
/// `handle` must be null or a live handle returned by
/// [`native_oidc_windows_cancellation_new`], and no authorization call may still
/// be using it.
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_cancellation_free(
    handle: *mut NativeOidcWindowsCancellationHandle,
) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

/// Runs Windows authorization synchronously and returns a result handle.
///
/// The UTF-8 JSON request contains either `issuer` or both
/// `authorization_endpoint` and `token_endpoint`, plus `client_id`,
/// `redirect_uri`, and `scopes`. Optional `additional_parameters` and
/// `additional_token_parameters` fields are arrays of `{ "name", "value" }`
/// objects. With explicit endpoints, set both `issuer` and `jwks_uri` to
/// validate OIDC ID Tokens.
/// The redirect URI must be an unported `http://127.0.0.1` URI. The adapter
/// chooses an available port, starts a loopback listener, and opens the system
/// browser. Call this function on a worker thread; use the cancellation handle
/// to cancel it from another thread.
///
/// On success, the result value is serialized authentication state containing
/// sensitive tokens. The host application must store it securely.
///
/// # Safety
///
/// `request_json_utf8` must be null or a valid NUL-terminated UTF-8 string.
/// `cancellation` must be null or a live handle returned by
/// [`native_oidc_windows_cancellation_new`] that remains alive until this function
/// returns.
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_authorize(
    request_json_utf8: *const c_char,
    cancellation: *const NativeOidcWindowsCancellationHandle,
) -> *mut NativeOidcWindowsAuthorizationResult {
    if cancellation.is_null() {
        return result(STATUS_ERROR, "cancellation handle must not be null");
    }
    let request_json = match copy_utf8_string(request_json_utf8) {
        Ok(request_json) => request_json,
        Err(error) => return result(STATUS_ERROR, error),
    };
    let cancellation = match cancellation.as_ref() {
        Some(cancellation) => cancellation.cancellation.clone(),
        None => return result(STATUS_ERROR, "cancellation handle must not be null"),
    };
    run_authorize(&request_json, cancellation)
}

/// Runs token refresh synchronously and returns a result handle.
///
/// The UTF-8 JSON request contains either `issuer` or both
/// `authorization_endpoint` and `token_endpoint`, plus `client_id` and the
/// `state` object serialized by a previous successful result. Optional
/// `additional_parameters` is an array of `{ "name", "value" }` objects added
/// to the token request; names must be unique. With explicit endpoints, set
/// both `issuer` and `jwks_uri` to validate a refreshed ID Token.
///
/// On success, the result value is the updated serialized authentication
/// state. The host application must persist it securely so later refreshes
/// present the current refresh token.
///
/// # Safety
///
/// `request_json_utf8` must be null or a valid NUL-terminated UTF-8 string.
/// `cancellation` must be null or a live handle returned by
/// [`native_oidc_windows_cancellation_new`] that remains alive until this function
/// returns.
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_refresh(
    request_json_utf8: *const c_char,
    cancellation: *const NativeOidcWindowsCancellationHandle,
) -> *mut NativeOidcWindowsRefreshResult {
    if cancellation.is_null() {
        return result(STATUS_ERROR, "cancellation handle must not be null");
    }
    let request_json = match copy_utf8_string(request_json_utf8) {
        Ok(request_json) => request_json,
        Err(error) => return result(STATUS_ERROR, error),
    };
    let cancellation = match cancellation.as_ref() {
        Some(cancellation) => cancellation.cancellation.clone(),
        None => return result(STATUS_ERROR, "cancellation handle must not be null"),
    };
    run_refresh(&request_json, cancellation)
}

/// Runs an OIDC RP-Initiated Logout synchronously and returns a result handle.
///
/// The UTF-8 JSON request contains either `issuer` or both
/// `authorization_endpoint` and `token_endpoint`, plus `client_id`. With
/// explicit endpoints, `end_session_endpoint` is required; with discovery it
/// overrides the discovered endpoint. `id_token_hint` is optional. When
/// `post_logout_redirect_uri` is set, it must be an unported `http://127.0.0.1`
/// URI: the adapter chooses an available port, opens the system browser, and
/// validates the returned state on a loopback callback. Call this function on
/// a worker thread; use the cancellation handle to cancel it from another
/// thread.
///
/// On success with a post-logout redirect, the result value is a JSON object
/// with the validated `state` and any `additional_parameters`. Without a
/// redirect, the browser is opened and the result value is empty.
///
/// # Safety
///
/// `request_json_utf8` must be null or a valid NUL-terminated UTF-8 string.
/// `cancellation` must be null or a live handle returned by
/// [`native_oidc_windows_cancellation_new`] that remains alive until this function
/// returns.
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_end_session(
    request_json_utf8: *const c_char,
    cancellation: *const NativeOidcWindowsCancellationHandle,
) -> *mut NativeOidcWindowsEndSessionResult {
    if cancellation.is_null() {
        return result(STATUS_ERROR, "cancellation handle must not be null");
    }
    let request_json = match copy_utf8_string(request_json_utf8) {
        Ok(request_json) => request_json,
        Err(error) => return result(STATUS_ERROR, error),
    };
    let cancellation = match cancellation.as_ref() {
        Some(cancellation) => cancellation.cancellation.clone(),
        None => return result(STATUS_ERROR, "cancellation handle must not be null"),
    };
    run_end_session(&request_json, cancellation)
}

/// Requests token revocation synchronously and returns a result handle.
///
/// The UTF-8 JSON request contains either an `issuer` for discovery, or both
/// `authorization_endpoint` and `token_endpoint` with a
/// `revocation_endpoint`, plus `client_id` and `token`. An explicit
/// `revocation_endpoint` overrides a discovered endpoint. `token_type_hint`
/// is optional and must be `access_token` or `refresh_token`.
///
/// This operation does not delete local authentication state. Call it on a
/// worker thread and delete local state regardless of success or failure.
///
/// # Safety
///
/// `request_json_utf8` must be null or a valid NUL-terminated UTF-8 string.
/// `cancellation` must be null or a live handle returned by
/// [`native_oidc_windows_cancellation_new`] that remains alive until this function
/// returns.
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_revoke(
    request_json_utf8: *const c_char,
    cancellation: *const NativeOidcWindowsCancellationHandle,
) -> *mut NativeOidcWindowsRevocationResult {
    if cancellation.is_null() {
        return result(STATUS_ERROR, "cancellation handle must not be null");
    }
    let request_json = match copy_utf8_string(request_json_utf8) {
        Ok(request_json) => request_json,
        Err(error) => return result(STATUS_ERROR, error),
    };
    let cancellation = match cancellation.as_ref() {
        Some(cancellation) => cancellation.cancellation.clone(),
        None => return result(STATUS_ERROR, "cancellation handle must not be null"),
    };
    run_revoke(&request_json, cancellation)
}

/// Returns the status of an authorization result.
///
/// Values are `0` for success, `1` for failure, and `2` for cancellation. A
/// null result is treated as failure.
///
/// # Safety
///
/// `authorization_result` must be null or a live result handle returned by
/// [`native_oidc_windows_authorize`].
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_authorization_result_status(
    authorization_result: *const NativeOidcWindowsAuthorizationResult,
) -> i32 {
    authorization_result
        .as_ref()
        .map_or(STATUS_ERROR, |result| result.status)
}

/// Returns the UTF-8 JSON state or error message from a result.
///
/// The returned string is owned by the result and remains valid until the
/// result is freed.
///
/// # Safety
///
/// `authorization_result` must be null or a live result handle returned by
/// [`native_oidc_windows_authorize`].
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_authorization_result_value(
    authorization_result: *const NativeOidcWindowsAuthorizationResult,
) -> *const c_char {
    authorization_result
        .as_ref()
        .map_or(ptr::null(), |result| result.value.as_ptr())
}

/// Frees an authorization result.
///
/// # Safety
///
/// `authorization_result` must be null or a live result handle returned by
/// [`native_oidc_windows_authorize`].
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_authorization_result_free(
    authorization_result: *mut NativeOidcWindowsAuthorizationResult,
) {
    if !authorization_result.is_null() {
        drop(Box::from_raw(authorization_result));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_abi_returns_and_frees_an_error_result() {
        let cancellation = native_oidc_windows_cancellation_new();
        let request = CString::new(
            r#"{
                "issuer":"not a URL",
                "client_id":"client",
                "redirect_uri":"http://127.0.0.1/callback",
                "scopes":["profile"]
            }"#,
        )
        .unwrap();
        let result = unsafe { native_oidc_windows_authorize(request.as_ptr(), cancellation) };
        assert_eq!(
            unsafe { native_oidc_windows_authorization_result_status(result) },
            STATUS_ERROR
        );
        assert_eq!(
            unsafe {
                CStr::from_ptr(native_oidc_windows_authorization_result_value(result))
                    .to_str()
                    .unwrap()
            },
            "issuer URL is invalid"
        );
        unsafe {
            native_oidc_windows_authorization_result_free(result);
            native_oidc_windows_cancellation_free(cancellation);
        }
    }

    #[test]
    fn c_abi_refresh_returns_and_frees_an_error_result() {
        let cancellation = native_oidc_windows_cancellation_new();
        let request = CString::new(
            r#"{
                "issuer":"not a URL",
                "client_id":"client",
                "state":{
                    "token_response":{"access_token":"access","token_type":"Bearer"},
                    "expires_at":null
                }
            }"#,
        )
        .unwrap();
        let result = unsafe { native_oidc_windows_refresh(request.as_ptr(), cancellation) };
        assert_eq!(
            unsafe { native_oidc_windows_authorization_result_status(result) },
            STATUS_ERROR
        );
        assert_eq!(
            unsafe {
                CStr::from_ptr(native_oidc_windows_authorization_result_value(result))
                    .to_str()
                    .unwrap()
            },
            "issuer URL is invalid"
        );
        unsafe {
            native_oidc_windows_authorization_result_free(result);
            native_oidc_windows_cancellation_free(cancellation);
        }
    }

    #[test]
    fn c_abi_end_session_returns_and_frees_an_error_result() {
        let cancellation = native_oidc_windows_cancellation_new();
        let request = CString::new(
            r#"{
                "authorization_endpoint":"https://issuer.example/authorize",
                "token_endpoint":"https://issuer.example/token",
                "end_session_endpoint":"http://insecure.example/logout",
                "client_id":"client"
            }"#,
        )
        .unwrap();
        let result = unsafe { native_oidc_windows_end_session(request.as_ptr(), cancellation) };
        assert_eq!(
            unsafe { native_oidc_windows_authorization_result_status(result) },
            STATUS_ERROR
        );
        assert_eq!(
            unsafe {
                CStr::from_ptr(native_oidc_windows_authorization_result_value(result))
                    .to_str()
                    .unwrap()
            },
            "invalid configuration: end-session endpoint must use HTTPS without user info or fragments"
        );
        unsafe {
            native_oidc_windows_authorization_result_free(result);
            native_oidc_windows_cancellation_free(cancellation);
        }
    }
}
