#[cfg(windows)]
use std::ffi::{c_char, CStr, CString};
#[cfg(windows)]
use std::ptr;

#[cfg(any(windows, test))]
use crate::windows::data::*;

#[cfg(any(windows, test))]
use crate::windows::loopback::*;

#[cfg(windows)]
use crate::windows::ops::*;

/// Opaque cancellation handle for a blocking Windows authorization call.
#[cfg(windows)]
pub struct NativeOidcWindowsCancellationHandle {
    cancellation: crate::CancellationHandle,
}

/// Opaque result returned by [`native_oidc_windows_authorize`].
#[cfg(windows)]
pub struct NativeOidcWindowsAuthorizationResult {
    status: i32,
    value: CString,
}

/// Opaque result returned by [`native_oidc_windows_refresh`].
#[cfg(windows)]
pub type NativeOidcWindowsRefreshResult = NativeOidcWindowsAuthorizationResult;

/// Opaque result returned by [`native_oidc_windows_end_session`].
#[cfg(windows)]
pub type NativeOidcWindowsEndSessionResult = NativeOidcWindowsAuthorizationResult;

#[cfg(windows)]
/// Opaque result returned by [`native_oidc_windows_revoke`].
pub type NativeOidcWindowsRevocationResult = NativeOidcWindowsAuthorizationResult;

#[cfg(windows)]
impl NativeOidcWindowsAuthorizationResult {
    fn new(status: i32, value: impl Into<String>) -> *mut Self {
        let value = value.into().replace('\0', "\\u0000");
        let value = CString::new(value).expect("NUL characters were escaped");
        Box::into_raw(Box::new(Self { status, value }))
    }
}

#[cfg(windows)]
fn parse_redirect_template(template: &str) -> std::result::Result<Url, crate::windows::WindowsAuthorizationError> {
    let mut redirect =
        Url::parse(template).map_err(|_| crate::windows::WindowsAuthorizationError::InvalidRedirectUri)?;
    if redirect.scheme() != "http"
        || redirect.host_str() != Some("127.0.0.1")
        || redirect.port().is_some()
        || !redirect.username().is_empty()
        || redirect.password().is_some()
        || redirect.fragment().is_some()
    {
        return Err(crate::windows::WindowsAuthorizationError::InvalidRedirectUri);
    }
    if redirect.path().is_empty() {
        redirect.set_path("/");
    }
    Ok(redirect)
}

#[cfg(windows)]
async fn wait_for_callback(
    listener: tokio::net::TcpListener,
    callback_path: &str,
    port: u16,
    cancellation: crate::CancellationHandle,
) -> std::result::Result<Url, crate::windows::WindowsAuthorizationError> {
    let mut connections = tokio::task::JoinSet::new();
    const MAX_CALLBACK_CONNECTIONS: usize = 32;
    const CALLBACK_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    let result = loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break Err(crate::AuthError::Cancelled.into()),
            finished = connections.join_next(), if !connections.is_empty() => {
                match finished {
                    Some(Ok(Ok(Some(callback)))) => break Ok(callback),
                    Some(Ok(Err(crate::windows::WindowsAuthorizationError::Core(error)))) => break Err(error.into()),
                    // A disconnected unrelated client must not terminate authorization.
                    Some(Ok(Ok(None) | Err(crate::windows::WindowsAuthorizationError::Loopback(_)))) => {},
                    Some(Err(error)) => break Err(std::io::Error::other(error).into()),
                    _ => {},
                }
            }
            accepted = listener.accept(), if connections.len() < MAX_CALLBACK_CONNECTIONS => {
                let (stream, _) = match accepted { Ok(connection) => connection, Err(error) => break Err(error.into()) };
                let path = callback_path.to_owned();
                let cancellation = cancellation.clone();
                connections.spawn(async move {
                    match tokio::time::timeout(CALLBACK_REQUEST_TIMEOUT,
                        handle_callback_connection(stream, &path, port, cancellation)).await {
                        Ok(result) => result,
                        Err(_) => Ok(None),
                    }
                });
            }
        }
    };
    // Drop sockets before returning success, error or cancellation.
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    result
}

#[cfg(windows)]
async fn handle_callback_connection(
    mut stream: tokio::net::TcpStream,
    callback_path: &str,
    port: u16,
    cancellation: crate::CancellationHandle,
) -> std::result::Result<Option<Url>, crate::windows::WindowsAuthorizationError> {
    let request = read_request_headers(&mut stream, &cancellation).await?;
    let outcome = request
        .as_deref()
        .map(|request| parse_callback_request(request, callback_path, port))
        .unwrap_or(crate::windows::loopback::CallbackRequest::Malformed {
            matches_path: false,
        });
    match outcome {
        crate::windows::loopback::CallbackRequest::Unrelated => write_response(&mut stream, 404, "Not Found").await?,
        crate::windows::loopback::CallbackRequest::Malformed {
            matches_path: false,
        } => write_response(&mut stream, 400, "Invalid request").await?,
        crate::windows::loopback::CallbackRequest::Malformed { matches_path: true } => {
            // Parsing, rather than the peer's willingness to read an error page,
            // determines whether a matching malformed callback is terminal.
            let _ = write_response(&mut stream, 400, "Invalid request").await;
            return crate::AuthError::InvalidAuthorizationResponse(
                "malformed loopback callback request",
            )
            .into();
        }
        crate::windows::loopback::CallbackRequest::Matching(callback) => {
            let _ = write_response(
                &mut stream,
                200,
                "Authorization complete. You may close this window.",
            )
            .await;
            return Ok(Some(callback));
        }
    }
    Ok(None)
}

#[cfg(windows)]
fn parse_callback_request(bytes: &[u8], callback_path: &str, port: u16) -> crate::windows::loopback::CallbackRequest {
    let Some(headers_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return crate::windows::loopback::CallbackRequest::Malformed {
            matches_path: false,
        };
    };
    let Ok(headers) = std::str::from_utf8(&bytes[..headers_end]) else {
        return crate::windows::loopback::CallbackRequest::Malformed {
            matches_path: false,
        };
    };
    let mut lines = headers.split("\r\n");
    let Some(request_line) = lines.next() else {
        return crate::windows::loopback::CallbackRequest::Malformed {
            matches_path: false,
        };
    };
    let request_parts: Vec<_> = request_line.split_whitespace().collect();
    if request_parts.len() != 3 {
        return crate::windows::loopback::CallbackRequest::Malformed {
            matches_path: false,
        };
    }
    let target = request_parts[1];
    if !target.starts_with('/') || target.contains('#') {
        return crate::windows::loopback::CallbackRequest::Malformed {
            matches_path: false,
        };
    }
    let request_path = target.split('?').next().unwrap_or_default();
    if request_path != callback_path {
        return crate::windows::loopback::CallbackRequest::Unrelated;
    }
    if request_parts[0] != "GET"
        || (request_parts[2] != "HTTP/1.0" && request_parts[2] != "HTTP/1.1")
    {
        return crate::windows::loopback::CallbackRequest::Malformed { matches_path: true };
    }

    let expected_host = format!("127.0.0.1:{port}");
    let mut host_headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return crate::windows::loopback::CallbackRequest::Malformed { matches_path: true };
        };
        if name.eq_ignore_ascii_case("host") {
            host_headers.push(value.trim());
        }
    }
    if host_headers.as_slice() != [expected_host.as_str()] {
        return crate::windows::loopback::CallbackRequest::Malformed { matches_path: true };
    }

    match Url::parse(&format!("http://127.0.0.1:{port}{target}")) {
        Ok(callback) => crate::windows::loopback::CallbackRequest::Matching(callback),
        Err(_) => crate::windows::loopback::CallbackRequest::Malformed { matches_path: true },
    }
}

#[cfg(windows)]
async fn read_request_headers(
    stream: &mut tokio::net::TcpStream,
    cancellation: &crate::CancellationHandle,
) -> std::result::Result<Option<Vec<u8>>, crate::windows::WindowsAuthorizationError> {
    let mut request = Vec::new();
    const MAX_REQUEST_SIZE: usize = 16 * 1024;
    let mut chunk = [0; 1024];
    while request.len() < MAX_REQUEST_SIZE {
        let read = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(crate::AuthError::Cancelled.into()),
            read = stream.read(&mut chunk) => read?,
        };
        if read == 0 {
            return Ok(None);
        }
        request.extend_from_slice(&chunk[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(Some(request));
        }
    }
    Ok(Some(request))
}

#[cfg(windows)]
async fn write_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    body: &str,
) -> std::result::Result<(), crate::windows::WindowsAuthorizationError> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

/// Creates a cancellation handle for [`native_oidc_windows_authorize`].
///
/// The returned handle must be freed with
/// [`native_oidc_windows_cancellation_free`].
#[cfg(windows)]
pub fn native_oidc_windows_cancellation_new() -> *mut NativeOidcWindowsCancellationHandle
{
    Box::into_raw(Box::new(NativeOidcWindowsCancellationHandle {
        cancellation: crate::CancellationHandle::new(),
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
#[cfg(windows)]
pub unsafe fn native_oidc_windows_cancellation_cancel(
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
#[cfg(windows)]
pub unsafe fn native_oidc_windows_cancellation_free(
    handle: *mut NativeOidcWindowsCancellationHandle,
) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[cfg(windows)]
fn open_system_browser(url: &Url) -> std::result::Result<(), crate::windows::WindowsAuthorizationError> {
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
        return Err(crate::windows::WindowsAuthorizationError::BrowserCouldNotBeOpened);
    }
    Ok(())
}

#[cfg(windows)]
fn authorize(
    request: crate::windows::data::WindowsAuthorizationRequest,
    cancellation: crate::CancellationHandle,
) -> std::result::Result<crate::AuthenticationState, crate::windows::WindowsAuthorizationError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| crate::windows::WindowsAuthorizationError::RuntimeInitialization(error.to_string()))?
        .block_on(crate::windows::ops::authorize_with_browser(
            request,
            cancellation,
            open_system_browser,
        ))
}

#[cfg(windows)]
fn refresh(
    request: crate::windows::data::WindowsRefreshRequest,
    cancellation: crate::CancellationHandle,
) -> std::result::Result<crate::AuthenticationState, crate::windows::WindowsAuthorizationError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| crate::windows::WindowsAuthorizationError::RuntimeInitialization(error.to_string()))?
        .block_on(crate::windows::ops::refresh_with_windows_request(request, cancellation))
}

#[cfg(windows)]
fn end_session(
    request: crate::windows::data::WindowsEndSessionRequest,
    cancellation: crate::CancellationHandle,
) -> std::result::Result<Option<crate::windows::data::WindowsEndSessionResponse>, crate::windows::WindowsAuthorizationError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| crate::windows::WindowsAuthorizationError::RuntimeInitialization(error.to_string()))?
        .block_on(crate::windows::ops::end_session_with_browser(
            request,
            cancellation,
            open_system_browser,
        ))
}

#[cfg(windows)]
fn revoke(
    request: crate::windows::data::WindowsRevocationRequest,
    cancellation: crate::CancellationHandle,
) -> std::result::Result<(), crate::windows::WindowsAuthorizationError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| crate::windows::WindowsAuthorizationError::RuntimeInitialization(error.to_string()))?
        .block_on(crate::windows::ops::revoke_with_windows_request(request, cancellation))
}

#[cfg(windows)]
fn result(status: i32, value: impl Into<String>) -> *mut NativeOidcWindowsAuthorizationResult {
    NativeOidcWindowsAuthorizationResult::new(status, value)
}

#[cfg(windows)]
fn run_authorize(
    request_json: &str,
    cancellation: crate::CancellationHandle,
) -> *mut NativeOidcWindowsAuthorizationResult {
    let request = match serde_json::from_str::<crate::windows::data::WindowsAuthorizationRequest>(request_json) {
        Ok(request) => request,
        Err(error) => return result(STATUS_ERROR, error.to_string()),
    };
    match authorize(request, cancellation) {
        Ok(state) => match serde_json::to_string(&state) {
            Ok(state) => result(STATUS_SUCCESS, state),
            Err(error) => result(STATUS_ERROR, error.to_string()),
        },
        crate::windows::WindowsAuthorizationError::Core(crate::AuthError::Cancelled) => {
            result(STATUS_CANCELLED, crate::AuthError::Cancelled.to_string())
        }
        error => result(STATUS_ERROR, error.to_string()),
    }
}

#[cfg(windows)]
fn run_refresh(
    request_json: &str,
    cancellation: crate::CancellationHandle,
) -> *mut NativeOidcWindowsRefreshResult {
    let request = match serde_json::from_str::<crate::windows::data::WindowsRefreshRequest>(request_json) {
        Ok(request) => request,
        Err(error) => return result(STATUS_ERROR, error.to_string()),
    };
    match refresh(request, cancellation) {
        Ok(state) => match serde_json::to_string(&state) {
            Ok(state) => result(STATUS_SUCCESS, state),
            Err(error) => result(STATUS_ERROR, error.to_string()),
        },
        crate::windows::WindowsAuthorizationError::Core(crate::AuthError::Cancelled) => {
            result(STATUS_CANCELLED, crate::AuthError::Cancelled.to_string())
        }
        error => result(STATUS_ERROR, error.to_string()),
    }
}

#[cfg(windows)]
fn run_end_session(
    request_json: &str,
    cancellation: crate::CancellationHandle,
) -> *mut NativeOidcWindowsEndSessionResult {
    let request = match serde_json::from_str::<crate::windows::data::WindowsEndSessionRequest>(request_json) {
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
        crate::windows::WindowsAuthorizationError::Core(crate::AuthError::Cancelled) => {
            result(STATUS_CANCELLED, crate::AuthError::Cancelled.to_string())
        }
        error => result(STATUS_ERROR, error.to_string()),
    }
}

#[cfg(windows)]
fn run_revoke(
    request_json: &str,
    cancellation: crate::CancellationHandle,
) -> *mut NativeOidcWindowsRevocationResult {
    let request = match serde_json::from_str::<crate::windows::data::WindowsRevocationRequest>(request_json) {
        Ok(request) => request,
        Err(error) => return result(STATUS_ERROR, error.to_string()),
    };
    match revoke(request, cancellation) {
        Ok(()) => result(STATUS_SUCCESS, ""),
        crate::windows::WindowsAuthorizationError::Core(crate::AuthError::Cancelled) => {
            result(STATUS_CANCELLED, crate::AuthError::Cancelled.to_string())
        }
        error => result(STATUS_ERROR, error.to_string()),
    }
}

#[cfg(windows)]
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
#[cfg(windows)]
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
#[cfg(windows)]
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
#[cfg(windows)]
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
#[cfg(windows)]
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
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_authorization_result_status(
    authorization_result: *const NativeOidcWindowsAuthorizationResult,
) -> i32 {
    #[cfg(windows)]
    const STATUS_SUCCESS: i32 = 0;
    #[cfg(windows)]
    const STATUS_ERROR: i32 = 1;
    #[cfg(windows)]
    const STATUS_CANCELLED: i32 = 2;

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
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_authorization_result_value(
    authorization_result: *const NativeOidcWindowsAuthorizationResult,
) -> *const c_char {
    #[cfg(windows)]
    use std::ptr;

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
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn native_oidc_windows_authorization_result_free(
    authorization_result: *mut NativeOidcWindowsAuthorizationResult,
) {
    if !authorization_result.is_null() {
        drop(Box::from_raw(authorization_result));
    }
}
