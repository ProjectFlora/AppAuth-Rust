use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{Ipv4Addr, SocketAddrV4},
    time::Duration,
};

use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::{
    ffi::{c_char, CStr, CString},
    ptr,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use url::Url;

use crate::{
    revoke_token, AuthError, AuthenticationState, AuthorizationRequest, CancellationHandle,
    EndSessionRequest, ReqwestTransport, RevocationTokenType, ServiceConfiguration,
};

const MAX_REQUEST_SIZE: usize = 16 * 1024;
const CALLBACK_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(windows)]
const STATUS_SUCCESS: i32 = 0;
#[cfg(windows)]
const STATUS_ERROR: i32 = 1;
#[cfg(windows)]
const STATUS_CANCELLED: i32 = 2;

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
    state: AuthenticationState,
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
    Core(#[from] AuthError),
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
    Loopback(#[from] io::Error),
}

/// Opaque cancellation handle for a blocking Windows authorization call.
#[cfg(windows)]
pub struct AppAuthWindowsCancellationHandle {
    cancellation: CancellationHandle,
}

/// Opaque result returned by [`appauth_windows_authorize`].
#[cfg(windows)]
pub struct AppAuthWindowsAuthorizationResult {
    status: i32,
    value: CString,
}

/// Opaque result returned by [`appauth_windows_refresh`].
#[cfg(windows)]
pub type AppAuthWindowsRefreshResult = AppAuthWindowsAuthorizationResult;

/// Opaque result returned by [`appauth_windows_end_session`].
#[cfg(windows)]
pub type AppAuthWindowsEndSessionResult = AppAuthWindowsAuthorizationResult;

#[cfg(windows)]
pub type AppAuthWindowsRevocationResult = AppAuthWindowsAuthorizationResult;

#[cfg(windows)]
impl AppAuthWindowsAuthorizationResult {
    fn new(status: i32, value: impl Into<String>) -> *mut Self {
        let value = value.into().replace('\0', "\\u0000");
        let value = CString::new(value).expect("NUL characters were escaped");
        Box::into_raw(Box::new(Self { status, value }))
    }
}

fn parse_redirect_template(template: &str) -> std::result::Result<Url, WindowsAuthorizationError> {
    let mut redirect =
        Url::parse(template).map_err(|_| WindowsAuthorizationError::InvalidRedirectUri)?;
    if redirect.scheme() != "http"
        || redirect.host_str() != Some("127.0.0.1")
        || redirect.port().is_some()
        || !redirect.username().is_empty()
        || redirect.password().is_some()
        || redirect.fragment().is_some()
    {
        return Err(WindowsAuthorizationError::InvalidRedirectUri);
    }
    if redirect.path().is_empty() {
        redirect.set_path("/");
    }
    Ok(redirect)
}

#[cfg(any(windows, test))]
fn ensure_unique_parameter_names(
    parameters: &[WindowsParameter],
) -> std::result::Result<(), WindowsAuthorizationError> {
    let mut names = BTreeSet::new();
    if parameters
        .iter()
        .any(|parameter| !names.insert(parameter.name.as_str()))
    {
        return Err(WindowsAuthorizationError::DuplicateParameter);
    }
    Ok(())
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
    issuer: Option<&'a str>,
    authorization_endpoint: Option<&'a str>,
    token_endpoint: Option<&'a str>,
    /// JWKS URI for ID Token validation; only used by `Oidc` operations.
    jwks_uri: Option<&'a str>,
    /// Revocation or end-session endpoint; only used by those operations.
    named_endpoint: Option<&'a str>,
}

/// Builds the service configuration shared by all blocking operations.
///
/// Either both `authorization_endpoint` and `token_endpoint` must be supplied
/// for explicit configuration, or `issuer` for discovery; a single endpoint is
/// rejected. `Oidc` operations additionally take `jwks_uri`, which must be
/// paired with `issuer` when endpoints are explicit. `Revocation` and
/// `EndSession` take the endpoint they attach, which is required with explicit
/// endpoints and overrides the discovered endpoint.
#[cfg(any(windows, test))]
async fn build_configuration(
    kind: ConfigurationKind,
    endpoints: EndpointSelection<'_>,
    transport: &ReqwestTransport,
    cancellation: &CancellationHandle,
) -> std::result::Result<ServiceConfiguration, WindowsAuthorizationError> {
    let EndpointSelection {
        issuer,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        named_endpoint,
    } = endpoints;
    match (authorization_endpoint, token_endpoint) {
        (Some(authorization_endpoint), Some(token_endpoint)) => {
            let authorization_endpoint = Url::parse(authorization_endpoint)
                .map_err(|_| WindowsAuthorizationError::InvalidEndpoint)?;
            let token_endpoint = Url::parse(token_endpoint)
                .map_err(|_| WindowsAuthorizationError::InvalidEndpoint)?;
            let named_endpoint = match kind {
                ConfigurationKind::Oidc => None,
                ConfigurationKind::Revocation | ConfigurationKind::EndSession => {
                    Some(named_endpoint.ok_or(WindowsAuthorizationError::InvalidEndpoint)?)
                }
            };
            let configuration = ServiceConfiguration::new(authorization_endpoint, token_endpoint)?;
            Ok(match kind {
                ConfigurationKind::Oidc => match (issuer, jwks_uri) {
                    (Some(issuer), Some(jwks_uri)) => configuration
                        .with_oidc_validation_endpoints(
                            Url::parse(issuer)
                                .map_err(|_| WindowsAuthorizationError::InvalidIssuer)?,
                            Url::parse(jwks_uri)
                                .map_err(|_| WindowsAuthorizationError::InvalidEndpoint)?,
                        )?,
                    (None, None) => configuration,
                    _ => return Err(WindowsAuthorizationError::InvalidIssuer),
                },
                ConfigurationKind::Revocation => configuration.with_revocation_endpoint(
                    Url::parse(named_endpoint.ok_or(WindowsAuthorizationError::InvalidEndpoint)?)
                        .map_err(|_| WindowsAuthorizationError::InvalidEndpoint)?,
                )?,
                ConfigurationKind::EndSession => configuration.with_end_session_endpoint(
                    Url::parse(named_endpoint.ok_or(WindowsAuthorizationError::InvalidEndpoint)?)
                        .map_err(|_| WindowsAuthorizationError::InvalidEndpoint)?,
                )?,
            })
        }
        (None, None) => {
            if matches!(kind, ConfigurationKind::Oidc) && jwks_uri.is_some() {
                return Err(WindowsAuthorizationError::InvalidIssuer);
            }
            let issuer = issuer.ok_or(WindowsAuthorizationError::InvalidIssuer)?;
            let issuer =
                Url::parse(issuer).map_err(|_| WindowsAuthorizationError::InvalidIssuer)?;
            let configuration =
                ServiceConfiguration::discover(issuer, transport, cancellation.clone()).await?;
            Ok(match kind {
                ConfigurationKind::Oidc => configuration,
                ConfigurationKind::Revocation => match named_endpoint {
                    Some(endpoint) => configuration.with_revocation_endpoint(
                        Url::parse(endpoint)
                            .map_err(|_| WindowsAuthorizationError::InvalidEndpoint)?,
                    )?,
                    None => configuration,
                },
                ConfigurationKind::EndSession => match named_endpoint {
                    Some(endpoint) => configuration.with_end_session_endpoint(
                        Url::parse(endpoint)
                            .map_err(|_| WindowsAuthorizationError::InvalidEndpoint)?,
                    )?,
                    None => configuration,
                },
            })
        }
        _ => Err(WindowsAuthorizationError::InvalidEndpoint),
    }
}

#[cfg(any(windows, test))]
async fn authorize_with_browser<F>(
    request: WindowsAuthorizationRequest,
    cancellation: CancellationHandle,
    open_browser: F,
) -> std::result::Result<AuthenticationState, WindowsAuthorizationError>
where
    F: FnOnce(&Url) -> std::result::Result<(), WindowsAuthorizationError>,
{
    if cancellation.is_cancelled() {
        return Err(AuthError::Cancelled.into());
    }
    let transport = ReqwestTransport::new()?;
    let configuration = build_configuration(
        ConfigurationKind::Oidc,
        EndpointSelection {
            issuer: request.issuer.as_deref(),
            authorization_endpoint: request.authorization_endpoint.as_deref(),
            token_endpoint: request.token_endpoint.as_deref(),
            jwks_uri: request.jwks_uri.as_deref(),
            named_endpoint: None,
        },
        &transport,
        &cancellation,
    )
    .await?;
    let redirect_template = parse_redirect_template(&request.redirect_uri)?;

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let mut redirect_uri = redirect_template;
    redirect_uri
        .set_port(Some(port))
        .map_err(|_| WindowsAuthorizationError::InvalidRedirectUri)?;

    let mut authorization_request = AuthorizationRequest::new(
        configuration,
        request.client_id,
        redirect_uri.clone(),
        request.scopes,
    )?;
    for parameter in request.additional_parameters {
        authorization_request =
            authorization_request.with_additional_parameter(parameter.name, parameter.value)?;
    }
    for parameter in request.additional_token_parameters {
        authorization_request = authorization_request
            .with_additional_token_parameter(parameter.name, parameter.value)?;
    }
    let authorization = authorization_request.begin()?;
    open_browser(authorization.authorization_url())?;

    let callback =
        wait_for_callback(listener, redirect_uri.path(), port, cancellation.clone()).await?;
    let response = authorization.parse_redirect(&callback)?;
    let tokens = authorization
        .exchange_code(&transport, &response, cancellation)
        .await?;
    Ok(authorization.authentication_state(tokens)?)
}

#[cfg(any(windows, test))]
async fn refresh_with_windows_request(
    request: WindowsRefreshRequest,
    cancellation: CancellationHandle,
) -> std::result::Result<AuthenticationState, WindowsAuthorizationError> {
    if cancellation.is_cancelled() {
        return Err(AuthError::Cancelled.into());
    }
    let transport = ReqwestTransport::new()?;
    let configuration = build_configuration(
        ConfigurationKind::Oidc,
        EndpointSelection {
            issuer: request.issuer.as_deref(),
            authorization_endpoint: request.authorization_endpoint.as_deref(),
            token_endpoint: request.token_endpoint.as_deref(),
            jwks_uri: request.jwks_uri.as_deref(),
            named_endpoint: None,
        },
        &transport,
        &cancellation,
    )
    .await?;
    ensure_unique_parameter_names(&request.additional_parameters)?;
    let additional_parameters: BTreeMap<String, String> = request
        .additional_parameters
        .into_iter()
        .map(|parameter| (parameter.name, parameter.value))
        .collect();
    let mut state = request.state;
    state
        .refresh_with_additional_parameters(
            &configuration,
            &request.client_id,
            &additional_parameters,
            &transport,
            cancellation,
        )
        .await?;
    Ok(state)
}

#[cfg(any(windows, test))]
async fn end_session_with_browser<F>(
    request: WindowsEndSessionRequest,
    cancellation: CancellationHandle,
    open_browser: F,
) -> std::result::Result<Option<WindowsEndSessionResponse>, WindowsAuthorizationError>
where
    F: FnOnce(&Url) -> std::result::Result<(), WindowsAuthorizationError>,
{
    if cancellation.is_cancelled() {
        return Err(AuthError::Cancelled.into());
    }
    let transport = ReqwestTransport::new()?;
    let configuration = build_configuration(
        ConfigurationKind::EndSession,
        EndpointSelection {
            issuer: request.issuer.as_deref(),
            authorization_endpoint: request.authorization_endpoint.as_deref(),
            token_endpoint: request.token_endpoint.as_deref(),
            jwks_uri: None,
            named_endpoint: request.end_session_endpoint.as_deref(),
        },
        &transport,
        &cancellation,
    )
    .await?;

    let mut end_session_request = EndSessionRequest::new(&configuration, request.client_id)?;
    if let Some(id_token_hint) = request.id_token_hint {
        end_session_request = end_session_request.with_id_token_hint(id_token_hint)?;
    }
    let Some(post_logout_redirect_uri) = request.post_logout_redirect_uri else {
        let session = end_session_request.begin()?;
        open_browser(session.end_session_url())?;
        return Ok(None);
    };

    let redirect_template = parse_redirect_template(&post_logout_redirect_uri)?;
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let mut redirect_uri = redirect_template;
    redirect_uri
        .set_port(Some(port))
        .map_err(|_| WindowsAuthorizationError::InvalidRedirectUri)?;
    end_session_request =
        end_session_request.with_post_logout_redirect_uri(redirect_uri.clone())?;
    let session = end_session_request.begin()?;
    open_browser(session.end_session_url())?;

    let callback =
        wait_for_callback(listener, redirect_uri.path(), port, cancellation.clone()).await?;
    let response = session.parse_redirect(&callback)?;
    let additional_parameters = response
        .additional_parameters()
        .iter()
        .map(|(name, value)| WindowsParameter {
            name: name.clone(),
            value: value.clone(),
        })
        .collect();
    Ok(Some(WindowsEndSessionResponse {
        state: response.state().to_owned(),
        additional_parameters,
    }))
}

#[cfg(any(windows, test))]
async fn revoke_with_windows_request(
    request: WindowsRevocationRequest,
    cancellation: CancellationHandle,
) -> std::result::Result<(), WindowsAuthorizationError> {
    if cancellation.is_cancelled() {
        return Err(AuthError::Cancelled.into());
    }
    let transport = ReqwestTransport::new()?;
    let configuration = build_configuration(
        ConfigurationKind::Revocation,
        EndpointSelection {
            issuer: request.issuer.as_deref(),
            authorization_endpoint: request.authorization_endpoint.as_deref(),
            token_endpoint: request.token_endpoint.as_deref(),
            jwks_uri: None,
            named_endpoint: request.revocation_endpoint.as_deref(),
        },
        &transport,
        &cancellation,
    )
    .await?;
    let token_type_hint = match request.token_type_hint.as_deref() {
        None => None,
        Some("access_token") => Some(RevocationTokenType::AccessToken),
        Some("refresh_token") => Some(RevocationTokenType::RefreshToken),
        Some(_) => {
            return Err(AuthError::InvalidConfiguration(
                "token type hint must be access_token or refresh_token",
            )
            .into());
        }
    };
    revoke_token(
        &configuration,
        &request.client_id,
        &request.token,
        token_type_hint,
        &transport,
        cancellation,
    )
    .await?;
    Ok(())
}

async fn wait_for_callback(
    listener: TcpListener,
    callback_path: &str,
    port: u16,
    cancellation: CancellationHandle,
) -> std::result::Result<Url, WindowsAuthorizationError> {
    loop {
        let (mut stream, _) = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(AuthError::Cancelled.into()),
            accepted = listener.accept() => accepted?,
        };
        let request = match tokio::time::timeout(
            CALLBACK_REQUEST_TIMEOUT,
            read_request_headers(&mut stream, &cancellation),
        )
        .await
        {
            Ok(request) => request?,
            Err(_) => continue,
        };
        let outcome = request
            .as_deref()
            .map(|request| parse_callback_request(request, callback_path, port))
            .unwrap_or(CallbackRequest::Malformed {
                matches_path: false,
            });

        match outcome {
            CallbackRequest::Unrelated => {
                write_response(&mut stream, 404, "Not Found").await?;
            }
            CallbackRequest::Malformed {
                matches_path: false,
            } => {
                write_response(&mut stream, 400, "Invalid request").await?;
            }
            CallbackRequest::Malformed { matches_path: true } => {
                write_response(&mut stream, 400, "Invalid request").await?;
                return Err(AuthError::InvalidAuthorizationResponse(
                    "malformed loopback callback request",
                )
                .into());
            }
            CallbackRequest::Matching(callback) => {
                write_response(
                    &mut stream,
                    200,
                    "Authorization complete. You may close this window.",
                )
                .await?;
                return Ok(callback);
            }
        }
    }
}

enum CallbackRequest {
    Unrelated,
    Malformed { matches_path: bool },
    Matching(Url),
}

fn parse_callback_request(bytes: &[u8], callback_path: &str, port: u16) -> CallbackRequest {
    let Some(headers_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return CallbackRequest::Malformed {
            matches_path: false,
        };
    };
    let Ok(headers) = std::str::from_utf8(&bytes[..headers_end]) else {
        return CallbackRequest::Malformed {
            matches_path: false,
        };
    };
    let mut lines = headers.split("\r\n");
    let Some(request_line) = lines.next() else {
        return CallbackRequest::Malformed {
            matches_path: false,
        };
    };
    let request_parts: Vec<_> = request_line.split_whitespace().collect();
    if request_parts.len() != 3 {
        return CallbackRequest::Malformed {
            matches_path: false,
        };
    }
    let target = request_parts[1];
    if !target.starts_with('/') || target.contains('#') {
        return CallbackRequest::Malformed {
            matches_path: false,
        };
    }
    let request_path = target.split('?').next().unwrap_or_default();
    if request_path != callback_path {
        return CallbackRequest::Unrelated;
    }
    if request_parts[0] != "GET"
        || (request_parts[2] != "HTTP/1.0" && request_parts[2] != "HTTP/1.1")
    {
        return CallbackRequest::Malformed { matches_path: true };
    }

    let expected_host = format!("127.0.0.1:{port}");
    let mut host_headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return CallbackRequest::Malformed { matches_path: true };
        };
        if name.eq_ignore_ascii_case("host") {
            host_headers.push(value.trim());
        }
    }
    if host_headers.as_slice() != [expected_host.as_str()] {
        return CallbackRequest::Malformed { matches_path: true };
    }

    match Url::parse(&format!("http://127.0.0.1:{port}{target}")) {
        Ok(callback) => CallbackRequest::Matching(callback),
        Err(_) => CallbackRequest::Malformed { matches_path: true },
    }
}

async fn read_request_headers(
    stream: &mut TcpStream,
    cancellation: &CancellationHandle,
) -> std::result::Result<Option<Vec<u8>>, WindowsAuthorizationError> {
    let mut request = Vec::new();
    let mut chunk = [0; 1024];
    while request.len() < MAX_REQUEST_SIZE {
        let read = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(AuthError::Cancelled.into()),
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

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    body: &str,
) -> std::result::Result<(), WindowsAuthorizationError> {
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
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

#[cfg(windows)]
fn result(status: i32, value: impl Into<String>) -> *mut AppAuthWindowsAuthorizationResult {
    AppAuthWindowsAuthorizationResult::new(status, value)
}

#[cfg(windows)]
fn run_authorize(
    request_json: &str,
    cancellation: CancellationHandle,
) -> *mut AppAuthWindowsAuthorizationResult {
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

#[cfg(windows)]
fn run_refresh(
    request_json: &str,
    cancellation: CancellationHandle,
) -> *mut AppAuthWindowsRefreshResult {
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

#[cfg(windows)]
fn run_end_session(
    request_json: &str,
    cancellation: CancellationHandle,
) -> *mut AppAuthWindowsEndSessionResult {
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

#[cfg(windows)]
fn run_revoke(
    request_json: &str,
    cancellation: CancellationHandle,
) -> *mut AppAuthWindowsRevocationResult {
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

/// Creates a cancellation handle for [`appauth_windows_authorize`].
///
/// The returned handle must be freed with
/// [`appauth_windows_cancellation_free`].
#[cfg(windows)]
#[no_mangle]
pub extern "C" fn appauth_windows_cancellation_new() -> *mut AppAuthWindowsCancellationHandle {
    Box::into_raw(Box::new(AppAuthWindowsCancellationHandle {
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
/// [`appauth_windows_cancellation_new`].
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn appauth_windows_cancellation_cancel(
    handle: *const AppAuthWindowsCancellationHandle,
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
/// [`appauth_windows_cancellation_new`], and no authorization call may still
/// be using it.
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn appauth_windows_cancellation_free(
    handle: *mut AppAuthWindowsCancellationHandle,
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
/// [`appauth_windows_cancellation_new`] that remains alive until this function
/// returns.
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn appauth_windows_authorize(
    request_json_utf8: *const c_char,
    cancellation: *const AppAuthWindowsCancellationHandle,
) -> *mut AppAuthWindowsAuthorizationResult {
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
/// [`appauth_windows_cancellation_new`] that remains alive until this function
/// returns.
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn appauth_windows_refresh(
    request_json_utf8: *const c_char,
    cancellation: *const AppAuthWindowsCancellationHandle,
) -> *mut AppAuthWindowsRefreshResult {
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
/// [`appauth_windows_cancellation_new`] that remains alive until this function
/// returns.
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn appauth_windows_end_session(
    request_json_utf8: *const c_char,
    cancellation: *const AppAuthWindowsCancellationHandle,
) -> *mut AppAuthWindowsEndSessionResult {
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
/// [`appauth_windows_cancellation_new`] that remains alive until this function
/// returns.
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn appauth_windows_revoke(
    request_json_utf8: *const c_char,
    cancellation: *const AppAuthWindowsCancellationHandle,
) -> *mut AppAuthWindowsRevocationResult {
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
/// [`appauth_windows_authorize`].
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn appauth_windows_authorization_result_status(
    authorization_result: *const AppAuthWindowsAuthorizationResult,
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
/// [`appauth_windows_authorize`].
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn appauth_windows_authorization_result_value(
    authorization_result: *const AppAuthWindowsAuthorizationResult,
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
/// [`appauth_windows_authorize`].
#[cfg(windows)]
#[no_mangle]
pub unsafe extern "C" fn appauth_windows_authorization_result_free(
    authorization_result: *mut AppAuthWindowsAuthorizationResult,
) {
    if !authorization_result.is_null() {
        drop(Box::from_raw(authorization_result));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenResponse;
    use tokio::{io::AsyncReadExt, task::JoinHandle};

    #[test]
    fn redirect_template_accepts_ipv4_loopback_and_rejects_other_hosts_or_ports() {
        assert_eq!(
            parse_redirect_template("http://127.0.0.1/oauth/callback")
                .unwrap()
                .path(),
            "/oauth/callback"
        );
        assert!(parse_redirect_template("http://localhost/oauth/callback").is_err());
        assert!(parse_redirect_template("http://127.0.0.1:8080/oauth/callback").is_err());
        assert!(parse_redirect_template("https://127.0.0.1/oauth/callback").is_err());
    }

    #[tokio::test]
    async fn revocation_honors_cancellation_before_network_setup() {
        let cancellation = CancellationHandle::new();
        cancellation.cancel();
        let request = WindowsRevocationRequest {
            issuer: None,
            authorization_endpoint: None,
            token_endpoint: None,
            revocation_endpoint: None,
            client_id: "native-client".to_owned(),
            token: "refresh-token".to_owned(),
            token_type_hint: Some("refresh_token".to_owned()),
        };

        assert!(matches!(
            revoke_with_windows_request(request, cancellation).await,
            Err(WindowsAuthorizationError::Core(AuthError::Cancelled))
        ));
    }

    #[test]
    fn request_json_accepts_discovery_or_explicit_endpoints() {
        let discovery: WindowsAuthorizationRequest = serde_json::from_str(
            r#"{
                "issuer":"https://issuer.example",
                "client_id":"client",
                "redirect_uri":"http://127.0.0.1/callback",
                "scopes":["profile"]
            }"#,
        )
        .unwrap();
        assert_eq!(discovery.issuer.as_deref(), Some("https://issuer.example"));

        let explicit: WindowsAuthorizationRequest = serde_json::from_str(
            r#"{
                "authorization_endpoint":"https://issuer.example/authorize",
                "token_endpoint":"https://issuer.example/token",
                "client_id":"client",
                "redirect_uri":"http://127.0.0.1/callback",
                "scopes":["profile"]
            }"#,
        )
        .unwrap();
        assert!(explicit.issuer.is_none());
    }

    #[tokio::test]
    async fn ignores_unrelated_paths_then_accepts_matching_callback() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let cancellation = CancellationHandle::new();
        let callback_task: JoinHandle<_> = tokio::spawn(wait_for_callback(
            listener,
            "/oauth/callback",
            port,
            cancellation,
        ));

        let unrelated = send_request(port, "/favicon.ico").await;
        assert!(unrelated.starts_with("HTTP/1.1 404"));

        let callback = send_request(port, "/oauth/callback?code=sample&state=state").await;
        assert!(callback.starts_with("HTTP/1.1 200"));
        assert_eq!(
            callback_task.await.unwrap().unwrap().as_str(),
            format!("http://127.0.0.1:{port}/oauth/callback?code=sample&state=state")
        );
    }

    #[tokio::test]
    async fn stalled_connection_does_not_block_matching_callback() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let callback_task = tokio::spawn(wait_for_callback(
            listener,
            "/oauth/callback",
            port,
            CancellationHandle::new(),
        ));

        let stalled_stream = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let response = tokio::time::timeout(
            CALLBACK_REQUEST_TIMEOUT + Duration::from_secs(1),
            send_request(port, "/oauth/callback?code=sample&state=state"),
        )
        .await
        .expect("callback should proceed after the stalled connection times out");

        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            callback_task.await.unwrap().unwrap().as_str(),
            format!("http://127.0.0.1:{port}/oauth/callback?code=sample&state=state")
        );
        drop(stalled_stream);
    }

    #[tokio::test]
    async fn matching_callback_with_invalid_host_is_terminal() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let callback_task = tokio::spawn(wait_for_callback(
            listener,
            "/oauth/callback",
            port,
            CancellationHandle::new(),
        ));
        let mut stream = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream
            .write_all(
                format!(
                    "GET /oauth/callback?code=sample HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 400"));
        assert!(matches!(
            callback_task.await.unwrap(),
            Err(WindowsAuthorizationError::Core(
                AuthError::InvalidAuthorizationResponse(_)
            ))
        ));
    }

    #[tokio::test]
    async fn cancellation_stops_the_loopback_callback_wait() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let cancellation = CancellationHandle::new();
        let callback_task = tokio::spawn(wait_for_callback(
            listener,
            "/oauth/callback",
            port,
            cancellation.clone(),
        ));
        cancellation.cancel();
        assert!(matches!(
            callback_task.await.unwrap(),
            Err(WindowsAuthorizationError::Core(AuthError::Cancelled))
        ));
    }

    #[tokio::test]
    async fn authorization_opens_external_url_and_exchanges_validated_callback() {
        let provider = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let provider_port = provider.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{provider_port}");
        let authorization_endpoint = format!("{issuer}/authorize");
        let token_endpoint = format!("{issuer}/token");
        let provider_task = tokio::spawn(async move {
            let (mut stream, _) = provider.accept().await.unwrap();
            read_http_request(&mut stream).await;
            write_http_response(
                &mut stream,
                r#"{"access_token":"access","token_type":"Bearer"}"#,
            )
            .await;
        });

        let request = WindowsAuthorizationRequest {
            issuer: None,
            authorization_endpoint: Some(authorization_endpoint),
            token_endpoint: Some(token_endpoint),
            jwks_uri: None,
            client_id: "windows-client".to_owned(),
            redirect_uri: "http://127.0.0.1/oauth/callback".to_owned(),
            scopes: vec!["profile".to_owned()],
            additional_parameters: Vec::new(),
            additional_token_parameters: Vec::new(),
        };
        let runtime = tokio::runtime::Handle::current();
        let state = authorize_with_browser(request, CancellationHandle::new(), move |url| {
            let redirect = url
                .query_pairs()
                .find_map(|(name, value)| (name == "redirect_uri").then_some(value.into_owned()))
                .unwrap();
            let state = url
                .query_pairs()
                .find_map(|(name, value)| (name == "state").then_some(value.into_owned()))
                .unwrap();
            let mut callback = Url::parse(&redirect).unwrap();
            callback
                .query_pairs_mut()
                .append_pair("code", "authorization-code")
                .append_pair("state", &state);
            runtime.spawn(async move {
                let target = format!(
                    "{}?{}",
                    callback.path(),
                    callback.query().expect("callback has query parameters")
                );
                let _ = send_request(callback.port().unwrap(), &target).await;
            });
            Ok(())
        })
        .await
        .unwrap();
        provider_task.await.unwrap();
        assert_eq!(state.token_response().access_token, "access");
    }

    #[tokio::test]
    async fn refresh_honors_cancellation_before_network_setup() {
        let cancellation = CancellationHandle::new();
        cancellation.cancel();
        let request = WindowsRefreshRequest {
            issuer: None,
            authorization_endpoint: None,
            token_endpoint: None,
            jwks_uri: None,
            client_id: "native-client".to_owned(),
            state: AuthenticationState::new(TokenResponse {
                access_token: "access".to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: None,
                refresh_token: Some("refresh-token".to_owned()),
                scope: None,
                id_token: None,
                additional_parameters: BTreeMap::new(),
            })
            .unwrap(),
            additional_parameters: Vec::new(),
        };

        assert!(matches!(
            refresh_with_windows_request(request, cancellation).await,
            Err(WindowsAuthorizationError::Core(AuthError::Cancelled))
        ));
    }

    #[tokio::test]
    async fn refresh_exchanges_refresh_token_and_updates_state() {
        let provider = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let provider_port = provider.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{provider_port}");
        let provider_task = tokio::spawn(async move {
            let (mut stream, _) = provider.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            let request = String::from_utf8(request).unwrap();
            assert!(request.contains("POST /token HTTP/1.1"));
            assert!(request.contains("grant_type=refresh_token"));
            assert!(request.contains("refresh_token=old-refresh-token"));
            assert!(request.contains("client_id=windows-client"));
            assert!(request.contains("prompt=none"));
            write_http_response(
                &mut stream,
                r#"{"access_token":"new-access","token_type":"Bearer","expires_in":3600,"refresh_token":"new-refresh-token"}"#,
            )
            .await;
        });

        let request = WindowsRefreshRequest {
            issuer: None,
            authorization_endpoint: Some(format!("{issuer}/authorize")),
            token_endpoint: Some(format!("{issuer}/token")),
            jwks_uri: None,
            client_id: "windows-client".to_owned(),
            state: AuthenticationState::new(TokenResponse {
                access_token: "access".to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: None,
                refresh_token: Some("old-refresh-token".to_owned()),
                scope: Some("profile".to_owned()),
                id_token: None,
                additional_parameters: BTreeMap::new(),
            })
            .unwrap(),
            additional_parameters: vec![WindowsParameter {
                name: "prompt".to_owned(),
                value: "none".to_owned(),
            }],
        };

        let refreshed = refresh_with_windows_request(request, CancellationHandle::new())
            .await
            .unwrap();
        provider_task.await.unwrap();
        assert_eq!(refreshed.token_response().access_token, "new-access");
        assert_eq!(
            refreshed.token_response().refresh_token.as_deref(),
            Some("new-refresh-token")
        );
        assert!(refreshed.expires_at().is_some());
    }

    #[tokio::test]
    async fn refresh_rejects_duplicate_additional_parameter_names() {
        let request = WindowsRefreshRequest {
            issuer: None,
            authorization_endpoint: Some("https://issuer.example/authorize".to_owned()),
            token_endpoint: Some("https://issuer.example/token".to_owned()),
            jwks_uri: None,
            client_id: "native-client".to_owned(),
            state: AuthenticationState::new(TokenResponse {
                access_token: "access".to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: None,
                refresh_token: Some("refresh-token".to_owned()),
                scope: None,
                id_token: None,
                additional_parameters: BTreeMap::new(),
            })
            .unwrap(),
            additional_parameters: vec![
                WindowsParameter {
                    name: "prompt".to_owned(),
                    value: "none".to_owned(),
                },
                WindowsParameter {
                    name: "prompt".to_owned(),
                    value: "consent".to_owned(),
                },
            ],
        };

        assert!(matches!(
            refresh_with_windows_request(request, CancellationHandle::new()).await,
            Err(WindowsAuthorizationError::DuplicateParameter)
        ));
    }

    #[test]
    fn refresh_request_json_round_trips_serialized_state() {
        let state = AuthenticationState::new(TokenResponse {
            access_token: "access".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: Some(3600),
            refresh_token: Some("refresh-token".to_owned()),
            scope: Some("profile".to_owned()),
            id_token: None,
            additional_parameters: BTreeMap::new(),
        })
        .unwrap();
        let serialized_state = serde_json::to_string(&state).unwrap();
        let state_value: serde_json::Value = serde_json::from_str(&serialized_state).unwrap();

        let request: WindowsRefreshRequest = serde_json::from_value(serde_json::json!({
            "authorization_endpoint": "https://issuer.example/authorize",
            "token_endpoint": "https://issuer.example/token",
            "client_id": "client",
            "state": state_value,
        }))
        .unwrap();
        assert_eq!(request.state.token_response().access_token, "access");
        assert_eq!(
            request.state.token_response().refresh_token.as_deref(),
            Some("refresh-token")
        );
        assert!(request.state.expires_at().is_some());

        let missing_token_response: std::result::Result<WindowsRefreshRequest, _> =
            serde_json::from_value(serde_json::json!({
                "client_id": "client",
                "state": {}
            }));
        assert!(missing_token_response.is_err());
    }

    #[tokio::test]
    async fn end_session_honors_cancellation_before_network_setup() {
        let cancellation = CancellationHandle::new();
        cancellation.cancel();
        let request = WindowsEndSessionRequest {
            issuer: None,
            authorization_endpoint: None,
            token_endpoint: None,
            end_session_endpoint: None,
            client_id: "native-client".to_owned(),
            id_token_hint: None,
            post_logout_redirect_uri: None,
        };

        assert!(matches!(
            end_session_with_browser(
                request,
                cancellation,
                |_| Ok::<(), WindowsAuthorizationError>(())
            )
            .await,
            Err(WindowsAuthorizationError::Core(AuthError::Cancelled))
        ));
    }

    #[tokio::test]
    async fn end_session_without_redirect_opens_browser_and_returns_no_result() {
        let opened = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let opened_for_browser = opened.clone();
        let request = WindowsEndSessionRequest {
            issuer: None,
            authorization_endpoint: Some("https://issuer.example/authorize".to_owned()),
            token_endpoint: Some("https://issuer.example/token".to_owned()),
            end_session_endpoint: Some("https://issuer.example/endsession".to_owned()),
            client_id: "native-client".to_owned(),
            id_token_hint: Some("id-token-hint".to_owned()),
            post_logout_redirect_uri: None,
        };

        let result = end_session_with_browser(request, CancellationHandle::new(), move |url| {
            *opened_for_browser.lock().unwrap() = Some(url.as_str().to_owned());
            Ok(())
        })
        .await
        .unwrap();

        assert!(result.is_none());
        let opened = Url::parse(opened.lock().unwrap().as_ref().unwrap()).unwrap();
        let query = opened.query().unwrap_or_default();
        assert!(query.contains("client_id=native-client"));
        assert!(query.contains("id_token_hint=id-token-hint"));
        assert!(!query.contains("state"));
        assert!(!query.contains("post_logout_redirect_uri"));
    }

    #[tokio::test]
    async fn end_session_with_redirect_validates_callback() {
        let opened = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let opened_for_browser = opened.clone();
        let request = WindowsEndSessionRequest {
            issuer: None,
            authorization_endpoint: Some("https://issuer.example/authorize".to_owned()),
            token_endpoint: Some("https://issuer.example/token".to_owned()),
            end_session_endpoint: Some("https://issuer.example/endsession".to_owned()),
            client_id: "native-client".to_owned(),
            id_token_hint: None,
            post_logout_redirect_uri: Some("http://127.0.0.1/logout/callback".to_owned()),
        };
        let runtime = tokio::runtime::Handle::current();
        let response = end_session_with_browser(request, CancellationHandle::new(), move |url| {
            let redirect = url
                .query_pairs()
                .find_map(|(name, value)| {
                    (name == "post_logout_redirect_uri").then_some(value.into_owned())
                })
                .unwrap();
            let state = url
                .query_pairs()
                .find_map(|(name, value)| (name == "state").then_some(value.into_owned()))
                .unwrap();
            let mut callback = Url::parse(&redirect).unwrap();
            callback
                .query_pairs_mut()
                .append_pair("state", &state)
                .append_pair("extra", "logout-extra");
            *opened_for_browser.lock().unwrap() = Some(url.as_str().to_owned());
            let target = format!(
                "{}?{}",
                callback.path(),
                callback.query().expect("callback has query parameters")
            );
            let callback_port = callback.port().unwrap();
            runtime.spawn(async move {
                let _ = send_request(callback_port, &target).await;
            });
            Ok(())
        })
        .await
        .unwrap()
        .expect("a requested post-logout redirect yields a validated response");

        let opened = Url::parse(opened.lock().unwrap().as_ref().unwrap()).unwrap();
        let expected_state = opened
            .query_pairs()
            .find(|(name, _)| name.as_ref() == "state")
            .map(|(_, value)| value.into_owned())
            .unwrap();
        assert_eq!(response.state, expected_state);
        assert_eq!(
            response.additional_parameters,
            vec![WindowsParameter {
                name: "extra".to_owned(),
                value: "logout-extra".to_owned(),
            }]
        );
    }

    #[tokio::test]
    async fn end_session_requires_configured_endpoint_with_explicit_endpoints() {
        let request = WindowsEndSessionRequest {
            issuer: None,
            authorization_endpoint: Some("https://issuer.example/authorize".to_owned()),
            token_endpoint: Some("https://issuer.example/token".to_owned()),
            end_session_endpoint: None,
            client_id: "native-client".to_owned(),
            id_token_hint: None,
            post_logout_redirect_uri: None,
        };

        assert!(matches!(
            end_session_with_browser(request, CancellationHandle::new(), |_| Ok::<
                (),
                WindowsAuthorizationError,
            >(()))
            .await,
            Err(WindowsAuthorizationError::InvalidEndpoint)
        ));
    }

    async fn send_request(port: u16, target: &str) -> String {
        let mut stream = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        stream
            .write_all(
                format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    async fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let read = stream.read(&mut chunk).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                let headers_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let headers = String::from_utf8_lossy(&request[..headers_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                    })
                    .unwrap_or(0);
                if request.len() >= headers_end + content_length {
                    break;
                }
            }
        }
        request
    }

    async fn write_http_response(stream: &mut TcpStream, body: &str) {
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn c_abi_returns_and_frees_an_error_result() {
        let cancellation = appauth_windows_cancellation_new();
        let request = CString::new(
            r#"{
                "issuer":"not a URL",
                "client_id":"client",
                "redirect_uri":"http://127.0.0.1/callback",
                "scopes":["profile"]
            }"#,
        )
        .unwrap();
        let result = unsafe { appauth_windows_authorize(request.as_ptr(), cancellation) };
        assert_eq!(
            unsafe { appauth_windows_authorization_result_status(result) },
            STATUS_ERROR
        );
        assert_eq!(
            unsafe {
                CStr::from_ptr(appauth_windows_authorization_result_value(result))
                    .to_str()
                    .unwrap()
            },
            "issuer URL is invalid"
        );
        unsafe {
            appauth_windows_authorization_result_free(result);
            appauth_windows_cancellation_free(cancellation);
        }
    }

    #[cfg(windows)]
    #[test]
    fn c_abi_refresh_returns_and_frees_an_error_result() {
        let cancellation = appauth_windows_cancellation_new();
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
        let result = unsafe { appauth_windows_refresh(request.as_ptr(), cancellation) };
        assert_eq!(
            unsafe { appauth_windows_authorization_result_status(result) },
            STATUS_ERROR
        );
        assert_eq!(
            unsafe {
                CStr::from_ptr(appauth_windows_authorization_result_value(result))
                    .to_str()
                    .unwrap()
            },
            "issuer URL is invalid"
        );
        unsafe {
            appauth_windows_authorization_result_free(result);
            appauth_windows_cancellation_free(cancellation);
        }
    }

    #[cfg(windows)]
    #[test]
    fn c_abi_end_session_returns_and_frees_an_error_result() {
        let cancellation = appauth_windows_cancellation_new();
        let request = CString::new(
            r#"{
                "authorization_endpoint":"https://issuer.example/authorize",
                "token_endpoint":"https://issuer.example/token",
                "end_session_endpoint":"http://insecure.example/logout",
                "client_id":"client"
            }"#,
        )
        .unwrap();
        let result = unsafe { appauth_windows_end_session(request.as_ptr(), cancellation) };
        assert_eq!(
            unsafe { appauth_windows_authorization_result_status(result) },
            STATUS_ERROR
        );
        assert_eq!(
            unsafe {
                CStr::from_ptr(appauth_windows_authorization_result_value(result))
                    .to_str()
                    .unwrap()
            },
            "invalid configuration: end-session endpoint must use HTTPS without user info or fragments"
        );
        unsafe {
            appauth_windows_authorization_result_free(result);
            appauth_windows_cancellation_free(cancellation);
        }
    }
}
