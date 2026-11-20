use std::{collections::BTreeMap, net::{Ipv4Addr, SocketAddrV4}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

#[cfg(any(windows, test))]
use std::ptr;

#[cfg(windows)]
use std::{
    ffi::{c_char, CStr, CString},
    ptr,
};

#[cfg(any(windows, test))]
use crate::{
    revoke_token, AuthError, AuthenticationState, AuthorizationRequest, CancellationHandle,
    EndSessionRequest, ReqwestTransport, RevocationTokenType, ServiceConfiguration,
};

use crate::windows::data::*;

const MAX_CALLBACK_CONNECTIONS: usize = 32;
const CALLBACK_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(any(windows, test))]
#[derive(Debug, Copy, Clone)]
enum ConfigurationKind {
    Oidc,
    Revocation,
    EndSession,
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
async fn build_service_configuration(
    authorization_endpoint: Option<&str>,
    token_endpoint: Option<&str>,
    issuer: Option<&str>,
    jwks_uri: Option<&str>,
    revocation_endpoint: Option<&str>,
    end_session_endpoint: Option<&str>,
    transport: &ReqwestTransport,
    cancellation: &CancellationHandle,
    kind: ConfigurationKind,
) -> std::result::Result<ServiceConfiguration, WindowsAuthorizationError> {
    match (authorization_endpoint, token_endpoint) {
        (Some(auth), Some(token)) => {
            let auth = Url::parse(auth)?;
            let token = Url::parse(token)?;
            let mut configuration = ServiceConfiguration::new(auth, token)?;

            // (2) Oidc の場合は OIDC 検証エンドポイントを附加
            if matches!(kind, ConfigurationKind::Oidc) {
                if let (Some(iss), Some(jwks)) = (issuer, jwks_uri) {
                    let iss = Url::parse(iss)?;
                    let jwks = Url::parse(jwks)?;
                    configuration = configuration.with_oidc_validation_endpoints(iss, jwks)?;
                }
            }

            // (3) Revocation/EndSession の named_endpoint 附加
            if matches!(kind, ConfigurationKind::Revocation | ConfigurationKind::EndSession) {
                match revocation_endpoint {
                    Some(ep) => {
                        let ep = Url::parse(ep)?;
                        configuration = configuration.with_revocation_endpoint(ep)?;
                    },
                    None => return Err(InvalidEndpointError),
                }
            }
            if matches!(kind, ConfigurationKind::EndSession) {
                match end_session_endpoint {
                    Some(ep) => {
                        let ep = Url::parse(ep)?;
                        configuration = configuration.with_end_session_endpoint(ep)?;
                    },
                    None => return Err(InvalidEndpointError),
                }
            }
            // Oidc の場合は named_endpoint を付加しない
        },
        (None, None) => {
            let issuer = Url::parse(issuer)?;
            let mut configuration = ServiceConfiguration::discovery(issuer, transport, cancellation.clone())?;

            // (2) Oidc の場合は OIDC 検証エンドポイントを附加
            if matches!(kind, ConfigurationKind::Oidc) {
                if let (Some(iss), Some(jwks)) = (issuer, jwks_uri) {
                    let iss = Url::parse(iss)?;
                    let jwks = Url::parse(jwks)?;
                    configuration = configuration.with_oidc_validation_endpoints(iss, jwks)?;
                }
            }
            // Revocation/EndSession の named_endpoint はない（iss から取得）
        },
        _ => return Err(InvalidEndpointError),
    }

    Ok(configuration)
}

#[cfg(any(windows, test))]
fn add_operation_endpoints(
    kind: ConfigurationKind,
    named_endpoint: Option<&str>,
    configuration: ServiceConfiguration,
) -> std::result::Result<ServiceConfiguration, WindowsAuthorizationError> {
    match kind {
        ConfigurationKind::Oidc => Ok(configuration),
        ConfigurationKind::Revocation | ConfigurationKind::EndSession => {
            match named_endpoint {
                Some(ep) => {
                    match kind {
                        ConfigurationKind::Revocation => {
                            let ep = Url::parse(ep)?;
                            Ok(configuration.with_revocation_endpoint(ep)?)
                        },
                        ConfigurationKind::EndSession => {
                            let ep = Url::parse(ep)?;
                            Ok(configuration.with_end_session_endpoint(ep)?)
                        },
                        _ => unreachable!(),
                    }
                },
                None => Err(InvalidEndpointError),
            }
        },
    }
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

    let configuration = build_service_configuration(
        authorization_endpoint,
        token_endpoint,
        issuer,
        jwks_uri,
        revocation_endpoint_from_kind(kind, named_endpoint),
        end_session_endpoint_from_kind(kind, named_endpoint),
        transport,
        cancellation,
        kind,
    ).await?;

    add_operation_endpoints(kind, named_endpoint, configuration)
}

/// Extracts the revocation endpoint for the given ConfigurationKind.
#[cfg(any(windows, test))]
fn revocation_endpoint_from_kind(kind: ConfigurationKind, named_endpoint: Option<&str>) -> Option<&str> {
    match kind {
        ConfigurationKind::Oidc => None,
        ConfigurationKind::Revocation => named_endpoint,
        ConfigurationKind::EndSession => None,
    }
}

/// Extracts the end-session endpoint for the given ConfigurationKind.
#[cfg(any(windows, test))]
fn end_session_endpoint_from_kind(kind: ConfigurationKind, named_endpoint: Option<&str>) -> Option<&str> {
    match kind {
        ConfigurationKind::Oidc => None,
        ConfigurationKind::Revocation => None,
        ConfigurationKind::EndSession => named_endpoint,
    }
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

    let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
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
        authorization_request =
            authorization_request.with_additional_token_parameter(parameter.name, parameter.value)?;
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
    let listener = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)).await?;
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

    use super::*;
    use crate::TokenResponse;
    use tokio::{io::AsyncReadExt, task::JoinHandle};

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
    async fn authorization_opens_external_url_and_exchanges_validated_callback() {
        let provider = tokio::net::TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let provider_port = provider.local_addr().unwrap().port();
        let issuer = format!("http://127.0.0.1:{provider_port}");
        let authorization_endpoint = format!("{issuer}/authorize");
        let token_endpoint = format!("{issuer}/token");
        let provider_task = tokio::spawn(async move {
            let (mut stream, _) = provider.accept().await.unwrap();
            tokio::io::AsyncReadExt::read_until(&mut stream, b"\r\n\r\n", &mut vec![]).await;
            tokio::io::AsyncWriteExt::write_all(
                &mut stream,
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 47\r\nConnection: close\r\n\r\n{\"access_token\":\"access\",\"token_type\":\"Bearer\"}",
            ).await;
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
                let _ = send_request(callback.port().unwrap(), &format!("{}?{}", callback.path(), callback.query().expect("callback has query parameters"))).await;
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
            state: crate::AuthenticationState::new(crate::TokenResponse {
                access_token: "access".to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: None,
                refresh_token: Some("refresh-token".to_owned()),
                scope: None,
                id_token: None,
                additional_parameters: std::collections::BTreeMap::new(),
            })
            .unwrap(),
            additional_parameters: Vec::new(),
        };

        assert!(matches!(
            refresh_with_windows_request(request, cancellation).await,
            Err(crate::windows::WindowsAuthorizationError::Core(crate::AuthError::Cancelled))
        ));
    }
}
