use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};

use tokio::net::TcpListener;
use url::Url;

use crate::{
    revoke_token, AuthError, AuthenticationState, AuthorizationRequest, CancellationHandle,
    EndSessionRequest, ReqwestTransport, RevocationTokenType, ServiceConfiguration,
};

use super::data::{
    ensure_unique_parameter_names, ConfigurationKind, ConfigurationSource, EndpointSelection,
    WindowsAuthorizationError, WindowsAuthorizationRequest, WindowsEndSessionRequest,
    WindowsEndSessionResponse, WindowsParameter, WindowsRefreshRequest,
    WindowsRevocationRequest,
};
use super::loopback::{parse_redirect_template, wait_for_callback};

/// A resolved service configuration and the source of its endpoints.
type ResolvedConfiguration = (ServiceConfiguration, ConfigurationSource);

/// Resolves the service configuration from a request's endpoints.
///
/// Either both `authorization_endpoint` and `token_endpoint` must be supplied
/// for explicit configuration, or `issuer` for discovery; a single endpoint is
/// rejected. `Revocation` and `EndSession` operations require their named
/// endpoint with explicit endpoints, and `Oidc` operations reject a
/// `jwks_uri` with discovery.
async fn build_service_configuration(
    kind: ConfigurationKind,
    endpoints: EndpointSelection<'_>,
    transport: &ReqwestTransport,
    cancellation: &CancellationHandle,
) -> std::result::Result<ResolvedConfiguration, WindowsAuthorizationError> {
    let EndpointSelection {
        issuer,
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        named_endpoint,
    } = endpoints;
    match (authorization_endpoint, token_endpoint) {
        (Some(authorization_endpoint), Some(token_endpoint)) => {
            let authorization_endpoint = parse_endpoint(authorization_endpoint)?;
            let token_endpoint = parse_endpoint(token_endpoint)?;
            if matches!(kind, ConfigurationKind::Revocation | ConfigurationKind::EndSession) {
                named_endpoint.ok_or(WindowsAuthorizationError::InvalidEndpoint)?;
            }
            let configuration = ServiceConfiguration::new(authorization_endpoint, token_endpoint)?;
            Ok((configuration, ConfigurationSource::Explicit))
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
            Ok((configuration, ConfigurationSource::Discovered))
        }
        _ => Err(WindowsAuthorizationError::InvalidEndpoint),
    }
}

/// Attaches the operation's endpoints to a resolved service configuration.
///
/// `Oidc` operations require `jwks_uri` to be paired with `issuer` when the
/// endpoints are explicit. `Revocation` and `EndSession` attach their named
/// endpoint, which is required with explicit endpoints and overrides the
/// discovered endpoint.
fn add_operation_endpoints(
    kind: ConfigurationKind,
    source: ConfigurationSource,
    endpoints: EndpointSelection<'_>,
    configuration: ServiceConfiguration,
) -> std::result::Result<ServiceConfiguration, WindowsAuthorizationError> {
    let EndpointSelection {
        issuer,
        jwks_uri,
        named_endpoint,
        ..
    } = endpoints;
    // The first stage already rejected explicit `Revocation` and `EndSession`
    // endpoints without their named endpoint, so `None` here means discovery.
    let named_endpoint = named_endpoint.map(parse_endpoint).transpose()?;
    match kind {
        ConfigurationKind::Oidc => match (source, issuer, jwks_uri) {
            (ConfigurationSource::Discovered, ..) | (_, None, None) => Ok(configuration),
            (_, Some(issuer), Some(jwks_uri)) => {
                let issuer =
                    Url::parse(issuer).map_err(|_| WindowsAuthorizationError::InvalidIssuer)?;
                let jwks_uri = parse_endpoint(jwks_uri)?;
                Ok(configuration.with_oidc_validation_endpoints(issuer, jwks_uri)?)
            }
            _ => Err(WindowsAuthorizationError::InvalidIssuer),
        },
        ConfigurationKind::Revocation => match named_endpoint {
            Some(endpoint) => Ok(configuration.with_revocation_endpoint(endpoint)?),
            None => Ok(configuration),
        },
        ConfigurationKind::EndSession => match named_endpoint {
            Some(endpoint) => Ok(configuration.with_end_session_endpoint(endpoint)?),
            None => Ok(configuration),
        },
    }
}

/// Parses an endpoint URL, reporting a malformed URL as an invalid endpoint.
fn parse_endpoint(endpoint: &str) -> std::result::Result<Url, WindowsAuthorizationError> {
    Url::parse(endpoint).map_err(|_| WindowsAuthorizationError::InvalidEndpoint)
}

/// Builds the service configuration shared by all blocking operations.
///
/// Either both `authorization_endpoint` and `token_endpoint` must be supplied
/// for explicit configuration, or `issuer` for discovery; a single endpoint is
/// rejected. `Oidc` operations additionally take `jwks_uri`, which must be
/// paired with `issuer` when endpoints are explicit. `Revocation` and
/// `EndSession` take the endpoint they attach, which is required with explicit
/// endpoints and overrides the discovered endpoint.
async fn build_configuration(
    kind: ConfigurationKind,
    endpoints: EndpointSelection<'_>,
    transport: &ReqwestTransport,
    cancellation: &CancellationHandle,
) -> std::result::Result<ServiceConfiguration, WindowsAuthorizationError> {
    let (configuration, source) =
        build_service_configuration(kind, endpoints, transport, cancellation).await?;
    add_operation_endpoints(kind, source, endpoints, configuration)
}

pub(super) async fn authorize_with_browser<F>(
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

pub(super) async fn refresh_with_windows_request(
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

pub(super) async fn end_session_with_browser<F>(
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

pub(super) async fn revoke_with_windows_request(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TokenResponse;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
}
