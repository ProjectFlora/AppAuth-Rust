#[cfg(any(windows, test))]
#[derive(Debug, Copy, Clone)]
enum ConfigurationKind {
    Oidc,
    Revocation,
    EndSession,
}

#[cfg(any(windows, test))]
const MAX_REQUEST_SIZE: usize = 16 * 1024;
#[cfg(any(windows, test))]
const MAX_CALLBACK_CONNECTIONS: usize = 32;
#[cfg(any(windows, test))]
const CALLBACK_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(any(windows, test))]
#[derive(Debug, Copy, Clone)]
struct EndpointSelection<'a> {
    issuer: Option<&'a str>,
    authorization_endpoint: Option<&'a str>,
    token_endpoint: Option<&'a str>,
    jwks_uri: Option<&'a str>,
    named_endpoint: Option<&'a str>,
}

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq)]
enum CallbackRequest {
    Unrelated,
    Malformed { matches_path: bool },
    Matching(Url),
}

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

async fn wait_for_callback(
    listener: tokio::net::TcpListener,
    callback_path: &str,
    port: u16,
    cancellation: crate::CancellationHandle,
) -> std::result::Result<Url, crate::windows::WindowsAuthorizationError> {
    let mut connections = tokio::task::JoinSet::new();
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
        .unwrap_or(CallbackRequest::Malformed {
            matches_path: false,
        });
    match outcome {
        CallbackRequest::Unrelated => write_response(&mut stream, 404, "Not Found").await?,
        CallbackRequest::Malformed {
            matches_path: false,
        } => write_response(&mut stream, 400, "Invalid request").await?,
        CallbackRequest::Malformed { matches_path: true } => {
            // Parsing, rather than the peer's willingness to read an error page,
            // determines whether a matching malformed callback is terminal.
            let _ = write_response(&mut stream, 400, "Invalid request").await;
            return crate::AuthError::InvalidAuthorizationResponse(
                "malformed loopback callback request",
            )
            .into();
        }
        CallbackRequest::Matching(callback) => {
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
    stream: &mut tokio::net::TcpStream,
    cancellation: &crate::CancellationHandle,
) -> std::result::Result<Option<Vec<u8>>, crate::windows::WindowsAuthorizationError> {
    let mut request = Vec::new();
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
