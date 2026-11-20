use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::{AuthError, CancellationHandle};

use super::data::WindowsAuthorizationError;

const MAX_REQUEST_SIZE: usize = 16 * 1024;
const MAX_CALLBACK_CONNECTIONS: usize = 32;
const CALLBACK_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn parse_redirect_template(
    template: &str,
) -> std::result::Result<Url, WindowsAuthorizationError> {
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

pub(super) async fn wait_for_callback(
    listener: TcpListener,
    callback_path: &str,
    port: u16,
    cancellation: CancellationHandle,
) -> std::result::Result<Url, WindowsAuthorizationError> {
    let mut connections = tokio::task::JoinSet::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => break Err(AuthError::Cancelled.into()),
            finished = connections.join_next(), if !connections.is_empty() => {
                match finished {
                    Some(Ok(Ok(Some(callback)))) => break Ok(callback),
                    Some(Ok(Err(WindowsAuthorizationError::Core(error)))) => break Err(error.into()),
                    // A disconnected unrelated client must not terminate authorization.
                    Some(Ok(Ok(None) | Err(WindowsAuthorizationError::Loopback(_)))) => {},
                    Some(Err(error)) => break Err(io::Error::other(error).into()),
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
    mut stream: TcpStream,
    callback_path: &str,
    port: u16,
    cancellation: CancellationHandle,
) -> std::result::Result<Option<Url>, WindowsAuthorizationError> {
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
            return Err(AuthError::InvalidAuthorizationResponse(
                "malformed loopback callback request",
            )
            .into());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::task::JoinHandle;

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

        let mut stalled_streams = Vec::new();
        for _ in 0..3 {
            let mut stream = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            stream
                .write_all(b"GET /oauth/callback HTTP/1.1\r\n")
                .await
                .unwrap();
            stalled_streams.push(stream);
        }
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            send_request(port, "/oauth/callback?code=sample&state=state"),
        )
        .await
        .expect("callback should proceed before stalled connections time out");

        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            callback_task.await.unwrap().unwrap().as_str(),
            format!("http://127.0.0.1:{port}/oauth/callback?code=sample&state=state")
        );
        for mut stream in stalled_streams {
            let mut bytes = [0; 1];
            let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut bytes))
                .await
                .unwrap();
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "stalled socket should close"
            );
        }
        assert!(
            TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn independent_loopback_operations_keep_callbacks_and_cancellation_separate() {
        let first = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let first_port = first.local_addr().unwrap().port();
        let second = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let second_port = second.local_addr().unwrap().port();
        assert_ne!(first_port, second_port);
        let cancellation = CancellationHandle::new();
        let first_task = tokio::spawn(wait_for_callback(
            first,
            "/callback",
            first_port,
            cancellation.clone(),
        ));
        let second_task = tokio::spawn(wait_for_callback(
            second,
            "/callback",
            second_port,
            CancellationHandle::new(),
        ));
        let mut stalled = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, first_port))
            .await
            .unwrap();
        stalled
            .write_all(b"GET /callback HTTP/1.1\r\n")
            .await
            .unwrap();
        cancellation.cancel();
        assert!(matches!(
            first_task.await.unwrap(),
            Err(WindowsAuthorizationError::Core(AuthError::Cancelled))
        ));
        let mut byte = [0; 1];
        let closed = tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(closed, Ok(0) | Err(_)));
        assert!(
            TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, first_port))
                .await
                .is_err()
        );
        assert!(send_request(second_port, "/callback?code=second&state=two")
            .await
            .starts_with("HTTP/1.1 200"));
        assert_eq!(
            second_task.await.unwrap().unwrap().query(),
            Some("code=second&state=two")
        );
        assert!(
            TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, second_port))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn duplicate_connections_return_one_callback_and_release_the_port() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(wait_for_callback(
            listener,
            "/callback",
            port,
            CancellationHandle::new(),
        ));
        let mut first = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut second = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        for stream in [&mut first, &mut second] {
            let _ = stream.write_all(format!("GET /callback?code=duplicate&state=state HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").as_bytes()).await;
        }
        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(result.query(), Some("code=duplicate&state=state"));
        drop(first);
        drop(second);
        assert!(
            TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
                .await
                .is_err()
        );
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
