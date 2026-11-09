use async_trait::async_trait;
use http::{HeaderMap, Method, StatusCode};
use url::Url;

use crate::{AuthError, CancellationHandle, Result};

/// An HTTP request issued by the OAuth/OIDC core.
pub struct HttpRequest {
    /// HTTP method.
    pub method: Method,
    /// Absolute endpoint URL.
    pub url: Url,
    /// Request headers.
    pub headers: HeaderMap,
    /// Request body bytes.
    pub body: Vec<u8>,
}

/// An HTTP response returned to the OAuth/OIDC core.
pub struct HttpResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body bytes.
    pub body: Vec<u8>,
}

/// Asynchronous HTTP transport used for OAuth/OIDC endpoint requests.
///
/// Implementations must not follow redirects. Redirect responses are returned
/// to the core as-is so credentials and authorization codes are not forwarded
/// to a different endpoint.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Executes one request and returns its response or transport error.
    async fn execute(
        &self,
        request: HttpRequest,
        cancellation: CancellationHandle,
    ) -> Result<HttpResponse>;
}

#[derive(Clone)]
/// Default `reqwest` transport for Rust callers that provide a Tokio runtime.
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Creates a transport configured not to follow HTTP redirects.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| AuthError::Transport)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn execute(
        &self,
        request: HttpRequest,
        cancellation: CancellationHandle,
    ) -> Result<HttpResponse> {
        let send = self
            .client
            .request(request.method, request.url)
            .headers(request.headers)
            .body(request.body)
            .send();

        let response = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(AuthError::Cancelled),
            response = send => response.map_err(|_| AuthError::Transport)?,
        };
        let status = response.status();
        let headers = response.headers().clone();
        let body = tokio::select! {
            biased;
            _ = cancellation.cancelled() => return Err(AuthError::Cancelled),
            body = response.bytes() => body.map_err(|_| AuthError::Transport)?.to_vec(),
        };

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc::{self, Receiver, Sender},
        thread::{self, JoinHandle},
        time::Duration,
    };

    use super::*;

    fn request(url: Url) -> HttpRequest {
        HttpRequest {
            method: Method::GET,
            url,
            headers: HeaderMap::new(),
            body: Vec::new(),
        }
    }

    fn local_server(response: Vec<u8>) -> (Url, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let bytes_read = stream.read(&mut request).unwrap();
            assert!(bytes_read > 0);
            stream.write_all(&response).unwrap();
        });
        (Url::parse(&format!("http://{address}/")).unwrap(), server)
    }

    fn waiting_server(
        response: Option<Vec<u8>>,
    ) -> (Url, Receiver<()>, Sender<()>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted_sender, accepted_receiver) = mpsc::channel();
        let (release_sender, release_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0; 1024];
            let bytes_read = stream.read(&mut request).unwrap();
            assert!(bytes_read > 0);
            if let Some(response) = response {
                stream.write_all(&response).unwrap();
                stream.flush().unwrap();
            }
            accepted_sender.send(()).unwrap();
            let _ = release_receiver.recv_timeout(Duration::from_secs(5));
        });
        (
            Url::parse(&format!("http://{address}/")).unwrap(),
            accepted_receiver,
            release_sender,
            server,
        )
    }

    async fn wait_until_accepted(accepted: Receiver<()>) {
        tokio::task::spawn_blocking(move || accepted.recv_timeout(Duration::from_secs(2)))
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn returns_redirect_responses_without_following_them() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let target_address = target.local_addr().unwrap();
        drop(target);
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: http://{target_address}/target\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let (url, server) = local_server(response.into_bytes());

        let response = ReqwestTransport::new()
            .unwrap()
            .execute(request(url), CancellationHandle::new())
            .await
            .unwrap();
        server.join().unwrap();

        assert_eq!(response.status, StatusCode::FOUND);
    }

    #[tokio::test]
    async fn cancels_an_in_flight_request() {
        let (url, accepted, release, server) = waiting_server(None);
        let cancellation = CancellationHandle::new();
        let request_cancellation = cancellation.clone();
        let execute = tokio::spawn(async move {
            ReqwestTransport::new()
                .unwrap()
                .execute(request(url), request_cancellation)
                .await
        });

        wait_until_accepted(accepted).await;
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), execute)
            .await
            .unwrap()
            .unwrap();
        release.send(()).unwrap();
        server.join().unwrap();

        assert!(matches!(result, Err(AuthError::Cancelled)));
    }

    #[tokio::test]
    async fn cancels_while_reading_a_response_body() {
        let headers_and_partial_body =
            b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: keep-alive\r\n\r\npartial"
                .to_vec();
        let (url, accepted, release, server) = waiting_server(Some(headers_and_partial_body));
        let cancellation = CancellationHandle::new();
        let request_cancellation = cancellation.clone();
        let execute = tokio::spawn(async move {
            ReqwestTransport::new()
                .unwrap()
                .execute(request(url), request_cancellation)
                .await
        });

        wait_until_accepted(accepted).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancellation.cancel();
        let result = tokio::time::timeout(Duration::from_secs(2), execute)
            .await
            .unwrap()
            .unwrap();
        release.send(()).unwrap();
        server.join().unwrap();

        assert!(matches!(result, Err(AuthError::Cancelled)));
    }
}
