use async_trait::async_trait;
use http::{HeaderMap, Method, StatusCode};
use url::Url;

use crate::{AuthError, CancellationHandle, Result};

pub struct HttpRequest {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// HTTP adapters must not follow redirects for OAuth requests.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn execute(
        &self,
        request: HttpRequest,
        cancellation: CancellationHandle,
    ) -> Result<HttpResponse>;
}

#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
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
