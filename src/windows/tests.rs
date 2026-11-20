#[cfg(test)]
pub mod tests {
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
