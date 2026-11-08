use std::{
    error::Error,
    io::{self, Write},
};

use appauth_rust::{
    AuthorizationRequest, CancellationHandle, ReqwestTransport, ServiceConfiguration,
};
use url::Url;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.len() != 3 {
        return Err(
            "usage: cargo run --example manual_authorization -- <issuer> <client-id> <redirect-uri>"
                .into(),
        );
    }

    let issuer = Url::parse(&arguments[0])?;
    let client_id = &arguments[1];
    let redirect_uri = Url::parse(&arguments[2])?;
    let transport = ReqwestTransport::new()?;

    let configuration =
        ServiceConfiguration::discover(issuer, &transport, CancellationHandle::new()).await?;
    let session = AuthorizationRequest::new(
        configuration,
        client_id,
        redirect_uri,
        vec!["openid".to_owned(), "profile".to_owned()],
    )?
    .begin()?;

    println!("Open this URL in your system browser:\n{}", session.authorization_url());
    print!("Paste the complete redirect URL: ");
    io::stdout().flush()?;

    let mut redirect = String::new();
    io::stdin().read_line(&mut redirect)?;
    let response = session.parse_redirect(&Url::parse(redirect.trim())?)?;
    let tokens = session
        .exchange_code(&transport, &response, CancellationHandle::new())
        .await?;
    let state = session.authentication_state(tokens)?;

    println!(
        "Authorization succeeded. Token state expires at: {:?}",
        state.expires_at()
    );
    Ok(())
}
