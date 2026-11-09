use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use http::{header, HeaderMap, HeaderValue, Method};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::{form_urlencoded, Host, Url};

use crate::{
    id_token::{validate_id_token, IdTokenValidation, JwksCache},
    pkce::{random_token, PkcePair},
    AuthError, CancellationHandle, HttpRequest, HttpTransport, Result,
};

const OIDC_DISCOVERY_PATH: [&str; 2] = [".well-known", "openid-configuration"];

const RESERVED_AUTHORIZATION_PARAMETERS: &[&str] = &[
    "client_id",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "redirect_uri",
    "response_type",
    "scope",
    "state",
];

const RESERVED_TOKEN_PARAMETERS: &[&str] = &[
    "client_assertion",
    "client_assertion_type",
    "client_id",
    "client_secret",
    "code",
    "code_verifier",
    "grant_type",
    "redirect_uri",
    "refresh_token",
    "scope",
];

const RESERVED_END_SESSION_PARAMETERS: &[&str] = &[
    "client_id",
    "id_token_hint",
    "logout_hint",
    "post_logout_redirect_uri",
    "state",
    "ui_locales",
];

#[derive(Clone)]
/// Authorization, token, OIDC, registration, and end-session endpoint configuration.
pub struct ServiceConfiguration {
    authorization_endpoint: Url,
    token_endpoint: Url,
    end_session_endpoint: Option<Url>,
    registration_endpoint: Option<Url>,
    issuer: Option<Url>,
    jwks_uri: Option<Url>,
    jwks_cache: JwksCache,
}

impl ServiceConfiguration {
    /// Creates a configuration from explicit authorization and token endpoints.
    pub fn new(authorization_endpoint: Url, token_endpoint: Url) -> Result<Self> {
        validate_endpoint(&authorization_endpoint)?;
        validate_endpoint(&token_endpoint)?;

        Ok(Self {
            authorization_endpoint,
            token_endpoint,
            end_session_endpoint: None,
            registration_endpoint: None,
            issuer: None,
            jwks_uri: None,
            jwks_cache: JwksCache::default(),
        })
    }

    /// Adds an HTTPS end-session endpoint.
    pub fn with_end_session_endpoint(mut self, endpoint: Url) -> Result<Self> {
        validate_logout_endpoint(&endpoint)?;
        self.end_session_endpoint = Some(endpoint);
        Ok(self)
    }

    /// Adds an HTTPS dynamic client registration endpoint.
    pub fn with_registration_endpoint(mut self, endpoint: Url) -> Result<Self> {
        validate_registration_endpoint(&endpoint)?;
        self.registration_endpoint = Some(endpoint);
        Ok(self)
    }

    /// Configures the issuer and JWKS endpoint used to validate ID Tokens.
    pub fn with_oidc_validation_endpoints(mut self, issuer: Url, jwks_uri: Url) -> Result<Self> {
        validate_issuer(&issuer)?;
        validate_oidc_endpoint(&jwks_uri)?;
        self.issuer = Some(issuer);
        self.jwks_uri = Some(jwks_uri);
        self.jwks_cache = JwksCache::default();
        Ok(self)
    }

    /// Loads and validates OpenID Provider metadata for `issuer`.
    ///
    /// The transport must not follow redirects. Discovery is required when the
    /// issuer and JWKS endpoint are needed for ID Token validation.
    pub async fn discover(
        issuer: Url,
        transport: &dyn HttpTransport,
        cancellation: CancellationHandle,
    ) -> Result<Self> {
        validate_issuer(&issuer)?;
        let discovery_url = oidc_discovery_url(&issuer)?;
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));

        let response = transport
            .execute(
                HttpRequest {
                    method: Method::GET,
                    url: discovery_url,
                    headers,
                    body: Vec::new(),
                },
                cancellation,
            )
            .await?;
        if !response.status.is_success() {
            return Err(AuthError::HttpStatus(response.status));
        }

        let metadata: DiscoveryMetadata = serde_json::from_slice(&response.body)
            .map_err(|_| AuthError::InvalidDiscoveryMetadata("response is not valid JSON"))?;
        if metadata.issuer != issuer.as_str() {
            return Err(AuthError::InvalidDiscoveryMetadata(
                "issuer does not match the requested issuer",
            ));
        }

        let authorization_endpoint = parse_discovered_endpoint(&metadata.authorization_endpoint)?;
        let token_endpoint = parse_discovered_endpoint(&metadata.token_endpoint)?;
        let end_session_endpoint = metadata
            .end_session_endpoint
            .as_deref()
            .map(parse_discovered_endpoint)
            .transpose()?;
        let registration_endpoint = metadata
            .registration_endpoint
            .as_deref()
            .map(parse_discovered_endpoint)
            .transpose()?;
        let jwks_uri = metadata
            .jwks_uri
            .as_deref()
            .map(parse_discovered_endpoint)
            .transpose()?;

        Ok(Self {
            authorization_endpoint,
            token_endpoint,
            end_session_endpoint,
            registration_endpoint,
            issuer: Some(issuer),
            jwks_uri,
            jwks_cache: JwksCache::default(),
        })
    }

    /// Returns the configured authorization endpoint.
    pub fn authorization_endpoint(&self) -> &Url {
        &self.authorization_endpoint
    }

    /// Returns the configured token endpoint.
    pub fn token_endpoint(&self) -> &Url {
        &self.token_endpoint
    }

    /// Returns the configured end-session endpoint, if any.
    pub fn end_session_endpoint(&self) -> Option<&Url> {
        self.end_session_endpoint.as_ref()
    }

    /// Returns the configured client registration endpoint, if any.
    pub fn registration_endpoint(&self) -> Option<&Url> {
        self.registration_endpoint.as_ref()
    }

    /// Returns the configured OIDC issuer, if any.
    pub fn issuer(&self) -> Option<&Url> {
        self.issuer.as_ref()
    }

    /// Returns the configured JWKS endpoint, if any.
    pub fn jwks_uri(&self) -> Option<&Url> {
        self.jwks_uri.as_ref()
    }
}

#[derive(Deserialize)]
struct DiscoveryMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    end_session_endpoint: Option<String>,
    registration_endpoint: Option<String>,
    jwks_uri: Option<String>,
}

/// Parameters used to create an Authorization Code + PKCE request.
///
/// ```
/// use appauth_rust::{AuthorizationRequest, ServiceConfiguration};
/// use url::Url;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let configuration = ServiceConfiguration::new(
///     Url::parse("https://issuer.example/authorize")?,
///     Url::parse("https://issuer.example/token")?,
/// )?;
/// let session = AuthorizationRequest::new(
///     configuration,
///     "native-client",
///     Url::parse("com.example.app:/oauth/callback")?,
///     vec!["profile".to_owned()],
/// )?
/// .begin()?;
/// let authorization_url = session.authorization_url();
/// # let _ = authorization_url;
/// # Ok(())
/// # }
/// ```
pub struct AuthorizationRequest {
    configuration: ServiceConfiguration,
    client_id: String,
    redirect_uri: Url,
    scopes: Vec<String>,
    additional_parameters: BTreeMap<String, String>,
    additional_token_parameters: BTreeMap<String, String>,
}

impl AuthorizationRequest {
    /// Creates an authorization request.
    ///
    /// Requests containing the `openid` scope require issuer and JWKS
    /// configuration so returned ID Tokens can be validated.
    pub fn new(
        configuration: ServiceConfiguration,
        client_id: impl Into<String>,
        redirect_uri: Url,
        scopes: Vec<String>,
    ) -> Result<Self> {
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "client ID must not be empty",
            ));
        }

        validate_redirect_uri(&redirect_uri)?;
        for scope in &scopes {
            validate_scope(scope)?;
        }
        if scopes.iter().any(|scope| scope == "openid")
            && (configuration.issuer.is_none() || configuration.jwks_uri.is_none())
        {
            return Err(AuthError::InvalidConfiguration(
                "OIDC issuer and JWKS endpoint are required to validate ID Tokens",
            ));
        }

        Ok(Self {
            configuration,
            client_id,
            redirect_uri,
            scopes,
            additional_parameters: BTreeMap::new(),
            additional_token_parameters: BTreeMap::new(),
        })
    }

    /// Adds a provider-specific authorization request parameter.
    pub fn with_additional_parameter(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self> {
        let name = name.into();
        if name.is_empty() || RESERVED_AUTHORIZATION_PARAMETERS.contains(&name.as_str()) {
            return Err(AuthError::InvalidConfiguration(
                "additional parameter has an empty or reserved name",
            ));
        }

        self.additional_parameters.insert(name, value.into());
        Ok(self)
    }

    /// Adds a provider-specific parameter to the token exchange request.
    pub fn with_additional_token_parameter(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self> {
        let name = name.into();
        validate_additional_token_parameter(&name)?;
        self.additional_token_parameters.insert(name, value.into());
        Ok(self)
    }

    /// Generates state, an optional OIDC nonce, and an S256 PKCE challenge.
    pub fn begin(self) -> Result<AuthorizationSession> {
        let mut authorization_url = self.configuration.authorization_endpoint.clone();
        reject_reserved_endpoint_parameters(&authorization_url)?;

        let state = random_token()?;
        let nonce = if self.scopes.iter().any(|scope| scope == "openid") {
            Some(random_token()?)
        } else {
            None
        };
        let pkce = PkcePair::generate()?;

        {
            let mut query = authorization_url.query_pairs_mut();
            query.append_pair("response_type", "code");
            query.append_pair("client_id", &self.client_id);
            query.append_pair("redirect_uri", self.redirect_uri.as_str());
            if !self.scopes.is_empty() {
                query.append_pair("scope", &self.scopes.join(" "));
            }
            query.append_pair("state", &state);
            if let Some(nonce) = &nonce {
                query.append_pair("nonce", nonce);
            }
            query.append_pair("code_challenge", pkce.challenge());
            query.append_pair("code_challenge_method", "S256");
            for (name, value) in self.additional_parameters {
                query.append_pair(&name, &value);
            }
        }

        Ok(AuthorizationSession {
            authorization_url,
            redirect_uri: self.redirect_uri,
            token_endpoint: self.configuration.token_endpoint,
            oidc_issuer: self.configuration.issuer,
            jwks_uri: self.configuration.jwks_uri,
            jwks_cache: self.configuration.jwks_cache,
            client_id: self.client_id,
            additional_token_parameters: self.additional_token_parameters,
            state,
            nonce,
            pkce,
        })
    }
}

/// A prepared authorization request and the session data needed to finish it.
pub struct AuthorizationSession {
    authorization_url: Url,
    redirect_uri: Url,
    token_endpoint: Url,
    oidc_issuer: Option<Url>,
    jwks_uri: Option<Url>,
    jwks_cache: JwksCache,
    client_id: String,
    additional_token_parameters: BTreeMap<String, String>,
    state: String,
    nonce: Option<String>,
    pkce: PkcePair,
}

impl AuthorizationSession {
    /// Returns the URL to open in an external user agent.
    pub fn authorization_url(&self) -> &Url {
        &self.authorization_url
    }

    /// Returns the generated OIDC nonce, or `None` when `openid` was not requested.
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Creates authentication state while retaining this session's OIDC nonce.
    ///
    /// Prefer this method over [`AuthenticationState::new`] after a successful
    /// code exchange so the nonce remains available during later refreshes.
    pub fn authentication_state(
        &self,
        token_response: TokenResponse,
    ) -> Result<AuthenticationState> {
        AuthenticationState::new_with_oidc_nonce(token_response, self.nonce.clone())
    }

    /// Validates a callback URL and extracts its authorization response.
    ///
    /// The redirect URI and state must match this session. OAuth error
    /// responses are returned as [`AuthError::AuthorizationServer`].
    pub fn parse_redirect(&self, redirect: &Url) -> Result<AuthorizationResponse> {
        validate_redirect_uri_match(&self.redirect_uri, redirect)?;

        let mut parameters = BTreeMap::new();
        let mut names = HashSet::new();
        for (name, value) in redirect.query_pairs() {
            if !names.insert(name.to_string()) {
                return Err(AuthError::InvalidAuthorizationResponse(
                    "response contains a duplicate parameter",
                ));
            }
            parameters.insert(name.into_owned(), value.into_owned());
        }

        for (name, expected_value) in self.redirect_uri.query_pairs() {
            if parameters.get(name.as_ref()) != Some(&expected_value.into_owned()) {
                return Err(AuthError::InvalidAuthorizationResponse(
                    "redirect URI query does not match",
                ));
            }
            parameters.remove(name.as_ref());
        }

        if parameters.get("state").map(String::as_str) != Some(self.state.as_str()) {
            return Err(AuthError::InvalidAuthorizationResponse("state mismatch"));
        }
        parameters.remove("state");

        let code = parameters.remove("code");
        let error = parameters.remove("error");
        if code.is_some() && error.is_some() {
            return Err(AuthError::InvalidAuthorizationResponse(
                "response contains both code and error",
            ));
        }
        if let Some(code) = code {
            if code.is_empty() {
                return Err(AuthError::InvalidAuthorizationResponse(
                    "authorization code must not be empty",
                ));
            }
            return Ok(AuthorizationResponse {
                code,
                state: self.state.clone(),
                additional_parameters: parameters,
            });
        }
        if let Some(code) = error {
            return Err(AuthError::AuthorizationServer {
                code,
                description: parameters.remove("error_description"),
            });
        }

        Err(AuthError::InvalidAuthorizationResponse(
            "response contains neither code nor error",
        ))
    }

    /// Exchanges a validated authorization code and verifies any returned ID Token.
    pub async fn exchange_code(
        &self,
        transport: &dyn HttpTransport,
        response: &AuthorizationResponse,
        cancellation: CancellationHandle,
    ) -> Result<TokenResponse> {
        if response.state != self.state {
            return Err(AuthError::InvalidAuthorizationResponse(
                "authorization response belongs to a different session",
            ));
        }
        if self.nonce.is_some() && (self.oidc_issuer.is_none() || self.jwks_uri.is_none()) {
            return Err(AuthError::InvalidConfiguration(
                "OIDC issuer and JWKS endpoint are required to validate ID Tokens",
            ));
        }

        let body = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code")
                .append_pair("code", &response.code)
                .append_pair("redirect_uri", self.redirect_uri.as_str())
                .append_pair("client_id", &self.client_id)
                .append_pair("code_verifier", self.pkce.verifier());
            for (name, value) in &self.additional_token_parameters {
                form.append_pair(name, value);
            }
            form.finish().into_bytes()
        };
        let token_response =
            send_token_request(&self.token_endpoint, body, transport, cancellation.clone()).await?;
        if self.nonce.is_some() && token_response.id_token.is_none() {
            return Err(AuthError::InvalidIdToken(
                "openid token response is missing an ID Token",
            ));
        }
        if let Some(id_token) = &token_response.id_token {
            let issuer = self
                .oidc_issuer
                .as_ref()
                .ok_or(AuthError::InvalidConfiguration(
                    "OIDC issuer is required to validate ID Tokens",
                ))?;
            let jwks_uri = self
                .jwks_uri
                .as_ref()
                .ok_or(AuthError::InvalidConfiguration(
                    "JWKS endpoint is required to validate ID Tokens",
                ))?;
            validate_id_token(
                IdTokenValidation {
                    token: id_token,
                    issuer,
                    jwks_uri,
                    client_id: &self.client_id,
                    expected_nonce: self.nonce.as_deref(),
                    require_nonce: self.nonce.is_some(),
                },
                &self.jwks_cache,
                transport,
                cancellation,
            )
            .await?;
        }
        Ok(token_response)
    }
}

/// A dynamic client registration request for a native public client.
pub struct ClientRegistrationRequest {
    registration_endpoint: Url,
    redirect_uris: Vec<Url>,
    client_name: Option<String>,
    initial_access_token: Option<String>,
}

impl ClientRegistrationRequest {
    /// Creates a request using the configured registration endpoint.
    ///
    /// At least one unique redirect URI is required.
    pub fn new(configuration: &ServiceConfiguration, redirect_uris: Vec<Url>) -> Result<Self> {
        let registration_endpoint =
            configuration
                .registration_endpoint
                .clone()
                .ok_or(AuthError::InvalidConfiguration(
                    "client registration endpoint is not configured",
                ))?;
        if redirect_uris.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "client registration requires at least one redirect URI",
            ));
        }

        let mut unique_redirect_uris = HashSet::new();
        for redirect_uri in &redirect_uris {
            validate_redirect_uri(redirect_uri)?;
            if !unique_redirect_uris.insert(redirect_uri.as_str()) {
                return Err(AuthError::InvalidConfiguration(
                    "client registration contains a duplicate redirect URI",
                ));
            }
        }

        Ok(Self {
            registration_endpoint,
            redirect_uris,
            client_name: None,
            initial_access_token: None,
        })
    }

    /// Sets the optional display name sent to the registration endpoint.
    pub fn with_client_name(mut self, client_name: impl Into<String>) -> Result<Self> {
        let client_name = client_name.into();
        if client_name.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "client name must not be empty",
            ));
        }
        self.client_name = Some(client_name);
        Ok(self)
    }

    /// Sets a per-request bearer token for a protected registration endpoint.
    pub fn with_initial_access_token(
        mut self,
        initial_access_token: impl Into<String>,
    ) -> Result<Self> {
        let initial_access_token = initial_access_token.into();
        validate_bearer_token(&initial_access_token)?;
        self.initial_access_token = Some(initial_access_token);
        Ok(self)
    }

    /// Registers the public client and returns its client ID.
    pub async fn register(
        self,
        transport: &dyn HttpTransport,
        cancellation: CancellationHandle,
    ) -> Result<ClientRegistrationResponse> {
        let metadata = ClientRegistrationMetadata {
            application_type: "native",
            redirect_uris: self.redirect_uris.iter().map(Url::as_str).collect(),
            response_types: ["code"],
            grant_types: ["authorization_code", "refresh_token"],
            token_endpoint_auth_method: "none",
            client_name: self.client_name.as_deref(),
        };
        let body = serde_json::to_vec(&metadata)
            .map_err(|_| AuthError::InvalidConfiguration("registration metadata is invalid"))?;

        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(initial_access_token) = &self.initial_access_token {
            let mut authorization =
                HeaderValue::from_str(&format!("Bearer {initial_access_token}")).map_err(|_| {
                    AuthError::InvalidConfiguration(
                        "initial access token is not a valid bearer token",
                    )
                })?;
            authorization.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, authorization);
        }

        let response = transport
            .execute(
                HttpRequest {
                    method: Method::POST,
                    url: self.registration_endpoint,
                    headers,
                    body,
                },
                cancellation,
            )
            .await?;
        if !response.status.is_success() {
            if let Ok(value) = serde_json::from_slice::<Value>(&response.body) {
                if let Some(code) = value.get("error").and_then(Value::as_str) {
                    return Err(AuthError::ClientRegistrationServer {
                        code: code.to_owned(),
                        description: value
                            .get("error_description")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    });
                }
            }
            return Err(AuthError::HttpStatus(response.status));
        }

        parse_client_registration_response(&response.body)
    }
}

#[derive(Serialize)]
struct ClientRegistrationMetadata<'a> {
    application_type: &'static str,
    redirect_uris: Vec<&'a str>,
    response_types: [&'static str; 1],
    grant_types: [&'static str; 2],
    token_endpoint_auth_method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<&'a str>,
}

/// The client identifier returned by dynamic registration.
pub struct ClientRegistrationResponse {
    client_id: String,
}

impl ClientRegistrationResponse {
    /// Returns the registered public client ID.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
}

/// Parameters for an OpenID Connect RP-Initiated Logout request.
pub struct EndSessionRequest {
    end_session_endpoint: Url,
    client_id: String,
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<Url>,
}

impl EndSessionRequest {
    /// Creates a logout request using the configured end-session endpoint.
    pub fn new(configuration: &ServiceConfiguration, client_id: impl Into<String>) -> Result<Self> {
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "client ID must not be empty",
            ));
        }

        let end_session_endpoint =
            configuration
                .end_session_endpoint
                .clone()
                .ok_or(AuthError::InvalidConfiguration(
                    "end-session endpoint is not configured",
                ))?;
        reject_reserved_end_session_parameters(&end_session_endpoint)?;

        Ok(Self {
            end_session_endpoint,
            client_id,
            id_token_hint: None,
            post_logout_redirect_uri: None,
        })
    }

    /// Adds an optional ID Token hint to the logout request.
    pub fn with_id_token_hint(mut self, id_token_hint: impl Into<String>) -> Result<Self> {
        let id_token_hint = id_token_hint.into();
        if id_token_hint.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "ID Token hint must not be empty",
            ));
        }
        self.id_token_hint = Some(id_token_hint);
        Ok(self)
    }

    /// Sets a callback URI; when set, a random state is generated and validated.
    pub fn with_post_logout_redirect_uri(mut self, redirect_uri: Url) -> Result<Self> {
        validate_redirect_uri(&redirect_uri)?;
        self.post_logout_redirect_uri = Some(redirect_uri);
        Ok(self)
    }

    /// Builds the logout URL and returns a session for validating its callback.
    pub fn begin(self) -> Result<EndSessionSession> {
        let state = self
            .post_logout_redirect_uri
            .as_ref()
            .map(|_| random_token())
            .transpose()?;
        let mut end_session_url = self.end_session_endpoint;
        {
            let mut query = end_session_url.query_pairs_mut();
            query.append_pair("client_id", &self.client_id);
            if let Some(id_token_hint) = &self.id_token_hint {
                query.append_pair("id_token_hint", id_token_hint);
            }
            if let Some(redirect_uri) = &self.post_logout_redirect_uri {
                query.append_pair("post_logout_redirect_uri", redirect_uri.as_str());
            }
            if let Some(state) = &state {
                query.append_pair("state", state);
            }
        }

        Ok(EndSessionSession {
            end_session_url,
            post_logout_redirect_uri: self.post_logout_redirect_uri,
            state,
        })
    }
}

/// A prepared logout URL and optional callback-validation state.
pub struct EndSessionSession {
    end_session_url: Url,
    post_logout_redirect_uri: Option<Url>,
    state: Option<String>,
}

impl EndSessionSession {
    /// Returns the URL to open in an external user agent.
    pub fn end_session_url(&self) -> &Url {
        &self.end_session_url
    }

    /// Validates the post-logout redirect and returns its state and extra parameters.
    pub fn parse_redirect(&self, redirect: &Url) -> Result<EndSessionResponse> {
        let expected_redirect_uri =
            self.post_logout_redirect_uri
                .as_ref()
                .ok_or(AuthError::InvalidEndSessionResponse(
                    "no post-logout redirect URI was requested",
                ))?;
        validate_end_session_redirect_uri_match(expected_redirect_uri, redirect)?;

        let mut parameters = BTreeMap::new();
        let mut names = HashSet::new();
        for (name, value) in redirect.query_pairs() {
            if !names.insert(name.to_string()) {
                return Err(AuthError::InvalidEndSessionResponse(
                    "response contains a duplicate parameter",
                ));
            }
            parameters.insert(name.into_owned(), value.into_owned());
        }

        for (name, expected_value) in expected_redirect_uri.query_pairs() {
            if parameters.get(name.as_ref()) != Some(&expected_value.into_owned()) {
                return Err(AuthError::InvalidEndSessionResponse(
                    "post-logout redirect URI query does not match",
                ));
            }
            parameters.remove(name.as_ref());
        }

        let returned_state =
            parameters
                .remove("state")
                .ok_or(AuthError::InvalidEndSessionResponse(
                    "response is missing state",
                ))?;
        if self.state.as_deref() != Some(returned_state.as_str()) {
            return Err(AuthError::InvalidEndSessionResponse("state mismatch"));
        }

        Ok(EndSessionResponse {
            state: returned_state,
            additional_parameters: parameters,
        })
    }
}

/// A validated end-session callback.
pub struct EndSessionResponse {
    state: String,
    additional_parameters: BTreeMap<String, String>,
}

impl EndSessionResponse {
    /// Returns the validated state value.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Returns unrecognized response parameters without interpreting them.
    pub fn additional_parameters(&self) -> &BTreeMap<String, String> {
        &self.additional_parameters
    }
}

/// A validated authorization callback containing an authorization code.
pub struct AuthorizationResponse {
    code: String,
    state: String,
    additional_parameters: BTreeMap<String, String>,
}

impl AuthorizationResponse {
    /// Returns the authorization code.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Returns the state matched against the originating session.
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Returns unrecognized response parameters without interpreting them.
    pub fn additional_parameters(&self) -> &BTreeMap<String, String> {
        &self.additional_parameters
    }
}

#[derive(Serialize, Deserialize)]
/// Token values returned by an OAuth token endpoint.
pub struct TokenResponse {
    /// The bearer access token.
    pub access_token: String,
    /// The token type, typically `Bearer`.
    pub token_type: String,
    /// Access-token lifetime in seconds, if supplied.
    pub expires_in: Option<u64>,
    /// Refresh token, if supplied.
    pub refresh_token: Option<String>,
    /// Granted scopes, if supplied.
    pub scope: Option<String>,
    /// Raw ID Token value. Tokens returned by code exchange are verified before return.
    pub id_token: Option<String>,
    #[serde(default)]
    /// Unrecognized token response values preserved as JSON.
    pub additional_parameters: BTreeMap<String, Value>,
}

/// Serializable token state. The host application remains responsible for secure storage.
#[derive(Serialize, Deserialize)]
pub struct AuthenticationState {
    token_response: TokenResponse,
    expires_at: Option<u64>,
    #[serde(default)]
    oidc_nonce: Option<String>,
}

impl AuthenticationState {
    /// Creates state and records expiry relative to the current system time.
    ///
    /// Use [`AuthorizationSession::authentication_state`] when the state
    /// follows an OIDC authorization and must retain that request's nonce.
    pub fn new(token_response: TokenResponse) -> Result<Self> {
        Self::new_with_oidc_nonce(token_response, None)
    }

    /// Creates state while retaining the nonce used for the OIDC authorization.
    ///
    /// This state contains sensitive tokens. The host application must encrypt
    /// it before persisting it.
    pub fn new_with_oidc_nonce(
        token_response: TokenResponse,
        oidc_nonce: Option<String>,
    ) -> Result<Self> {
        if oidc_nonce
            .as_deref()
            .is_some_and(|nonce| nonce.trim().is_empty())
        {
            return Err(AuthError::InvalidConfiguration(
                "OIDC nonce must not be empty",
            ));
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::Clock)?;
        Self::new_at_with_oidc_nonce(token_response, now.as_secs(), oidc_nonce)
    }

    #[cfg(test)]
    fn new_at(token_response: TokenResponse, now: u64) -> Result<Self> {
        Self::new_at_with_oidc_nonce(token_response, now, None)
    }

    fn new_at_with_oidc_nonce(
        token_response: TokenResponse,
        now: u64,
        oidc_nonce: Option<String>,
    ) -> Result<Self> {
        let expires_at = token_response
            .expires_in
            .map(|expires_in| {
                now.checked_add(expires_in)
                    .ok_or(AuthError::InvalidTokenResponse(
                        "expires_in exceeds the supported range",
                    ))
            })
            .transpose()?;
        Ok(Self {
            token_response,
            expires_at,
            oidc_nonce,
        })
    }

    /// Returns the current token response.
    pub fn token_response(&self) -> &TokenResponse {
        &self.token_response
    }

    /// Returns the access-token expiration as seconds since the Unix epoch.
    pub fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    /// Returns `None` when the token response did not include `expires_in`.
    pub fn is_expired_at(&self, unix_time_seconds: u64) -> Option<bool> {
        self.expires_at
            .map(|expires_at| unix_time_seconds >= expires_at)
    }

    /// Refreshes explicitly and only updates this state after a successful response.
    ///
    /// No automatic refresh is performed. If the operation fails, the existing
    /// state remains unchanged.
    pub async fn refresh(
        &mut self,
        configuration: &ServiceConfiguration,
        client_id: &str,
        transport: &dyn HttpTransport,
        cancellation: CancellationHandle,
    ) -> Result<()> {
        self.refresh_with_additional_parameters(
            configuration,
            client_id,
            &BTreeMap::new(),
            transport,
            cancellation,
        )
        .await
    }

    /// Refreshes using additional token endpoint parameters.
    ///
    /// No automatic refresh is performed. If the operation fails, the existing
    /// state remains unchanged.
    pub async fn refresh_with_additional_parameters(
        &mut self,
        configuration: &ServiceConfiguration,
        client_id: &str,
        additional_parameters: &BTreeMap<String, String>,
        transport: &dyn HttpTransport,
        cancellation: CancellationHandle,
    ) -> Result<()> {
        if client_id.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "client ID must not be empty",
            ));
        }
        validate_additional_token_parameters(additional_parameters)?;
        let refresh_token = self
            .token_response
            .refresh_token
            .as_deref()
            .filter(|refresh_token| !refresh_token.trim().is_empty())
            .ok_or(AuthError::InvalidConfiguration(
                "authentication state has no refresh token",
            ))?;

        let body = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "refresh_token")
                .append_pair("refresh_token", refresh_token)
                .append_pair("client_id", client_id);
            for (name, value) in additional_parameters {
                form.append_pair(name, value);
            }
            form.finish().into_bytes()
        };
        let mut refreshed = send_token_request(
            &configuration.token_endpoint,
            body,
            transport,
            cancellation.clone(),
        )
        .await?;
        if let Some(id_token) = &refreshed.id_token {
            let issuer = configuration
                .issuer
                .as_ref()
                .ok_or(AuthError::InvalidConfiguration(
                    "OIDC issuer is required to validate ID Tokens",
                ))?;
            let jwks_uri =
                configuration
                    .jwks_uri
                    .as_ref()
                    .ok_or(AuthError::InvalidConfiguration(
                        "JWKS endpoint is required to validate ID Tokens",
                    ))?;
            validate_id_token(
                IdTokenValidation {
                    token: id_token,
                    issuer,
                    jwks_uri,
                    client_id,
                    expected_nonce: self.oidc_nonce.as_deref(),
                    require_nonce: false,
                },
                &configuration.jwks_cache,
                transport,
                cancellation,
            )
            .await?;
        }

        if refreshed.refresh_token.is_none() {
            refreshed.refresh_token = Some(refresh_token.to_owned());
        }
        if refreshed.scope.is_none() {
            refreshed.scope = self.token_response.scope.clone();
        }
        if refreshed.id_token.is_none() {
            refreshed.id_token = self.token_response.id_token.clone();
        }

        let mut updated_state = Self::new(refreshed)?;
        updated_state.oidc_nonce = self.oidc_nonce.clone();
        *self = updated_state;
        Ok(())
    }
}

async fn send_token_request(
    token_endpoint: &Url,
    body: Vec<u8>,
    transport: &dyn HttpTransport,
    cancellation: CancellationHandle,
) -> Result<TokenResponse> {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );

    let response = transport
        .execute(
            HttpRequest {
                method: Method::POST,
                url: token_endpoint.clone(),
                headers,
                body,
            },
            cancellation,
        )
        .await?;

    if !response.status.is_success() {
        if let Ok(value) = serde_json::from_slice::<Value>(&response.body) {
            if let Some(code) = value.get("error").and_then(Value::as_str) {
                return Err(AuthError::AuthorizationServer {
                    code: code.to_owned(),
                    description: value
                        .get("error_description")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                });
            }
        }
        return Err(AuthError::HttpStatus(response.status));
    }

    parse_token_response(&response.body)
}

fn parse_token_response(body: &[u8]) -> Result<TokenResponse> {
    let mut object: Map<String, Value> = serde_json::from_slice(body)
        .map_err(|_| AuthError::InvalidTokenResponse("response is not a JSON object"))?;

    let access_token = take_required_string(&mut object, "access_token")?;
    let token_type = take_required_string(&mut object, "token_type")?;
    if access_token.is_empty() || token_type.is_empty() {
        return Err(AuthError::InvalidTokenResponse(
            "access_token and token_type must not be empty",
        ));
    }

    let expires_in = take_optional_u64(&mut object, "expires_in")?;
    let refresh_token = take_optional_string(&mut object, "refresh_token")?;
    if matches!(refresh_token.as_deref(), Some("")) {
        return Err(AuthError::InvalidTokenResponse(
            "refresh_token must not be empty",
        ));
    }
    let scope = take_optional_string(&mut object, "scope")?;
    let id_token = take_optional_string(&mut object, "id_token")?;

    Ok(TokenResponse {
        access_token,
        token_type,
        expires_in,
        refresh_token,
        scope,
        id_token,
        additional_parameters: object.into_iter().collect(),
    })
}

fn parse_client_registration_response(body: &[u8]) -> Result<ClientRegistrationResponse> {
    let mut object: Map<String, Value> = serde_json::from_slice(body).map_err(|_| {
        AuthError::InvalidClientRegistrationResponse("response is not a JSON object")
    })?;
    if object.contains_key("client_secret") {
        return Err(AuthError::InvalidClientRegistrationResponse(
            "public client registration response must not include a client_secret",
        ));
    }
    if object.get("application_type").and_then(Value::as_str) != Some("native") {
        return Err(AuthError::InvalidClientRegistrationResponse(
            "application_type is not native",
        ));
    }
    if object
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        != Some("none")
    {
        return Err(AuthError::InvalidClientRegistrationResponse(
            "token endpoint authentication method is not none",
        ));
    }

    let client_id = object
        .remove("client_id")
        .and_then(|value| value.as_str().map(str::to_owned))
        .filter(|client_id| !client_id.trim().is_empty())
        .ok_or(AuthError::InvalidClientRegistrationResponse(
            "client_id is missing or invalid",
        ))?;
    Ok(ClientRegistrationResponse { client_id })
}

fn take_required_string(object: &mut Map<String, Value>, key: &str) -> Result<String> {
    object
        .remove(key)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or(AuthError::InvalidTokenResponse(
            "required string field is missing or invalid",
        ))
}

fn take_optional_string(object: &mut Map<String, Value>, key: &str) -> Result<Option<String>> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(AuthError::InvalidTokenResponse(
            "optional string field has an invalid value",
        )),
    }
}

fn take_optional_u64(object: &mut Map<String, Value>, key: &str) -> Result<Option<u64>> {
    match object.remove(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => {
            value
                .as_u64()
                .map(Some)
                .ok_or(AuthError::InvalidTokenResponse(
                    "expires_in must be a non-negative integer",
                ))
        }
        Some(_) => Err(AuthError::InvalidTokenResponse(
            "expires_in must be a non-negative integer",
        )),
    }
}

fn validate_endpoint(endpoint: &Url) -> Result<()> {
    let is_https = endpoint.scheme() == "https";
    let is_loopback_host = match endpoint.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    };
    let is_loopback_http = endpoint.scheme() == "http" && is_loopback_host;
    if (!is_https && !is_loopback_http)
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(AuthError::InvalidConfiguration(
            "endpoints must use HTTPS or loopback HTTP without user info or fragments",
        ));
    }
    Ok(())
}

fn validate_logout_endpoint(endpoint: &Url) -> Result<()> {
    if endpoint.scheme() != "https" || validate_endpoint(endpoint).is_err() {
        return Err(AuthError::InvalidConfiguration(
            "end-session endpoint must use HTTPS without user info or fragments",
        ));
    }
    Ok(())
}

fn validate_registration_endpoint(endpoint: &Url) -> Result<()> {
    if endpoint.scheme() != "https" || validate_endpoint(endpoint).is_err() {
        return Err(AuthError::InvalidConfiguration(
            "client registration endpoint must use HTTPS without user info or fragments",
        ));
    }
    Ok(())
}

fn validate_oidc_endpoint(endpoint: &Url) -> Result<()> {
    if endpoint.scheme() != "https" || validate_endpoint(endpoint).is_err() {
        return Err(AuthError::InvalidConfiguration(
            "JWKS endpoint must use HTTPS without user info or fragments",
        ));
    }
    Ok(())
}

fn validate_bearer_token(token: &str) -> Result<()> {
    let mut padding_started = false;
    let mut has_token_character = false;
    for byte in token.bytes() {
        if byte == b'=' {
            padding_started = true;
        } else if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        {
            if padding_started {
                return Err(AuthError::InvalidConfiguration(
                    "initial access token is not a valid bearer token",
                ));
            }
            has_token_character = true;
        } else {
            return Err(AuthError::InvalidConfiguration(
                "initial access token is not a valid bearer token",
            ));
        }
    }
    if !has_token_character {
        return Err(AuthError::InvalidConfiguration(
            "initial access token is not a valid bearer token",
        ));
    }
    Ok(())
}

fn reject_reserved_end_session_parameters(endpoint: &Url) -> Result<()> {
    if endpoint
        .query_pairs()
        .any(|(name, _)| RESERVED_END_SESSION_PARAMETERS.contains(&name.as_ref()))
    {
        return Err(AuthError::InvalidConfiguration(
            "end-session endpoint query contains a reserved parameter",
        ));
    }
    Ok(())
}

fn validate_additional_token_parameter(name: &str) -> Result<()> {
    if name.is_empty() || RESERVED_TOKEN_PARAMETERS.contains(&name) {
        return Err(AuthError::InvalidConfiguration(
            "additional token parameter has an empty or reserved name",
        ));
    }
    Ok(())
}

fn validate_additional_token_parameters(parameters: &BTreeMap<String, String>) -> Result<()> {
    for name in parameters.keys() {
        validate_additional_token_parameter(name)?;
    }
    Ok(())
}

fn validate_issuer(issuer: &Url) -> Result<()> {
    if issuer.scheme() != "https"
        || issuer.host_str().is_none()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || issuer.query().is_some()
        || issuer.fragment().is_some()
    {
        return Err(AuthError::InvalidConfiguration(
            "OIDC issuer must be an HTTPS URL without user info, query, or fragment",
        ));
    }
    Ok(())
}

fn oidc_discovery_url(issuer: &Url) -> Result<Url> {
    let mut discovery_url = issuer.clone();
    let mut path_segments = discovery_url
        .path_segments_mut()
        .map_err(|_| AuthError::InvalidConfiguration("OIDC issuer URL cannot be a base URL"))?;
    path_segments.pop_if_empty();
    path_segments.extend(OIDC_DISCOVERY_PATH);
    drop(path_segments);
    Ok(discovery_url)
}

fn parse_discovered_endpoint(value: &str) -> Result<Url> {
    let endpoint = Url::parse(value)
        .map_err(|_| AuthError::InvalidDiscoveryMetadata("endpoint is not a valid URL"))?;
    if endpoint.scheme() != "https" || validate_endpoint(&endpoint).is_err() {
        return Err(AuthError::InvalidDiscoveryMetadata(
            "endpoints must use HTTPS without user info or fragments",
        ));
    }
    Ok(endpoint)
}

fn validate_redirect_uri(redirect_uri: &Url) -> Result<()> {
    if redirect_uri.scheme().is_empty()
        || redirect_uri.fragment().is_some()
        || !redirect_uri.username().is_empty()
        || redirect_uri.password().is_some()
    {
        return Err(AuthError::InvalidConfiguration(
            "redirect URI must have a scheme and must not contain credentials or a fragment",
        ));
    }
    if redirect_uri.query_pairs().any(|(name, _)| {
        matches!(
            name.as_ref(),
            "code" | "state" | "error" | "error_description" | "error_uri" | "iss"
        )
    }) {
        return Err(AuthError::InvalidConfiguration(
            "redirect URI query contains an authorization response parameter",
        ));
    }
    Ok(())
}

fn validate_scope(scope: &str) -> Result<()> {
    if scope.is_empty()
        || !scope.bytes().all(|byte| {
            byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
        })
    {
        return Err(AuthError::InvalidConfiguration(
            "scope values must be non-empty RFC 6749 scope tokens",
        ));
    }
    Ok(())
}

fn reject_reserved_endpoint_parameters(endpoint: &Url) -> Result<()> {
    if endpoint
        .query_pairs()
        .any(|(name, _)| RESERVED_AUTHORIZATION_PARAMETERS.contains(&name.as_ref()))
    {
        return Err(AuthError::InvalidConfiguration(
            "authorization endpoint query contains a reserved parameter",
        ));
    }
    Ok(())
}

fn validate_redirect_uri_match(expected: &Url, received: &Url) -> Result<()> {
    if !redirect_uris_match(expected, received) {
        return Err(AuthError::InvalidAuthorizationResponse(
            "redirect URI does not match the request",
        ));
    }
    Ok(())
}

fn validate_end_session_redirect_uri_match(expected: &Url, received: &Url) -> Result<()> {
    if !redirect_uris_match(expected, received) {
        return Err(AuthError::InvalidEndSessionResponse(
            "post-logout redirect URI does not match the request",
        ));
    }
    Ok(())
}

fn redirect_uris_match(expected: &Url, received: &Url) -> bool {
    received.fragment().is_none()
        && expected.scheme() == received.scheme()
        && expected.username() == received.username()
        && expected.password() == received.password()
        && expected.host_str() == received.host_str()
        && expected.port() == received.port()
        && expected.path() == received.path()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use http::StatusCode;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::{HttpRequest, HttpResponse};

    struct TestTransport {
        request: Mutex<Option<HttpRequest>>,
        response: Mutex<Option<HttpResponse>>,
    }

    #[async_trait]
    impl HttpTransport for TestTransport {
        async fn execute(
            &self,
            request: HttpRequest,
            _cancellation: CancellationHandle,
        ) -> Result<HttpResponse> {
            *self.request.lock().unwrap() = Some(request);
            Ok(self.response.lock().unwrap().take().unwrap())
        }
    }

    fn test_transport(status: StatusCode, body: &'static [u8]) -> TestTransport {
        TestTransport {
            request: Mutex::new(None),
            response: Mutex::new(Some(HttpResponse {
                status,
                headers: HeaderMap::new(),
                body: body.to_vec(),
            })),
        }
    }

    fn discovery_transport(body: &'static [u8]) -> TestTransport {
        test_transport(StatusCode::OK, body)
    }

    fn request(scopes: &[&str]) -> AuthorizationRequest {
        let mut configuration = ServiceConfiguration::new(
            Url::parse("https://issuer.example/authorize").unwrap(),
            Url::parse("https://issuer.example/token").unwrap(),
        )
        .unwrap();
        if scopes.contains(&"openid") {
            configuration = configuration
                .with_oidc_validation_endpoints(
                    Url::parse("https://issuer.example/").unwrap(),
                    Url::parse("https://issuer.example/keys").unwrap(),
                )
                .unwrap();
        }
        AuthorizationRequest::new(
            configuration,
            "native-client",
            Url::parse("com.example.app:/oauth2redirect").unwrap(),
            scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        )
        .unwrap()
    }

    fn authentication_state() -> AuthenticationState {
        AuthenticationState::new_at(
            TokenResponse {
                access_token: "old-access".to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: Some(60),
                refresh_token: Some("old-refresh".to_owned()),
                scope: Some("openid profile".to_owned()),
                id_token: Some("old-id".to_owned()),
                additional_parameters: BTreeMap::new(),
            },
            1_000,
        )
        .unwrap()
    }

    fn service_configuration() -> ServiceConfiguration {
        ServiceConfiguration::new(
            Url::parse("https://issuer.example/authorize").unwrap(),
            Url::parse("https://issuer.example/token").unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn openid_authorization_requires_validation_endpoints_before_browser_launch() {
        assert!(matches!(
            AuthorizationRequest::new(
                service_configuration(),
                "native-client",
                Url::parse("com.example.app:/oauth2redirect").unwrap(),
                vec!["openid".to_owned()],
            ),
            Err(AuthError::InvalidConfiguration(
                "OIDC issuer and JWKS endpoint are required to validate ID Tokens"
            ))
        ));
    }

    #[test]
    fn authentication_state_serializes_expiration() {
        let state = authentication_state();

        assert_eq!(state.expires_at(), Some(1_060));
        assert_eq!(state.is_expired_at(1_059), Some(false));
        assert_eq!(state.is_expired_at(1_060), Some(true));

        let serialized = serde_json::to_vec(&state).unwrap();
        let restored: AuthenticationState = serde_json::from_slice(&serialized).unwrap();
        assert_eq!(restored.expires_at(), Some(1_060));
        assert_eq!(
            restored.token_response().access_token,
            state.token_response().access_token
        );

        let token_response = TokenResponse {
            access_token: "access".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
            additional_parameters: BTreeMap::new(),
        };
        let state_without_expiry = AuthenticationState::new_at(token_response, 1_000).unwrap();
        assert_eq!(state_without_expiry.expires_at(), None);
        assert_eq!(state_without_expiry.is_expired_at(2_000), None);
    }

    #[test]
    fn authorization_session_carries_nonce_into_serialized_authentication_state() {
        let session = request(&["openid"]).begin().unwrap();
        let state = session
            .authentication_state(TokenResponse {
                access_token: "access".to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: None,
                refresh_token: Some("refresh".to_owned()),
                scope: Some("openid".to_owned()),
                id_token: Some("validated-id-token".to_owned()),
                additional_parameters: BTreeMap::new(),
            })
            .unwrap();

        let serialized = serde_json::to_value(&state).unwrap();
        assert_eq!(
            serialized["oidc_nonce"],
            serde_json::json!(session.nonce().unwrap())
        );
        let restored: AuthenticationState = serde_json::from_value(serialized).unwrap();
        assert_eq!(
            serde_json::to_value(restored).unwrap()["oidc_nonce"],
            serde_json::json!(session.nonce().unwrap())
        );
    }

    #[tokio::test]
    async fn refresh_updates_tokens_and_retains_omitted_refresh_fields() {
        let mut state = authentication_state();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let transport = test_transport(
            StatusCode::OK,
            br#"{
                "access_token":"new-access",
                "token_type":"Bearer",
                "expires_in":3600
            }"#,
        );
        let additional_parameters =
            BTreeMap::from([("audience".to_owned(), "https://api.example".to_owned())]);

        state
            .refresh_with_additional_parameters(
                &service_configuration(),
                "native-client",
                &additional_parameters,
                &transport,
                CancellationHandle::new(),
            )
            .await
            .unwrap();

        let request = transport.request.lock().unwrap().take().unwrap();
        let form: BTreeMap<_, _> = form_urlencoded::parse(&request.body).into_owned().collect();
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.url.as_str(), "https://issuer.example/token");
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("refresh_token")
        );
        assert_eq!(
            form.get("refresh_token").map(String::as_str),
            Some("old-refresh")
        );
        assert_eq!(
            form.get("client_id").map(String::as_str),
            Some("native-client")
        );
        assert_eq!(
            form.get("audience").map(String::as_str),
            Some("https://api.example")
        );
        assert_eq!(state.token_response().access_token, "new-access");
        assert_eq!(
            state.token_response().refresh_token.as_deref(),
            Some("old-refresh")
        );
        assert_eq!(
            state.token_response().scope.as_deref(),
            Some("openid profile")
        );
        assert_eq!(state.token_response().id_token.as_deref(), Some("old-id"));
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expires_at = state.expires_at().unwrap();
        assert!(expires_at >= before + 3_600 && expires_at <= after + 3_600);
    }

    #[tokio::test]
    async fn refresh_rotates_refresh_token_and_preserves_state_on_failure() {
        let mut state = authentication_state();
        let transport = test_transport(
            StatusCode::OK,
            br#"{
                "access_token":"new-access",
                "token_type":"Bearer",
                "refresh_token":"rotated-refresh"
            }"#,
        );
        state
            .refresh(
                &service_configuration(),
                "native-client",
                &transport,
                CancellationHandle::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            state.token_response().refresh_token.as_deref(),
            Some("rotated-refresh")
        );

        let before = serde_json::to_value(&state).unwrap();
        let error_transport =
            test_transport(StatusCode::BAD_REQUEST, br#"{"error":"invalid_grant"}"#);
        assert!(matches!(
            state
                .refresh(
                    &service_configuration(),
                    "native-client",
                    &error_transport,
                    CancellationHandle::new(),
                )
                .await,
            Err(AuthError::AuthorizationServer { code, .. }) if code == "invalid_grant"
        ));
        assert_eq!(serde_json::to_value(&state).unwrap(), before);

        let invalid_response = test_transport(
            StatusCode::OK,
            br#"{
                "access_token":"new-access",
                "token_type":"Bearer",
                "refresh_token":""
            }"#,
        );
        assert!(matches!(
            state
                .refresh(
                    &service_configuration(),
                    "native-client",
                    &invalid_response,
                    CancellationHandle::new(),
                )
                .await,
            Err(AuthError::InvalidTokenResponse(
                "refresh_token must not be empty"
            ))
        ));
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }

    #[tokio::test]
    async fn refresh_rejects_an_invalid_returned_id_token_without_updating_state() {
        let mut state = AuthenticationState::new_with_oidc_nonce(
            TokenResponse {
                access_token: "old-access".to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: None,
                refresh_token: Some("old-refresh".to_owned()),
                scope: Some("openid".to_owned()),
                id_token: Some("old-id".to_owned()),
                additional_parameters: BTreeMap::new(),
            },
            Some("original-nonce".to_owned()),
        )
        .unwrap();
        let before = serde_json::to_value(&state).unwrap();
        let configuration = service_configuration()
            .with_oidc_validation_endpoints(
                Url::parse("https://issuer.example/").unwrap(),
                Url::parse("https://issuer.example/keys").unwrap(),
            )
            .unwrap();
        let transport = test_transport(
            StatusCode::OK,
            br#"{
                "access_token":"new-access",
                "token_type":"Bearer",
                "id_token":"not.a.jwt"
            }"#,
        );

        assert!(matches!(
            state
                .refresh(
                    &configuration,
                    "native-client",
                    &transport,
                    CancellationHandle::new(),
                )
                .await,
            Err(AuthError::InvalidIdToken(
                "JWT header is malformed or unsupported"
            ))
        ));
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }

    #[tokio::test]
    async fn refresh_without_a_refresh_token_does_not_send_a_request() {
        let mut state = AuthenticationState::new_at(
            TokenResponse {
                access_token: "access".to_owned(),
                token_type: "Bearer".to_owned(),
                expires_in: None,
                refresh_token: None,
                scope: None,
                id_token: None,
                additional_parameters: BTreeMap::new(),
            },
            1_000,
        )
        .unwrap();
        let transport = test_transport(StatusCode::OK, br#"{}"#);

        assert!(matches!(
            state
                .refresh(
                    &service_configuration(),
                    "native-client",
                    &transport,
                    CancellationHandle::new(),
                )
                .await,
            Err(AuthError::InvalidConfiguration(
                "authentication state has no refresh token"
            ))
        ));
        assert!(transport.request.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn refresh_rejects_reserved_additional_parameters_before_sending() {
        let mut state = authentication_state();
        let additional_parameters =
            BTreeMap::from([("client_secret".to_owned(), "not-allowed".to_owned())]);
        let transport = test_transport(StatusCode::OK, br#"{}"#);

        assert!(matches!(
            state
                .refresh_with_additional_parameters(
                    &service_configuration(),
                    "native-client",
                    &additional_parameters,
                    &transport,
                    CancellationHandle::new(),
                )
                .await,
            Err(AuthError::InvalidConfiguration(
                "additional token parameter has an empty or reserved name"
            ))
        ));
        assert!(transport.request.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn discovery_uses_issuer_path_and_validates_endpoints() {
        let transport = discovery_transport(
            br#"{
                "issuer":"https://issuer.example/tenant",
                "authorization_endpoint":"https://issuer.example/tenant/authorize",
                "token_endpoint":"https://issuer.example/tenant/token",
                "end_session_endpoint":"https://issuer.example/tenant/logout",
                "registration_endpoint":"https://issuer.example/tenant/register",
                "jwks_uri":"https://issuer.example/tenant/keys"
            }"#,
        );

        let configuration = ServiceConfiguration::discover(
            Url::parse("https://issuer.example/tenant").unwrap(),
            &transport,
            CancellationHandle::new(),
        )
        .await
        .unwrap();
        let request = transport.request.lock().unwrap().take().unwrap();

        assert_eq!(
            request.url.as_str(),
            "https://issuer.example/tenant/.well-known/openid-configuration"
        );
        assert_eq!(request.method, Method::GET);
        assert_eq!(
            request.headers.get(header::ACCEPT).unwrap(),
            "application/json"
        );
        assert_eq!(
            configuration.authorization_endpoint().as_str(),
            "https://issuer.example/tenant/authorize"
        );
        assert_eq!(
            configuration.token_endpoint().as_str(),
            "https://issuer.example/tenant/token"
        );
        assert_eq!(
            configuration.end_session_endpoint().unwrap().as_str(),
            "https://issuer.example/tenant/logout"
        );
        assert_eq!(
            configuration.registration_endpoint().unwrap().as_str(),
            "https://issuer.example/tenant/register"
        );
        assert_eq!(
            configuration.issuer().unwrap().as_str(),
            "https://issuer.example/tenant"
        );
        assert_eq!(
            configuration.jwks_uri().unwrap().as_str(),
            "https://issuer.example/tenant/keys"
        );
    }

    #[tokio::test]
    async fn discovery_rejects_mismatched_issuer_and_insecure_endpoints() {
        let mismatched_issuer = discovery_transport(
            br#"{
                "issuer":"https://other.example",
                "authorization_endpoint":"https://issuer.example/authorize",
                "token_endpoint":"https://issuer.example/token"
            }"#,
        );
        assert!(matches!(
            ServiceConfiguration::discover(
                Url::parse("https://issuer.example").unwrap(),
                &mismatched_issuer,
                CancellationHandle::new(),
            )
            .await,
            Err(AuthError::InvalidDiscoveryMetadata(
                "issuer does not match the requested issuer"
            ))
        ));

        let insecure_endpoint = discovery_transport(
            br#"{
                "issuer":"https://issuer.example/",
                "authorization_endpoint":"http://issuer.example/authorize",
                "token_endpoint":"https://issuer.example/token"
            }"#,
        );
        assert!(matches!(
            ServiceConfiguration::discover(
                Url::parse("https://issuer.example").unwrap(),
                &insecure_endpoint,
                CancellationHandle::new(),
            )
            .await,
            Err(AuthError::InvalidDiscoveryMetadata(
                "endpoints must use HTTPS without user info or fragments"
            ))
        ));

        let insecure_logout_endpoint = discovery_transport(
            br#"{
                "issuer":"https://issuer.example/",
                "authorization_endpoint":"https://issuer.example/authorize",
                "token_endpoint":"https://issuer.example/token",
                "end_session_endpoint":"http://issuer.example/logout"
            }"#,
        );
        assert!(matches!(
            ServiceConfiguration::discover(
                Url::parse("https://issuer.example").unwrap(),
                &insecure_logout_endpoint,
                CancellationHandle::new(),
            )
            .await,
            Err(AuthError::InvalidDiscoveryMetadata(
                "endpoints must use HTTPS without user info or fragments"
            ))
        ));

        let insecure_registration_endpoint = discovery_transport(
            br#"{
                "issuer":"https://issuer.example/",
                "authorization_endpoint":"https://issuer.example/authorize",
                "token_endpoint":"https://issuer.example/token",
                "registration_endpoint":"http://issuer.example/register"
            }"#,
        );
        assert!(matches!(
            ServiceConfiguration::discover(
                Url::parse("https://issuer.example").unwrap(),
                &insecure_registration_endpoint,
                CancellationHandle::new(),
            )
            .await,
            Err(AuthError::InvalidDiscoveryMetadata(
                "endpoints must use HTTPS without user info or fragments"
            ))
        ));
    }

    #[tokio::test]
    async fn client_registration_sends_public_native_metadata() {
        let configuration = service_configuration()
            .with_registration_endpoint(Url::parse("https://issuer.example/register").unwrap())
            .unwrap();
        let redirect_uri = Url::parse("com.example.app:/oauth2redirect").unwrap();
        let transport = test_transport(
            StatusCode::CREATED,
            br#"{
                "client_id":"registered-client",
                "application_type":"native",
                "token_endpoint_auth_method":"none"
            }"#,
        );
        let response = ClientRegistrationRequest::new(&configuration, vec![redirect_uri.clone()])
            .unwrap()
            .with_client_name("Example App")
            .unwrap()
            .with_initial_access_token("registration-token")
            .unwrap()
            .register(&transport, CancellationHandle::new())
            .await
            .unwrap();

        assert_eq!(response.client_id(), "registered-client");
        let request = transport.request.lock().unwrap().take().unwrap();
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.url.as_str(), "https://issuer.example/register");
        assert_eq!(
            request.headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let authorization = request.headers.get(header::AUTHORIZATION).unwrap();
        assert_eq!(authorization, "Bearer registration-token");
        assert!(authorization.is_sensitive());

        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["application_type"], "native");
        assert_eq!(body["client_name"], "Example App");
        assert_eq!(
            body["grant_types"],
            serde_json::json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(
            body["redirect_uris"],
            serde_json::json!([redirect_uri.as_str()])
        );
        assert_eq!(body["response_types"], serde_json::json!(["code"]));
        assert_eq!(body["token_endpoint_auth_method"], "none");
        assert!(body.get("client_secret").is_none());
    }

    #[tokio::test]
    async fn client_registration_rejects_responses_that_are_not_public_clients() {
        let configuration = service_configuration()
            .with_registration_endpoint(Url::parse("https://issuer.example/register").unwrap())
            .unwrap();
        let request = || {
            ClientRegistrationRequest::new(
                &configuration,
                vec![Url::parse("com.example.app:/oauth2redirect").unwrap()],
            )
            .unwrap()
        };

        let with_client_secret = test_transport(
            StatusCode::CREATED,
            br#"{
                "client_id":"registered-client",
                "client_secret":"must-not-be-used",
                "application_type":"native",
                "token_endpoint_auth_method":"none"
            }"#,
        );
        assert!(matches!(
            request()
                .register(&with_client_secret, CancellationHandle::new())
                .await,
            Err(AuthError::InvalidClientRegistrationResponse(
                "public client registration response must not include a client_secret"
            ))
        ));

        let wrong_auth_method = test_transport(
            StatusCode::CREATED,
            br#"{
                "client_id":"registered-client",
                "application_type":"native",
                "token_endpoint_auth_method":"client_secret_basic"
            }"#,
        );
        assert!(matches!(
            request()
                .register(&wrong_auth_method, CancellationHandle::new())
                .await,
            Err(AuthError::InvalidClientRegistrationResponse(
                "token endpoint authentication method is not none"
            ))
        ));
    }

    #[tokio::test]
    async fn client_registration_surfaces_server_errors() {
        let configuration = service_configuration()
            .with_registration_endpoint(Url::parse("https://issuer.example/register").unwrap())
            .unwrap();
        let transport = test_transport(
            StatusCode::BAD_REQUEST,
            br#"{
                "error":"invalid_redirect_uri",
                "error_description":"redirect URI is not allowed"
            }"#,
        );
        let result = ClientRegistrationRequest::new(
            &configuration,
            vec![Url::parse("com.example.app:/oauth2redirect").unwrap()],
        )
        .unwrap()
        .register(&transport, CancellationHandle::new())
        .await;

        let request = transport.request.lock().unwrap().take().unwrap();
        assert!(request.headers.get(header::AUTHORIZATION).is_none());
        assert!(matches!(
            result,
            Err(AuthError::ClientRegistrationServer {
                code,
                description: Some(description),
            }) if code == "invalid_redirect_uri" && description == "redirect URI is not allowed"
        ));
    }

    #[test]
    fn client_registration_validates_endpoint_redirects_and_access_tokens() {
        let configuration = service_configuration();
        let redirect_uri = Url::parse("com.example.app:/oauth2redirect").unwrap();
        assert!(matches!(
            configuration
                .clone()
                .with_registration_endpoint(Url::parse("http://issuer.example/register").unwrap()),
            Err(AuthError::InvalidConfiguration(
                "client registration endpoint must use HTTPS without user info or fragments"
            ))
        ));
        assert!(matches!(
            ClientRegistrationRequest::new(&configuration, vec![redirect_uri.clone()]),
            Err(AuthError::InvalidConfiguration(
                "client registration endpoint is not configured"
            ))
        ));

        let configuration = configuration
            .with_registration_endpoint(Url::parse("https://issuer.example/register").unwrap())
            .unwrap();
        assert!(matches!(
            ClientRegistrationRequest::new(&configuration, vec![]),
            Err(AuthError::InvalidConfiguration(
                "client registration requires at least one redirect URI"
            ))
        ));
        assert!(matches!(
            ClientRegistrationRequest::new(
                &configuration,
                vec![redirect_uri.clone(), redirect_uri]
            ),
            Err(AuthError::InvalidConfiguration(
                "client registration contains a duplicate redirect URI"
            ))
        ));
        assert!(matches!(
            ClientRegistrationRequest::new(
                &configuration,
                vec![Url::parse("com.example.app:/oauth2redirect?state=unexpected").unwrap()]
            ),
            Err(AuthError::InvalidConfiguration(
                "redirect URI query contains an authorization response parameter"
            ))
        ));
        assert!(matches!(
            ClientRegistrationRequest::new(
                &configuration,
                vec![Url::parse("com.example.app:/oauth2redirect").unwrap()]
            )
            .unwrap()
            .with_initial_access_token("not a bearer token"),
            Err(AuthError::InvalidConfiguration(
                "initial access token is not a valid bearer token"
            ))
        ));
    }

    #[test]
    fn end_session_request_builds_parameters_and_validates_the_callback() {
        let configuration = service_configuration()
            .with_end_session_endpoint(
                Url::parse("https://issuer.example/logout?tenant=example").unwrap(),
            )
            .unwrap();
        let redirect_uri = Url::parse("com.example.app:/logout?source=app").unwrap();
        let session = EndSessionRequest::new(&configuration, "native-client")
            .unwrap()
            .with_id_token_hint("id-token-hint")
            .unwrap()
            .with_post_logout_redirect_uri(redirect_uri)
            .unwrap()
            .begin()
            .unwrap();
        let parameters: BTreeMap<_, _> = session
            .end_session_url()
            .query_pairs()
            .into_owned()
            .collect();
        let state = parameters.get("state").unwrap();

        assert_eq!(
            parameters.get("client_id").map(String::as_str),
            Some("native-client")
        );
        assert_eq!(
            parameters.get("id_token_hint").map(String::as_str),
            Some("id-token-hint")
        );
        assert_eq!(
            parameters
                .get("post_logout_redirect_uri")
                .map(String::as_str),
            Some("com.example.app:/logout?source=app")
        );
        assert_eq!(
            parameters.get("tenant").map(String::as_str),
            Some("example")
        );

        let callback = Url::parse(&format!(
            "com.example.app:/logout?source=app&state={state}&logout=complete"
        ))
        .unwrap();
        let response = session.parse_redirect(&callback).unwrap();
        assert_eq!(response.state(), state);
        assert_eq!(
            response
                .additional_parameters()
                .get("logout")
                .map(String::as_str),
            Some("complete")
        );

        let mismatched_state =
            Url::parse("com.example.app:/logout?source=app&state=wrong").unwrap();
        assert!(matches!(
            session.parse_redirect(&mismatched_state),
            Err(AuthError::InvalidEndSessionResponse("state mismatch"))
        ));
        let missing_state = Url::parse("com.example.app:/logout?source=app").unwrap();
        assert!(matches!(
            session.parse_redirect(&missing_state),
            Err(AuthError::InvalidEndSessionResponse(
                "response is missing state"
            ))
        ));
        let duplicate_state = Url::parse(&format!(
            "com.example.app:/logout?source=app&state={state}&state={state}"
        ))
        .unwrap();
        assert!(matches!(
            session.parse_redirect(&duplicate_state),
            Err(AuthError::InvalidEndSessionResponse(
                "response contains a duplicate parameter"
            ))
        ));
    }

    #[test]
    fn end_session_rejects_missing_or_insecure_endpoints() {
        let configuration = service_configuration();
        assert!(matches!(
            EndSessionRequest::new(&configuration, "native-client"),
            Err(AuthError::InvalidConfiguration(
                "end-session endpoint is not configured"
            ))
        ));

        assert!(matches!(
            configuration
                .clone()
                .with_end_session_endpoint(Url::parse("http://issuer.example/logout").unwrap()),
            Err(AuthError::InvalidConfiguration(
                "end-session endpoint must use HTTPS without user info or fragments"
            ))
        ));

        let endpoint_with_reserved_query = configuration
            .with_end_session_endpoint(
                Url::parse("https://issuer.example/logout?state=attacker").unwrap(),
            )
            .unwrap();
        assert!(matches!(
            EndSessionRequest::new(&endpoint_with_reserved_query, "native-client"),
            Err(AuthError::InvalidConfiguration(
                "end-session endpoint query contains a reserved parameter"
            ))
        ));
    }

    #[test]
    fn authorization_request_uses_code_and_s256_pkce() {
        let session = request(&["openid", "profile"]).begin().unwrap();
        let parameters: BTreeMap<_, _> = session
            .authorization_url()
            .query_pairs()
            .into_owned()
            .collect();

        assert_eq!(
            parameters.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            parameters.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        assert_eq!(parameters.get("nonce").map(String::as_str), session.nonce());
        assert_eq!(
            parameters.get("scope").map(String::as_str),
            Some("openid profile")
        );
        assert_eq!(
            parameters.get("redirect_uri").map(String::as_str),
            Some("com.example.app:/oauth2redirect")
        );
    }

    #[test]
    fn authorization_response_requires_matching_redirect_and_state() {
        let session = request(&["openid"]).begin().unwrap();
        let state = &session.state;
        let redirect = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=auth-code&state={state}&provider_hint=tenant"
        ))
        .unwrap();

        let response = session.parse_redirect(&redirect).unwrap();
        assert_eq!(response.code(), "auth-code");
        assert_eq!(
            response
                .additional_parameters
                .get("provider_hint")
                .map(String::as_str),
            Some("tenant")
        );
    }

    #[test]
    fn authorization_response_rejects_mismatched_state_and_redirect_uri() {
        let session = request(&["openid"]).begin().unwrap();
        let wrong_state =
            Url::parse("com.example.app:/oauth2redirect?code=auth-code&state=wrong").unwrap();
        assert!(matches!(
            session.parse_redirect(&wrong_state),
            Err(AuthError::InvalidAuthorizationResponse("state mismatch"))
        ));

        let wrong_path =
            Url::parse("com.example.app:/different?code=auth-code&state=state").unwrap();
        assert!(matches!(
            session.parse_redirect(&wrong_path),
            Err(AuthError::InvalidAuthorizationResponse(
                "redirect URI does not match the request"
            ))
        ));
    }

    #[test]
    fn rejects_duplicate_and_conflicting_authorization_parameters() {
        let session = request(&[]).begin().unwrap();
        let state = &session.state;
        let duplicate = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=one&code=two&state={state}"
        ))
        .unwrap();
        assert!(matches!(
            session.parse_redirect(&duplicate),
            Err(AuthError::InvalidAuthorizationResponse(
                "response contains a duplicate parameter"
            ))
        ));

        let conflict = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=one&error=denied&state={state}"
        ))
        .unwrap();
        assert!(matches!(
            session.parse_redirect(&conflict),
            Err(AuthError::InvalidAuthorizationResponse(
                "response contains both code and error"
            ))
        ));
    }

    #[test]
    fn additional_parameters_cannot_override_protocol_fields() {
        let result = request(&[]).with_additional_parameter("state", "attacker-controlled");
        assert!(matches!(
            result,
            Err(AuthError::InvalidConfiguration(
                "additional parameter has an empty or reserved name"
            ))
        ));
    }

    #[test]
    fn additional_token_parameters_cannot_override_protocol_or_client_fields() {
        for name in ["grant_type", "refresh_token", "client_id", "client_secret"] {
            let result = request(&[]).with_additional_token_parameter(name, "caller-value");
            assert!(matches!(
                result,
                Err(AuthError::InvalidConfiguration(
                    "additional token parameter has an empty or reserved name"
                ))
            ));
        }
    }

    #[tokio::test]
    async fn code_exchange_sends_verifier_and_preserves_unknown_token_fields() {
        let session = request(&[])
            .with_additional_token_parameter("audience", "https://api.example")
            .unwrap()
            .begin()
            .unwrap();
        let redirect = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=auth-code&state={}",
            session.state
        ))
        .unwrap();
        let authorization_response = session.parse_redirect(&redirect).unwrap();
        let transport = test_transport(
            StatusCode::OK,
            br#"{
                "access_token":"access",
                "token_type":"Bearer",
                "expires_in":3600,
                "refresh_token":"refresh",
                "provider_data":{"key":"value"}
            }"#,
        );

        let token_response = session
            .exchange_code(
                &transport,
                &authorization_response,
                CancellationHandle::new(),
            )
            .await
            .unwrap();
        let sent_request = transport.request.lock().unwrap().take().unwrap();
        let form: BTreeMap<_, _> = form_urlencoded::parse(&sent_request.body)
            .into_owned()
            .collect();
        let challenge = session
            .authorization_url()
            .query_pairs()
            .find(|(name, _)| name == "code_challenge")
            .unwrap()
            .1;
        let verifier = form.get("code_verifier").unwrap();

        assert_eq!(sent_request.method, Method::POST);
        assert_eq!(sent_request.url.as_str(), "https://issuer.example/token");
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(form.get("code").map(String::as_str), Some("auth-code"));
        assert_eq!(
            form.get("audience").map(String::as_str),
            Some("https://api.example")
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            challenge
        );
        assert_eq!(token_response.access_token, "access");
        assert_eq!(token_response.id_token, None);
        assert_eq!(
            token_response.additional_parameters["provider_data"]["key"],
            "value"
        );
    }

    #[tokio::test]
    async fn openid_code_exchange_rejects_missing_or_malformed_id_tokens() {
        for (body, expected_error) in [
            (
                br#"{"access_token":"access","token_type":"Bearer"}"#.as_slice(),
                "openid token response is missing an ID Token",
            ),
            (
                br#"{"access_token":"access","token_type":"Bearer","id_token":"not.a.jwt"}"#
                    .as_slice(),
                "JWT header is malformed or unsupported",
            ),
        ] {
            let session = request(&["openid"]).begin().unwrap();
            let redirect = Url::parse(&format!(
                "com.example.app:/oauth2redirect?code=auth-code&state={}",
                session.state
            ))
            .unwrap();
            let authorization_response = session.parse_redirect(&redirect).unwrap();
            let transport = test_transport(StatusCode::OK, body);

            assert!(matches!(
                session
                    .exchange_code(
                        &transport,
                        &authorization_response,
                        CancellationHandle::new(),
                    )
                    .await,
                Err(AuthError::InvalidIdToken(message)) if message == expected_error
            ));
        }
    }

    #[tokio::test]
    async fn code_exchange_surfaces_oauth_errors() {
        let session = request(&[]).begin().unwrap();
        let redirect = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=auth-code&state={}",
            session.state
        ))
        .unwrap();
        let authorization_response = session.parse_redirect(&redirect).unwrap();
        let transport = test_transport(
            StatusCode::BAD_REQUEST,
            br#"{"error":"invalid_grant","error_description":"expired code"}"#,
        );

        assert!(matches!(
            session
                .exchange_code(
                    &transport,
                    &authorization_response,
                    CancellationHandle::new()
                )
                .await,
            Err(AuthError::AuthorizationServer { code, .. }) if code == "invalid_grant"
        ));
    }

    #[tokio::test]
    async fn token_requests_surface_http_status_without_an_oauth_error_body() {
        let transport = test_transport(StatusCode::SERVICE_UNAVAILABLE, b"temporarily unavailable");

        assert!(matches!(
            send_token_request(
                &Url::parse("https://issuer.example/token").unwrap(),
                Vec::new(),
                &transport,
                CancellationHandle::new(),
            )
            .await,
            Err(AuthError::HttpStatus(status)) if status == StatusCode::SERVICE_UNAVAILABLE
        ));
    }

    #[tokio::test]
    async fn code_exchange_rejects_response_from_another_session() {
        let first_session = request(&[]).begin().unwrap();
        let second_session = request(&[]).begin().unwrap();
        let redirect = Url::parse(&format!(
            "com.example.app:/oauth2redirect?code=auth-code&state={}",
            first_session.state
        ))
        .unwrap();
        let authorization_response = first_session.parse_redirect(&redirect).unwrap();
        let transport = test_transport(
            StatusCode::OK,
            br#"{"access_token":"access","token_type":"Bearer"}"#,
        );

        assert!(matches!(
            second_session
                .exchange_code(
                    &transport,
                    &authorization_response,
                    CancellationHandle::new()
                )
                .await,
            Err(AuthError::InvalidAuthorizationResponse(
                "authorization response belongs to a different session"
            ))
        ));
        assert!(transport.request.lock().unwrap().is_none());
    }

    #[test]
    fn rejects_insecure_remote_endpoints_and_response_parameters_in_redirect_uri() {
        let insecure_endpoint = ServiceConfiguration::new(
            Url::parse("http://issuer.example/authorize").unwrap(),
            Url::parse("https://issuer.example/token").unwrap(),
        );
        assert!(matches!(
            insecure_endpoint,
            Err(AuthError::InvalidConfiguration(_))
        ));

        let configuration = ServiceConfiguration::new(
            Url::parse("https://issuer.example/authorize").unwrap(),
            Url::parse("https://issuer.example/token").unwrap(),
        )
        .unwrap();
        assert!(matches!(
            AuthorizationRequest::new(
                configuration,
                "native-client",
                Url::parse("com.example.app:/callback?state=static").unwrap(),
                vec![],
            ),
            Err(AuthError::InvalidConfiguration(
                "redirect URI query contains an authorization response parameter"
            ))
        ));
    }
}
