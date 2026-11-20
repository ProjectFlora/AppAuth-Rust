import NativeOIDC
import XCTest

/// Host-side smoke for the Swift package: exercises the generated API through
/// the FFI module provided by the binary target without any network activity.
/// Deeper adapter and callback behavior is covered by the scripts in
/// `scripts/check-apple-*.sh` and the release consumer checks.
final class NativeOIDCTests: XCTestCase {
    /// Token state JSON in the shape produced by `FfiAuthenticationState.toJson()`.
    private let stateJson = #"{"token_response":{"access_token":"old","token_type":"Bearer","refresh_token":"refresh"}}"#

    func testServiceConfigurationBuilder() throws {
        let configuration = try FfiServiceConfiguration(
            authorizationEndpoint: "https://idp.example/authorize",
            tokenEndpoint: "https://idp.example/token"
        )
        let withValidation = try configuration.withOidcValidationEndpoints(
            issuer: "https://idp.example",
            jwksUri: "https://idp.example/.well-known/jwks.json"
        )
        // The issuer is normalized with a trailing slash.
        XCTAssertEqual(withValidation.issuer(), "https://idp.example/")
        XCTAssertEqual(withValidation.jwksUri(), "https://idp.example/.well-known/jwks.json")
    }

    // MARK: - Test Helpers

    /// A fake transport that records requests and returns predefined responses.
    final class ScriptedTransport: NativeHttpTransport, @unchecked Sendable {
        var recordedRequests: [FfiHttpRequest] = []
        var responseToReturn: Result<FfiHttpResponse, Error>?

        func execute(request: FfiHttpRequest, cancellation: FfiCancellationHandle) async throws -> FfiHttpResponse {
            recordedRequests.append(request)
            if let result = responseToReturn {
                switch result {
                case .success(let response):
                    return response
                case .failure(let error):
                    throw error
                }
            }
            fatalError("No response configured for ScriptedTransport")
        }
    }

    /// A transport that simulates a long-running request and responds to cancellation.
    final class BlockingTransport: NativeHttpTransport, @unchecked Sendable {
        func execute(request: FfiHttpRequest, cancellation: FfiCancellationHandle) async throws -> FfiHttpResponse {
            await cancellation.cancelled()
            throw FfiError.Cancelled
        }
    }

    // MARK: - Discovery (D)

    func testD1() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(
            status: 200,
            headers: [],
            body: #"{"issuer":"https://idp.example/","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token","revocation_endpoint":"https://idp.example/revoke","registration_endpoint":"https://id.example/register","end_session_endpoint":"https://idp.example/logout"}"#.data(using: .utf8)!
        ))

        let config = try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: FfiCancellationHandle())
        
        XCTAssertEqual(config.issuer(), "https://idp.example/")
        XCTAssertEqual(config.authorizationEndpoint(), "https://idp.example/authorize")
        XCTAssertEqual(config.tokenEndpoint(), "https://idp.example/token")
        XCTAssertEqual(config.revocationEndpoint(), "https://idp.example/revoke")
        // registrationEndpoint and endSessionEndpoint are not exposed via getters in FfiServiceConfiguration.
        
        XCTAssertEqual(transport.recordedRequests.count, 1)
        let request = transport.recordedRequests[0]
        print("Request headers: \(request.headers.map { "\($0.name): \(String(data: $0.value, encoding: .utf8) ?? "")" })")
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.url, "https://idp.example/.well-known/openid-configuration")
        XCTAssertTrue(request.headers.contains { $0.name.caseInsensitiveCompare("Accept") == .orderedSame && String(data: $0.value, encoding: .utf8) == "application/json" })
    }

    func testD2() async {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 404, headers: [], body: Data()))

        do {
            _ = try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .HttpStatus(let status) = error {
                XCTAssertEqual(status, 404)
            } else {
                XCTFail("Expected .HttpStatus(status: 404), got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testD3() async {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 200, headers: [], body: "not json".data(using: .utf8)!))

        do {
            _ = try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidResponse = error {
                // Success
            } else {
                XCTFail("Expected .InvalidResponse, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testD4() async {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 200, headers: [], body: #"{"issuer":"https://other.example/","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token"}"#.data(using: .utf8)!))

        do {
            _ = try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidResponse = error {
                // Success
            } else {
                XCTFail("Expected .InvalidResponse, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testD5() async {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 200, headers: [], body: Data()))

        do {
            _ = try await FfiServiceConfiguration.discover(issuer: "http://idp.example", transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidRequest = error {
                // Success
            } else {
                XCTFail("Expected .InvalidRequest, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
        XCTAssertEqual(transport.recordedRequests.count, 0)
    }

    func testD6() async {
        let transport = ScriptedTransport()
        // Using a custom error to simulate FfiError.InvalidResponse("boom") from the transport
        struct MockError: Error {} 
        // Note: The issue says "transport が FfiError.InvalidResponse("boom") を投げる". 
        // Since the transport is a Swift object, we can throw any error.
        // But FfiError is an enum defined in native_oidc.swift, so we can throw that directly if it's available.
        transport.responseToReturn = .failure(FfiError.InvalidResponse("boom"))

        do {
            _ = try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .TransportFailure(let message) = error {
                XCTAssertTrue(message.contains("boom"))
            } else {
                XCTFail("Expected .TransportFailure containing 'boom', got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testD7() async {
        let transport = ScriptedTransport()
        // Swift: URLError simulation
        transport.responseToReturn = .failure(URLError(.badServerResponse))

        do {
            _ = try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .TransportFailure(let message) = error {
                print("D7 Actual: \(message)")
                XCTAssertEqual(message, "HTTP transport failed")
            } else {
                XCTFail("Expected .TransportFailure, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testR1() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 200, headers: [], body: #"{"hint":"access_token"}"#.data(using: .utf8)!))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: "access_token", transport: transport, cancellation: FfiCancellationHandle())
        
        XCTAssertEqual(transport.recordedRequests.count, 1)
        let request = transport.recordedRequests[0]
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.url, "https://idp.example/revoke")
        let body = String(data: request.body, encoding: .utf8) ?? ""
        XCTAssertTrue(body.contains("token=t1"))
        XCTAssertTrue(body.contains("client_id=c1"))
        XCTAssertTrue(body.contains("token_type_hint=access_token"))
    }

    func testR2() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 200, headers: [], body: Data()))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: FfiCancellationHandle())
        
        XCTAssertEqual(transport.recordedRequests.count, 1)
        let request = transport.recordedRequests[0]
        let body = String(data: request.body, encoding: .utf8) ?? ""
        XCTAssertFalse(body.contains("token_type_hint"))
    }

    func testR3() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 200, headers: [], body: Data()))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        do {
            try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: "id_token", transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidRequest = error {
                // Success
            } else {
                XCTFail("Expected .InvalidRequest, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
        XCTAssertEqual(transport.recordedRequests.count, 0)
    }

    func testR4() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 200, headers: [], body: Data()))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")

        do {
            try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidRequest = error {
                // Success
            } else {
                XCTFail("Expected .InvalidRequest, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
        XCTAssertEqual(transport.recordedRequests.count, 0)
    }

    func testR5() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 400, headers: [], body: #"{"error":"unsupported_token_type","error_description":"nope"}"#.data(using: .utf8)!))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        do {
            try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .AuthorizationServer(let code, let description) = error {
                XCTAssertEqual(code, "unsupported_token_type")
                XCTAssertEqual(description, "nope")
            } else {
                XCTFail("Expected .AuthorizationServer, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testR6() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 503, headers: [], body: #"{"error":"unsupported_token_type","error_description":"nope"}"#.data(using: .utf8)!))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        do {
            try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .HttpStatus(let status) = error {
                XCTAssertEqual(status, 503)
            } else {
                XCTFail("Expected .HttpStatus(status: 503), got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testR7() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .failure(FfiError.TransportFailure("down"))

        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        do {
            try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .TransportFailure(let message) = error {
                XCTAssertTrue(message.contains("down"))
            } else {
                XCTFail("Expected .TransportFailure containing 'down', got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    // MARK: - Registration (G)

    func testG1() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 201, headers: [], body: #"{"client_id":"c1","application_type":"native","token_endpoint_auth_method":"none"}"#.data(using: .utf8)!))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRegistrationEndpoint(endpoint: "https://idp.example/register")

        let options = FfiRegistrationOptions(
            redirectUris: ["https://app.example/callback"],
            clientName: "My App",
            initialAccessToken: "iat"
        )

        let response = try await NativeOIDC.registerPublicClient(configuration: config, options: options, transport: transport, cancellation: FfiCancellationHandle())
        XCTAssertEqual(response.clientId, "c1")

        XCTAssertEqual(transport.recordedRequests.count, 1)
        let request = transport.recordedRequests[0]
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.url, "https://idp.example/register")
        let body = String(data: request.body, encoding: .utf8) ?? ""
        XCTAssertTrue(body.contains("redirect_uris"))
        XCTAssertTrue(body.contains("My App"))
        XCTAssertTrue(request.headers.contains { $0.name.caseInsensitiveCompare("Authorization") == .orderedSame && String(data: $0.value, encoding: .utf8) == "Bearer iat" })
    }

    func testG2() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 400, headers: [], body: #"{"error":"invalid_redirect_uri","error_description":"bad"}"#.data(using: .utf8)!))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRegistrationEndpoint(endpoint: "https://idp.example/register")

        let options = FfiRegistrationOptions(
            redirectUris: ["https://app.example/callback"],
            clientName: "My App",
            initialAccessToken: nil
        )

        do {
            _ = try await NativeOIDC.registerPublicClient(configuration: config, options: options, transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .ClientRegistrationServer(let code, let description) = error {
                XCTAssertEqual(code, "invalid_redirect_uri")
                XCTAssertEqual(description, "bad")
            } else {
                XCTFail("Expected .ClientRegistrationServer, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testG3() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 201, headers: [], body: #"{"client_id":"c1","application_type":"native","token_endpoint_auth_method":"none","client_secret":"sec"}"#.data(using: .utf8)!))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRegistrationEndpoint(endpoint: "https://idp.example/register")

        let options = FfiRegistrationOptions(
            redirectUris: ["https://app.example/callback"],
            clientName: "My App",
            initialAccessToken: nil
        )

        do {
            _ = try await NativeOIDC.registerPublicClient(configuration: config, options: options, transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidResponse = error {
                // Success
            } else {
                XCTFail("Expected .InvalidResponse, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testG4() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 500, headers: [], body: Data()))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRegistrationEndpoint(endpoint: "https://idp.example/register")

        let options = FfiRegistrationOptions(
            redirectUris: ["https://app.example/callback"],
            clientName: "My App",
            initialAccessToken: nil
        )

        do {
            _ = try await NativeOIDC.registerPublicClient(configuration: config, options: options, transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .HttpStatus(let status) = error {
                XCTAssertEqual(status, 500)
            } else {
                XCTFail("Expected .HttpStatus(status: 500), got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testG5() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 201, headers: [], body: Data()))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
        
        let options = FfiRegistrationOptions(
            redirectUris: ["https://app.example/callback"],
            clientName: "My App",
            initialAccessToken: nil
        )
        
        do {
            _ = try await NativeOIDC.registerPublicClient(configuration: config, options: options, transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidRequest = error {
                // Success
            } else {
                XCTFail("Expected .InvalidRequest, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
        XCTAssertEqual(transport.recordedRequests.count, 0)
    }

    func testG6() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .failure(FfiError.TransportFailure("down"))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRegistrationEndpoint(endpoint: "https://idp.example/register")
        
        let options = FfiRegistrationOptions(redirectUris: ["https://app.example/callback"], clientName: nil, initialAccessToken: nil)
        
        do {
            _ = try await NativeOIDC.registerPublicClient(configuration: config, options: options, transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .TransportFailure(let message) = error {
                XCTAssertTrue(message.contains("down"))
            } else {
                XCTFail("Expected .TransportFailure containing 'down', got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    // MARK: - End Session (E)

    func testE1() async throws {
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withEndSessionEndpoint(endpoint: "https://idp.example/logout")

        let options = FfiEndSessionOptions(
            clientId: "c1",
            idTokenHint: "id_token",
            postLogoutRedirectUri: "com.example.app:/logout"
        )

        let session = try NativeOIDC.beginEndSession(configuration: config, options: options)
        let url = session.endSessionUrl()
        print("E1 Generated URL: \(url)")
        XCTAssertTrue(url.contains("client_id=c1"))
        XCTAssertTrue(url.contains("id_token_hint=id_token"))
        XCTAssertTrue(url.contains("post_logout_redirect_uri=com.example.app%3A%2Flogout")) // encoded

        // Extract state from the generated URL to simulate a valid redirect response
        let urlComponents = URLComponents(string: url)!
        let state = urlComponents.queryItems?.first { $0.name == "state" }?.value ?? "s1"
        let redirectUri = "com.example.app:/logout?state=\(state)&extra=1"
        let response = try session.parseRedirect(redirectUri: redirectUri)
        XCTAssertEqual(response.state, state)
        XCTAssertTrue(response.additionalParameters.contains { $0.name == "extra" && $0.value == "1" })
    }

    func testE2() async throws {
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withEndSessionEndpoint(endpoint: "https://idp.example/logout")

        let options = FfiEndSessionOptions(
            clientId: "c1",
            idTokenHint: "id_token",
            postLogoutRedirectUri: "com.example.app:/logout"
        )

        let session = try NativeOIDC.beginEndSession(configuration: config, options: options)
        let redirectUri = "https://idp.example/logout?state=wrong_state"
        
        do {
            _ = try session.parseRedirect(redirectUri: redirectUri)
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidResponse = error {
                // Success
            } else {
                XCTFail("Expected .InvalidResponse, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testE3() async throws {
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withEndSessionEndpoint(endpoint: "https://idp.example/logout")

        let options = FfiEndSessionOptions(
            clientId: "c1",
            idTokenHint: "id_token",
            postLogoutRedirectUri: nil
        )

        let session = try NativeOIDC.beginEndSession(configuration: config, options: options)
        let redirectUri = "https://idp.example/logout?state=s1"
        
        do {
            _ = try session.parseRedirect(redirectUri: redirectUri)
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidResponse = error {
                // Success
            } else {
                XCTFail("Expected .InvalidResponse, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testE4() async throws {
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")

        let options = FfiEndSessionOptions(
            clientId: "c1",
            idTokenHint: "id_token",
            postLogoutRedirectUri: "com.example.app:/logout"
        )

        do {
            _ = try NativeOIDC.beginEndSession(configuration: config, options: options)
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidRequest = error {
                // Success
            } else {
                XCTFail("Expected .InvalidRequest, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testE5() async throws {
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withEndSessionEndpoint(endpoint: "https://idp.example/logout")

        let session = try NativeOIDC.beginEndSession(configuration: config, options: FfiEndSessionOptions(clientId: "c1", idTokenHint: nil, postLogoutRedirectUri: nil))
        
        do {
            _ = try session.parseRedirect(redirectUri: "not a url")
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidRequest = error {
                // Success
            } else {
                XCTFail("Expected .InvalidRequest, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    // MARK: - Authentication State JSON (S)

    func testS1() async throws {
        let state = try FfiAuthenticationState.fromJson(serialized: stateJson)
        let serialized = try await state.toJson()
        let restored = try FfiAuthenticationState.fromJson(serialized: serialized)
        let reserialized = try await restored.toJson()

        XCTAssertEqual(reserialized, serialized)
        let response = await restored.tokenResponse()
        XCTAssertEqual(response.accessToken, "old")
        XCTAssertEqual(response.tokenType, "Bearer")
        XCTAssertEqual(response.refreshToken, "refresh")
    }

    func testS2() async throws {
        do {
            _ = try FfiAuthenticationState.fromJson(serialized: "{")
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .InvalidRequest = error {
                // Success
            } else {
                XCTFail("Expected .InvalidRequest, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    // MARK: - Cancellation (C)

    func testC1() async throws {
        let transport = BlockingTransport()
        let cancellation = FfiCancellationHandle()
        
        let task = Task {
            try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: cancellation)
        }
        
        // Give it a moment to start
        try await Task.sleep(nanoseconds: 10_000_000)
        cancellation.cancel()
        
        do {
            _ = try await task.value
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .Cancelled = error {
                // Success
            } else {
                XCTFail("Expected .Cancelled, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testC2() async throws {
        let transport = BlockingTransport()
        let cancellation = FfiCancellationHandle()
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        let task = Task {
            try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: cancellation)
        }
        
        try await Task.sleep(nanoseconds: 10_000_000)
        cancellation.cancel()
        
        do {
            try await task.value
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .Cancelled = error {
                // Success
            } else {
                XCTFail("Expected .Cancelled, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testC3() async throws {
        let transport = BlockingTransport()
        let cancellation = FfiCancellationHandle()
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRegistrationEndpoint(endpoint: "https://idp.example/register")

        let options = FfiRegistrationOptions(redirectUris: ["https://app.example/callback"], clientName: nil, initialAccessToken: nil)

        let task = Task {
            try await NativeOIDC.registerPublicClient(configuration: config, options: options, transport: transport, cancellation: cancellation)
        }
        
        try await Task.sleep(nanoseconds: 10_000_000)
        cancellation.cancel()
        
        do {
            _ = try await task.value
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .Cancelled = error {
                // Success
            } else {
                XCTFail("Expected .Cancelled, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testC4() async throws {
        let transport = BlockingTransport()
        let cancellation = FfiCancellationHandle()
        
        // Create a state manually using fromJson to avoid needing a real token response.
        let state = try FfiAuthenticationState.fromJson(serialized: #"{"token_response":{"access_token":"old","token_type":"Bearer","refresh_token":"refresh"}}"#)
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
        
        let task = Task {
            try await state.refresh(configuration: config, clientId: "c1", additionalParameters: [], transport: transport, cancellation: cancellation)
        }
        
        try await Task.sleep(nanoseconds: 10_000_000)
        cancellation.cancel()

        do {
            try await task.value
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .Cancelled = error {
                // Success
            } else {
                XCTFail("Expected .Cancelled, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }

    func testC5() async throws {
        class NonResponsiveTransport: NativeHttpTransport, @unchecked Sendable {
            func execute(request: FfiHttpRequest, cancellation: FfiCancellationHandle) async throws -> FfiHttpResponse {
                await cancellation.cancelled() // Typo here
                throw FfiError.Cancelled
            }
        }
        
        let transport = NonResponsiveTransport()
        let cancellation = FfiCancellationHandle()
        
        // C5 requires tests for revoke and refresh.
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        let task = Task {
            try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: cancellation)
        }
        
        try await Task.sleep(nanoseconds: 10_000_000)
        cancellation.cancel()
        
        do {
            try await task.value
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .Cancelled = error {
                // Success
            } else {
                XCTFail("Expected .Cancelled, got \(error)")
            }
        } catch {
            XCTFail("Expected FfiError, got \(error)")
        }
    }
}
