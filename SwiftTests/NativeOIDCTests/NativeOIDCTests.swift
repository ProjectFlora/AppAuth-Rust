import Foundation
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

    /// A transport that simulates a long-running request. It signals the
    /// test when it enters `execute`, then waits for the cancellation
    /// handle to fire before returning `.Cancelled`.
    final class BlockingTransport: NativeHttpTransport, @unchecked Sendable {
        let started = Once()

        func execute(request: FfiHttpRequest, cancellation: FfiCancellationHandle) async throws -> FfiHttpResponse {
            started.fire()
            await cancellation.cancelled()
            throw FfiError.Cancelled
        }
    }

    /// A transport that never answers its request. It signals the test
    /// when it enters `execute`, waits for the cancellation handle to
    /// fire, and then suspends without ever returning a response or an
    /// error. Used by C5: because the transport cannot produce the result,
    /// a `.Cancelled` outcome can only come from the Rust core racing the
    /// handle against the transport.
    final class UnresponsiveTransport: NativeHttpTransport, @unchecked Sendable {
        let started = Once()

        func execute(request: FfiHttpRequest, cancellation: FfiCancellationHandle) async throws -> FfiHttpResponse {
            started.fire()
            await cancellation.cancelled()
            // After the handle fires, never answer: keep suspending. The
            // request stays pending, so a core implementation that waits on
            // the transport would hang. When Rust wins the race it drops this
            // future and the UniFFI drop callback cancels the task, so the
            // sleep error must propagate to exit the loop (a `try?` here
            // would spin at full CPU on every iteration). The vtable then
            // reports the error for an already-dropped future, which the
            // scaffolding ignores.
            while true {
                try await Task.sleep(for: .seconds(1))
            }
        }
    }

    /// A one-shot, thread-safe event signal used to order the test against
    /// a transport callback.
    final class Once: @unchecked Sendable {
        private let lock = NSLock()
        private var _fired = false

        var fired: Bool {
            lock.lock()
            defer { lock.unlock() }
            return _fired
        }

        func fire() {
            lock.lock()
            _fired = true
            lock.unlock()
        }
    }

    /// The recorded completion of an operation the test runs in a
    /// background task.
    enum FfiOutcome: Equatable {
        case success(String)
        case failure(FfiError)
    }

    /// First-wins storage for the completion of a background operation.
    ///
    /// The generated async helpers suspend on a continuation that only
    /// Rust resumes, so a cancelled Swift task cannot abandon a
    /// `task.value` await; the tests observe completion through this box
    /// with a bounded poll instead.
    final class OutcomeBox: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: FfiOutcome?

        func recordSuccess(_ description: String) {
            lock.lock()
            if stored == nil { stored = .success(description) }
            lock.unlock()
        }

        func recordFailure(_ error: FfiError) {
            lock.lock()
            if stored == nil { stored = .failure(error) }
            lock.unlock()
        }

        var current: FfiOutcome? {
            lock.lock()
            defer { lock.unlock() }
            return stored
        }

        /// Polls every 5 ms until a completion is recorded or `duration`
        /// elapses.
        func wait(_ duration: Duration) async -> FfiOutcome? {
            let clock = ContinuousClock()
            let deadline = clock.now + duration
            while true {
                if let stored = current { return stored }
                if clock.now >= deadline { return nil }
                do {
                    try await Task.sleep(for: .milliseconds(5))
                } catch {
                    // The test task was cancelled; stop polling.
                    return nil
                }
            }
        }
    }

    /// Decodes a form-urlencoded request body into all fields as
    /// [name, value] pairs, preserving order, duplicates, and empty
    /// values. Comparing the complete list rejects a renamed, duplicated,
    /// or emptied field that substring or dictionary matching would still
    /// accept.
    private func formFields(_ body: Data) -> [[String]] {
        guard let text = String(data: body, encoding: .utf8) else {
            return []
        }
        var fields = [[String]]()
        for pair in text.split(separator: "&", omittingEmptySubsequences: false) {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let name = String(parts[0])
            let value = parts.count > 1 ? (String(parts[1]).removingPercentEncoding ?? String(parts[1])) : ""
            fields.append([name, value])
        }
        return fields
    }

    // MARK: - Discovery (D)

    func testD1() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(
            status: 200,
            headers: [],
            body: #"{"issuer":"https://idp.example/","authorization_endpoint":"https://idp.example/authorize","token_endpoint":"https://idp.example/token","revocation_endpoint":"https://idp.example/revoke","registration_endpoint":"https://idp.example/register","end_session_endpoint":"https://idp.example/logout","jwks_uri":"https://idp.example/.well-known/jwks.json"}"#.data(using: .utf8)!
        ))

        let config = try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: FfiCancellationHandle())

        XCTAssertEqual(config.issuer(), "https://idp.example/")
        XCTAssertEqual(config.authorizationEndpoint(), "https://idp.example/authorize")
        XCTAssertEqual(config.tokenEndpoint(), "https://idp.example/token")
        XCTAssertEqual(config.revocationEndpoint(), "https://idp.example/revoke")
        XCTAssertEqual(config.jwksUri(), "https://idp.example/.well-known/jwks.json")
        // registrationEndpoint and endSessionEndpoint have no getters on the
        // Swift API, so verify discovery retained them by running each
        // operation against the discovered configuration and asserting the
        // advertised URL.

        let registrationTransport = ScriptedTransport()
        registrationTransport.responseToReturn = .success(FfiHttpResponse(status: 201, headers: [], body: #"{"client_id":"c1","application_type":"native","token_endpoint_auth_method":"none"}"#.data(using: .utf8)!))
        let registrationOptions = FfiRegistrationOptions(redirectUris: ["https://app.example/callback"], clientName: nil, initialAccessToken: nil)
        _ = try await NativeOIDC.registerPublicClient(configuration: config, options: registrationOptions, transport: registrationTransport, cancellation: FfiCancellationHandle())
        XCTAssertEqual(registrationTransport.recordedRequests.count, 1)
        XCTAssertEqual(registrationTransport.recordedRequests[0].url, "https://idp.example/register")

        let endSession = try NativeOIDC.beginEndSession(configuration: config, options: FfiEndSessionOptions(clientId: "c1", idTokenHint: nil, postLogoutRedirectUri: nil))
        XCTAssertTrue(endSession.endSessionUrl().hasPrefix("https://idp.example/logout"))

        XCTAssertEqual(transport.recordedRequests.count, 1)
        let request = transport.recordedRequests[0]
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
        // #164 D6: the transport throws FfiError.InvalidResponse("boom").
        // The variant is not preserved across the transport boundary and
        // becomes TransportFailure carrying the original message.
        let transport = ScriptedTransport()
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
        // #164 D7: a transport that throws an ordinary Swift error (not a
        // FfiError) must surface as TransportFailure carrying the Transport
        // variant's display text, "HTTP transport failed".
        let transport = ScriptedTransport()
        transport.responseToReturn = .failure(URLError(.badServerResponse))

        do {
            _ = try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: FfiCancellationHandle())
            XCTFail("Expected error")
        } catch let error as FfiError {
            if case .TransportFailure(let message) = error {
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
        // The complete field list: a renamed, duplicated, or emptied
        // field fails the comparison.
        XCTAssertEqual(formFields(request.body), [
            ["token", "t1"],
            ["client_id", "c1"],
            ["token_type_hint", "access_token"],
        ])
    }

    func testR2() async throws {
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 200, headers: [], body: Data()))
        
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: FfiCancellationHandle())
        
        XCTAssertEqual(transport.recordedRequests.count, 1)
        let request = transport.recordedRequests[0]
        // The complete field list: without a hint the request must carry
        // only token and client_id, not even an empty token_type_hint.
        XCTAssertEqual(formFields(request.body), [
            ["token", "t1"],
            ["client_id", "c1"],
        ])
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
        let bodyObject = try XCTUnwrap(JSONSerialization.jsonObject(with: request.body) as? [String: Any])
        XCTAssertEqual(bodyObject["redirect_uris"] as? [String], ["https://app.example/callback"])
        XCTAssertEqual(bodyObject["client_name"] as? String, "My App")
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
        // #164 G6: a malformed redirect URI must be rejected before any
        // request is made.
        let transport = ScriptedTransport()
        transport.responseToReturn = .success(FfiHttpResponse(status: 201, headers: [], body: Data()))

        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRegistrationEndpoint(endpoint: "https://idp.example/register")

        let options = FfiRegistrationOptions(redirectUris: ["https://app.example/callback", "not a url"], clientName: nil, initialAccessToken: nil)

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
        // The malformed redirect URI must be rejected before calling the
        // transport.
        XCTAssertEqual(transport.recordedRequests.count, 0)
    }

    func testG7() async throws {
        // A transport failure while the registration request is in flight
        // is surfaced as TransportFailure carrying the transport's message.
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
        XCTAssertEqual(transport.recordedRequests.count, 1)
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
        // Compare the exact query fields: substring matching would accept
        // client_id=c10 or id_token_hint=id_token_extra.
        let urlComponents = try XCTUnwrap(URLComponents(string: url))
        let query = try XCTUnwrap(urlComponents.queryItems)
        XCTAssertEqual(query.count, 4)
        XCTAssertEqual(query.filter { $0.name == "client_id" }.map(\.value), ["c1"])
        XCTAssertEqual(query.filter { $0.name == "id_token_hint" }.map(\.value), ["id_token"])
        XCTAssertEqual(query.filter { $0.name == "post_logout_redirect_uri" }.map(\.value), ["com.example.app:/logout"])
        // The session must carry the generated state.
        let state = try XCTUnwrap(query.first { $0.name == "state" }?.value)

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
        // Keep the configured callback URI and vary only the state, so the
        // failure exercises the state comparison rather than the URI match
        // check that runs first.
        let redirectUri = "com.example.app:/logout?state=wrong_state"
        
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
            // Assert the exact diagnostic so a state mismatch cannot
            // stand in for the missing-redirect branch.
            if case .InvalidResponse(let message) = error {
                XCTAssertEqual(message, "no post-logout redirect URI was requested")
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
    //
    // The C tests must not order themselves against the operation with a
    // fixed `Task.sleep`: under CI load the child task may not have
    // started, and the test would pass on a pre-execution cancel without
    // verifying in-flight cancellation. Instead each test:
    //   1. waits, with a deadline, for the transport to report that it
    //      entered `execute`,
    //   2. cancels the shared handle, so the request is guaranteed in
    //      flight,
    //   3. waits, with a deadline, for the operation to complete through
    //      an `OutcomeBox` the operation task writes to (a `task.value`
    //      await cannot be bounded because the generated async helpers
    //      suspend on a continuation that only Rust resumes),
    //   4. asserts the completion is `.Cancelled`.
    //
    // `awaitFlag` polls `isReady` every 5 ms, returning `true` once it
    // succeeds and `false` when `duration` elapses.

    private func awaitFlag(_ duration: Duration, _ isReady: () -> Bool) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now + duration
        while true {
            if isReady() { return true }
            if clock.now >= deadline { return false }
            do {
                try await Task.sleep(for: .milliseconds(5))
            } catch {
                // The test task was cancelled; stop polling.
                return false
            }
        }
    }

    func testC1() async throws {
        // discover must observe a cancellation issued while its request is
        // in flight.
        let transport = BlockingTransport()
        let cancellation = FfiCancellationHandle()
        let outcome = OutcomeBox()

        let task = Task {
            do {
                _ = try await FfiServiceConfiguration.discover(issuer: "https://idp.example/", transport: transport, cancellation: cancellation)
                outcome.recordSuccess("discover")
            } catch let error as FfiError {
                outcome.recordFailure(error)
            } catch {
                outcome.recordFailure(FfiError.Internal("unexpected Swift error: \(error)"))
            }
        }

        guard await awaitFlag(.seconds(10), { transport.started.fired }) else {
            task.cancel()
            XCTFail("C1: transport.execute was not entered within 10 seconds")
            return
        }
        cancellation.cancel()

        guard let result = await outcome.wait(.seconds(10)) else {
            task.cancel()
            XCTFail("C1: discover did not complete within 10 seconds after cancellation")
            return
        }
        guard case .failure(FfiError.Cancelled) = result else {
            XCTFail("C1: expected .Cancelled, got \(result)")
            return
        }
    }

    func testC2() async throws {
        // revoke must observe a cancellation issued while its request is
        // in flight.
        let transport = BlockingTransport()
        let cancellation = FfiCancellationHandle()
        let outcome = OutcomeBox()

        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRevocationEndpoint(endpoint: "https://idp.example/revoke")

        let task = Task {
            do {
                try await NativeOIDC.revoke(configuration: config, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: cancellation)
                outcome.recordSuccess("revoke")
            } catch let error as FfiError {
                outcome.recordFailure(error)
            } catch {
                outcome.recordFailure(FfiError.Internal("unexpected Swift error: \(error)"))
            }
        }

        guard await awaitFlag(.seconds(10), { transport.started.fired }) else {
            task.cancel()
            XCTFail("C2: transport.execute was not entered within 10 seconds")
            return
        }
        cancellation.cancel()

        guard let result = await outcome.wait(.seconds(10)) else {
            task.cancel()
            XCTFail("C2: revoke did not complete within 10 seconds after cancellation")
            return
        }
        guard case .failure(FfiError.Cancelled) = result else {
            XCTFail("C2: expected .Cancelled, got \(result)")
            return
        }
    }

    func testC3() async throws {
        // register_public_client must observe a cancellation issued while
        // its request is in flight.
        let transport = BlockingTransport()
        let cancellation = FfiCancellationHandle()
        let outcome = OutcomeBox()

        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")
            .withRegistrationEndpoint(endpoint: "https://idp.example/register")

        let options = FfiRegistrationOptions(redirectUris: ["https://app.example/callback"], clientName: nil, initialAccessToken: nil)

        let task = Task {
            do {
                _ = try await NativeOIDC.registerPublicClient(configuration: config, options: options, transport: transport, cancellation: cancellation)
                outcome.recordSuccess("register_public_client")
            } catch let error as FfiError {
                outcome.recordFailure(error)
            } catch {
                outcome.recordFailure(FfiError.Internal("unexpected Swift error: \(error)"))
            }
        }

        guard await awaitFlag(.seconds(10), { transport.started.fired }) else {
            task.cancel()
            XCTFail("C3: transport.execute was not entered within 10 seconds")
            return
        }
        cancellation.cancel()

        guard let result = await outcome.wait(.seconds(10)) else {
            task.cancel()
            XCTFail("C3: register_public_client did not complete within 10 seconds after cancellation")
            return
        }
        guard case .failure(FfiError.Cancelled) = result else {
            XCTFail("C3: expected .Cancelled, got \(result)")
            return
        }
    }

    func testC4() async throws {
        // refresh must observe a cancellation issued while its request is
        // in flight, and must leave the token state unchanged.
        let transport = BlockingTransport()
        let cancellation = FfiCancellationHandle()
        let outcome = OutcomeBox()

        // Create a state manually using fromJson to avoid needing a real token response.
        let state = try FfiAuthenticationState.fromJson(serialized: stateJson)
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")

        let task = Task {
            do {
                try await state.refresh(configuration: config, clientId: "c1", additionalParameters: [], transport: transport, cancellation: cancellation)
                outcome.recordSuccess("refresh")
            } catch let error as FfiError {
                outcome.recordFailure(error)
            } catch {
                outcome.recordFailure(FfiError.Internal("unexpected Swift error: \(error)"))
            }
        }

        guard await awaitFlag(.seconds(10), { transport.started.fired }) else {
            task.cancel()
            XCTFail("C4: transport.execute was not entered within 10 seconds")
            return
        }
        cancellation.cancel()

        guard let result = await outcome.wait(.seconds(10)) else {
            task.cancel()
            XCTFail("C4: refresh did not complete within 10 seconds after cancellation")
            return
        }
        guard case .failure(FfiError.Cancelled) = result else {
            XCTFail("C4: expected .Cancelled, got \(result)")
            return
        }

        // A cancelled refresh must not update the token state.
        let response = await state.tokenResponse()
        XCTAssertEqual(response.accessToken, "old")
        XCTAssertEqual(response.tokenType, "Bearer")
        XCTAssertEqual(response.refreshToken, "refresh")
    }

    func testC5() async throws {
        // The `UnresponsiveTransport` never answers after the handle
        // fires, so a `.Cancelled` outcome can only be produced by the
        // Rust core racing the handle against the transport. Both revoke
        // and refresh must complete, within a deadline, with `.Cancelled`
        // from the core.
        let config = try FfiServiceConfiguration(authorizationEndpoint: "https://idp.example/authorize", tokenEndpoint: "https://idp.example/token")

        do {
            let transport = UnresponsiveTransport()
            let cancellation = FfiCancellationHandle()
            let outcome = OutcomeBox()
            let revocation = try config.withRevocationEndpoint(endpoint: "https://idp.example/revoke")

            let task = Task {
                do {
                    try await NativeOIDC.revoke(configuration: revocation, clientId: "c1", token: "t1", tokenTypeHint: nil, transport: transport, cancellation: cancellation)
                    outcome.recordSuccess("revoke")
                } catch let error as FfiError {
                    outcome.recordFailure(error)
                } catch {
                    outcome.recordFailure(FfiError.Internal("unexpected Swift error: \(error)"))
                }
            }

            guard await awaitFlag(.seconds(10), { transport.started.fired }) else {
                task.cancel()
                XCTFail("C5: revoke transport.execute was not entered within 10 seconds")
                return
            }
            cancellation.cancel()

            guard let result = await outcome.wait(.seconds(10)) else {
                task.cancel()
                XCTFail("C5: revoke did not complete within 10 seconds after cancellation; the core is waiting on the unresponsive transport")
                return
            }
            guard case .failure(FfiError.Cancelled) = result else {
                XCTFail("C5: expected .Cancelled from the core for revoke, got \(result)")
                return
            }
        }

        do {
            let transport = UnresponsiveTransport()
            let cancellation = FfiCancellationHandle()
            let outcome = OutcomeBox()
            let state = try FfiAuthenticationState.fromJson(serialized: stateJson)

            let task = Task {
                do {
                    try await state.refresh(configuration: config, clientId: "c1", additionalParameters: [], transport: transport, cancellation: cancellation)
                    outcome.recordSuccess("refresh")
                } catch let error as FfiError {
                    outcome.recordFailure(error)
                } catch {
                    outcome.recordFailure(FfiError.Internal("unexpected Swift error: \(error)"))
                }
            }

            guard await awaitFlag(.seconds(10), { transport.started.fired }) else {
                task.cancel()
                XCTFail("C5: refresh transport.execute was not entered within 10 seconds")
                return
            }
            cancellation.cancel()

            guard let result = await outcome.wait(.seconds(10)) else {
                task.cancel()
                XCTFail("C5: refresh did not complete within 10 seconds after cancellation; the core is waiting on the unresponsive transport")
                return
            }
            guard case .failure(FfiError.Cancelled) = result else {
                XCTFail("C5: expected .Cancelled from the core for refresh, got \(result)")
                return
            }
        }
    }
}
