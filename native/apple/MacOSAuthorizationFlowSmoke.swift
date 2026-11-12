#if os(macOS)
  import Foundation
  import Darwin

  @main
  struct MacOSAuthorizationFlowSmoke {
    static func main() async throws {
      try await checkLoopbackListener()

      let provider = try MacOSMockOAuthProvider()
      let providerPort = try await provider.start()
      do {
        try await checkNativeTransport(providerPort: providerPort)
        await provider.verifyTransportChecks()
        let configuration = try FfiServiceConfiguration(
          authorizationEndpoint: "http://127.0.0.1:\(providerPort)/authorize",
          tokenEndpoint: "http://127.0.0.1:\(providerPort)/token"
        )
        let options = FfiAuthorizationOptions(
          clientId: "macos-smoke-client",
          redirectUri: "http://127.0.0.1/oauth/callback",
          scopes: ["profile"],
          additionalParameters: [],
          additionalTokenParameters: []
        )
        try await checkInvalidStateAndReuse(configuration: configuration, options: options)
        let adapter = MacOSAuthorizationAdapter { authorizationURL in
          let (_, response) = try await URLSession.shared.data(from: authorizationURL)
          guard (response as? HTTPURLResponse)?.statusCode == 200 else {
            throw URLError(.badServerResponse)
          }
        }
        let authenticationState = try await adapter.authorize(
          configuration: configuration,
          options: options,
          transport: URLSessionNativeHttpTransport()
        )
        let tokenResponse = await authenticationState.tokenResponse()
        precondition(tokenResponse.accessToken == "mock-access-token")
        precondition(tokenResponse.scope == "profile")
        try await provider.verifyCompletedFlow()
      } catch {
        await provider.stop()
        throw error
      }
      await provider.stop()
    }

    private static func checkLoopbackListener() async throws {
      let listener = try LoopbackHTTPListener(callbackPath: "/oauth/callback")
      let port = try await listener.start()
      let httpConfiguration = URLSessionConfiguration.ephemeral
      httpConfiguration.timeoutIntervalForRequest = 2
      httpConfiguration.timeoutIntervalForResource = 3
      let callbackSession = URLSession(configuration: httpConfiguration)
      defer { callbackSession.invalidateAndCancel() }
      let callbackTask = Task {
        try await listener.waitForCallback()
      }

      let stalled = try openSocket(port: port, request: "GET /oauth/callback HTTP/1.1\r\n")
      defer { Darwin.close(stalled) }
      let independent = try LoopbackHTTPListener(callbackPath: "/oauth/callback")
      let independentPort = try await independent.start()
      precondition(independentPort != port)
      await independent.cancel()

      let wrongPath = URL(string: "http://127.0.0.1:\(port)/favicon.ico")!
      let (_, wrongResponse) = try await callbackSession.data(from: wrongPath)
      precondition((wrongResponse as? HTTPURLResponse)?.statusCode == 404)

      let callbackURL = URL(
        string: "http://127.0.0.1:\(port)/oauth/callback?code=auth-code&state=state"
      )!
      let (_, callbackResponse) = try await callbackSession.data(from: callbackURL)
      precondition((callbackResponse as? HTTPURLResponse)?.statusCode == 200)

      let receivedCallback = try await callbackTask.value
      let receivedComponents = URLComponents(string: receivedCallback)
      precondition(receivedComponents?.path == "/oauth/callback")
      precondition(
        receivedComponents?.queryItems?.contains {
          $0.name == "state" && $0.value == "state"
        } == true)

      do {
        _ = try await callbackSession.data(from: callbackURL)
        preconditionFailure("completed listener accepted another callback")
      } catch is URLError {
      }

      let stoppedBeforeStart = try LoopbackHTTPListener(callbackPath: "/oauth/callback")
      await stoppedBeforeStart.cancel()
      do {
        _ = try await stoppedBeforeStart.start()
        preconditionFailure("cancelled listener started")
      } catch FfiError.Cancelled {
      }

      let cancelledListener = try LoopbackHTTPListener(callbackPath: "/oauth/callback")
      _ = try await cancelledListener.start()
      let cancelledCallbackTask = Task {
        try await cancelledListener.waitForCallback()
      }
      await cancelledListener.cancel()
      do {
        _ = try await cancelledCallbackTask.value
        preconditionFailure("cancelled listener returned a callback")
      } catch FfiError.Cancelled {
      }
    }
    private static func checkNativeTransport(providerPort: UInt16) async throws {
      let supplied = URLSessionConfiguration.ephemeral
      let cache = URLCache(memoryCapacity: 1024 * 1024, diskCapacity: 0)
      supplied.urlCache = cache
      supplied.requestCachePolicy = .returnCacheDataElseLoad
      let transport = URLSessionNativeHttpTransport(configuration: supplied)
      precondition(supplied.urlCache === cache)
      let base = "http://127.0.0.1:\(providerPort)"
      let request = FfiHttpRequest(
        method: "GET", url: "\(base)/transport-redirect", headers: [], body: Data())
      let redirected = try await transport.execute(
        request: request, cancellation: FfiCancellationHandle())
      precondition(redirected.status == 302)
      let url = URL(string: "\(base)/transport-cache")!
      let cached = HTTPURLResponse(
        url: url, statusCode: 200, httpVersion: "HTTP/1.1",
        headerFields: ["Cache-Control": "max-age=300"])!
      cache.storeCachedResponse(
        CachedURLResponse(response: cached, data: Data("stale".utf8)), for: URLRequest(url: url))
      for version in 1...2 {
        let response = try await transport.execute(
          request: FfiHttpRequest(
            method: "GET", url: url.absoluteString, headers: [], body: Data()),
          cancellation: FfiCancellationHandle())
        precondition(String(data: response.body, encoding: .utf8) == "version-\(version)")
      }
      let cancelled = FfiCancellationHandle()
      cancelled.cancel()
      do {
        _ = try await transport.execute(request: request, cancellation: cancelled)
        preconditionFailure("cancelled transport request succeeded")
      } catch FfiError.Cancelled {
      }
    }

    @MainActor
    private static func checkInvalidStateAndReuse(
      configuration: FfiServiceConfiguration, options: FfiAuthorizationOptions
    ) async throws {
      let adapter = MacOSAuthorizationAdapter { url in
        let request = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        let redirect = request.queryItems!.first { $0.name == "redirect_uri" }!.value!
        var callback = URLComponents(string: redirect)!
        callback.queryItems = [
          URLQueryItem(name: "code", value: "code"),
          URLQueryItem(name: "state", value: "another-operation"),
        ]
        let (_, response) = try await URLSession.shared.data(from: callback.url!)
        precondition((response as? HTTPURLResponse)?.statusCode == 200)
      }
      for _ in 0..<2 {
        do {
          _ = try await adapter.authorize(
            configuration: configuration, options: options,
            transport: URLSessionNativeHttpTransport())
          preconditionFailure("state mismatch accepted")
        } catch FfiError.InvalidResponse {
        }
      }
    }

    private static func openSocket(port: UInt16, request: String) throws -> Int32 {
      let socket = Darwin.socket(AF_INET, SOCK_STREAM, 0)
      guard socket >= 0 else { throw URLError(.cannotConnectToHost) }
      var address = sockaddr_in()
      address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
      address.sin_family = sa_family_t(AF_INET)
      address.sin_port = port.bigEndian
      address.sin_addr.s_addr = inet_addr("127.0.0.1")
      let connected = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
          Darwin.connect(socket, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
      }
      guard connected == 0 else {
        Darwin.close(socket)
        throw URLError(.cannotConnectToHost)
      }
      let bytes = Array(request.utf8)
      let sent = bytes.withUnsafeBytes { Darwin.send(socket, $0.baseAddress, $0.count, 0) }
      guard sent == bytes.count else {
        Darwin.close(socket)
        throw URLError(.networkConnectionLost)
      }
      return socket
    }
  }
#endif
