#if os(macOS)
  import Foundation

  @main
  struct MacOSAuthorizationFlowSmoke {
    static func main() async throws {
      try await checkLoopbackListener()

      let provider = try MacOSMockOAuthProvider()
      let providerPort = try await provider.start()
      do {
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
      let callbackTask = Task {
        try await listener.waitForCallback()
      }

      let wrongPath = URL(string: "http://127.0.0.1:\(port)/favicon.ico")!
      let (_, wrongResponse) = try await URLSession.shared.data(from: wrongPath)
      precondition((wrongResponse as? HTTPURLResponse)?.statusCode == 404)

      let callbackURL = URL(
        string: "http://127.0.0.1:\(port)/oauth/callback?code=auth-code&state=state"
      )!
      let (_, callbackResponse) = try await URLSession.shared.data(from: callbackURL)
      precondition((callbackResponse as? HTTPURLResponse)?.statusCode == 200)

      let receivedCallback = try await callbackTask.value
      let receivedComponents = URLComponents(string: receivedCallback)
      precondition(receivedComponents?.path == "/oauth/callback")
      precondition(
        receivedComponents?.queryItems?.contains {
          $0.name == "state" && $0.value == "state"
        } == true)

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
  }
#endif
