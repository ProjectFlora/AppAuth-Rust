#if os(macOS)
  import Foundation

  @main
  struct MacOSLoopbackListenerSmoke {
    static func main() async throws {
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
