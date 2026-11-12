#if os(iOS)
  import AuthenticationServices
  import Foundation
  import UIKit

  @main
  @MainActor
  final class IOSAuthorizationFlowSmoke: UIResponder, UIApplicationDelegate {
    func application(
      _ application: UIApplication,
      didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
      return true
    }

    func application(
      _ application: UIApplication,
      configurationForConnecting connectingSceneSession: UISceneSession,
      options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
      UISceneConfiguration(
        name: "Default Configuration",
        sessionRole: connectingSceneSession.role
      )
    }
  }

  @MainActor
  final class IOSAuthorizationFlowSmokeSceneDelegate: UIResponder, UIWindowSceneDelegate,
    ASWebAuthenticationPresentationContextProviding
  {
    var window: UIWindow?

    func scene(
      _ scene: UIScene,
      willConnectTo session: UISceneSession,
      options connectionOptions: UIScene.ConnectionOptions
    ) {
      guard let windowScene = scene as? UIWindowScene else {
        return
      }
      let window = UIWindow(windowScene: windowScene)
      window.rootViewController = UIViewController()
      window.makeKeyAndVisible()
      self.window = window
      Task { @MainActor in
        try? await Task.sleep(nanoseconds: 1_000_000_000)
        await runAuthorizationFlow()
      }
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
      guard let window else {
        fatalError("authorization presentation window is unavailable")
      }
      return window
    }

    private func runAuthorizationFlow() async {
      do {
        guard let providerPort = Self.providerPort() else {
          throw IOSAuthorizationFlowSmokeError.missingProviderPort
        }
        let configuration = try FfiServiceConfiguration(
          authorizationEndpoint: "http://127.0.0.1:\(providerPort)/authorize",
          tokenEndpoint: "http://127.0.0.1:\(providerPort)/token"
        )
        let options = FfiAuthorizationOptions(
          clientId: "ios-smoke-client",
          redirectUri: "appauth-smoke://oauth/callback",
          scopes: ["profile"],
          additionalParameters: [],
          additionalTokenParameters: []
        )
        try await checkBrowserLifecycle(configuration: configuration, options: options)
        let adapter = IOSAuthorizationAdapter(
          presentationContextProvider: self,
          prefersEphemeralWebBrowserSession: true
        )
        let authenticationState = try await adapter.authorize(
          configuration: configuration,
          options: options,
          transport: URLSessionNativeHttpTransport()
        )
        let tokenResponse = await authenticationState.tokenResponse()
        guard tokenResponse.accessToken == "mock-access-token",
          tokenResponse.scope == "profile"
        else {
          throw IOSAuthorizationFlowSmokeError.unexpectedTokenResponse
        }
        writeResult("success")
      } catch {
        writeResult("failure: \(String(describing: error))")
      }
    }

    private func checkBrowserLifecycle(
      configuration: FfiServiceConfiguration,
      options: FfiAuthorizationOptions
    ) async throws {
      let probe = IOSBrowserProbe()
      let transport = IOSLifecycleTransport()
      let adapter = IOSAuthorizationAdapter(
        presentationContextProvider: self,
        prefersEphemeralWebBrowserSession: true,
        browserSessionFactory: probe.makeSession
      )

      // Explicit cancellation must not rely on a browser completion callback.
      let cancelled = Task {
        try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
      }
      let oldSession = await probe.nextSession()
      precondition(oldSession.prefersEphemeralWebBrowserSession)
      adapter.cancel()
      adapter.cancel()
      do {
        _ = try await cancelled.value
        preconditionFailure("cancelled authorization completed")
      } catch FfiError.Cancelled {}
      precondition(oldSession.cancelCount == 1)

      // An old completion must not clear the active session or resume twice.
      let current = Task {
        try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
      }
      let currentSession = await probe.nextSession()
      oldSession.complete()
      oldSession.dismiss()
      await Task.yield()
      do {
        _ = try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
        preconditionFailure("concurrent authorization accepted")
      } catch IOSAuthorizationAdapterError.authorizationSessionAlreadyRunning {}
      currentSession.complete()
      currentSession.complete()
      let state = try await current.value
      let token = await state.tokenResponse()
      precondition(token.accessToken == "lifecycle-access")
      let exchanges = await transport.exchanges
      precondition(exchanges == 1)

      // Swift task cancellation, without any browser completion, releases state.
      let taskCancelled = Task {
        try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
      }
      let taskSession = await probe.nextSession()
      taskSession.completeOnCancel = true
      taskCancelled.cancel()
      do {
        _ = try await taskCancelled.value
        preconditionFailure("task cancellation ignored")
      } catch FfiError.Cancelled {}
      precondition(taskSession.cancelCount == 1)

      let createdBefore = probe.createdCount
      let preCancelled = Task {
        try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
      }
      preCancelled.cancel()
      do {
        _ = try await preCancelled.value
        preconditionFailure("pre-cancelled task opened browser")
      } catch FfiError.Cancelled {}
      precondition(probe.createdCount == createdBefore)

      let dismissed = Task {
        try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
      }
      let dismissedSession = await probe.nextSession()
      dismissedSession.dismiss()
      do {
        _ = try await dismissed.value
        preconditionFailure("dismissal accepted")
      } catch FfiError.Cancelled {}

      // Both startup failure and absent completion payload release the adapter.
      probe.shouldStart = false
      do {
        _ = try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
        preconditionFailure("failed browser start accepted")
      } catch IOSAuthorizationAdapterError.authorizationSessionCouldNotStart {}
      _ = await probe.nextSession()
      probe.shouldStart = true
      let missing = Task {
        try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
      }
      let missingSession = await probe.nextSession()
      missingSession.finish(url: nil, error: nil)
      do {
        _ = try await missing.value
        preconditionFailure("missing callback accepted")
      } catch IOSAuthorizationAdapterError.missingCallbackURL {}

      let browserError = Task {
        try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
      }
      let errorSession = await probe.nextSession()
      errorSession.finish(url: nil, error: URLError(.cannotConnectToHost))
      do {
        _ = try await browserError.value
        preconditionFailure("browser error ignored")
      } catch let error as URLError { precondition(error.code == .cannotConnectToHost) }

      let invalid = Task {
        try await adapter.authorize(
          configuration: configuration, options: options, transport: transport)
      }
      let invalidSession = await probe.nextSession()
      invalidSession.complete(state: "another-operation")
      do {
        _ = try await invalid.value
        preconditionFailure("foreign state accepted")
      } catch FfiError.InvalidResponse {}
      let finalExchanges = await transport.exchanges
      precondition(finalExchanges == 1)
    }

    private static func providerPort() -> UInt16? {
      let arguments = ProcessInfo.processInfo.arguments
      guard let optionIndex = arguments.firstIndex(of: "--oauth-provider-port"),
        arguments.indices.contains(optionIndex + 1)
      else {
        return nil
      }
      return UInt16(arguments[optionIndex + 1])
    }

    private func writeResult(_ result: String) {
      let resultURL = FileManager.default.urls(
        for: .documentDirectory,
        in: .userDomainMask
      )[0].appendingPathComponent("authorization-flow-result")
      do {
        try Data(result.utf8).write(to: resultURL, options: .atomic)
      } catch {
        NSLog("Could not write authorization-flow result: %@", String(describing: error))
      }
    }
  }

  @MainActor
  private final class IOSBrowserProbe {
    var shouldStart = true
    var createdCount: Int { sessions.count }
    private var sessions: [IOSProbeSession] = []
    private var delivered = 0
    private var waiter: CheckedContinuation<IOSProbeSession, Never>?

    func makeSession(
      url: URL, callback: ASWebAuthenticationSession.Callback,
      completion: @escaping IOSBrowserCompletion
    ) -> any IOSBrowserSession {
      let session = IOSProbeSession(url: url, shouldStart: shouldStart, completion: completion)
      sessions.append(session)
      if let waiter {
        self.waiter = nil
        delivered += 1
        waiter.resume(returning: session)
      }
      return session
    }

    func nextSession() async -> IOSProbeSession {
      if delivered < sessions.count {
        defer { delivered += 1 }
        return sessions[delivered]
      }
      return await withCheckedContinuation { waiter = $0 }
    }
  }

  @MainActor
  private final class IOSProbeSession: IOSBrowserSession {
    var presentationContextProvider: (any ASWebAuthenticationPresentationContextProviding)?
    var prefersEphemeralWebBrowserSession = false
    private let url: URL
    private let shouldStart: Bool
    private let completion: IOSBrowserCompletion
    private(set) var cancelCount = 0
    var completeOnCancel = false

    init(url: URL, shouldStart: Bool, completion: @escaping IOSBrowserCompletion) {
      self.url = url
      self.shouldStart = shouldStart
      self.completion = completion
    }

    func start() -> Bool { shouldStart }
    func cancel() {
      cancelCount += 1
      if completeOnCancel { dismiss() }
    }
    func finish(url: URL?, error: (any Error)?) { completion(url, error) }
    func dismiss() {
      completion(nil, ASWebAuthenticationSessionError(.canceledLogin))
    }
    func complete(state overrideState: String? = nil) {
      let query = URLComponents(url: url, resolvingAgainstBaseURL: false)!.queryItems!
      let redirect = query.first { $0.name == "redirect_uri" }!.value!
      let state = overrideState ?? query.first { $0.name == "state" }!.value!
      var callback = URLComponents(string: redirect)!
      callback.queryItems = [
        URLQueryItem(name: "code", value: "code"), URLQueryItem(name: "state", value: state),
      ]
      completion(callback.url!, nil)
    }
  }

  private actor IOSLifecycleTransport: NativeHttpTransport {
    private(set) var exchanges = 0
    func execute(request: FfiHttpRequest, cancellation: FfiCancellationHandle) async throws
      -> FfiHttpResponse
    {
      exchanges += 1
      return FfiHttpResponse(
        status: 200, headers: [],
        body: Data("{\"access_token\":\"lifecycle-access\",\"token_type\":\"Bearer\"}".utf8))
    }
  }

  enum IOSAuthorizationFlowSmokeError: Error {
    case missingProviderPort
    case unexpectedTokenResponse
  }
#endif
