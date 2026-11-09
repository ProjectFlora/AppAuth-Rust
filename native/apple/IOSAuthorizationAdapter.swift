#if os(iOS)
  import AuthenticationServices
  import Foundation

  /// Errors raised while preparing or running an iOS browser authorization.
  public enum IOSAuthorizationAdapterError: Error {
    /// An authorization session is already active on this adapter.
    case authorizationSessionAlreadyRunning
    /// The system could not start the authentication session.
    case authorizationSessionCouldNotStart
    /// The generated authorization URL could not be represented as a URL.
    case invalidAuthorizationURL
    /// The configured callback URI is invalid or unsupported.
    case invalidCallbackURL
    /// The system returned neither a callback URL nor an error.
    case missingCallbackURL
  }

  @MainActor
  /// Runs authorization in `ASWebAuthenticationSession` and exchanges the callback code.
  ///
  /// The host application must register its custom callback scheme or configure
  /// the associated domain used for verified HTTPS callbacks.
  public final class IOSAuthorizationAdapter {
    private let presentationContextProvider: any ASWebAuthenticationPresentationContextProviding
    private let prefersEphemeralWebBrowserSession: Bool
    private var activeSession: ASWebAuthenticationSession?
    private var activeCancellation: FfiCancellationHandle?
    private var isRunning = false

    /// Creates an adapter using the host application's presentation context.
    ///
    /// Set `prefersEphemeralWebBrowserSession` to avoid sharing browser cookies
    /// with the user's regular browsing session.
    public init(
      presentationContextProvider: any ASWebAuthenticationPresentationContextProviding,
      prefersEphemeralWebBrowserSession: Bool = false
    ) {
      self.presentationContextProvider = presentationContextProvider
      self.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
    }

    /// Launches the system authentication session and completes code exchange.
    ///
    /// Only one operation may run on an adapter at a time. Cancelling the Swift
    /// task or calling `cancel()` cancels the browser session and core request.
    public func authorize(
      configuration: FfiServiceConfiguration,
      options: FfiAuthorizationOptions,
      transport: NativeHttpTransport
    ) async throws -> FfiAuthenticationState {
      guard !isRunning else {
        throw IOSAuthorizationAdapterError.authorizationSessionAlreadyRunning
      }

      isRunning = true
      let cancellation = FfiCancellationHandle()
      activeCancellation = cancellation

      return try await withTaskCancellationHandler {
        defer {
          activeSession = nil
          activeCancellation = nil
          isRunning = false
        }

        let authorization = try beginAuthorization(
          configuration: configuration,
          options: options,
          transport: transport
        )
        guard let authorizationURL = URL(string: authorization.authorizationUrl()) else {
          throw IOSAuthorizationAdapterError.invalidAuthorizationURL
        }
        let callback = try Self.callback(for: options.redirectUri)
        let callbackURL = try await authenticate(
          authorizationURL: authorizationURL,
          callback: callback,
          cancellation: cancellation
        )
        guard !cancellation.isCancelled() else {
          throw FfiError.Cancelled
        }

        let response = try authorization.parseRedirect(
          redirectUri: callbackURL.absoluteString
        )
        return try await authorization.exchangeCode(
          response: response,
          cancellation: cancellation
        )
      } onCancel: { [weak self] in
        cancellation.cancel()
        Task { @MainActor [weak self] in
          self?.activeSession?.cancel()
        }
      }
    }

    /// Cancels the active browser session and any in-flight core request.
    public func cancel() {
      activeCancellation?.cancel()
      activeSession?.cancel()
    }

    private func authenticate(
      authorizationURL: URL,
      callback: ASWebAuthenticationSession.Callback,
      cancellation: FfiCancellationHandle
    ) async throws -> URL {
      try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<URL, any Error>) in
        let session = ASWebAuthenticationSession(
          url: authorizationURL,
          callback: callback
        ) { [weak self] callbackURL, error in
          self?.activeSession = nil

          if let callbackURL {
            continuation.resume(returning: callbackURL)
          } else if let webError = error as? ASWebAuthenticationSessionError,
            webError.code == .canceledLogin
          {
            cancellation.cancel()
            continuation.resume(throwing: FfiError.Cancelled)
          } else if let error {
            continuation.resume(throwing: error)
          } else {
            continuation.resume(
              throwing: IOSAuthorizationAdapterError.missingCallbackURL
            )
          }
        }
        session.presentationContextProvider = presentationContextProvider
        session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
        activeSession = session

        guard session.start() else {
          activeSession = nil
          continuation.resume(
            throwing: IOSAuthorizationAdapterError.authorizationSessionCouldNotStart
          )
          return
        }
      }
    }

    private static func callback(
      for redirectURI: String
    ) throws -> ASWebAuthenticationSession.Callback {
      guard let components = URLComponents(string: redirectURI),
        let scheme = components.scheme?.lowercased()
      else {
        throw IOSAuthorizationAdapterError.invalidCallbackURL
      }

      if scheme == "https" {
        guard let host = components.host,
          components.port == nil || components.port == 443,
          components.user == nil,
          components.password == nil,
          components.fragment == nil
        else {
          throw IOSAuthorizationAdapterError.invalidCallbackURL
        }
        return .https(host: host, path: components.path.isEmpty ? "/" : components.path)
      }

      guard scheme != "http" else {
        throw IOSAuthorizationAdapterError.invalidCallbackURL
      }
      return .customScheme(scheme)
    }
  }
#endif
