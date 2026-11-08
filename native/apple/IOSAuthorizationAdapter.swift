#if os(iOS)
  import AuthenticationServices
  import Foundation

  public enum IOSAuthorizationAdapterError: Error {
    case authorizationSessionAlreadyRunning
    case authorizationSessionCouldNotStart
    case invalidAuthorizationURL
    case invalidCallbackURL
    case missingCallbackURL
  }

  @MainActor
  public final class IOSAuthorizationAdapter {
    private let presentationContextProvider: any ASWebAuthenticationPresentationContextProviding
    private let prefersEphemeralWebBrowserSession: Bool
    private var activeSession: ASWebAuthenticationSession?
    private var activeCancellation: FfiCancellationHandle?
    private var isRunning = false

    public init(
      presentationContextProvider: any ASWebAuthenticationPresentationContextProviding,
      prefersEphemeralWebBrowserSession: Bool = false
    ) {
      self.presentationContextProvider = presentationContextProvider
      self.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
    }

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
