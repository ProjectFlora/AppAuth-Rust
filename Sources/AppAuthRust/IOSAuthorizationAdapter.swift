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
  protocol IOSBrowserSession: AnyObject {
    var presentationContextProvider: (any ASWebAuthenticationPresentationContextProviding)? {
      get set
    }
    var prefersEphemeralWebBrowserSession: Bool { get set }
    func start() -> Bool
    func cancel()
  }

  extension ASWebAuthenticationSession: IOSBrowserSession {}

  typealias IOSBrowserCompletion = @Sendable (URL?, (any Error)?) -> Void
  typealias IOSBrowserSessionFactory =
    @MainActor (
      URL, ASWebAuthenticationSession.Callback, @escaping IOSBrowserCompletion
    ) -> any IOSBrowserSession

  @MainActor
  private final class IOSBrowserWait {
    private var continuation: CheckedContinuation<URL, any Error>?

    init(_ continuation: CheckedContinuation<URL, any Error>) {
      self.continuation = continuation
    }

    func finish(_ result: Result<URL, any Error>) {
      guard let continuation else { return }
      self.continuation = nil
      continuation.resume(with: result)
    }
  }

  @MainActor
  /// Runs authorization in `ASWebAuthenticationSession` and exchanges the callback code.
  ///
  /// The host application must register its custom callback scheme or configure
  /// the associated domain used for verified HTTPS callbacks.
  public final class IOSAuthorizationAdapter {
    private let presentationContextProvider: any ASWebAuthenticationPresentationContextProviding
    private let prefersEphemeralWebBrowserSession: Bool
    private let browserSessionFactory: IOSBrowserSessionFactory
    private var activeSession: (any IOSBrowserSession)?
    private var activeWait: IOSBrowserWait?
    private var activeCancellation: FfiCancellationHandle?
    private var isRunning = false

    /// Creates an adapter using the host application's presentation context.
    ///
    /// Set `prefersEphemeralWebBrowserSession` to avoid sharing browser cookies
    /// with the user's regular browsing session.
    public convenience init(
      presentationContextProvider: any ASWebAuthenticationPresentationContextProviding,
      prefersEphemeralWebBrowserSession: Bool = false
    ) {
      self.init(
        presentationContextProvider: presentationContextProvider,
        prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession,
        browserSessionFactory: { url, callback, completion in
          ASWebAuthenticationSession(url: url, callback: callback, completionHandler: completion)
        }
      )
    }

    // Internal seam: tests replace only browser presentation, keeping the same
    // authorization, callback validation, cancellation and code-exchange path.
    init(
      presentationContextProvider: any ASWebAuthenticationPresentationContextProviding,
      prefersEphemeralWebBrowserSession: Bool,
      browserSessionFactory: @escaping IOSBrowserSessionFactory
    ) {
      self.browserSessionFactory = browserSessionFactory
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
          self?.cancelBrowser(cancellation: cancellation)
        }
      }
    }

    /// Cancels the active browser session and any in-flight core request.
    public func cancel() {
      guard let cancellation = activeCancellation else { return }
      cancellation.cancel()
      cancelBrowser(cancellation: cancellation)
    }

    private func cancelBrowser(cancellation: FfiCancellationHandle) {
      guard activeCancellation === cancellation else { return }
      let session = activeSession
      activeSession = nil
      let wait = activeWait
      activeWait = nil
      // Explicit cancellation must complete even if the OS does not invoke the
      // session completion handler. Clear identity before a synchronous callback.
      wait?.finish(.failure(FfiError.Cancelled))
      session?.cancel()
    }

    private func authenticate(
      authorizationURL: URL,
      callback: ASWebAuthenticationSession.Callback,
      cancellation: FfiCancellationHandle
    ) async throws -> URL {
      guard !cancellation.isCancelled() else { throw FfiError.Cancelled }
      return try await withCheckedThrowingContinuation {
        (continuation: CheckedContinuation<URL, any Error>) in
        let wait = IOSBrowserWait(continuation)
        activeWait = wait
        let session = browserSessionFactory(authorizationURL, callback) {
          [weak self, weak wait] callbackURL, error in
          Task { @MainActor [weak self, weak wait] in
            guard let self, let wait, self.activeWait === wait else { return }
            self.activeSession = nil
            self.activeWait = nil
            if let callbackURL {
              wait.finish(.success(callbackURL))
            } else if let webError = error as? ASWebAuthenticationSessionError,
              webError.code == .canceledLogin
            {
              cancellation.cancel()
              wait.finish(.failure(FfiError.Cancelled))
            } else if let error {
              wait.finish(.failure(error))
            } else {
              wait.finish(.failure(IOSAuthorizationAdapterError.missingCallbackURL))
            }
          }
        }
        session.presentationContextProvider = presentationContextProvider
        session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
        activeSession = session

        guard session.start() else {
          activeSession = nil
          activeWait = nil
          wait.finish(.failure(IOSAuthorizationAdapterError.authorizationSessionCouldNotStart))
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
