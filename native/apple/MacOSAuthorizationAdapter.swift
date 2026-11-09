#if os(macOS)
  import AppKit
  import Foundation
  import Network

  public enum MacOSAuthorizationAdapterError: Error {
    case authorizationSessionAlreadyRunning
    case browserCouldNotBeOpened
    case invalidAuthorizationURL
    case invalidLoopbackRedirectURI
    case malformedLoopbackRequest
  }

  @MainActor
  public final class MacOSAuthorizationAdapter {
    private let openAuthorizationURL: @MainActor @Sendable (URL) async throws -> Void
    private var activeCancellation: FfiCancellationHandle?
    private var activeListener: LoopbackHTTPListener?
    private var isRunning = false

    public init(
      openAuthorizationURL: @escaping @MainActor @Sendable (URL) async throws -> Void = { url in
        guard NSWorkspace.shared.open(url) else {
          throw MacOSAuthorizationAdapterError.browserCouldNotBeOpened
        }
      }
    ) {
      self.openAuthorizationURL = openAuthorizationURL
    }

    public func authorize(
      configuration: FfiServiceConfiguration,
      options: FfiAuthorizationOptions,
      transport: NativeHttpTransport
    ) async throws -> FfiAuthenticationState {
      guard !isRunning else {
        throw MacOSAuthorizationAdapterError.authorizationSessionAlreadyRunning
      }

      let redirectComponents = try Self.loopbackRedirectComponents(options.redirectUri)
      let listener = try LoopbackHTTPListener(callbackPath: redirectComponents.percentEncodedPath)
      let cancellation = FfiCancellationHandle()
      activeCancellation = cancellation
      activeListener = listener
      isRunning = true

      return try await withTaskCancellationHandler {
        defer {
          activeCancellation = nil
          activeListener = nil
          isRunning = false
        }

        do {
          let port = try await listener.start()
          var options = options
          var actualRedirect = redirectComponents
          actualRedirect.port = Int(port)
          guard let actualRedirectURI = actualRedirect.string else {
            throw MacOSAuthorizationAdapterError.invalidLoopbackRedirectURI
          }
          options.redirectUri = actualRedirectURI

          let authorization = try beginAuthorization(
            configuration: configuration,
            options: options,
            transport: transport
          )
          guard let authorizationURL = URL(string: authorization.authorizationUrl()) else {
            throw MacOSAuthorizationAdapterError.invalidAuthorizationURL
          }

          let callbackTask = Task {
            try await listener.waitForCallback()
          }
          do {
            try await openAuthorizationURL(authorizationURL)
          } catch {
            callbackTask.cancel()
            throw error
          }

          let callbackURI = try await callbackTask.value
          guard !cancellation.isCancelled() else {
            throw FfiError.Cancelled
          }
          let response = try authorization.parseRedirect(redirectUri: callbackURI)
          return try await authorization.exchangeCode(
            response: response,
            cancellation: cancellation
          )
        } catch {
          await listener.cancel()
          throw error
        }
      } onCancel: {
        cancellation.cancel()
        Task {
          await listener.cancel()
        }
      }
    }

    public func cancel() {
      activeCancellation?.cancel()
      if let activeListener {
        Task {
          await activeListener.cancel()
        }
      }
    }

    private static func loopbackRedirectComponents(_ redirectURI: String) throws -> URLComponents {
      guard var components = URLComponents(string: redirectURI),
        components.scheme == "http",
        components.host == "127.0.0.1",
        components.port == nil,
        components.user == nil,
        components.password == nil,
        components.fragment == nil
      else {
        throw MacOSAuthorizationAdapterError.invalidLoopbackRedirectURI
      }
      if components.percentEncodedPath.isEmpty {
        components.percentEncodedPath = "/"
      }
      return components
    }
  }

  actor LoopbackHTTPListener {
    private static let maximumRequestSize = 16 * 1024
    private static let headerTerminator = Data([13, 10, 13, 10])

    private let callbackPath: String
    private let listener: NWListener
    private let queue = DispatchQueue(label: "appauth-rust.loopback-listener")
    private var readyContinuation: CheckedContinuation<UInt16, any Error>?
    private var callbackContinuation: CheckedContinuation<String, any Error>?
    private var callbackResult: Result<String, any Error>?
    private var callbackPending = false
    private var boundPort: UInt16?
    private var activeConnections: [NWConnection] = []
    private var isStopped = false

    init(callbackPath: String) throws {
      self.callbackPath = callbackPath

      let parameters = NWParameters.tcp
      parameters.requiredLocalEndpoint = .hostPort(
        host: .ipv4(.loopback),
        port: .any
      )
      parameters.acceptLocalOnly = true
      listener = try NWListener(using: parameters, on: .any)
      listener.newConnectionHandler = { [weak self] connection in
        Task {
          await self?.accept(connection)
        }
      }
      listener.stateUpdateHandler = { [weak self] state in
        Task {
          await self?.update(state)
        }
      }
    }

    func start() async throws -> UInt16 {
      try await withCheckedThrowingContinuation { continuation in
        readyContinuation = continuation
        listener.start(queue: queue)
      }
    }

    func waitForCallback() async throws -> String {
      if let callbackResult {
        return try callbackResult.get()
      }
      if isStopped && !callbackPending {
        throw FfiError.Cancelled
      }
      return try await withCheckedThrowingContinuation { continuation in
        callbackContinuation = continuation
      }
    }

    func cancel() {
      guard !isStopped else {
        return
      }
      isStopped = true
      listener.cancel()
      for connection in activeConnections {
        connection.cancel()
      }
      activeConnections.removeAll()
      readyContinuation?.resume(throwing: FfiError.Cancelled)
      readyContinuation = nil
      resolveCallback(.failure(FfiError.Cancelled))
    }

    private func update(_ state: NWListener.State) {
      switch state {
      case .ready:
        guard let port = listener.port?.rawValue else {
          fail(MacOSAuthorizationAdapterError.invalidLoopbackRedirectURI)
          return
        }
        boundPort = port
        readyContinuation?.resume(returning: port)
        readyContinuation = nil
      case .failed(let error):
        fail(error)
      case .cancelled:
        if !isStopped {
          fail(FfiError.Cancelled)
        }
      default:
        break
      }
    }

    private func accept(_ connection: NWConnection) {
      guard !isStopped else {
        connection.cancel()
        return
      }
      activeConnections.append(connection)
      connection.start(queue: queue)
      receive(on: connection, accumulated: Data())
    }

    private func receive(on connection: NWConnection, accumulated: Data) {
      connection.receive(
        minimumIncompleteLength: 1,
        maximumLength: Self.maximumRequestSize
      ) { [weak self] data, _, isComplete, error in
        let received = accumulated + (data ?? Data())
        Task {
          await self?.received(
            received,
            on: connection,
            isComplete: isComplete,
            failed: error != nil
          )
        }
      }
    }

    private func received(
      _ data: Data,
      on connection: NWConnection,
      isComplete: Bool,
      failed: Bool
    ) {
      guard !isStopped else {
        connection.cancel()
        return
      }
      if let terminator = data.range(of: Self.headerTerminator) {
        let requestHeader = data[..<terminator.lowerBound]
        guard let requestHeaders = String(data: requestHeader, encoding: .ascii),
          let requestLine = requestHeaders.components(separatedBy: "\r\n").first
        else {
          respond(status: 400, body: "Invalid request", on: connection)
          return
        }
        let fields = requestLine.split(separator: " ", omittingEmptySubsequences: true)
        guard fields.count >= 2 else {
          respond(status: 400, body: "Invalid request", on: connection)
          return
        }
        let target = String(fields[1])
        let requestPath =
          target.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
          .first
          .map(String.init) ?? ""
        guard requestPath == callbackPath else {
          respond(status: 404, body: "Not Found", on: connection)
          return
        }
        guard fields.count == 3,
          fields[0] == "GET",
          fields[2] == "HTTP/1.0" || fields[2] == "HTTP/1.1"
        else {
          completeCallback(
            .failure(MacOSAuthorizationAdapterError.malformedLoopbackRequest),
            on: connection,
            status: 400,
            body: "Invalid request"
          )
          return
        }

        guard let boundPort else {
          fail(MacOSAuthorizationAdapterError.invalidLoopbackRedirectURI)
          return
        }
        let expectedHost = "127.0.0.1:\(boundPort)"
        let hostHeaders =
          requestHeaders
          .components(separatedBy: "\r\n")
          .dropFirst()
          .compactMap { line -> String? in
            guard let separator = line.firstIndex(of: ":"),
              line[..<separator].caseInsensitiveCompare("Host") == .orderedSame
            else {
              return nil
            }
            return line[line.index(after: separator)...]
              .trimmingCharacters(in: .whitespaces)
          }
        guard hostHeaders == [expectedHost] else {
          completeCallback(
            .failure(MacOSAuthorizationAdapterError.malformedLoopbackRequest),
            on: connection,
            status: 400,
            body: "Invalid request"
          )
          return
        }
        let callbackURI = "http://127.0.0.1:\(boundPort)\(target)"
        guard URLComponents(string: callbackURI)?.url != nil else {
          completeCallback(
            .failure(MacOSAuthorizationAdapterError.malformedLoopbackRequest),
            on: connection,
            status: 400,
            body: "Invalid request"
          )
          return
        }
        completeCallback(
          .success(callbackURI),
          on: connection,
          status: 200,
          body: "Authorization complete. You may close this window."
        )
      } else if failed || isComplete || data.count >= Self.maximumRequestSize {
        respond(status: 400, body: "Invalid request", on: connection)
      } else {
        receive(on: connection, accumulated: data)
      }
    }

    private func respond(status: Int, body: String, on connection: NWConnection) {
      sendResponse(status: status, body: body, on: connection) { [weak self] in
        Task {
          await self?.remove(connection)
        }
      }
    }

    private func completeCallback(
      _ result: Result<String, any Error>,
      on connection: NWConnection,
      status: Int,
      body: String
    ) {
      isStopped = true
      callbackPending = true
      listener.cancel()
      for activeConnection in activeConnections where activeConnection !== connection {
        activeConnection.cancel()
      }
      activeConnections = [connection]
      sendResponse(status: status, body: body, on: connection) { [weak self] in
        Task {
          await self?.remove(connection)
          await self?.resolveCallback(result)
        }
      }
    }

    private func sendResponse(
      status: Int,
      body: String,
      on connection: NWConnection,
      completion: @escaping @Sendable () -> Void
    ) {
      let bodyData = Data(body.utf8)
      let response =
        Data(
          "HTTP/1.1 \(status) \(status == 200 ? "OK" : status == 404 ? "Not Found" : "Bad Request")\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: \(bodyData.count)\r\nConnection: close\r\n\r\n"
            .utf8
        ) + bodyData
      connection.send(
        content: response,
        completion: .contentProcessed { _ in
          connection.cancel()
          completion()
        })
    }

    private func resolveCallback(_ result: Result<String, any Error>) {
      if let callbackContinuation {
        self.callbackContinuation = nil
        callbackContinuation.resume(with: result)
      } else {
        callbackResult = result
      }
    }

    private func fail(_ error: any Error) {
      guard !isStopped else {
        return
      }
      isStopped = true
      listener.cancel()
      for connection in activeConnections {
        connection.cancel()
      }
      activeConnections.removeAll()
      readyContinuation?.resume(throwing: error)
      readyContinuation = nil
      resolveCallback(.failure(error))
    }

    private func remove(_ connection: NWConnection) {
      activeConnections.removeAll { $0 === connection }
    }
  }
#endif
