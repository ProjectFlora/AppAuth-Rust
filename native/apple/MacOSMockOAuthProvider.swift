#if os(macOS)
  import CryptoKit
  import Foundation
  import Network

  actor MacOSMockOAuthProvider {
    private static let maximumRequestSize = 16 * 1024
    private static let headerTerminator = Data([13, 10, 13, 10])

    private let listener: NWListener
    private let queue = DispatchQueue(label: "appauth-rust.mock-oauth-provider")
    private var readyContinuation: CheckedContinuation<UInt16, any Error>?
    private var expectedChallenge: String?
    private var expectedRedirectURI: String?
    private var expectedState: String?
    private var tokenExchangeVerified = false

    init() throws {
      let parameters = NWParameters.tcp
      parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
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

    func stop() {
      listener.cancel()
    }

    func verifyCompletedFlow() throws {
      guard expectedChallenge != nil,
        expectedRedirectURI != nil,
        expectedState != nil,
        tokenExchangeVerified
      else {
        throw MacOSMockOAuthProviderError.incompleteAuthorizationFlow
      }
    }

    private func update(_ state: NWListener.State) {
      switch state {
      case .ready:
        guard let port = listener.port?.rawValue else {
          readyContinuation?.resume(throwing: MacOSMockOAuthProviderError.listenerUnavailable)
          readyContinuation = nil
          return
        }
        readyContinuation?.resume(returning: port)
        readyContinuation = nil
      case .failed(let error):
        readyContinuation?.resume(throwing: error)
        readyContinuation = nil
      default:
        break
      }
    }

    private func accept(_ connection: NWConnection) {
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
      guard data.count <= Self.maximumRequestSize else {
        respond(status: 413, reason: "Payload Too Large", body: "", on: connection)
        return
      }
      guard let terminator = data.range(of: Self.headerTerminator) else {
        if failed || isComplete {
          respond(status: 400, reason: "Bad Request", body: "", on: connection)
        } else {
          receive(on: connection, accumulated: data)
        }
        return
      }

      let headerData = data[..<terminator.lowerBound]
      guard let headerText = String(data: headerData, encoding: .ascii),
        let requestLine = headerText.components(separatedBy: "\r\n").first,
        let contentLength = contentLength(in: headerText)
      else {
        respond(status: 400, reason: "Bad Request", body: "", on: connection)
        return
      }
      let bodyStart = terminator.upperBound
      guard data.count - bodyStart >= contentLength else {
        if failed || isComplete {
          respond(status: 400, reason: "Bad Request", body: "", on: connection)
        } else {
          receive(on: connection, accumulated: data)
        }
        return
      }
      guard let body = String(data: data[bodyStart...], encoding: .utf8) else {
        respond(status: 400, reason: "Bad Request", body: "", on: connection)
        return
      }

      let fields = requestLine.split(separator: " ", omittingEmptySubsequences: true)
      guard fields.count == 3,
        fields[2] == "HTTP/1.0" || fields[2] == "HTTP/1.1"
      else {
        respond(status: 400, reason: "Bad Request", body: "", on: connection)
        return
      }
      let method = String(fields[0])
      let target = String(fields[1])
      if method == "GET", target.hasPrefix("/authorize?") {
        authorize(target: target, on: connection)
      } else if method == "POST", target == "/token" {
        exchangeToken(body: body, on: connection)
      } else {
        respond(status: 404, reason: "Not Found", body: "", on: connection)
      }
    }

    private func contentLength(in headers: String) -> Int? {
      let values = headers.components(separatedBy: "\r\n").dropFirst().compactMap { line -> Int? in
        guard let separator = line.firstIndex(of: ":"),
          line[..<separator].caseInsensitiveCompare("Content-Length") == .orderedSame
        else {
          return nil
        }
        return Int(line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces))
      }
      guard values.count <= 1 else {
        return nil
      }
      let length = values.first ?? 0
      guard length >= 0 else {
        return nil
      }
      return length
    }

    private func authorize(target: String, on connection: NWConnection) {
      guard let components = URLComponents(string: "http://127.0.0.1\(target)"),
        let clientID = uniqueValue("client_id", in: components),
        clientID == "macos-smoke-client",
        uniqueValue("response_type", in: components) == "code",
        uniqueValue("scope", in: components) == "profile",
        uniqueValue("code_challenge_method", in: components) == "S256",
        let challenge = uniqueValue("code_challenge", in: components),
        let state = uniqueValue("state", in: components),
        let redirectURI = uniqueValue("redirect_uri", in: components),
        var redirect = URLComponents(string: redirectURI),
        redirect.scheme == "http",
        redirect.host == "127.0.0.1",
        redirect.path == "/oauth/callback",
        redirect.port != nil
      else {
        respond(status: 400, reason: "Bad Request", body: "", on: connection)
        return
      }

      expectedChallenge = challenge
      expectedRedirectURI = redirectURI
      expectedState = state
      redirect.queryItems = [
        URLQueryItem(name: "code", value: "mock-authorization-code"),
        URLQueryItem(name: "state", value: state),
      ]
      guard let callbackURL = redirect.url?.absoluteString else {
        respond(status: 400, reason: "Bad Request", body: "", on: connection)
        return
      }
      respond(
        status: 302,
        reason: "Found",
        body: "",
        headers: ["Location": callbackURL],
        on: connection
      )
    }

    private func exchangeToken(body: String, on connection: NWConnection) {
      guard let components = URLComponents(string: "http://127.0.0.1/?\(body)"),
        let grantType = uniqueValue("grant_type", in: components),
        grantType == "authorization_code",
        let code = uniqueValue("code", in: components),
        code == "mock-authorization-code",
        let redirectURI = uniqueValue("redirect_uri", in: components),
        redirectURI == expectedRedirectURI,
        let verifier = uniqueValue("code_verifier", in: components),
        let expectedChallenge,
        Self.pkceChallenge(for: verifier) == expectedChallenge,
        uniqueValue("client_id", in: components) == "macos-smoke-client"
      else {
        respond(status: 400, reason: "Bad Request", body: "", on: connection)
        return
      }

      tokenExchangeVerified = true
      respond(
        status: 200,
        reason: "OK",
        body:
          #"{"access_token":"mock-access-token","token_type":"Bearer","expires_in":3600,"refresh_token":"mock-refresh-token","scope":"profile"}"#,
        headers: ["Content-Type": "application/json"],
        on: connection
      )
    }

    private func uniqueValue(_ name: String, in components: URLComponents) -> String? {
      let matches = components.queryItems?.filter { $0.name == name } ?? []
      guard matches.count == 1 else {
        return nil
      }
      return matches[0].value
    }

    private static func pkceChallenge(for verifier: String) -> String {
      Data(SHA256.hash(data: Data(verifier.utf8)))
        .base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    }

    private func respond(
      status: Int,
      reason: String,
      body: String,
      headers: [String: String] = [:],
      on connection: NWConnection
    ) {
      let bodyData = Data(body.utf8)
      let customHeaders = headers.map { "\($0.key): \($0.value)\r\n" }.joined()
      let response =
        Data(
          "HTTP/1.1 \(status) \(reason)\r\n\(customHeaders)Content-Length: \(bodyData.count)\r\nConnection: close\r\n\r\n"
            .utf8
        ) + bodyData
      connection.send(
        content: response,
        completion: .contentProcessed { _ in
          connection.cancel()
        })
    }
  }

  enum MacOSMockOAuthProviderError: Error {
    case incompleteAuthorizationFlow
    case listenerUnavailable
  }
#endif
