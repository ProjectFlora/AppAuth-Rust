import Foundation

private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, Sendable {
  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    willPerformHTTPRedirection response: HTTPURLResponse,
    newRequest request: URLRequest,
    completionHandler: @escaping (URLRequest?) -> Void
  ) {
    completionHandler(nil)
  }
}

/// `URLSession`-based UniFFI transport that returns redirects without following them.
public final class URLSessionNativeHttpTransport: NativeHttpTransport, @unchecked Sendable {
  private let redirectDelegate: NoRedirectDelegate
  private let session: URLSession

  /// Creates a transport with the supplied session configuration.
  public init(configuration: URLSessionConfiguration = .ephemeral) {
    let redirectDelegate = NoRedirectDelegate()
    self.redirectDelegate = redirectDelegate
    self.session = URLSession(
      configuration: configuration,
      delegate: redirectDelegate,
      delegateQueue: nil
    )
  }

  /// Executes one HTTP request and propagates task or core cancellation.
  public func execute(
    request: FfiHttpRequest,
    cancellation: FfiCancellationHandle
  ) async throws -> FfiHttpResponse {
    guard let url = URL(string: request.url) else {
      throw FfiError.InvalidRequest("HTTP request URL is invalid")
    }
    guard !cancellation.isCancelled() else {
      throw FfiError.Cancelled
    }

    var urlRequest = URLRequest(url: url)
    urlRequest.httpMethod = request.method
    urlRequest.httpBody = request.body
    for header in request.headers {
      guard let value = String(bytes: header.value, encoding: .utf8) else {
        throw FfiError.InvalidRequest("HTTP header value is not valid UTF-8")
      }
      urlRequest.setValue(value, forHTTPHeaderField: header.name)
    }

    let requestTask = Task {
      try await session.data(for: urlRequest)
    }
    let cancellationTask = Task {
      await cancellation.cancelled()
      requestTask.cancel()
    }

    do {
      let (body, response) = try await withTaskCancellationHandler {
        try await requestTask.value
      } onCancel: {
        requestTask.cancel()
      }
      cancellationTask.cancel()

      guard let response = response as? HTTPURLResponse else {
        throw FfiError.TransportFailure("HTTP response is not an HTTPURLResponse")
      }
      return FfiHttpResponse(
        status: UInt16(response.statusCode),
        headers: response.allHeaderFields.map { name, value in
          FfiHttpHeader(
            name: String(describing: name),
            value: Data(String(describing: value).utf8)
          )
        },
        body: body
      )
    } catch {
      cancellationTask.cancel()
      if cancellation.isCancelled() || Task.isCancelled || (error as? URLError)?.code == .cancelled
      {
        throw FfiError.Cancelled
      }
      throw FfiError.TransportFailure(error.localizedDescription)
    }
  }
}
