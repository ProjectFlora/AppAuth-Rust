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

  enum IOSAuthorizationFlowSmokeError: Error {
    case missingProviderPort
    case unexpectedTokenResponse
  }
#endif
