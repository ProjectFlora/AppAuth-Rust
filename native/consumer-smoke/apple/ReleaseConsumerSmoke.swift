import Foundation

@main
struct ReleaseConsumerSmoke {
  static func main() throws {
    let configuration = try FfiServiceConfiguration(
      authorizationEndpoint: "https://issuer.example/authorize",
      tokenEndpoint: "https://issuer.example/token"
    )
    precondition(configuration.authorizationEndpoint() == "https://issuer.example/authorize")
    precondition(configuration.tokenEndpoint() == "https://issuer.example/token")
  }
}
