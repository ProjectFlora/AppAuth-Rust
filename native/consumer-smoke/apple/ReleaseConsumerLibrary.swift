import Foundation

func validateReleaseConsumerLinking() throws {
  let configuration = try FfiServiceConfiguration(
    authorizationEndpoint: "https://issuer.example/authorize",
    tokenEndpoint: "https://issuer.example/token"
  )
  precondition(configuration.authorizationEndpoint() == "https://issuer.example/authorize")
}
