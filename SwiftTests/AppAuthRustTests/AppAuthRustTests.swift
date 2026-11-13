import AppAuthRust
import XCTest

/// Host-side smoke for the Swift package: exercises the generated API through
/// the FFI module provided by the binary target without any network activity.
/// Deeper adapter and callback behavior is covered by the scripts in
/// `scripts/check-apple-*.sh` and the release consumer checks.
final class AppAuthRustTests: XCTestCase {
    /// Token state JSON in the shape produced by `FfiAuthenticationState.toJson()`.
    private let stateJson = #"{"token_response":{"access_token":"old","token_type":"Bearer","refresh_token":"refresh"}}"#

    func testAuthenticationStateJsonRoundTrip() async throws {
        let state = try FfiAuthenticationState.fromJson(serialized: stateJson)
        let serialized = try await state.toJson()
        let restored = try FfiAuthenticationState.fromJson(serialized: serialized)
        let reserialized = try await restored.toJson()

        XCTAssertEqual(reserialized, serialized)
        let response = await restored.tokenResponse()
        XCTAssertEqual(response.accessToken, "old")
        XCTAssertEqual(response.tokenType, "Bearer")
        XCTAssertEqual(response.refreshToken, "refresh")
    }

    func testServiceConfigurationBuilder() throws {
        let configuration = try FfiServiceConfiguration(
            authorizationEndpoint: "https://idp.example/authorize",
            tokenEndpoint: "https://idp.example/token"
        )
        let withValidation = try configuration.withOidcValidationEndpoints(
            issuer: "https://idp.example",
            jwksUri: "https://idp.example/.well-known/jwks.json"
        )
        // The issuer is normalized with a trailing slash.
        XCTAssertEqual(withValidation.issuer(), "https://idp.example/")
        XCTAssertEqual(withValidation.jwksUri(), "https://idp.example/.well-known/jwks.json")
    }
}
