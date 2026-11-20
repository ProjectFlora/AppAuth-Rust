#include "native_oidc_windows.h"

int main() {
    NativeOidcWindowsCancellationHandle* cancellation =
        native_oidc_windows_cancellation_new();
    if (cancellation == nullptr) {
        return 1;
    }

    native_oidc_windows_cancellation_cancel(cancellation);

    // Invalid JSON must produce an error result for every operation,
    // regardless of the cancellation state.
    const char* invalid_request = "{\"client_id\":\"consumer\",}";

    NativeOidcWindowsRefreshResult* refresh =
        native_oidc_windows_refresh(invalid_request, cancellation);
    if (refresh == nullptr ||
        native_oidc_windows_authorization_result_status(refresh) !=
            NATIVE_OIDC_WINDOWS_AUTHORIZATION_ERROR) {
        return 1;
    }
    native_oidc_windows_authorization_result_free(refresh);

    NativeOidcWindowsEndSessionResult* end_session =
        native_oidc_windows_end_session(invalid_request, cancellation);
    if (end_session == nullptr ||
        native_oidc_windows_authorization_result_status(end_session) !=
            NATIVE_OIDC_WINDOWS_AUTHORIZATION_ERROR) {
        return 1;
    }
    native_oidc_windows_authorization_result_free(end_session);

    // Test refresh with new endpoint using HTTP revocation (loopback allowed per Request 1)
    const char* refreshSuccessRequest = R"({
      "authorization_endpoint":"https://issuer.example/authorize",
      "token_endpoint":"https://issuer.example/token",
      "revocation_endpoint":"http://127.0.0.1:9999/revoke",
      "client_id":"consumer",
      "state":{"token_response":{"access_token":"old","token_type":"Bearer","refresh_token":"refresh"}},
      "additional_parameters":[{"name":"audience","value":"https://api.example"}]
    })";

    NativeOidcWindowsRefreshResult* refreshSuccess =
        native_oidc_windows_refresh(refreshSuccessRequest, cancellation);
    if (refreshSuccess == nullptr ||
        native_oidc_windows_authorization_result_status(refreshSuccess) !=
            NATIVE_OIDC_WINDOWS_AUTHORIZATION_SUCCESS) {
        return 1;
    }

    // Value should not be null and should contain access_token:new-access, refresh_token:new-refresh
    const char* value = native_oidc_windows_authorization_result_value(refreshSuccess);
    if (value == nullptr || value[0] == '\0') {
        std::cerr << "Refresh success result value is null or empty" << std::endl;
        native_oidc_windows_authorization_result_free(refreshSuccess);
        return 1;
    }

    // Check for expected fields in the value
    bool hasAccessToken = (std::string(value).find("access_token") != std::string::npos);
    bool hasNewAccess = (std::string(value).find("new-access") != std::string::npos);
    if (!hasAccessToken || !hasNewAccess) {
        std::cerr << "Refresh result missing expected access_token:new-access field" << std::endl;
        native_oidc_windows_authorization_result_free(refreshSuccess);
        return 1;
    }

    native_oidc_windows_authorization_result_free(refreshSuccess);

    // Test revoke with new endpoint using HTTP revocation (loopback allowed per Request 1)
    const char* revokeSuccessRequest = R"({
      "authorization_endpoint":"https://issuer.example/authorize",
      "token_endpoint":"https://issuer.example/token",
      "revocation_endpoint":"http://127.0.0.1:9999/revoke",
      "client_id":"consumer",
      "token":"refresh",
      "token_type_hint":"refresh_token"
    })";

    NativeOidcWindowsRevocationResult* revokeSuccess =
        native_oidc_windows_revoke(revokeSuccessRequest, cancellation);
    if (revokeSuccess == nullptr ||
        native_oidc_windows_authorization_result_status(revokeSuccess) !=
            NATIVE_OIDC_WINDOWS_AUTHORIZATION_SUCCESS) {
        return 1;
    }

    // Value should be empty string for successful revoke
    const char* revokeValue = native_oidc_windows_authorization_result_value(revokeSuccess);
    if (revokeValue == nullptr) {
        std::cerr << "Revoke success result value is null" << std::endl;
        native_oidc_windows_authorization_result_free(revokeSuccess);
        return 1;
    }

    // Check that value is empty string
    if (strlen(revokeValue) != 0) {
        std::cerr << "Revoke success result value should be empty but got: " << revokeValue << std::endl;
        native_oidc_windows_authorization_result_free(revokeSuccess);
        return 1;
    }

    // Free the revoke result and cancellation
    native_oidc_windows_authorization_result_free(revokeSuccess);
    native_oidc_windows_cancellation_free(cancellation);

    return 0;
}
