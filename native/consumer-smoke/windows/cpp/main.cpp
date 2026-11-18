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

    native_oidc_windows_cancellation_free(cancellation);
    return 0;
}
