#include "appauth_windows.h"

int main() {
    AppAuthWindowsCancellationHandle* cancellation =
        appauth_windows_cancellation_new();
    if (cancellation == nullptr) {
        return 1;
    }

    appauth_windows_cancellation_cancel(cancellation);

    // Invalid JSON must produce an error result for every operation,
    // regardless of the cancellation state.
    const char* invalid_request = "{\"client_id\":\"consumer\",}";

    AppAuthWindowsRefreshResult* refresh =
        appauth_windows_refresh(invalid_request, cancellation);
    if (refresh == nullptr ||
        appauth_windows_authorization_result_status(refresh) !=
            APPAUTH_WINDOWS_AUTHORIZATION_ERROR) {
        return 1;
    }
    appauth_windows_authorization_result_free(refresh);

    AppAuthWindowsEndSessionResult* end_session =
        appauth_windows_end_session(invalid_request, cancellation);
    if (end_session == nullptr ||
        appauth_windows_authorization_result_status(end_session) !=
            APPAUTH_WINDOWS_AUTHORIZATION_ERROR) {
        return 1;
    }
    appauth_windows_authorization_result_free(end_session);

    appauth_windows_cancellation_free(cancellation);
    return 0;
}
