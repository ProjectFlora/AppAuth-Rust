#include "appauth_windows.h"

int main() {
    AppAuthWindowsCancellationHandle* cancellation =
        appauth_windows_cancellation_new();
    if (cancellation == nullptr) {
        return 1;
    }

    appauth_windows_cancellation_cancel(cancellation);
    appauth_windows_cancellation_free(cancellation);
    return 0;
}
