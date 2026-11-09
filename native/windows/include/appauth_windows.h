#ifndef APPAUTH_WINDOWS_H
#define APPAUTH_WINDOWS_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define APPAUTH_WINDOWS_API __declspec(dllimport)
#else
#define APPAUTH_WINDOWS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AppAuthWindowsCancellationHandle AppAuthWindowsCancellationHandle;
typedef struct AppAuthWindowsAuthorizationResult AppAuthWindowsAuthorizationResult;

enum AppAuthWindowsAuthorizationStatus {
    APPAUTH_WINDOWS_AUTHORIZATION_SUCCESS = 0,
    APPAUTH_WINDOWS_AUTHORIZATION_ERROR = 1,
    APPAUTH_WINDOWS_AUTHORIZATION_CANCELLED = 2
};

APPAUTH_WINDOWS_API AppAuthWindowsCancellationHandle *
appauth_windows_cancellation_new(void);

APPAUTH_WINDOWS_API void
appauth_windows_cancellation_cancel(const AppAuthWindowsCancellationHandle *handle);

APPAUTH_WINDOWS_API void
appauth_windows_cancellation_free(AppAuthWindowsCancellationHandle *handle);

/*
 * Blocks until authorization completes or is cancelled. Pass a UTF-8 JSON
 * request with either issuer discovery or authorization_endpoint and
 * token_endpoint, plus client_id, redirect_uri, scopes, and optional
 * additional_parameters / additional_token_parameters arrays.
 */
APPAUTH_WINDOWS_API AppAuthWindowsAuthorizationResult *
appauth_windows_authorize(
    const char *request_json_utf8,
    const AppAuthWindowsCancellationHandle *cancellation);

APPAUTH_WINDOWS_API int32_t
appauth_windows_authorization_result_status(
    const AppAuthWindowsAuthorizationResult *authorization_result);

/* The returned UTF-8 string is owned by authorization_result. */
APPAUTH_WINDOWS_API const char *
appauth_windows_authorization_result_value(
    const AppAuthWindowsAuthorizationResult *authorization_result);

APPAUTH_WINDOWS_API void
appauth_windows_authorization_result_free(
    AppAuthWindowsAuthorizationResult *authorization_result);

#ifdef __cplusplus
}
#endif

#endif
