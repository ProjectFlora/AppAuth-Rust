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
typedef AppAuthWindowsAuthorizationResult AppAuthWindowsRevocationResult;
typedef AppAuthWindowsAuthorizationResult AppAuthWindowsRefreshResult;
typedef AppAuthWindowsAuthorizationResult AppAuthWindowsEndSessionResult;

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

/*
 * Blocks while refreshing tokens. Pass UTF-8 JSON with either issuer discovery
 * or authorization_endpoint and token_endpoint, plus client_id and the state
 * object from a previous successful result; with explicit endpoints, pair
 * jwks_uri with issuer to validate a refreshed ID token. The optional
 * additional_parameters array uses unique names. The success value is the
 * updated serialized state, which the host must persist.
 */
APPAUTH_WINDOWS_API AppAuthWindowsRefreshResult *
appauth_windows_refresh(
    const char *request_json_utf8,
    const AppAuthWindowsCancellationHandle *cancellation);

/*
 * Blocks while ending the session. Pass UTF-8 JSON with either issuer
 * discovery or authorization_endpoint, token_endpoint, and
 * end_session_endpoint, plus client_id; id_token_hint is optional. With
 * post_logout_redirect_uri, an unported http://127.0.0.1 URI: an available
 * port is chosen, the system browser is opened, and the returned state is
 * validated on a loopback callback. The success value is the validated
 * response, or empty without a post-logout redirect.
 */
APPAUTH_WINDOWS_API AppAuthWindowsEndSessionResult *
appauth_windows_end_session(
    const char *request_json_utf8,
    const AppAuthWindowsCancellationHandle *cancellation);

/*
 * Blocks while revoking a token. Pass UTF-8 JSON with either issuer discovery
 * or authorization_endpoint, token_endpoint, and revocation_endpoint, plus
 * client_id, token, and optional token_type_hint.
 */
APPAUTH_WINDOWS_API AppAuthWindowsRevocationResult *
appauth_windows_revoke(
    const char *request_json_utf8,
    const AppAuthWindowsCancellationHandle *cancellation);

/* The result accessors also accept refresh and end-session result handles. */
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
