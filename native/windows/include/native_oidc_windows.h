#ifndef NATIVE_OIDC_WINDOWS_H
#define NATIVE_OIDC_WINDOWS_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define NATIVE_OIDC_WINDOWS_API __declspec(dllimport)
#else
#define NATIVE_OIDC_WINDOWS_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NativeOidcWindowsCancellationHandle NativeOidcWindowsCancellationHandle;
typedef struct NativeOidcWindowsAuthorizationResult NativeOidcWindowsAuthorizationResult;
typedef NativeOidcWindowsAuthorizationResult NativeOidcWindowsRevocationResult;
typedef NativeOidcWindowsAuthorizationResult NativeOidcWindowsRefreshResult;
typedef NativeOidcWindowsAuthorizationResult NativeOidcWindowsEndSessionResult;

enum NativeOidcWindowsAuthorizationStatus {
    NATIVE_OIDC_WINDOWS_AUTHORIZATION_SUCCESS = 0,
    NATIVE_OIDC_WINDOWS_AUTHORIZATION_ERROR = 1,
    NATIVE_OIDC_WINDOWS_AUTHORIZATION_CANCELLED = 2
};

NATIVE_OIDC_WINDOWS_API NativeOidcWindowsCancellationHandle *
native_oidc_windows_cancellation_new(void);

NATIVE_OIDC_WINDOWS_API void
native_oidc_windows_cancellation_cancel(const NativeOidcWindowsCancellationHandle *handle);

NATIVE_OIDC_WINDOWS_API void
native_oidc_windows_cancellation_free(NativeOidcWindowsCancellationHandle *handle);

/*
 * Blocks until authorization completes or is cancelled. Pass a UTF-8 JSON
 * request with either issuer discovery or authorization_endpoint and
 * token_endpoint, plus client_id, redirect_uri, scopes, and optional
 * additional_parameters / additional_token_parameters arrays.
 */
NATIVE_OIDC_WINDOWS_API NativeOidcWindowsAuthorizationResult *
native_oidc_windows_authorize(
    const char *request_json_utf8,
    const NativeOidcWindowsCancellationHandle *cancellation);

/*
 * Blocks while refreshing tokens. Pass UTF-8 JSON with either issuer discovery
 * or authorization_endpoint and token_endpoint, plus client_id and the state
 * object from a previous successful result; with explicit endpoints, pair
 * jwks_uri with issuer to validate a refreshed ID token. The optional
 * additional_parameters array uses unique names. The success value is the
 * updated serialized state, which the host must persist.
 */
NATIVE_OIDC_WINDOWS_API NativeOidcWindowsRefreshResult *
native_oidc_windows_refresh(
    const char *request_json_utf8,
    const NativeOidcWindowsCancellationHandle *cancellation);

/*
 * Blocks while ending the session. Pass UTF-8 JSON with either issuer
 * discovery or authorization_endpoint, token_endpoint, and
 * end_session_endpoint, plus client_id; id_token_hint is optional. With
 * post_logout_redirect_uri, an unported http://127.0.0.1 URI: an available
 * port is chosen, the system browser is opened, and the returned state is
 * validated on a loopback callback. The success value is the validated
 * response, or empty without a post-logout redirect.
 */
NATIVE_OIDC_WINDOWS_API NativeOidcWindowsEndSessionResult *
native_oidc_windows_end_session(
    const char *request_json_utf8,
    const NativeOidcWindowsCancellationHandle *cancellation);

/*
 * Blocks while revoking a token. Pass UTF-8 JSON with either issuer discovery
 * or authorization_endpoint, token_endpoint, and revocation_endpoint, plus
 * client_id, token, and optional token_type_hint.
 */
NATIVE_OIDC_WINDOWS_API NativeOidcWindowsRevocationResult *
native_oidc_windows_revoke(
    const char *request_json_utf8,
    const NativeOidcWindowsCancellationHandle *cancellation);

/* The result accessors also accept refresh and end-session result handles. */
NATIVE_OIDC_WINDOWS_API int32_t
native_oidc_windows_authorization_result_status(
    const NativeOidcWindowsAuthorizationResult *authorization_result);

/* The returned UTF-8 string is owned by authorization_result. */
NATIVE_OIDC_WINDOWS_API const char *
native_oidc_windows_authorization_result_value(
    const NativeOidcWindowsAuthorizationResult *authorization_result);

NATIVE_OIDC_WINDOWS_API void
native_oidc_windows_authorization_result_free(
    NativeOidcWindowsAuthorizationResult *authorization_result);

#ifdef __cplusplus
}
#endif

#endif
