# Windows desktop adapter

The Windows adapter is a blocking C ABI over the shared Rust authorization
core. It opens authorization in the system browser and receives the callback
on a dynamically allocated IPv4 loopback port. Build the `appauth-rust`
`cdylib` for `x86_64-pc-windows-msvc` and include
[`include/appauth_windows.h`](include/appauth_windows.h) from C or C++.

Call `appauth_windows_authorize` on a worker thread. Its request is a
NUL-terminated UTF-8 JSON object. Use either `issuer` to discover provider
metadata, or explicit `authorization_endpoint` and `token_endpoint` values.
With explicit endpoints, supply both `issuer` and `jwks_uri` to enable OIDC ID
Token validation:

```json
{
  "issuer": "https://issuer.example",
  "client_id": "native-client",
  "redirect_uri": "http://127.0.0.1/oauth/callback",
  "scopes": ["openid", "profile"],
  "additional_parameters": [],
  "additional_token_parameters": []
}
```

Declare the redirect URI with the authorization server. The adapter replaces
the absent port with an available port and registers that complete URI in the
authorization request. `additional_parameters` and
`additional_token_parameters` are optional arrays of `{ "name", "value" }`
objects.

Create a cancellation handle before starting authorization. It can be
cancelled from another thread; keep it alive until the blocking authorization
call returns, then free it. Free the result after copying its value. A
successful result value is the serialized authentication state, which contains
sensitive tokens and must be stored securely. Non-success values are UTF-8
error messages.

## C++ usage

```cpp
#include "appauth_windows.h"
#include <string>
#include <thread>

const char *requestJsonUtf8 = R"({
  "issuer": "https://issuer.example",
  "client_id": "native-client",
  "redirect_uri": "http://127.0.0.1/oauth/callback",
  "scopes": ["openid", "profile"]
})";
auto *cancellation = appauth_windows_cancellation_new();
int resultStatus = APPAUTH_WINDOWS_AUTHORIZATION_ERROR;
std::string resultValue;
std::thread worker([&] {
    auto *result = appauth_windows_authorize(requestJsonUtf8, cancellation);
    resultStatus = appauth_windows_authorization_result_status(result);
    const auto *value = appauth_windows_authorization_result_value(result);
    if (value != nullptr) {
        resultValue = value;
    }
    appauth_windows_authorization_result_free(result);
});
// Call cancellation_cancel from another thread to cancel the operation.
worker.join();
appauth_windows_cancellation_free(cancellation);
```

To cancel while the call is running, invoke
`appauth_windows_cancellation_cancel(cancellation)` from another thread. After
joining, inspect `resultStatus` and `resultValue` on the caller thread.

## .NET interop

The same C ABI can be called from C# or VB.NET using P/Invoke. Declare UTF-8
strings explicitly and use `IntPtr` for the opaque handles. For example, with
C#:

```csharp
[DllImport("appauth_rust.dll", CallingConvention = CallingConvention.Cdecl,
    EntryPoint = "appauth_windows_authorize")]
internal static extern IntPtr Authorize(
    [MarshalAs(UnmanagedType.LPUTF8Str)] string requestJson,
    IntPtr cancellation);
```

[`dotnet/AppAuthWindows.cs`](dotnet/AppAuthWindows.cs) provides an async C#
wrapper that runs the blocking call on a worker and connects a
`CancellationToken` to the native cancellation handle. The wrapper project
targets .NET Standard 2.1. Add the wrapper and `appauth_rust.dll` to a
compatible Windows .NET application:

```csharp
var stateJson = await AppAuthWindows.AuthorizeAsync(requestJson, cancellationToken);
```

VB.NET can call the same C ABI with P/Invoke.

The adapter currently targets the `x86_64-pc-windows-msvc` Rust target. The
supported Windows client versions are those supported by Microsoft at each
release; review the matrix and validation targets for every release.
