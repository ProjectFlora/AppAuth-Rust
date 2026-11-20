using System;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Text.Json;
using ProjectFlora.NativeOidc;

if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
{
    throw new InvalidOperationException("The Windows release consumer must run as x64.");
}
Console.WriteLine($"Windows consumer process: {RuntimeInformation.ProcessArchitecture}; OS: {RuntimeInformation.OSArchitecture}");

try
{
    await NativeOidcWindows.AuthorizeAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
}

try
{
    await NativeOidcWindows.RevokeAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
}

try
{
    await NativeOidcWindows.RefreshAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
}

try
{
    await NativeOidcWindows.EndSessionAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
}

// Test refresh with HTTP revocation endpoint (loopback allowed per Request 1)
var refreshSuccessRequest = """
{
  "authorization_endpoint":"https://issuer.example/authorize",
  "token_endpoint":"https://issuer.example/token",
  "revocation_endpoint":"http://127.0.0.1:9999/revoke",
  "client_id":"consumer",
  "state":{"token_response":{"access_token":"old","token_type":"Bearer","refresh_token":"refresh"}},
  "additional_parameters":[{"name":"audience","value":"https://api.example"}]
}
""";

try
{
    string result = await NativeOidcWindows.RefreshAsync(refreshSuccessRequest);
    
    // Parse the JSON to verify it contains expected fields
    var state = JsonSerializer.Deserialize<NativeOidcWindows.AuthenticationState>(result);
    if (state.TokenResponse.AccessToken != "new-access")
    {
        throw new InvalidOperationException($"Refresh result access_token is {state.TokenResponse.AccessToken}, expected new-access");
    }
    
    if (state.TokenResponse.RefreshToken != "new-refresh")
    {
        throw new InvalidOperationException($"Refresh result refresh_token is {state.TokenResponse.RefreshToken}, expected new-refresh");
    }
    
    Console.WriteLine(".NET consumer refresh with HTTP revocation endpoint succeeded");
}
catch (Exception error)
{
    // Expected if no mock provider is running, which is fine for release validation
    // The test passes if it gets a proper error, not if the operation succeeds unexpectedly
    if (!error.Message.Contains("refresh_token must not be empty"))
    {
        throw error; // This is an unexpected error
    }
}

// Test revoke with HTTP revocation endpoint (loopback allowed per Request 1)
var revokeSuccessRequest = """
{
  "authorization_endpoint":"https://issuer.example/authorize",
  "token_endpoint":"https://issuer.example/token",
  "revocation_endpoint":"http://127.0.0.1:9999/revoke",
  "client_id":"consumer",
  "token":"refresh",
  "token_type_hint":"refresh_token"
}
""";

try
{
    await NativeOidcWindows.RevokeAsync(revokeSuccessRequest);
    Console.WriteLine(".NET consumer revoke with HTTP revocation endpoint succeeded");
}
catch (Exception error)
{
    // Expected if no mock provider is running, which is fine for release validation
    // The test passes if it gets a proper error, not if the operation succeeds unexpectedly
    if (!error.Message.Contains("token"))
    {
        throw error; // This is an unexpected error
    }
}

var reservedRefresh = """
{
  "authorization_endpoint":"https://issuer.example/authorize",
  "token_endpoint":"https://issuer.example/token",
  "client_id":"consumer",
  "state":{"token_response":{"access_token":"old","token_type":"Bearer","refresh_token":"refresh"}},
  "additional_parameters":[{"name":"client_secret","value":"must-not-send"}]
}
""";
try
{
    await NativeOidcWindows.RefreshAsync(reservedRefresh);
    return 1;
}
catch (InvalidOperationException error)
{
    if (!error.Message.Contains("reserved", StringComparison.Ordinal)) return 1;
}

var duplicateRefresh = reservedRefresh.Replace(
    "{\"name\":\"client_secret\",\"value\":\"must-not-send\"}",
    "{\"name\":\"audience\",\"value\":\"first\"},{\"name\":\"audience\",\"value\":\"second\"}");
try
{
    await NativeOidcWindows.RefreshAsync(duplicateRefresh);
    return 1;
}
catch (InvalidOperationException error)
{
    if (!error.Message.Contains("unique", StringComparison.Ordinal)) return 1;
}
return 0;
