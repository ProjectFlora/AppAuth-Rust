using System;
using System.Runtime.InteropServices;
using ProjectFlora.AppAuthRust;

if (RuntimeInformation.ProcessArchitecture != Architecture.X64)
{
    throw new InvalidOperationException("The Windows release consumer must run as x64.");
}
Console.WriteLine($"Windows consumer process: {RuntimeInformation.ProcessArchitecture}; OS: {RuntimeInformation.OSArchitecture}");

try
{
    await AppAuthWindows.AuthorizeAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
}

try
{
    await AppAuthWindows.RevokeAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
}

try
{
    await AppAuthWindows.RefreshAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
}

try
{
    await AppAuthWindows.EndSessionAsync("{");
    return 1;
}
catch (InvalidOperationException)
{
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
    await AppAuthWindows.RefreshAsync(reservedRefresh);
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
    await AppAuthWindows.RefreshAsync(duplicateRefresh);
    return 1;
}
catch (InvalidOperationException error)
{
    if (!error.Message.Contains("unique", StringComparison.Ordinal)) return 1;
}
return 0;
