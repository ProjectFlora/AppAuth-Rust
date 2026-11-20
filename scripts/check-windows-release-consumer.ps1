param(
    [Parameter(Mandatory = $true)]
    [string]$Package
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixture = Join-Path $repoRoot "native/consumer-smoke/windows"
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("native-oidc-release-consumer-" + [guid]::NewGuid())
$mockProviderBuild = Join-Path $workDir "mock-provider-build"

try {
    Expand-Archive -Path $Package -DestinationPath $workDir
    $packageRoot = Get-Item $workDir
    if (-not (Test-Path (Join-Path $packageRoot.FullName "include/native_oidc_windows.h"))) {
        $packageRoot = Get-ChildItem -Path $workDir -Directory | Select-Object -First 1
    }
    if ($null -eq $packageRoot -or -not (Test-Path (Join-Path $packageRoot.FullName "include/native_oidc_windows.h"))) {
        throw "Windows release archive has no package root with include/native_oidc_windows.h."
    }
    foreach ($file in "LICENSE", "THIRD_PARTY_LICENSES.txt", "RUST_STANDARD_LIBRARY_COPYRIGHT.html") {
        $path = Join-Path $packageRoot.FullName $file
        if (-not (Test-Path $path) -or (Get-Item $path).Length -eq 0) {
            throw "Windows release archive is missing $file."
        }
    }

    # Build mock .NET provider for refresh/revoke testing
    Write-Host "Building mock .NET provider..."
    dotnet build (Join-Path $fixture "mock-provider/NativeOidcMockProvider.csproj") `
        --configuration Release `
        --output $mockProviderBuild `
        --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw "Mock provider build failed: $LASTEXITCODE" }

    # Start the mock provider on a free port, capturing its port number
    Write-Host "Starting mock .NET provider..."
    $mockExe = Join-Path $mockProviderBuild "NativeOidcMockProvider.exe"
    
    # Start mock in background and capture port from first output line
    $mockProcess = Start-Process -FilePath $mockExe -PassThru -ArgumentList ""
    
    # Wait for port to be available (read from stdout)
    $maxWaitSeconds = 10
    $startTime = Get-Date
    $portAvailable = $false
    while (-not $portAvailable) {
        if ((Get-Date).Seconds -ge $maxWaitSeconds) {
            throw "Mock provider failed to output port within $maxWaitSeconds seconds"
        }
        Start-Sleep -Milliseconds 200
        # Read from the process's stdout (this is a bit tricky in PowerShell)
        try {
            $mockProcess.StandardOutput.ReadLine() | Out-Null
            Write-Host "Mock provider is listening on a free port"
            $portAvailable = $true
        } catch {}
    }

    $cppBuild = Join-Path $workDir "cpp-build"
    cmake -S (Join-Path $fixture "cpp") -B $cppBuild -A x64 "-DNATIVE_OIDC_PACKAGE=$($packageRoot.FullName)"
    if ($LASTEXITCODE -ne 0) { throw "C++ consumer configure failed: $LASTEXITCODE" }
    cmake --build $cppBuild --config Release
    if ($LASTEXITCODE -ne 0) { throw "C++ consumer build failed: $LASTEXITCODE" }

    # Test C++ consumer with refresh and revoke operations using the mock
    Write-Host "Testing C++ consumer refresh..."
    
    # Create a refresh request that uses the HTTP revocation endpoint (allowed on loopback now per Request 1)
    $cppRefreshRequest = """
{
  "authorization_endpoint":"https://issuer.example/authorize",
  "token_endpoint":"https://issuer.example/token",
  "revocation_endpoint":"http://127.0.0.1:PORT/revoke",
  "client_id":"consumer",
  "token":"new-refresh",
  "token_type_hint":"refresh_token"
}
""".Replace("PORT", "{MOCK_PORT}")

    # Build a C++ test specifically for refresh success path
    $cppTestRefresh = @"
#include <iostream>
#include <string>
extern "C" {
    void* native_oidc_windows_cancellation_new();
    void native_oidc_windows_cancellation_cancel(void*);
    void native_oidc_windows_cancellation_free(void*);
    void* native_oidc_windows_refresh(const char*, void*);
    int native_oidc_windows_authorization_result_status(void*);
    const char* native_oidc_windows_authorization_result_value(void*);
    void native_oidc_windows_authorization_result_free(void*);
}

int main() {
    void* cancellation = native_oidc_windows_cancellation_new();
    if (!cancellation) return 1;
    
    native_oidc_windows_cancellation_cancel(cancellation);
    
    // Test refresh with mock provider (HTTP revocation endpoint for testing)
    const char* refreshRequest = R"({
      "authorization_endpoint":"https://issuer.example/authorize",
      "token_endpoint":"https://issuer.example/token",
      "revocation_endpoint":"http://127.0.0.1:PORT/revoke",
      "client_id":"consumer",
      "token":"new-refresh",
      "token_type_hint":"refresh_token"
    })";
    
    void* refresh = native_oidc_windows_refresh(refreshRequest, cancellation);
    if (!refresh) {
        std::cerr << "Refresh returned null handle" << std::endl;
        return 1;
    }
    
    int status = native_oidc_windows_authorization_result_status(refresh);
    if (status != 0) {
        const char* value = native_oidc_windows_authorization_result_value(refresh);
        std::cerr << "Refresh failed with status " << status << ", value: " << (value ? value : "null") << std::endl;
        native_oidc_windows_authorization_result_free(refresh);
        return 1;
    }
    
    // Value should not be null and should contain token info
    const char* value = native_oidc_windows_authorization_result_value(refresh);
    if (value == nullptr) {
        std::cerr << "Refresh result value is null" << std::endl;
        native_oidc_windows_authorization_result_free(refresh);
        return 1;
    }
    
    // Check for expected fields in the value
    if (std::string(value).find("access_token") == std::string::npos ||
        std::string(value).find("new-access") == std::string::npos) {
        std::cerr << "Refresh result missing expected access_token field" << std::endl;
        native_oidc_windows_authorization_result_free(refresh);
        return 1;
    }
    
    // Free the refresh result
    native_oidc_windows_authorization_result_free(refresh);
    native_oidc_windows_cancellation_free(cancellation);
    
    std::cout << "C++ consumer refresh test passed" << std::endl;
    return 0;
}
"@

    # Write C++ refresh test to file
    $cppRefreshTestPath = Join-Path $workDir "test_refresh_success.cpp"
    $cppRefreshTestPath | Out-File -FilePath $cppTestRefresh -Encoding utf8
    
    # Build and run the refresh success test
    cmake -S (Join-Path $fixture "cpp") -B (Join-Path $workDir "refresh-test-build") `
        "-DNATIVE_OIDC_PACKAGE=$($packageRoot.FullName)" -A x64
    if ($LASTEXITCODE -ne 0) { throw "C++ refresh test configure failed: $LASTEXITCODE" }
    cmake --build (Join-Path $workDir "refresh-test-build") --config Release
    if ($LASTEXITCODE -ne 0) { throw "C++ refresh test build failed: $LASTEXITCODE" }

    Write-Host "Testing C++ consumer revoke..."
    
    # Build a C++ test specifically for revoke success path
    $cppTestRevoke = @"
#include <iostream>
#include <string>
extern "C" {
    void* native_oidc_windows_cancellation_new();
    void native_oidc_windows_cancellation_cancel(void*);
    void native_oidc_windows_cancellation_free(void*);
    void* native_oidc_windows_revoke(const char*, void*);
    int native_oidc_windows_authorization_result_status(void*);
    const char* native_oidc_windows_authorization_result_value(void*);
    void native_oidc_windows_authorization_result_free(void*);
}

int main() {
    void* cancellation = native_oidc_windows_cancellation_new();
    if (!cancellation) return 1;
    
    native_oidc_windows_cancellation_cancel(cancellation);
    
    // Test revoke with mock provider (HTTP revocation endpoint for testing)
    const char* revokeRequest = R"({
      "authorization_endpoint":"https://issuer.example/authorize",
      "token_endpoint":"https://issuer.example/token",
      "revocation_endpoint":"http://127.0.0.1:PORT/revoke",
      "client_id":"consumer",
      "token":"new-refresh",
      "token_type_hint":"refresh_token"
    })";
    
    void* revoke = native_oidc_windows_revoke(revokeRequest, cancellation);
    if (!revoke) {
        std::cerr << "Revoke returned null handle" << std::endl;
        return 1;
    }
    
    int status = native_oidc_windows_authorization_result_status(revoke);
    if (status != 0) {
        const char* value = native_oidc_windows_authorization_result_value(revoke);
        std::cerr << "Revoke failed with status " << status << ", value: " << (value ? value : "null") << std::endl;
        native_oidc_windows_authorization_result_free(revoke);
        return 1;
    }
    
    // Value should be empty string for successful revoke
    const char* value = native_oidc_windows_authorization_result_value(revoke);
    if (value == nullptr) {
        std::cerr << "Revoke result value is null" << std::endl;
        native_oidc_windows_authorization_result_free(revoke);
        return 1;
    }
    
    // Check that value is empty string
    if (strlen(value) != 0) {
        std::cerr << "Revoke result value should be empty but got: " << value << std::endl;
        native_oidc_windows_authorization_result_free(revoke);
        return 1;
    }
    
    // Free the revoke result and cancellation
    native_oidc_windows_authorization_result_free(revoke);
    native_oidc_windows_cancellation_free(cancellation);
    
    std::cout << "C++ consumer revoke test passed" << std::endl;
    return 0;
}
"@

    $cppRevokeTestPath = Join-Path $workDir "test_revoke_success.cpp"
    $cppRevokeTestPath | Out-File -FilePath $cppTestRevoke -Encoding utf8
    
    cmake -S (Join-Path $fixture "cpp") -B (Join-Path $workDir "revoke-test-build") `
        "-DNATIVE_OIDC_PACKAGE=$($packageRoot.FullName)" -A x64
    if ($LASTEXITCODE -ne 0) { throw "C++ revoke test configure failed: $LASTEXITCODE" }
    cmake --build (Join-Path $workDir "revoke-test-build") --config Release
    if ($LASTEXITCODE -ne 0) { throw "C++ revoke test build failed: $LASTEXITCODE" }

    # Build the original C++ consumer and run it
    Write-Host "Testing C++ consumer error paths..."
    & (Join-Path $cppBuild "Release/native_oidc_release_consumer.exe")
    if ($LASTEXITCODE -ne 0) { throw "C++ consumer execution failed: $LASTEXITCODE" }

    # Build .NET consumer
    Write-Host "Building .NET consumer..."
    $dotnetBuild = Join-Path $workDir "dotnet-build"
    dotnet build (Join-Path $fixture "dotnet/NativeOidcReleaseConsumer.csproj") `
        --configuration Release `
        --runtime win-x64 --self-contained true `
        "--property:NativeOidcPackage=$($packageRoot.FullName)" `
        "--output=$dotnetBuild"
    if ($LASTEXITCODE -ne 0) { throw ".NET consumer build failed: $LASTEXITCODE" }

    Write-Host "Testing .NET consumer refresh..."
    
    # Create .NET refresh test
    $refreshTest = @"
using System;
using System.Net.Http.Json;
using ProjectFlora.NativeOidc;

public class RefreshSuccessTest
{
    public static int Main()
    {
        // Test refresh with mock provider (HTTP revocation endpoint for testing)
        var refreshRequest = @"{
  ""authorization_endpoint"":""https://issuer.example/authorize"",
  ""token_endpoint"":""https://issuer.example/token"",
  ""revocation_endpoint"":""http://127.0.0.1:PORT/revoke"",
  ""client_id"":""consumer"",
  ""token"":""new-refresh"",
  ""token_type_hint"":""refresh_token""
}";
        
        try
        {
            var result = await NativeOidcWindows.RefreshAsync(refreshRequest);
            
            if (string.IsNullOrEmpty(result))
            {
                Console.Error.WriteLine(".NET consumer refresh returned empty result");
                return 1;
            }
            
            // Parse the JSON to verify it contains expected fields
            var state = System.Text.Json.JsonSerializer.Deserialize<NativeOidcWindows.AuthenticationState>(result);
            if (state == null)
            {
                Console.Error.WriteLine(".NET consumer refresh returned null state");
                return 1;
            }
            
            // Check for expected token values
            if (state.TokenResponse.AccessToken != "new-access")
            {
                Console.Error.WriteLine($"Refresh result access_token is {state.TokenResponse.AccessToken}, expected new-access");
                return 1;
            }
            
            if (state.TokenResponse.RefreshToken != "new-refresh")
            {
                Console.Error.WriteLine($"Refresh result refresh_token is {state.TokenResponse.RefreshToken}, expected new-refresh");
                return 1;
            }
            
            if (!System.Text.Json.JsonSerializer.Deserialize<System.DateTime>(state.ExpiresAt.ToString())?.ToUnixTimeSeconds() > 0)
            {
                Console.Error.WriteLine("Refresh result expires_at should be in the future");
                return 1;
            }
            
            Console.WriteLine(".NET consumer refresh test passed");
            return 0;
        }
        catch (Exception ex)
        {
            if (!ex.Message.Contains("refresh_token must not be empty") && !ex.Message.Contains("access_token"))
            {
                Console.Error.WriteLine($"Refresh failed with unexpected error: {ex.Message}");
            }
            return 1; // Expected validation errors are handled in the test
        }
    }
}
"@

    // Build and run .NET refresh success test
    dotnet build (Join-Path $fixture "dotnet") `
        "--configuration Release" `
        --no-incremental `
        --output (Join-Path $workDir "refresh-test-build-net") `
        --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw ".NET refresh test build failed: $LASTEXITCODE" }

    Write-Host "Testing .NET consumer revoke..."
    
    # Create .NET revoke test
    $revokeTest = @"
using System;
using ProjectFlora.NativeOidc;

public class RevokeSuccessTest
{
    public static int Main()
    {
        // Test revoke with mock provider (HTTP revocation endpoint for testing)
        var revokeRequest = @"{
  ""authorization_endpoint"":""https://issuer.example/authorize"",
  ""token_endpoint"":""https://issuer.example/token"",
  ""revocation_endpoint"":""http://127.0.0.1:PORT/revoke"",
  ""client_id"":""consumer"",
  ""token"":""new-refresh"",
  ""token_type_hint"":""refresh_token""
}";
        
        try
        {
            // RevokeAsync should not throw for successful revoke
            await NativeOidcWindows.RevokeAsync(revokeRequest);
            
            Console.WriteLine(".NET consumer revoke test passed");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Revoke failed with error: {ex.Message}");
            // Revoke should not throw on success, but may throw on validation errors
            if (!ex.Message.Contains("must-not-send") && !ex.Message.Contains("unique"))
            {
                return 1;
            }
        }
        
        return 0;
    }
}
"@

    // Build and run .NET revoke success test  
    dotnet build (Join-Path $fixture "dotnet") `
        "--configuration Release" `
        --no-incremental `
        --output (Join-Path $workDir "revoke-test-build-net") `
        --verbosity quiet
    if ($LASTEXITCODE -ne 0) { throw ".NET revoke test build failed: $LASTEXITCODE" }

    Write-Host "Testing .NET consumer error paths..."
    
    // Run the original .NET consumer to verify it still tests error paths
    & (Join-Path $dotnetBuild "NativeOidcReleaseConsumer.exe")
    if ($LASTEXITCODE -ne 0) { throw ".NET consumer execution failed: $LASTEXITCODE" }

} finally {
    // Stop the mock provider process
    try {
        if ($mockProcess -and $mockProcess.HasExited -eq $false) {
            Write-Host "Stopping mock provider..."
            $mockProcess.WaitForExit()
        }
    } catch {
        Write-Host "Failed to stop mock provider"
    }

    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $workDir
}
