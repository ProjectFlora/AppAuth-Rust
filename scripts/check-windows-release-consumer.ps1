param(
    [Parameter(Mandatory = $true)]
    [string]$Package
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixture = Join-Path $repoRoot "native/consumer-smoke/windows"
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("native-oidc-release-consumer-" + [guid]::NewGuid())

try {
    Expand-Archive -Path $Package -DestinationPath $workDir
    $packageRoot = Get-Item $workDir
    if (-not (Test-Path (Join-Path $packageRoot.FullName "include/native_oidc_windows.h"))) {
        $packageRoot = Get-ChildItem -Path $workDir -Directory | Select-Object -First 1
    }
    if ($null -eq $packageRoot -or -not (Test-Path (Join-Path $packageRoot.FullName "include/native_oidc_windows.h"))) {
        throw "Windows release archive has no package root with include/native_oidc_windows.h."
    }
    foreach ($file in "LICENSE", "THIRD_PARTY_LICENSES.txt") {
        $path = Join-Path $packageRoot.FullName $file
        if (-not (Test-Path $path) -or (Get-Item $path).Length -eq 0) {
            throw "Windows release archive is missing $file."
        }
    }

    $cppBuild = Join-Path $workDir "cpp-build"
    cmake -S (Join-Path $fixture "cpp") -B $cppBuild -A x64 "-DNATIVE_OIDC_PACKAGE=$($packageRoot.FullName)"
    if ($LASTEXITCODE -ne 0) { throw "C++ consumer configure failed: $LASTEXITCODE" }
    cmake --build $cppBuild --config Release
    if ($LASTEXITCODE -ne 0) { throw "C++ consumer build failed: $LASTEXITCODE" }
    & (Join-Path $cppBuild "Release/native_oidc_release_consumer.exe")
    if ($LASTEXITCODE -ne 0) { throw "C++ consumer execution failed: $LASTEXITCODE" }

    $dotnetBuild = Join-Path $workDir "dotnet-build"
    dotnet build (Join-Path $fixture "dotnet/NativeOidcReleaseConsumer.csproj") `
        --configuration Release `
        --runtime win-x64 --self-contained true `
        "--property:NativeOidcPackage=$($packageRoot.FullName)" `
        "--output=$dotnetBuild"
    if ($LASTEXITCODE -ne 0) { throw ".NET consumer build failed: $LASTEXITCODE" }
    & (Join-Path $dotnetBuild "NativeOidcReleaseConsumer.exe")
    if ($LASTEXITCODE -ne 0) { throw ".NET consumer execution failed: $LASTEXITCODE" }
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $workDir
}
