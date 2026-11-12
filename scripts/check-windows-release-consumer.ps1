param(
    [Parameter(Mandatory = $true)]
    [string]$Package
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$fixture = Join-Path $repoRoot "native/consumer-smoke/windows"
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("appauth-rust-release-consumer-" + [guid]::NewGuid())

try {
    Expand-Archive -Path $Package -DestinationPath $workDir
    $packageRoot = Get-Item $workDir
    if (-not (Test-Path (Join-Path $packageRoot.FullName "include/appauth_windows.h"))) {
        $packageRoot = Get-ChildItem -Path $workDir -Directory | Select-Object -First 1
    }
    if ($null -eq $packageRoot -or -not (Test-Path (Join-Path $packageRoot.FullName "include/appauth_windows.h"))) {
        throw "Windows release archive has no package root with include/appauth_windows.h."
    }

    $cppBuild = Join-Path $workDir "cpp-build"
    cmake -S (Join-Path $fixture "cpp") -B $cppBuild "-DAPPAUTH_PACKAGE=$($packageRoot.FullName)"
    if ($LASTEXITCODE -ne 0) { throw "C++ consumer configure failed: $LASTEXITCODE" }
    cmake --build $cppBuild --config Release
    if ($LASTEXITCODE -ne 0) { throw "C++ consumer build failed: $LASTEXITCODE" }
    & (Join-Path $cppBuild "Release/appauth_release_consumer.exe")
    if ($LASTEXITCODE -ne 0) { throw "C++ consumer execution failed: $LASTEXITCODE" }

    $dotnetBuild = Join-Path $workDir "dotnet-build"
    dotnet build (Join-Path $fixture "dotnet/AppAuthReleaseConsumer.csproj") `
        --configuration Release `
        "--property:AppAuthPackage=$($packageRoot.FullName)" `
        "--output=$dotnetBuild"
    if ($LASTEXITCODE -ne 0) { throw ".NET consumer build failed: $LASTEXITCODE" }
    & (Join-Path $dotnetBuild "AppAuthReleaseConsumer.exe")
    if ($LASTEXITCODE -ne 0) { throw ".NET consumer execution failed: $LASTEXITCODE" }
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $workDir
}
