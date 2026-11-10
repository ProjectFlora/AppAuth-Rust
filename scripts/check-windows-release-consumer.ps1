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
    $packageRoot = Get-ChildItem -Path $workDir -Directory | Select-Object -First 1
    if ($null -eq $packageRoot) {
        throw "Windows release archive has no package directory."
    }

    $cppBuild = Join-Path $workDir "cpp-build"
    cmake -S (Join-Path $fixture "cpp") -B $cppBuild "-DAPPAUTH_PACKAGE=$($packageRoot.FullName)"
    cmake --build $cppBuild --config Release
    & (Join-Path $cppBuild "Release/appauth_release_consumer.exe")

    $dotnetBuild = Join-Path $workDir "dotnet-build"
    dotnet build (Join-Path $fixture "dotnet/AppAuthReleaseConsumer.csproj") `
        --configuration Release `
        "--property:AppAuthPackage=$($packageRoot.FullName)" `
        "--output=$dotnetBuild"
    & (Join-Path $dotnetBuild "AppAuthReleaseConsumer.exe")
} finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $workDir
}
