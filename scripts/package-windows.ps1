# Builds the Windows release library and packages it as <Package>.zip, with
# the header, the .NET wrapper, LICENSE and the license notices at the zip
# root. Run scripts/generate-third-party-licenses.sh first (from bash, with
# the same Rust toolchain); the package takes its notices from
# target/licenses/.
param(
    [Parameter(Mandatory = $true)]
    [string]$Package
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $repoRoot

try {
    $notices = "target/licenses/THIRD_PARTY_LICENSES.txt", "target/licenses/RUST_STANDARD_LIBRARY_COPYRIGHT.html"
    foreach ($notice in $notices) {
        if (-not (Test-Path $notice)) {
            throw "$notice is missing; run scripts/generate-third-party-licenses.sh first."
        }
    }

    cargo build --locked --release --lib --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw "Windows release build failed: $LASTEXITCODE" }

    New-Item -ItemType Directory -Force "$Package/include" | Out-Null
    New-Item -ItemType Directory -Force "$Package/dotnet" | Out-Null
    $target = "target/x86_64-pc-windows-msvc/release"
    Copy-Item "$target/native_oidc.dll" $Package
    Copy-Item "$target/native_oidc.dll.lib" $Package
    Copy-Item "native/windows/include/native_oidc_windows.h" "$Package/include"
    Copy-Item "native/windows/dotnet/NativeOidcWindows.cs" "$Package/dotnet"
    Copy-Item "native/windows/dotnet/NativeOidcWindows.csproj" "$Package/dotnet"
    Copy-Item "native/windows/README.md" $Package
    Copy-Item "LICENSE" $Package
    Copy-Item $notices $Package
    Compress-Archive -Path "$Package/*" -DestinationPath "$Package.zip" -Force
} finally {
    Pop-Location
}
