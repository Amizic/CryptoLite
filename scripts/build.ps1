<#
CryptoLite build helper.
Builds the project with the local, in-workspace toolchain (tools\mingw64) and
the local OpenSSL installation (tools\openssl-install).

Usage:
    pwsh -ExecutionPolicy Bypass -File scripts/build.ps1 -Linkage static
    pwsh -ExecutionPolicy Bypass -File scripts/build.ps1 -Linkage shared -Clean
    pwsh -ExecutionPolicy Bypass -File scripts/build.ps1 -Linkage shared -Test
#>
param(
    [ValidateSet("shared", "static")] [string]$Linkage = "static",
    [switch]$Clean,
    [switch]$Test
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot   # .../CryptoLite
$toolsRoot   = Join-Path $projectRoot "..\tools"  # .../tools

if (-not (Test-Path $toolsRoot)) {
    throw "Toolchain not found: $toolsRoot"
}

# Local toolchain first, so no system-wide installation is ever needed.
$env:Path = @(
    (Join-Path $toolsRoot "mingw64\bin"),
    (Join-Path $toolsRoot "vcpkg"),
    $env:Path
) -join ";"

# Keep all temporary files inside the workspace as well.
$tmpDir = Join-Path $projectRoot "..\.tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$env:TMP = $tmpDir
$env:TEMP = $tmpDir

foreach ($tool in "g++", "cmake", "mingw32-make") {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required tool not found on PATH: $tool"
    }
}

$buildDir = Join-Path $projectRoot "build-$Linkage"
if ($Clean -and (Test-Path $buildDir)) {
    Remove-Item -Recurse -Force $buildDir
}

$shared = if ($Linkage -eq "shared") { "ON" } else { "OFF" }

$opensslInstall = Join-Path $toolsRoot "openssl-install"
if (-not (Test-Path $opensslInstall)) {
    throw "Local OpenSSL installation not found: $opensslInstall"
}

$cmakeArgs = @(
    "-S", $projectRoot,
    "-B", $buildDir,
    "-G", "MinGW Makefiles",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DBUILD_SHARED_LIBS=$shared",
    "-DOPENSSL_ROOT_DIR=$opensslInstall",
    # No try-compile executables need to run during configure.
    "-DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY"
)

& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) { throw "cmake configure failed (exit $LASTEXITCODE)" }

& cmake --build $buildDir
if ($LASTEXITCODE -ne 0) { throw "cmake build failed (exit $LASTEXITCODE)" }

if ($Test) {
    Write-Host ""
    Write-Host "Running the CryptoLite test suite (ctest)..."
    & ctest --test-dir $buildDir --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw "ctest failed (exit $LASTEXITCODE)" }
}

Write-Host ""
Write-Host "Build finished: $(Join-Path $buildDir 'CryptoLite_tests.exe')"
