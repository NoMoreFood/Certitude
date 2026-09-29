#
# Copyright (c) Bryan Berns.
# Licensed under GPLv3. See LICENSE.md.
#

#requires -Version 5.1
param(
    [Parameter(Mandatory = $true)][string] $BinaryDirectory,
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [Parameter(Mandatory = $true)][string] $StageDirectory,
    [Parameter(Mandatory = $true)][string] $TimestampUrl,
    [Parameter(Mandatory = $true)][string] $ProductName
)

# Fail packaging promptly when a PowerShell operation or external tool fails.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Tool([string] $Path, [string[]] $Arguments)
{
    # Propagate external build and signing failures into the packaging error path.
    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Path failed with exit code $LASTEXITCODE." }
}

try
{
    # Resolve repository, build-output, and staging locations before packaging.
    $repositoryDirectory = [IO.Path]::GetFullPath("$PSScriptRoot\..")
    $projectDirectory = Join-Path $repositoryDirectory 'Code'
    $BinaryDirectory = [IO.Path]::GetFullPath($BinaryDirectory)
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    $StageDirectory = [IO.Path]::GetFullPath($StageDirectory)
    $executable = Join-Path $BinaryDirectory 'Certitude.exe'

    # Derive the portable package name from the declared release version.
    $assemblyInfo = Get-Content -LiteralPath "$projectDirectory\App.xaml.cs" -Raw -Encoding UTF8
    $versionMatch = [regex]::Match($assemblyInfo, 'AssemblyFileVersion\("(\d+\.\d+\.\d+\.\d+)"\)')
    if (!$versionMatch.Success) { throw 'AssemblyFileVersion must contain a four-part release version.' }
    $releaseVersion = [version] $versionMatch.Groups[1].Value
    $version = if ($releaseVersion.Revision -eq 0) { $releaseVersion.ToString(3) } else { $releaseVersion.ToString() }
    $packageName = "Certitude-$version-x64.zip"
    $packagePath = Join-Path $OutputDirectory $packageName

    # Clear prior staging content and the same-version package before rebuilding.
    if (Test-Path -LiteralPath $StageDirectory) { Remove-Item -LiteralPath $StageDirectory -Recurse -Force }
    if (Test-Path -LiteralPath $packagePath) { Remove-Item -LiteralPath $packagePath -Force }

    # Locate MSBuild through Visual Studio discovery, falling back to the command path.
    $msbuild = $null
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf)
    {
        $msbuild = Invoke-Tool $vswhere @('-latest', '-products', '*', '-requires', 'Microsoft.Component.MSBuild',
            '-find', 'MSBuild\**\Bin\MSBuild.exe') | Select-Object -First 1
    }
    if (!$msbuild)
    {
        $command = Get-Command MSBuild.exe -CommandType Application -ErrorAction SilentlyContinue
        if ($command) { $msbuild = $command.Source }
    }
    # Explain the required build tools when no usable MSBuild installation is found.
    if (!$msbuild)
    {
        throw ('Install Visual Studio 2026 or C# 14 Build Tools with .NET desktop tools ' +
            'and the .NET 4.7.2 targeting pack.')
    }

    # Choose the newest SDK signing tool for the host processor architecture.
    $sdkRoot = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' `
        -Name KitsRoot10 -ErrorAction SilentlyContinue
    if (!$sdkRoot) { $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10' }
    $hostArchitecture = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $hostArchitecture = $env:PROCESSOR_ARCHITEW6432 }
    $toolArchitecture = switch ($hostArchitecture) { 'ARM64' { 'arm64' } 'AMD64' { 'x64' } default { 'x86' } }
    $signTool = Get-ChildItem -LiteralPath (Join-Path $sdkRoot 'bin') -Directory |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version] $_.Name } -Descending |
        ForEach-Object { Join-Path $_.FullName "$toolArchitecture\signtool.exe" } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (!$signTool) { throw 'Install the Windows SDK signing tools before packaging.' }

    # Set timestamped SHA-256 signing options and prefer the current user signing store.
    $signOptions = @('sign', '/a', '/fd', 'sha256', '/tr', $TimestampUrl, '/td', 'sha256', '/d', $ProductName)
    $signingStore = $null
    $now = Get-Date
    foreach ($location in @('CurrentUser', 'LocalMachine'))
    {
        $certificateStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $location)
        try
        {
            # Find a currently valid code-signing certificate with an associated private key.
            $certificateStore.Open('ReadOnly, OpenExistingOnly')
            $certificates = @($certificateStore.Certificates.Find('FindByApplicationPolicy',
                '1.3.6.1.5.5.7.3.3', $false) | Where-Object {
                $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now
            })
            if ($certificates.Count -eq 0) { continue }
            $signingStore = $location
            break
        }
        finally
        {
            $certificateStore.Dispose()
        }
    }
    # Require an available signer and select the machine store when necessary.
    if (!$signingStore)
    {
        throw 'No valid code-signing certificate with a private key was found in either Personal store.'
    }
    if ($signingStore -eq 'LocalMachine') { $signOptions += '/sm' }

    # Rebuild Release x64 and require the output version to match the package version.
    Write-Host "Rebuilding Certitude $version in Release x64 mode with $msbuild."
    Invoke-Tool $msbuild @("$projectDirectory\Certitude.sln", '/nologo', '/verbosity:minimal', '/m', '/t:Rebuild',
        '/p:Configuration=Release', '/p:Platform=x64', "/p:OutputPath=$BinaryDirectory/", "/p:OutDir=$BinaryDirectory/")
    if (!(Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'MSBuild did not produce Certitude.exe.' }
    $binaryVersion = [version] (Get-Item -LiteralPath $executable).VersionInfo.FileVersion
    if ($binaryVersion -ne $releaseVersion) { throw 'The built executable does not match the release version.' }

    # Stage the portable executable, configuration, and project documentation.
    $portableDirectory = Join-Path $StageDirectory 'Portable'
    New-Item -ItemType Directory -Path $portableDirectory | Out-Null
    Copy-Item -LiteralPath $executable, "$executable.config", "$repositoryDirectory\README.md", `
        "$repositoryDirectory\LICENSE.md" -Destination $portableDirectory

    # Sign the staged executable and verify its Authenticode signature and timestamp.
    $signedExecutable = Join-Path $portableDirectory 'Certitude.exe'
    Write-Host "Signing Certitude $version; SignTool: $signTool; certificate store: $signingStore"
    Invoke-Tool $signTool ($signOptions + $signedExecutable)
    Invoke-Tool $signTool @('verify', '/pa', '/tw', $signedExecutable)

    # Create the portable archive and publish it in the release output directory.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stagedPackage = Join-Path $StageDirectory $packageName
    [IO.Compression.ZipFile]::CreateFromDirectory($portableDirectory, $stagedPackage,
        [IO.Compression.CompressionLevel]::Optimal, $false)
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    [IO.File]::Copy($stagedPackage, $packagePath, $false)
    Write-Host "Signed portable release ready: $packagePath"
}
catch
{
    # Report build or signing failure and return a failing exit code to the batch launcher.
    Write-Error "Build and signing failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
