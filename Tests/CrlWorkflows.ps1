#
# Copyright (c) Bryan Berns.
# Licensed under GPLv3. See LICENSE.md.
#

#requires -Version 5.1
param([string] $MSBuild = "${env:ProgramFiles}\Microsoft Visual Studio\18\Enterprise\MSBuild\Current\Bin\MSBuild.exe")

$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath("$PSScriptRoot\..")
$output = Join-Path $repository 'Code\obj\CrlWorkflowChecks'
$null = New-Item -ItemType Directory -Path $output -Force
$targets = Join-Path $output 'Checks.targets'
$source = [Security.SecurityElement]::Escape((Join-Path $PSScriptRoot 'CrlWorkflows.cs'))
[IO.File]::WriteAllText($targets, "<Project><ItemGroup><Compile Include=`"$source`" /></ItemGroup></Project>")

# Compile the real application sources with an offline test entry point in an isolated output directory.
& $MSBuild "$repository\Code\Certitude.csproj" /nologo /verbosity:minimal /m `
    /p:Configuration=Debug /p:Platform=x64 /p:StartupObject=Certitude.WorkflowChecks `
    "/p:CustomAfterMicrosoftCommonTargets=$targets" "/p:OutputPath=$output\bin\" `
    "/p:IntermediateOutputPath=$output\obj\"
if ($LASTEXITCODE -ne 0) { throw 'Workflow check build failed.' }
& "$output\bin\Certitude.exe" $repository | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Workflow checks failed.' }
