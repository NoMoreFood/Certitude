#
# Copyright (c) Bryan Berns.
# Licensed under GPLv3. See LICENSE.md.
#

#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath("$PSScriptRoot\..")
$temporary = Join-Path $repository ('Build\Temp\PackageSafety-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary -Force

try
{
    # Every invocation must reject overlapping paths before deleting content or reaching build/signing tools.
    foreach ($protected in @('BinaryDirectory', 'OutputDirectory'))
    {
        foreach ($relationship in @('equal', 'parent', 'child'))
        {
            $stage = Join-Path $temporary "$protected-$relationship"
            $target = switch ($relationship)
            {
                'equal' { $stage }
                'parent' { $temporary }
                'child' { Join-Path $stage 'protected' }
            }
            $null = New-Item -ItemType Directory -Path $stage -Force
            $sentinel = Join-Path $stage 'preserve.txt'
            [IO.File]::WriteAllText($sentinel, 'Existing content')
            $binary = Join-Path $temporary 'binaries'
            $output = Join-Path $temporary 'releases'
            if ($protected -eq 'BinaryDirectory') { $binary = $target } else { $output = $target }
            $log = Join-Path $temporary 'result.txt'
            $errors = Join-Path $temporary 'errors.txt'
            $arguments = @('-NoProfile', '-NonInteractive', '-File', "`"$repository\Build\Build.ps1`"",
                '-BinaryDirectory', "`"$binary`"", '-OutputDirectory', "`"$output`"",
                '-StageDirectory', "`"$stage`"", '-TimestampUrl', 'https://invalid.example', '-ProductName', 'Test')
            $process = Start-Process powershell.exe -ArgumentList $arguments -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput $log -RedirectStandardError $errors
            $null = $process.Handle
            if (!$process.WaitForExit(15000))
            {
                $process.Kill()
                throw 'Invalid packaging paths did not fail promptly.'
            }
            if ($process.ExitCode -eq 0 -or (Get-Content -LiteralPath $errors -Raw) -notmatch 'must not overlap')
            { throw "Packaging did not reject $protected $relationship overlap." }
            if (!(Test-Path -LiteralPath $sentinel) -or [IO.File]::ReadAllText($sentinel) -ne 'Existing content')
            { throw "Packaging deleted existing content before rejecting $protected $relationship overlap." }
        }
    }
    Write-Host 'All six packaging overlap checks passed; no build or signing tools were invoked.'
}
finally
{
    # Delete only the unique fixture folder resolved beneath this repository's temporary build directory.
    $boundary = [IO.Path]::GetFullPath((Join-Path $repository 'Build\Temp')) + '\'
    if (!$temporary.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase))
    { throw 'Unexpected package test cleanup location.' }
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
