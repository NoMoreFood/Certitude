#
# Copyright (c) Bryan Berns.
# Licensed under GPLv3. See LICENSE.md.
#

#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$repository = [IO.Path]::GetFullPath("$PSScriptRoot\..")
$temporary = Join-Path $repository ('Build\Temp\PackageSafety-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temporary -Force
$links = [Collections.Generic.List[string]]::new()

try
{
    # Every invocation must reject unsafe paths before deleting content or reaching build/signing tools.
    foreach ($protected in @('BinaryDirectory', 'OutputDirectory'))
    {
        foreach ($relationship in @('equal', 'parent', 'child', 'junction', 'junction-parent'))
        {
            $stage = Join-Path $temporary "$protected-$relationship"
            $target = switch ($relationship)
            {
                'equal' { $stage }
                'parent' { $temporary }
                'child' { Join-Path $stage 'protected' }
                default { Join-Path $temporary "$protected-$relationship-target" }
            }
            $expected = 'must not overlap'
            if ($relationship.StartsWith('junction'))
            {
                # Exercise both a linked staging folder and an ordinary child reached through a linked parent.
                $null = New-Item -ItemType Directory -Path $target
                $null = New-Item -ItemType Junction -Path $stage -Target $target
                $links.Add($stage)
                $expected = 'must not traverse'
                if ($relationship -eq 'junction-parent')
                {
                    $stage = Join-Path $stage 'Stage'
                    $target = Join-Path $target 'Stage'
                }
            }
            if (!(Test-Path -LiteralPath $stage)) { $null = New-Item -ItemType Directory -Path $stage }
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
            if ($process.ExitCode -eq 0 -or (Get-Content -LiteralPath $errors -Raw) -notmatch $expected)
            { throw "Packaging did not reject $protected $relationship." }
            if (!(Test-Path -LiteralPath $sentinel) -or [IO.File]::ReadAllText($sentinel) -ne 'Existing content')
            { throw "Packaging deleted existing content before rejecting $protected $relationship overlap." }
        }
    }
    Write-Host 'All ten packaging path checks passed; no build or signing tools were invoked.'
}
finally
{
    # Delete only the unique fixture folder resolved beneath this repository's temporary build directory.
    $boundary = [IO.Path]::GetFullPath((Join-Path $repository 'Build\Temp')) + '\'
    if (!$temporary.StartsWith($boundary, [StringComparison]::OrdinalIgnoreCase))
    { throw 'Unexpected package test cleanup location.' }
    foreach ($link in $links)
    {
        if (!$link.StartsWith($temporary + '\', [StringComparison]::OrdinalIgnoreCase))
        { throw 'Unexpected package test junction location.' }
        if (Test-Path -LiteralPath $link) { [IO.Directory]::Delete($link) }
    }
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
