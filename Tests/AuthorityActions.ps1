#
# Copyright (c) Bryan Berns.
# Licensed under GPLv3. See LICENSE.md.
#

#requires -Version 5.1
param([string] $AssemblyPath = "$PSScriptRoot\..\Code\bin\Debug\Certitude.exe")

# Exercise the real batch runner with simulated CA calls; no CA is contacted.
$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom([IO.Path]::GetFullPath($AssemblyPath))
$reportType = $assembly.GetType('Certitude.TimeReport', $true)
$operationType = [Func``2].MakeGenericType([string], $reportType)
$runner = $assembly.GetType('Certitude.CaAdministration', $true).GetMethod('RunAuthorities',
    [Reflection.BindingFlags] 'Static, NonPublic')
$calls = [Collections.Generic.List[string]]::new()
$targets = @('one\CA One', 'two\CA Two', 'three\CA Three')

function Assert([bool] $condition, [string] $message)
{
    if (!$condition) { throw $message }
}

function Report([string] $text)
{
    [Activator]::CreateInstance($reportType, [object[]] @($text))
}

function Run([string[]] $names, [scriptblock] $operation,
    [Threading.CancellationToken] $token = [Threading.CancellationToken]::None)
{
    $callback = [Management.Automation.LanguagePrimitives]::ConvertTo($operation, $operationType)
    $runner.Invoke($null, [object[]] @($names, $callback, $token, $null)).ToString()
}

# One denied CA must not prevent later CAs from running or hide earlier results.
$result = Run ($targets + 'ONE\CA ONE') {
    param($target)
    $calls.Add($target)
    if ($target -eq $targets[1]) { throw 'Access denied by simulated CA' }
    Report "Returned publication status for $target"
}
Assert ($calls.Count -eq 3 -and $calls[2] -eq $targets[2]) 'Every distinct CA must be attempted once.'
foreach ($target in $targets) { Assert ($result.Contains("CA: $target")) "Missing target report: $target" }
Assert ($result.Contains('Access denied') -and $result.Contains('1 calls failed; 0 not attempted.')) `
    'The partial failure must remain visible.'
Assert ($result.Contains("Returned publication status for $($targets[0])") -and
    $result.Contains("Returned publication status for $($targets[2])")) 'Successful results must remain visible.'

# Total failure still produces one identifiable result per CA.
$calls.Clear()
$result = Run $targets { param($target) $calls.Add($target); throw 'Simulated offline CA' }
Assert ($calls.Count -eq 3 -and $result.Contains('3 calls failed; 0 not attempted.')) `
    'Total failure must attempt every CA and report the failures.'

# Cancelling a batch preserves the completed result and leaves later CAs untouched.
$calls.Clear()
$cancellation = [Threading.CancellationTokenSource]::new()
try
{
    $result = Run $targets {
        param($target)
        $calls.Add($target)
        $cancellation.Cancel()
        Report 'Publication returned'
    } $cancellation.Token
    Assert ($calls.Count -eq 1 -and $result.Contains('Publication returned') -and
        $result.Contains('2 not attempted.') -and $result.Contains('Completed CA changes remain applied')) `
        'Cancellation must preserve completed changes and report skipped targets.'
    $calls.Clear()
    $result = Run $targets { param($target) $calls.Add($target); Report 'Unexpected call' } $cancellation.Token
    Assert ($calls.Count -eq 0 -and $result.Contains('3 not attempted.')) `
        'A pre-cancelled batch must not contact a CA.'
}
finally { $cancellation.Dispose() }

# Validate the entire target list before any operation can change a CA.
foreach ($invalidTargets in @(@($targets[0], 'All CAs'), @()))
{
    $calls.Clear()
    $rejected = $false
    try { $null = Run $invalidTargets { param($target) $calls.Add($target); Report 'Unexpected call' } }
    catch { $rejected = $_.Exception.GetBaseException() -is [ArgumentException] }
    Assert ($rejected -and $calls.Count -eq 0) 'Invalid or empty targets must be rejected before the first CA call.'
}

# Query failures must not remove administrative targets from the connected selection.
$storeType = $assembly.GetType('Certitude.CertificateStore', $true)
$allType = $assembly.GetType('Certitude.AllCertificateStore', $true)
$sources = [Array]::CreateInstance($storeType, $targets.Count)
for ($i = 0; $i -lt $targets.Count; $i++)
{
    $sources.SetValue([Activator]::CreateInstance($storeType, [object[]] @($targets[$i])), $i)
}
$constructor = $allType.GetConstructors([Reflection.BindingFlags] 'Instance, NonPublic') |
    Where-Object { $_.GetParameters()[0].ParameterType.IsGenericType }
$all = $constructor.Invoke([object[]] (,$sources))
$unavailable = $allType.GetField('unavailable', [Reflection.BindingFlags] 'Instance, NonPublic').GetValue($all)
$null = $unavailable.TryAdd($targets[1], 'Simulated certificate query failure')
$connected = $storeType.GetProperty('Configurations', [Reflection.BindingFlags] 'Instance, NonPublic').GetValue($all)
Assert ($connected.Count -eq 3 -and $connected -contains $targets[1]) `
    'Administrative actions must include connected CAs whose certificate queries failed.'

Write-Host 'Authority action regression checks passed.'
