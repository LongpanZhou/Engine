# Automated driver test loop. Repeats until `sc start Driver` completes with the service RUNNING and it
# survives the soak, or the cycle budget runs out. Each cycle: hard reset, boot, copy, create, start, verify.
# The default is the shipping release build. Pass -Config debug when diagnosing under a debugger: that
# build carries print() output, but also debug-only code paths, so it is not the artifact to soak-test.
param(
    [int]$MaxCycles = 3,
    [int]$SoakSeconds = 30,
    [ValidateSet('release', 'debug')]
    [string]$Config = 'release'
)

$ErrorActionPreference = 'Continue'
$vmrun     = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
$vmx       = 'C:\Users\27175\Downloads\Vmware\Windows 10 x64.vmx'
$buildDir  = if ($Config -eq 'debug') { 'build-debug' } else { 'build' }
$driverSrc = Join-Path $PSScriptRoot "Driver\$buildDir\Driver.sys"
$gDir      = 'C:\Users\vmdebug\Desktop'
$logHost   = $PSScriptRoot

function Log($m) { "$(Get-Date -Format HH:mm:ss) $m" }

function Vm($argsList) {
    & $vmrun -T ws -gu vmdebug -gp 123456 @argsList 2>$null
    return $LASTEXITCODE
}

# Polls tools state until running or timeout
function Wait-ToolsReady([int]$TimeoutSec) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        $st = & $vmrun -T ws checkToolsState $vmx 2>$null
        if ($st -match 'running') { return $true }
        Start-Sleep -Seconds 4
    }
    return $false
}

# Runs a command in the guest, returns stdout+stderr text
function G-Run([string]$CmdIn) {
    $outGuest = "$gDir\grun.out"
    Remove-Item "$logHost\tmp.out" -ErrorAction SilentlyContinue
    [void](Vm @('runScriptInGuest', $vmx, 'C:\Windows\System32\cmd.exe', "/c $CmdIn > $outGuest 2>&1"))
    $ret = "$logHost\grun.in"
    [void](Vm @('copyFileFromGuestToHost', $vmx, $outGuest, $ret))
    if (Test-Path $ret) { $t = Get-Content $ret -Raw; Remove-Item $ret; return $t }
    return ''
}

function G-Write([string]$Text, [string]$GuestPath) {
    $tmp = "$logHost\gw.tmp"
    Set-Content -Path $tmp -Value $Text -NoNewline -Encoding Ascii
    [void](Vm @('copyFileFromHostToGuest', $vmx, $tmp, $GuestPath))
    Remove-Item $tmp -ErrorAction SilentlyContinue
}

$results = @()
for ($i = 1; $i -le $MaxCycles; $i++) {
    Log "=== CYCLE ${i}: hard reset ==="
    [void](& $vmrun -T ws reset $vmx hard 2>$null)

    if (-not (Wait-ToolsReady 300)) { Log "CYCLE ${i}: tools never came up"; $results += "cycle$i=boot-fail"; continue }

    Log "CYCLE ${i}: boot complete, copying driver"
    $rc = $null
    $rc = Vm @('copyFileFromHostToGuest', $vmx, $driverSrc, "$gDir\Driver.sys")
    if ($rc -ne 0) { Log "CYCLE ${i}: copy failed exit=$rc"; $results += "cycle$i=copy-fail"; continue }

    Log "CYCLE ${i}: (re)creating service"
    $null = G-Run 'sc delete Driver'
    $mk = G-Run 'sc create Driver type= kernel binPath= C:\Users\vmdebug\Desktop\Driver.sys'
    Log "CYCLE ${i}: create -> $(($mk -replace '\r?\n', ' | '))"

    Log "CYCLE ${i}: starting service"
    $startOt = G-Run 'sc start Driver'
    $flat = $startOt -replace "`r`n", ' | '
    Log "CYCLE ${i}: sc start -> $flat"

    # fast-fail path is inside sc start's 30s timeout verdict; if the start hung, the cmd was killed at its
    # own budget and grun.out is empty/partial
    $st2 = G-Run 'sc query Driver'
    $qFlat = $st2 -replace "`r`n", ' | '
    if ($st2 -match 'RUNNING') {
        Log "CYCLE ${i}: driver RUNNING, soak $SoakSeconds s"
        Start-Sleep -Seconds $SoakSeconds
        $st3 = G-Run 'sc query Driver'
        Log "CYCLE ${i}: post-soak query -> $(($st3 -replace '\r\n', ' | '))"
        Start-Sleep -Seconds 3
        $st4 = G-Run 'sc query Driver'
        if ($st4 -match 'RUNNING') {
            Log "SUCCESS on cycle ${i}: loaded, RUNNING, survived soak"
            $results += "cycle$i=SUCCESS"
            break
        } else {
            Log "CYCLE ${i}: died during soak"
            $results += "cycle$i=soak-die"
            continue
        }
    } else {
        Log "CYCLE ${i}: not RUNNING after start (see query above)"
        $results += "cycle$i=start-fail"
        continue
    }
}

Log "RESULT: $($results -join '; ')"
"RESULT: $($results -join '; ')" > "$logHost\test-result.txt"
