# Copyright 2026 atframework
#
# Run the node-level TCP stream benchmark matrix against
# benchmark_node_stream_send/recv and collect JSON results.
#
# usage: benchmark_node_stream_matrix.ps1 -BinDir <dir> -ResultDir <dir> [-DurationSec 15] [-Address ipv4://127.0.0.1:16500]
#
# Combo layout (per size):
#   1. crypto dimension: 6 crypto algorithms with compression=none
#   2. compression dimension: 5 compression presets with crypto=none
#   3. combined dimension: 4 compression presets x 3 AEAD-safe crypto algorithms
# The receiver is started in the background; the sender floods until the duration
# elapses and both processes write JSON reports into the combo directory.

param(
  [Parameter(Mandatory = $true)][string]$BinDir,
  [Parameter(Mandatory = $true)][string]$ResultDir,
  [double]$DurationSec = 15,
  [string]$Address = "ipv4://127.0.0.1:16500",
  # Optional shm://key: receiver also listens on it so the peer's connect-back
  # upgrades the data channel to shared memory
  [string]$ShmAddress = ""
)

$ErrorActionPreference = "Stop"

$SendBin = Join-Path $BinDir "benchmark_node_stream_send.exe"
$RecvBin = Join-Path $BinDir "benchmark_node_stream_recv.exe"
if (-not (Test-Path $SendBin)) {
  Write-Error "benchmark_node_stream_send.exe not found in $BinDir"
}

# The sender also listens (port+1) so the peer's connect-back builds the designed
# ctrl/data connection pair instead of a degenerate self loop.
$Port = [int]($Address -replace '.*:', '')
$SendListenAddr = ($Address -replace ':\d+$', '') + ":$($Port + 1)"

$Cryptos = @("none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20", "chacha20-poly1305-ietf")
$Compressions = @(
  @{ comp = "lz4"; level = "fast" },
  @{ comp = "lz4"; level = "default" },
  @{ comp = "zstd"; level = "default" },
  @{ comp = "zstd"; level = "high-ratio" }
)
$CombinedCryptos = @("aes-128-gcm", "aes-256-gcm", "chacha20-poly1305-ietf")
$Sizes = @(200, 1024, 8192, 65536, 307200)

# Build the explicit combo list to avoid duplicating the none/none baseline
$Combos = @()
foreach ($Crypto in $Cryptos) {
  $Combos += @{ crypto = $Crypto; comp = "none"; level = "default" }
}
foreach ($Comp in $Compressions) {
  $Combos += @{ crypto = "none"; comp = $Comp.comp; level = $Comp.level }
}
foreach ($Comp in $Compressions) {
  foreach ($Crypto in $CombinedCryptos) {
    $Combos += @{ crypto = $Crypto; comp = $Comp.comp; level = $Comp.level }
  }
}

New-Item -Path $ResultDir -ItemType Directory -Force | Out-Null

$Total = $Combos.Count * $Sizes.Count
$Index = 0
$Failed = 0

foreach ($Size in $Sizes) {
  foreach ($Combo in $Combos) {
    $Index += 1
    $Name = "$($Combo.crypto)__$($Combo.comp)-$($Combo.level)__${Size}"
    $OutDir = Join-Path $ResultDir $Name
    New-Item -Path $OutDir -ItemType Directory -Force | Out-Null

    Write-Output "=== [$Index/$Total] $Name ==="

    $RecvArgs = @($Address, "200000001",
      "--crypto=$($Combo.crypto)", "--compression=$($Combo.comp)", "--level=$($Combo.level)",
      "--payload-size=$Size")
    if ($ShmAddress -ne "") {
      $RecvArgs += "--extra-listen=$ShmAddress"
    }
    $RecvArgs += "--json=$(Join-Path $OutDir 'recv.json')"
    $RecvProc = Start-Process -FilePath $RecvBin -ArgumentList $RecvArgs `
      -RedirectStandardError (Join-Path $OutDir "recv.stderr.log") -PassThru -NoNewWindow

    # give the listener a moment to bind
    Start-Sleep -Seconds 1

    $SendArgs = @($Address, "200000002", "200000001", "$Size", "$DurationSec",
      "--crypto=$($Combo.crypto)", "--compression=$($Combo.comp)", "--level=$($Combo.level)",
      "--listen=$SendListenAddr",
      "--json=$(Join-Path $OutDir 'send.json')")
    $SendProc = Start-Process -FilePath $SendBin -ArgumentList $SendArgs `
      -RedirectStandardError (Join-Path $OutDir "send.stderr.log") -PassThru -NoNewWindow
    $SendProc.WaitForExit() | Out-Null

    # receiver exits when the sender disconnects; do not hang forever
    $Waited = 0
    while (-not $RecvProc.HasExited -and $Waited -lt 30) {
      Start-Sleep -Seconds 1
      $Waited += 1
    }
    if (-not $RecvProc.HasExited) {
      Write-Warning "receiver did not exit in time, killing: $Name"
      try { $RecvProc.Kill() } catch {}
      $Failed += 1
    }

    if ((Test-Path (Join-Path $OutDir "recv.json")) -and (Test-Path (Join-Path $OutDir "send.json"))) {
      Write-Output "    done: $OutDir"
    }
    else {
      Write-Warning "MISSING RESULT: $OutDir"
      $Failed += 1
    }
  }
}

Write-Output "=== matrix finished, $Failed failed runs, results in $ResultDir ==="
