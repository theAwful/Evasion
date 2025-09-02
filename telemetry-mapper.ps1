<#
.SYNOPSIS
  Read-only telemetry/EDR surface mapper for Windows (safe).
.DESCRIPTION
  Enumerates: host info, services, likely AV/EDR, Sysmon, ETW publishers, kernel drivers,
  installed programs, proxy/DNS, last input/user activity. Produces JSON and pretty output.
.NOTES
  - Run elevated (Admin) for maximum coverage. If not elevated some probes will gracefully skip.
  - This script does NOT attempt to disable, bypass, or tamper with anything.
  - Do not ask for AMSI/.NET bypasses here — coordinate with target owner or use an authorized agent when needed.
#>

Param(
  [switch]$Full = $false,
  [switch]$AsJson = $false,
  [string]$OutFile = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

function Get-HostInfo {
  [PSCustomObject]@{
    Hostname   = $env:COMPUTERNAME
    OS         = (Get-CimInstance Win32_OperatingSystem).Caption
    Build      = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    IPs        = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notlike '*Teredo*' } | Select-Object -ExpandProperty IPAddress) -join ', '
    CheckedAt  = (Get-Date).ToUniversalTime().ToString("o")
  }
}

function Get-SecurityProducts {
  # Best-effort list of AV/EDR-like services & installed programs
  $services = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Status -in @('Running','Stopped') }
  $candidates = @()

  foreach ($svc in $services) {
    $name = $svc.Name
    $display = $svc.DisplayName
    # common security service indicator keywords
    if ($display -match 'Defend|McAfee|CrowdStrike|Carbon Black|Sentinel|Symantec|Sophos|Trend|ESET|Bitdefender|Sentinel|Cylance|Elastic' -or
        $name -match 'WinDefend|MsMp|crowdstrike|csagent|cb|carbon|sentinel|symantec|savservice|ekrn') {
      $candidates += [PSCustomObject]@{
        Name = $display
        Service = $name
        Status = $svc.Status
      }
    }
  }

  # Also check uninstall registry keys for installed product names
  $uninst = @()
  $hklmPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )
  foreach ($p in $hklmPaths) {
    Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | ForEach-Object {
      if ($_.DisplayName) {
        if ($_.DisplayName -match 'Defend|CrowdStrike|Carbon Black|McAfee|Sophos|Symantec|ESET|Trend|Bitdefender|Splunk|Sysmon') {
          $uninst += [PSCustomObject]@{
            DisplayName = $_.DisplayName
            Publisher   = $_.Publisher
            Version     = $_.DisplayVersion
          }
        }
      }
    }
  }

  return @{ Services = $candidates; Uninstall = $uninst }
}

function Get-Sysmon {
  # Detect Sysmon service or binary presence
  $found = @()
  # service
  $svc = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue
  if ($svc) {
    $found += [PSCustomObject]@{ Name='Sysmon'; Source='Service'; Status = $svc.Status }
  }
  # check running processes for sysmon
  $proc = Get-Process -Name sysmon -ErrorAction SilentlyContinue
  if ($proc) {
    $found += [PSCustomObject]@{ Name='Sysmon'; Source='Process'; Pid = $proc.Id }
  }
  return $found
}

function Get-ETWProviders {
  # Read registry list of event publisher GUIDs (best-effort); map to provider names if present
  $root = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers'
  $list = @()
  if (Test-Path $root) {
    Get-ChildItem -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
      $guid = $_.PSChildName
      $displayName = (Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue).MessageFile -split ',' | Select-Object -First 1
      $list += [PSCustomObject]@{ GUID = $guid; MessageFile = $displayName }
    }
  }
  else {
    # fallback: wevtutil enum-publishers (may require elevation)
    $out = wevtutil enum-publishers 2>$null
    if ($out) {
      # simple parse for GUID lines
      foreach ($l in $out) {
        if ($l -match 'Publisher: (.*)') {
          $list += [PSCustomObject]@{ Raw = $l }
        }
      }
    }
  }
  return $list
}

function Get-KernelDrivers {
  $drivers = @()
  $sd = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction SilentlyContinue
  foreach ($d in $sd) {
    # best-effort filter for security drivers by name/publisher keywords
    if ($d.DisplayName -match 'Driver|Filter|KEXT|Carbon|Crowd|Cb|Sentinel|Symantec|McAfee|Sophos|ESET|Trend' -or
        $d.Name -match 'sysmon|mbam|mcafee|crowdstrike|cb|carbon|sentinel') {
      $drivers += [PSCustomObject]@{
        Name = $d.Name
        DisplayName = $d.DisplayName
        Path = $d.PathName
        State = $d.State
        StartMode = $d.StartMode
      }
    }
  }
  return $drivers
}

function Get-InstalledPrograms {
  # light-weight list (do NOT return entire registries)
  $res = @()
  $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
  foreach ($p in $paths) {
    Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | ForEach-Object {
      if ($_.DisplayName) {
        $res += [PSCustomObject]@{ Name=$_.DisplayName; Publisher=$_.Publisher; Version=$_.DisplayVersion }
      }
    }
  }
  return $res | Select-Object -Unique -Property Name, Publisher, Version
}

function Get-NetworkObservability {
  $proxy = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue).ProxyServer
  $dns = (Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses) -join ', '
  return [PSCustomObject]@{ Proxy = $proxy; DNS = $dns }
}

function Get-UserActivity {
  Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class LastInput {
  [StructLayout(LayoutKind.Sequential)]
  public struct LASTINPUTINFO {
    public uint cbSize;
    public uint dwTime;
  }
  [DllImport("user32.dll")]
  public static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
  [DllImport("kernel32.dll")]
  public static extern uint GetTickCount();
  public static uint GetIdleSeconds() {
    LASTINPUTINFO li = new LASTINPUTINFO();
    li.cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(li);
    if (!GetLastInputInfo(ref li)) return 0;
    uint tick = GetTickCount();
    return (tick - li.dwTime) / 1000;
  }
}
"@ -ErrorAction SilentlyContinue

  $idle = 0
  try { $idle = [LastInput]::GetIdleSeconds() } catch {}
  $sessions = (quser.exe 2>$null) -ne $null
  return [PSCustomObject]@{ LastInputSeconds = $idle; InteractiveSessions = (if ($sessions) { (quser.exe | Select-Object -Skip 1 | Measure-Object).Count } else { 0 }) }
}

# ---- Main ----
$host = Get-HostInfo
$fp = [ordered]@{
  host = $host
  security_products = Get-SecurityProducts
  sysmon = Get-Sysmon
}

if ($Full) {
  $fp.etw_providers = Get-ETWProviders
  $fp.kernel_drivers = Get-KernelDrivers
  $fp.installed_programs = Get-InstalledPrograms
  $fp.network = Get-NetworkObservability
  $fp.user_activity = Get-UserActivity
}

# Summarize heuristic (simple)
function Summarize-Findings([hashtable]$m) {
  $score = 0
  if ($m.security_products.Services.Count -gt 0) { $score += 3 }
  if ($m.sysmon.Count -gt 0) { $score += 2 }
  if ($m.kernel_drivers -and $m.kernel_drivers.Count -gt 0) { $score += 2 }
  $risk = 'low'
  if ($score -ge 6) { $risk = 'high' } elseif ($score -ge 3) { $risk = 'medium' }
  return [PSCustomObject]@{ risk = $risk; score = $score }
}

$summary = Summarize-Findings $fp
$fp.summary = $summary

if ($AsJson) {
  $json = $fp | ConvertTo-Json -Depth 6
  if ($OutFile) { $json | Out-File -FilePath $OutFile -Encoding utf8 }
  else { $json | Write-Output }
} else {
  Write-Host "== Telemetry Mapper Summary ==" -ForegroundColor Cyan
  Write-Host "Host: $($host.Hostname)  OS: $($host.OS)  Checked: $($host.CheckedAt)"
  Write-Host "Risk (heuristic): $($summary.risk)  (score: $($summary.score))`n"
  Write-Host "Detected security services:"
  if ($fp.security_products.Services.Count -eq 0) { Write-Host "  None obvious (best-effort)" } else {
    $fp.security_products.Services | ForEach-Object { Write-Host "  - $($_.Name) [$($_.Service)] Status: $($_.Status)" }
  }
  if ($fp.sysmon.Count -gt 0) {
    Write-Host "`nSysmon:"
    $fp.sysmon | ForEach-Object { Write-Host "  - $($_.Name) via $($_.Source) $(if ($_.Pid) { \"pid=$($_.Pid)\" } )" }
  }
  if ($Full) {
    Write-Host "`nETW providers (sample):"
    if ($fp.etw_providers.Count -gt 0) { $fp.etw_providers | Select-Object -First 10 | ForEach-Object { Write-Host \"  - $($_.GUID)  $($_.MessageFile)\" } }
    else { Write-Host "  none enumerated or insufficient privileges." }
    Write-Host "`nKernel drivers (sample):"
    if ($fp.kernel_drivers) { $fp.kernel_drivers | Select-Object -First 10 | ForEach-Object { Write-Host \"  - $($_.Name)  $($_.Path)\" } }
    Write-Host "`nNetwork:"
    Write-Host \"  Proxy: $($fp.network.Proxy)  DNS: $($fp.network.DNS)\"
    Write-Host "`nUser activity:"
    Write-Host \"  Idle seconds: $($fp.user_activity.LastInputSeconds)  Interactive sessions: $($fp.user_activity.InteractiveSessions)\"
  }
  if ($OutFile -and $AsJson) { Write-Host \"Wrote JSON to $OutFile\" }
}
