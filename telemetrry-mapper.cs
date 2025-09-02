// dotnet new console -n TelemetryMapper
// replace Program.cs with below, then dotnet build

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Management; // add System.Management nuget for non-core functions
using System.ServiceProcess;
using Microsoft.Win32;

class HostInfo {
  public string Hostname {get;set;}
  public string OS {get;set;}
  public string CheckedAt {get;set;}
}

class RiskMap {
  public HostInfo host {get;set;}
  public List<object> security_products {get;set;}
  public List<object> etw_providers {get;set;}
  public object summary {get;set;}
}

class Program {
  static HostInfo GetHostInfo() {
    return new HostInfo {
      Hostname = Environment.MachineName,
      OS = GetOSCaption(),
      CheckedAt = DateTime.UtcNow.ToString("o")
    };
  }

  static string GetOSCaption() {
    try {
      using(var search = new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem")) {
        foreach (ManagementObject mo in search.Get()) {
          return mo["Caption"]?.ToString();
        }
      }
    } catch {}
    return "Unknown";
  }

  static List<object> GetSecurityProducts() {
    var list = new List<object>();
    try {
      ServiceController[] services = ServiceController.GetServices();
      foreach(var svc in services) {
        var d = svc.DisplayName ?? svc.ServiceName;
        if (d.IndexOf("Defend", StringComparison.OrdinalIgnoreCase) >= 0
          || d.IndexOf("Crowd", StringComparison.OrdinalIgnoreCase) >= 0
          || d.IndexOf("McAfee", StringComparison.OrdinalIgnoreCase) >= 0
          || d.IndexOf("Symantec", StringComparison.OrdinalIgnoreCase) >= 0
          || d.IndexOf("Sophos", StringComparison.OrdinalIgnoreCase) >= 0
          || d.IndexOf("ESET", StringComparison.OrdinalIgnoreCase) >= 0
          || d.IndexOf("Trend", StringComparison.OrdinalIgnoreCase) >= 0) {
            list.Add(new { Name = d, Service = svc.ServiceName, Status = svc.Status.ToString() });
        }
      }
    } catch {}
    return list;
  }

  static List<object> GetETWProviders() {
    var list = new List<object>();
    try {
      using(var baseKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers")) {
        if (baseKey != null) {
          foreach (var name in baseKey.GetSubKeyNames()) {
            using(var k = baseKey.OpenSubKey(name)) {
              var msg = k.GetValue("MessageFile")?.ToString();
              list.Add(new { GUID = name, MessageFile = msg });
            }
          }
        }
      }
    } catch {}
    return list;
  }

  static object Summarize(List<object> sec) {
    int score = 0;
    if (sec.Count > 0) score += 3;
    string risk = score >= 6 ? "high" : (score >= 3 ? "medium" : "low");
    return new { risk_level = risk, note = "heuristic summary" };
  }

  static void Main(string[] args) {
    var rm = new RiskMap {
      host = GetHostInfo(),
      security_products = GetSecurityProducts(),
      etw_providers = GetETWProviders()
    };
    rm.summary = Summarize(rm.security_products);
    var opts = new JsonSerializerOptions { WriteIndented = true };
    Console.WriteLine(JsonSerializer.Serialize(rm, opts));
  }
}
