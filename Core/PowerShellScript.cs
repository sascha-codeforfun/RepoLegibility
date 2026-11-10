using System.Text.RegularExpressions;

namespace RepoLegibility.Core;

/// <summary>
/// What a PowerShell script does, named by the commands in it: "changes firewall rules
/// (Set-NetFirewallRule)". Read from the script's text as the source shows it; nothing is run.
/// </summary>
public static class PowerShellScript
{
    private static readonly Regex Cmdlet = new(
        @"(?<![\w-])(?<verb>Get|Set|New|Remove|Add|Enable|Disable|Start|Stop|Restart|Invoke|Import|Export|Clear|Register|Unregister|Update|Install|Uninstall|Test|Copy|Move|Rename|Grant|Revoke|Block|Unblock|Suspend|Resume|Mount|Dismount|Reset|Repair|Protect|Unprotect|Send|Receive|Save|Backup|Restore|Lock|Unlock|Expand|Compress)-(?<noun>[A-Z][A-Za-z0-9]+)\b",
        RegexOptions.Compiled);

    private static readonly Regex Alias = new(@"(?<![\w-])(?<a>iex|iwr|irm|saps|kill)(?![\w-])", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    // Commands that only shape output or handle values: not what the script does to the machine.
    private static readonly HashSet<string> Plumbing = new(StringComparer.OrdinalIgnoreCase)
    {
        "Get-Date", "Get-Member", "Get-Variable", "Set-Variable", "New-Variable", "Remove-Variable", "Clear-Variable",
        "Get-Location", "Set-Location", "Get-Random", "Get-Culture", "Get-UICulture", "Get-Host", "New-Object",
        "Get-Command", "Test-Path", "Get-Help", "Add-Member", "New-TimeSpan", "Start-Sleep", "Get-Unique"
    };

    private static readonly Dictionary<string, string> Verbs = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Get"] = "reads", ["Set"] = "changes", ["New"] = "creates", ["Remove"] = "removes", ["Add"] = "adds",
        ["Enable"] = "turns on", ["Disable"] = "turns off", ["Start"] = "starts", ["Stop"] = "stops", ["Restart"] = "restarts",
        ["Invoke"] = "runs", ["Import"] = "imports", ["Export"] = "exports", ["Clear"] = "clears", ["Register"] = "registers",
        ["Unregister"] = "unregisters", ["Update"] = "updates", ["Install"] = "installs", ["Uninstall"] = "uninstalls",
        ["Test"] = "checks", ["Copy"] = "copies", ["Move"] = "moves", ["Rename"] = "renames", ["Grant"] = "grants",
        ["Revoke"] = "revokes", ["Block"] = "blocks", ["Unblock"] = "unblocks", ["Suspend"] = "pauses", ["Resume"] = "resumes",
        ["Mount"] = "mounts", ["Dismount"] = "dismounts", ["Reset"] = "resets", ["Repair"] = "repairs", ["Protect"] = "protects",
        ["Unprotect"] = "unprotects", ["Send"] = "sends", ["Receive"] = "receives", ["Save"] = "saves", ["Backup"] = "backs up",
        ["Restore"] = "restores", ["Lock"] = "locks", ["Unlock"] = "unlocks", ["Expand"] = "unpacks", ["Compress"] = "packs"
    };

    // Nouns in plain words, most specific first (prefix match).
    private static readonly (string Noun, string Words)[] Nouns =
    [
        ("NetFirewallRule", "firewall rules"), ("NetFirewallProfile", "firewall profiles"), ("NetFirewallSetting", "firewall settings"),
        ("NetFirewallApplicationFilter", "the programs of firewall rules"), ("NetFirewallPortFilter", "the ports of firewall rules"),
        ("NetFirewallAddressFilter", "the addresses of firewall rules"), ("NetFirewallServiceFilter", "the services of firewall rules"),
        ("NetFirewall", "firewall settings"), ("NetIPsec", "IPsec rules"),
        ("MpPreference", "Microsoft Defender settings"), ("MpComputerStatus", "Microsoft Defender's status"), ("MpThreat", "Microsoft Defender's threat list"),
        ("MpScan", "a Microsoft Defender scan"), ("MpSignature", "Microsoft Defender's signatures"), ("Mp", "Microsoft Defender"),
        ("ScheduledTask", "scheduled tasks"), ("Service", "Windows services"), ("Process", "running programs"),
        ("ItemProperty", "registry values or file properties"), ("ChildItem", "folder contents"), ("Item", "files, folders or registry keys"),
        ("Content", "file contents"), ("Acl", "permissions"), ("LocalUser", "local user accounts"), ("LocalGroupMember", "members of local groups"),
        ("LocalGroup", "local groups"), ("NetAdapter", "network adapters"), ("NetIPAddress", "IP addresses"), ("NetIPInterface", "network interfaces"),
        ("NetRoute", "network routes"), ("NetConnectionProfile", "network profiles (public or private)"), ("NetTCPConnection", "open network connections"),
        ("NetUDPEndpoint", "open UDP ports"), ("DnsClientServerAddress", "DNS servers"), ("DnsClientCache", "the DNS cache"), ("DnsClient", "DNS settings"),
        ("WinEvent", "the Windows event logs"), ("EventLog", "the Windows event logs"), ("AuthenticodeSignature", "file signatures"),
        ("FileHash", "file checksums"), ("WebRequest", "a web address"), ("RestMethod", "a web service"), ("Expression", "text as PowerShell code"),
        ("Command", "a command"), ("CimInstance", "system information (CIM/WMI)"), ("WmiObject", "system information (WMI)"),
        ("GPRegistryValue", "group policy settings"), ("GPO", "group policy objects"), ("GPResultantSetOfPolicy", "the group policy result"),
        ("AppxPackage", "installed apps"), ("WindowsOptionalFeature", "Windows features"), ("WindowsCapability", "Windows features"),
        ("ExecutionPolicy", "script restrictions (execution policy)"), ("BitLocker", "BitLocker drive encryption"), ("Tpm", "the TPM"),
        ("Computer", "the computer"), ("Partition", "disk partitions"), ("Volume", "drive volumes"), ("Disk", "disks"),
        ("Printer", "printers"), ("SmbShare", "shared folders"), ("SmbMapping", "mapped network drives"), ("PSDrive", "PowerShell drives"),
        ("Module", "PowerShell modules"), ("PackageProvider", "package sources"), ("Package", "software packages"), ("Certificate", "certificates"),
        ("Clipboard", "the clipboard"), ("Credential", "a credential"), ("Job", "background jobs"), ("Archive", "an archive"),
        ("ComputerRestorePoint", "restore points"), ("NetQosPolicy", "network priority policies"), ("VpnConnection", "VPN connections"),
    ];

    /// <summary>The commands in a script that act on the machine, in order, each once.</summary>
    public static List<string> Commands(string script)
    {
        var found = new List<string>();
        foreach (Match m in Cmdlet.Matches(script))
        {
            var c = m.Value;
            if (!Plumbing.Contains(c) && !found.Contains(c, StringComparer.OrdinalIgnoreCase)) found.Add(c);
        }
        foreach (Match m in Alias.Matches(script))
        {
            var c = m.Groups["a"].Value.ToLowerInvariant() switch
            {
                "iex" => "Invoke-Expression", "iwr" => "Invoke-WebRequest", "irm" => "Invoke-RestMethod", "saps" => "Start-Process", _ => "Stop-Process"
            };
            if (!found.Contains(c, StringComparer.OrdinalIgnoreCase)) found.Add(c);
        }
        return found;
    }

    /// <summary>"changes firewall rules (Set-NetFirewallRule)".</summary>
    public static string Words(string command)
    {
        var m = Cmdlet.Match(command);
        if (!m.Success) return command;
        var verb = Verbs.TryGetValue(m.Groups["verb"].Value, out var v) ? v : m.Groups["verb"].Value.ToLowerInvariant();
        var noun = m.Groups["noun"].Value;
        var words = Nouns.FirstOrDefault(n => noun.StartsWith(n.Noun, StringComparison.OrdinalIgnoreCase)).Words
                    ?? Regex.Replace(noun, "(?<=[a-z])(?=[A-Z])", " ").ToLowerInvariant();
        return $"{verb} {words} ({command})";
    }

    /// <summary>The commands in plain words, changes first: "changes firewall rules (Set-NetFirewallRule), reads … and 3 more".</summary>
    public static string Describe(IReadOnlyList<string> commands, int max = 4)
    {
        if (commands.Count == 0) return "";
        var ordered = commands.OrderBy(c => c.StartsWith("Get-", StringComparison.OrdinalIgnoreCase) || c.StartsWith("Test-", StringComparison.OrdinalIgnoreCase) ? 1 : 0).ToList();
        var shown = ordered.Take(max).Select(Words).ToList();
        var text = shown.Count == 1 ? shown[0] : string.Join(", ", shown.Take(shown.Count - 1)) + (ordered.Count > max ? ", " : " and ") + shown[^1];
        return ordered.Count > max ? text + $" and {ordered.Count - max} more" : text;
    }

    /// <summary>What's worth saying about how it runs, in plain words with the switch in brackets.</summary>
    public static List<string> Flags(string text)
    {
        var flags = new List<string>();
        if (Regex.IsMatch(text, @"(?i)-(?:ep|ex|exec|executionpolicy)\s+(?:bypass|unrestricted)\b"))
            flags.Add("runs with script restrictions off (-ExecutionPolicy Bypass)");
        if (Regex.IsMatch(text, @"(?i)(?:^|\s)-(?:e|ec|en|enc|encodedcommand)\s"))
            flags.Add("the script is passed encoded (-EncodedCommand)");
        if (Regex.IsMatch(text, @"(?i)-(?:w|win|windowstyle)\s+hidden\b"))
            flags.Add("runs in a hidden window (-WindowStyle Hidden)");
        if (Regex.IsMatch(text, @"(?i)\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile)\b") && Regex.IsMatch(text, @"(?i)\b(?:iex|Invoke-Expression)\b"))
            flags.Add("downloads code and runs it (Invoke-WebRequest | Invoke-Expression)");
        else if (Regex.IsMatch(text, @"(?i)(?<![\w-])(?:iex|Invoke-Expression)(?![\w-])"))
            flags.Add("runs text as code (Invoke-Expression)");
        return flags;
    }
}
