using System.Text.RegularExpressions;

namespace RepoLegibility.Core;

/// <summary>
/// Well-known system commands that change security or recovery, in plain words: what a reader should
/// know before reading the command itself. Matched on the command text the source shows.
/// </summary>
public static class Commands
{
    private static readonly (Regex Pattern, string Words)[] Known =
    [
        (R(@"\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b.*\|\s*(?:iex|Invoke-Expression)\b"), "Downloads a script and runs it straight away"),
        (R(@"^\s*(?:iex|Invoke-Expression)\b|[;|]\s*(?:iex|Invoke-Expression)\b"), "Runs text as PowerShell code"),
        (R(@"\bnetsh\b.*\badvfirewall\b.*\bstate\s+off\b.*|\bnetsh\b.*\bfirewall\b.*\bopmode\s+(?:mode=)?disable\b"), "Turns off Windows Firewall"),
        (R(@"\bnetsh\b.*\b(?:advfirewall\s+firewall|firewall)\s+add\s+(?:rule|allowedprogram|portopening)\b"), "Adds a Windows Firewall rule"),
        (R(@"\bSet-NetFirewallProfile\b.*-Enabled\s+(?:False|\$false|0)\b"), "Turns off Windows Firewall"),
        (R(@"\bAdd-MpPreference\b.*-Exclusion(?:Path|Process|Extension|IpAddress)\b"), "Adds a Microsoft Defender exclusion, so Defender stops scanning there"),
        (R(@"\bSet-MpPreference\b.*-Disable\w+\s+(?:\$true|1|true)\b"), "Turns off part of Microsoft Defender"),
        (R(@"\bvssadmin\b.*\bdelete\s+shadows\b|\bwmic\b.*\bshadowcopy\b.*\bdelete\b|\bvssadmin\b.*\bresize\s+shadowstorage\b"), "Deletes Volume Shadow Copies (restore points and previous versions)"),
        (R(@"\bbcdedit\b.*\brecoveryenabled\s+no\b|\bbcdedit\b.*\bbootstatuspolicy\s+ignoreallfailures\b"), "Turns off Windows recovery at boot"),
        (R(@"\bbcdedit\b"), "Changes the Windows boot configuration"),
        (R(@"\bschtasks\b.*\s/create\b"), "Creates a scheduled task"),
        (R(@"\breg(?:\.exe)?\s+add\b.*\\CurrentVersion\\Run(?:Once)?\b"), "Adds a program that starts with Windows"),
        (R(@"\breg(?:\.exe)?\s+(?:add|delete)\b"), "Changes the registry"),
        (R(@"\bicacls\b.*\s/grant\b.*\b(?:Everyone|\*S-1-1-0|Users|Authenticated Users)\b"), "Gives everyone access to a file or folder"),
        (R(@"\btakeown\b"), "Takes ownership of files"),
        (R(@"\bwevtutil\b.*\b(?:cl|clear-log)\b|\bClear-EventLog\b"), "Clears a Windows event log"),
        (R(@"\bnet1?\s+localgroup\s+administrators\b.*\s/add\b"), "Adds a user to the administrators group"),
        (R(@"\bnet1?\s+user\b.*\s/add\b"), "Adds a Windows user account"),
        (R(@"\bsc(?:\.exe)?\s+(?:create|config)\b|\bNew-Service\b"), "Creates or changes a Windows service"),
        (R(@"\bsc(?:\.exe)?\s+(?:stop|delete)\b|\bStop-Service\b"), "Stops or removes a Windows service"),
        (R(@"\bshutdown(?:\.exe)?\b|\bRestart-Computer\b|\bStop-Computer\b"), "Shuts down or restarts the computer"),
        (R(@"\bauditpol\b.*\b(?:/clear|/remove|disable)\b"), "Turns off Windows auditing"),
    ];

    private static Regex R(string pattern) => new(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>What the command does, in plain words, or null when it isn't one of the known ones.</summary>
    public static string? Describe(string command)
    {
        foreach (var (pattern, words) in Known)
            if (pattern.IsMatch(command))
                return words + (words.EndsWith("Firewall", StringComparison.Ordinal) && Regex.IsMatch(command, @"\ballprofiles\b", RegexOptions.IgnoreCase) ? " for all profiles" : "");
        return null;
    }
}
