using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace RepoLegibility.Core;

/// <summary>One file from the zip. Text is set for files read as text; binaries keep only their hash and kind.</summary>
public sealed class RepoFile
{
    public required string Path { get; init; }
    public required long Bytes { get; init; }
    public string? Text { get; init; }
    /// <summary>Set for black boxes: executable code or an archive that can carry it.</summary>
    public string? BlackBoxKind { get; init; }
    public string? Sha256 { get; init; }
    public bool SkippedTooLarge { get; init; }

    public string Extension => System.IO.Path.GetExtension(Path).ToLowerInvariant();
    public string Name => System.IO.Path.GetFileName(Path);
    public string Dir => Path.Contains('/') ? Path[..Path.LastIndexOf('/')] : "";
}

/// <summary>
/// Reads a repo zip into memory, once, read-only. A single wrapper folder (GitHub's "Repo-main/",
/// or a folder named after the app) is taken off the paths. Nothing is extracted to disk.
/// </summary>
public sealed class RepoArchive
{
    /// <summary>Text files larger than this are listed as not covered instead of read.</summary>
    public const long MaxTextBytes = 8L * 1024 * 1024;

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".csx", ".csproj", ".props", ".targets", ".xaml", ".json", ".config", ".manifest", ".xml",
        ".yml", ".yaml", ".md", ".txt", ".sln", ".slnx", ".resx", ".editorconfig", ".gitignore", ".gitattributes",
        ".ps1", ".psm1", ".psd1", ".cmd", ".bat", ".sh", ".js", ".mjs", ".ts", ".py", ".vb", ".vbproj", ".fs", ".fsproj",
        ".fsx", ".cpp", ".c", ".h", ".hpp", ".go", ".rs", ".java", ".kt", ".rb", ".php", ".html", ".htm", ".css",
        ".sql", ".ini", ".toml", ".nuspec", ".pubxml", ".user", ".runsettings", ".razor", ".cshtml", ".vbs", ".wsf"
    };

    private static readonly HashSet<string> CodeArchives = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".jar", ".war", ".ear", ".nupkg", ".snupkg", ".vsix", ".apk", ".whl", ".7z", ".rar", ".tar", ".gz",
        ".tgz", ".cab", ".msi", ".msix", ".appx", ".appxbundle", ".msixbundle"
    };

    private static readonly HashSet<string> BinaryCode = new(StringComparer.OrdinalIgnoreCase)
    {
        ".dll", ".exe", ".so", ".dylib", ".pdb", ".lib", ".a", ".o", ".obj", ".winmd", ".sys", ".ocx", ".class",
        ".wasm", ".pyd", ".node", ".com", ".scr", ".cpl", ".drv"
    };

    public required string ZipName { get; init; }
    public required string Sha256 { get; init; }
    public required long ZipBytes { get; init; }
    /// <summary>The wrapper folder's name, or the zip's name without extension.</summary>
    public required string RepoName { get; init; }
    public required IReadOnlyList<RepoFile> Files { get; init; }

    public static RepoArchive Read(string zipPath, Action<string, int?, int?>? report = null)
    {
        // Read once, shared, so another program can keep the file open; then work from memory.
        byte[] bytes;
        using (var stream = new FileStream(zipPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
        {
            bytes = new byte[stream.Length];
            stream.ReadExactly(bytes);
        }

        var sha = Convert.ToHexStringLower(SHA256.HashData(bytes));
        using var zip = new ZipArchive(new MemoryStream(bytes, writable: false), ZipArchiveMode.Read);

        var entries = zip.Entries
            .Where(e => !e.FullName.EndsWith('/') && !e.FullName.EndsWith('\\'))
            .ToList();

        var names = entries.Select(e => e.FullName.Replace('\\', '/').TrimStart('/')).ToList();
        string? wrapper = CommonWrapper(names);
        var repoName = wrapper ?? Path.GetFileNameWithoutExtension(zipPath);

        var files = new List<RepoFile>(entries.Count);
        for (int i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            var path = names[i];
            if (wrapper is not null) path = path[(wrapper.Length + 1)..];
            if (path.Length == 0) continue;
            if (i % 25 == 0) report?.Invoke($"Reading {path}", i, entries.Count);
            files.Add(ReadEntry(entry, path));
        }

        return new RepoArchive
        {
            ZipName = Path.GetFileName(zipPath),
            Sha256 = sha,
            ZipBytes = bytes.LongLength,
            RepoName = repoName,
            Files = files.OrderBy(f => f.Path, StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    /// <summary>The one top folder every entry sits in, or null.</summary>
    private static string? CommonWrapper(List<string> names)
    {
        if (names.Count == 0) return null;
        string? top = null;
        foreach (var name in names)
        {
            int slash = name.IndexOf('/');
            if (slash <= 0) return null;
            var first = name[..slash];
            if (top is null) top = first;
            else if (!top.Equals(first, StringComparison.Ordinal)) return null;
        }
        return top;
    }

    private static RepoFile ReadEntry(ZipArchiveEntry entry, string path)
    {
        var ext = Path.GetExtension(path);
        long length = entry.Length;

        // Enough of the start to read a PE header: e_lfanew at 0x3C points to "PE\0\0", usually within 1 KB.
        byte[] head = new byte[HeadBytes];
        int headLength;
        byte[]? all = null;

        bool wantText = TextExtensions.Contains(ext) || ext.Length == 0;
        bool small = length <= MaxTextBytes;

        using (var s = entry.Open())
        {
            if (small)
            {
                using var ms = new MemoryStream((int)Math.Max(0, length));
                s.CopyTo(ms);
                all = ms.ToArray();
                headLength = Math.Min(HeadBytes, all.Length);
                Array.Copy(all, head, headLength);
            }
            else
            {
                headLength = s.ReadAtLeast(head, HeadBytes, throwOnEndOfStream: false);
            }
        }

        var kind = BlackBoxKindOf(ext, head, headLength);
        if (kind is not null)
        {
            string hash = all is not null ? Convert.ToHexStringLower(SHA256.HashData(all)) : HashLarge(entry);
            return new RepoFile { Path = path, Bytes = length, BlackBoxKind = kind, Sha256 = hash };
        }

        if (wantText && all is not null && !LooksBinary(all))
            return new RepoFile { Path = path, Bytes = length, Text = Decode(all) };

        return new RepoFile { Path = path, Bytes = length, SkippedTooLarge = wantText && all is null };
    }

    private static string HashLarge(ZipArchiveEntry entry)
    {
        using var s = entry.Open();
        return Convert.ToHexStringLower(SHA256.HashData(s));
    }

    private const int HeadBytes = 4096;

    /// <summary>Executable code by its header, or by its extension when it has no header of its own.</summary>
    private static string? BlackBoxKindOf(string ext, byte[] h, int n)
    {
        if (n >= 2 && h[0] == 'M' && h[1] == 'Z')
        {
            // "MZ" alone doesn't make a program: a real one points (e_lfanew at 0x3C) to a "PE\0\0" header.
            if (n >= 0x40)
            {
                int pe = BitConverter.ToInt32(h, 0x3C);
                if (pe >= 0x40 && pe + 4 <= n && h[pe] == 'P' && h[pe + 1] == 'E' && h[pe + 2] == 0 && h[pe + 3] == 0)
                    return "Windows executable or library (PE)";
                if (pe >= 0x40 && pe + 4 > n && pe < 0x10000000)
                    return "Windows executable or library (PE header beyond the first 4 KB, not checked)";
            }
            return "Starts with MZ, but not a valid Windows executable (too small or malformed)";
        }
        if (n >= 4 && h[0] == 0x7F && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') return "Linux executable or library (ELF)";
        if (n >= 4 && ((h[0] == 0xFE && h[1] == 0xED && h[2] == 0xFA && (h[3] == 0xCE || h[3] == 0xCF))
                       || ((h[0] == 0xCE || h[0] == 0xCF) && h[1] == 0xFA && h[2] == 0xED && h[3] == 0xFE)))
            return "macOS executable or library (Mach-O)";
        if (n >= 4 && h[0] == 0xCA && h[1] == 0xFE && h[2] == 0xBA && h[3] == 0xBE) return "Java class or macOS universal binary";
        if (n >= 4 && h[0] == 0 && h[1] == 'a' && h[2] == 's' && h[3] == 'm') return "WebAssembly module";
        if (CodeArchives.Contains(ext))
        {
            if (n >= 2 && h[0] == 'P' && h[1] == 'K') return "Archive (" + ext.TrimStart('.') + ")";
            return "Archive (" + ext.TrimStart('.') + ")";
        }
        if (BinaryCode.Contains(ext)) return "Compiled code (" + ext.TrimStart('.') + ")";
        return null;
    }

    private static bool LooksBinary(byte[] data)
    {
        int n = Math.Min(data.Length, 8000);
        // UTF-16 text has zero bytes too; its BOM tells it apart.
        if (n >= 2 && ((data[0] == 0xFF && data[1] == 0xFE) || (data[0] == 0xFE && data[1] == 0xFF))) return false;
        for (int i = 0; i < n; i++)
            if (data[i] == 0) return true;
        return false;
    }

    private static string Decode(byte[] data)
    {
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE) return Encoding.Unicode.GetString(data, 2, data.Length - 2);
        if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(data, 2, data.Length - 2);
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) return Encoding.UTF8.GetString(data, 3, data.Length - 3);
        return Encoding.UTF8.GetString(data);
    }
}
