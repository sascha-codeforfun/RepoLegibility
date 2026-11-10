using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace RepoLegibility.Core.Pdf;

/// <summary>
/// Minimal read-only view of a TrueType / OpenType font program: just what the PDF font
/// dictionaries and the glyph-ID self-check need (head, maxp, loca, glyf).
/// </summary>
internal sealed class TrueTypeFile
{
    private readonly byte[] _data;
    private readonly Dictionary<string, (int Offset, int Length)> _tables = new(StringComparer.Ordinal);
    private readonly int _locaFormat;

    /// <summary>True for CFF-flavoured OpenType ('OTTO'); embedded as FontFile3 /OpenType.</summary>
    public bool IsCff { get; }
    public int UnitsPerEm { get; }
    public int NumGlyphs { get; }
    public short XMin { get; }
    public short YMin { get; }
    public short XMax { get; }
    public short YMax { get; }

    private TrueTypeFile(byte[] data)
    {
        _data = data;
        if (data.Length < 12) throw new FormatException("the font data is too short to be a font file.");
        uint version = U32(0);
        if (version == 0x74746366) // 'ttcf'
            throw new FormatException("the font data is a font collection (.ttc), which cannot be embedded in full.");
        IsCff = version == 0x4F54544F; // 'OTTO'
        if (!IsCff && version != 0x00010000 && version != 0x74727565) // 1.0 or 'true'
            throw new FormatException("the font data is not a TrueType or OpenType font.");

        int numTables = U16(4);
        for (int i = 0; i < numTables; i++)
        {
            int rec = 12 + i * 16;
            Need(rec, 16);
            string tag = Encoding.ASCII.GetString(data, rec, 4);
            int offset = checked((int)U32(rec + 8));
            int length = checked((int)U32(rec + 12));
            Need(offset, length);
            _tables[tag] = (offset, length);
        }

        var head = Table("head", 54);
        UnitsPerEm = U16(head + 18);
        if (UnitsPerEm == 0) throw new FormatException("the font's head table has unitsPerEm = 0.");
        XMin = S16(head + 36);
        YMin = S16(head + 38);
        XMax = S16(head + 40);
        YMax = S16(head + 42);
        _locaFormat = S16(head + 50);
        NumGlyphs = U16(Table("maxp", 6) + 4);
    }

    public static TrueTypeFile Parse(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return new TrueTypeFile(data);
    }

    public bool HasTable(string tag) => _tables.ContainsKey(tag);

    /// <summary>
    /// True if glyph <paramref name="gid"/> has outline data in 'glyf'. CFF fonts cannot be checked
    /// this way and always return true for glyph IDs in range.
    /// </summary>
    public bool HasOutline(ushort gid)
    {
        if (gid >= NumGlyphs) return false;
        if (IsCff) return true;
        if (!_tables.TryGetValue("loca", out var loca) || !_tables.ContainsKey("glyf")) return false;
        long start, end;
        if (_locaFormat == 0)
        {
            if ((gid + 2) * 2 > loca.Length) return false;
            start = U16(loca.Offset + gid * 2) * 2L;
            end = U16(loca.Offset + (gid + 1) * 2) * 2L;
        }
        else
        {
            if ((gid + 2) * 4 > loca.Length) return false;
            start = U32(loca.Offset + gid * 4);
            end = U32(loca.Offset + (gid + 1) * 4);
        }
        return end > start;
    }

    private int Table(string tag, int minLength)
    {
        if (!_tables.TryGetValue(tag, out var t))
            throw new FormatException($"the font has no '{tag}' table.");
        if (t.Length < minLength)
            throw new FormatException($"the font's '{tag}' table is truncated.");
        return t.Offset;
    }

    private void Need(int offset, int length)
    {
        if (offset < 0 || length < 0 || (long)offset + length > _data.Length)
            throw new FormatException("the font data is truncated or corrupt.");
    }

    private int U16(int o) { Need(o, 2); return BinaryPrimitives.ReadUInt16BigEndian(_data.AsSpan(o)); }
    private short S16(int o) { Need(o, 2); return BinaryPrimitives.ReadInt16BigEndian(_data.AsSpan(o)); }
    private uint U32(int o) { Need(o, 4); return BinaryPrimitives.ReadUInt32BigEndian(_data.AsSpan(o)); }
}
