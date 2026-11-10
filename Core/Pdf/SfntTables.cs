using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;

namespace RepoLegibility.Core.Pdf;

/// <summary>
/// Keeps only the tables of a font program that a PDF draws with. A subset from Windows keeps
/// every table of the font: colour layers (COLR, CPAL: megabytes in a colour emoji font, even for a
/// few symbols), bitmaps, layout (GSUB, GPOS) and hinting caches (hdmx, LTSH) — none of which a PDF
/// viewer reads, since the text is already laid out as glyph IDs. Glyph IDs, outlines and metrics
/// stay exactly as they are.
/// </summary>
internal static class SfntTables
{
    /// <summary>
    /// What a viewer needs from an embedded TrueType program (PDF 32000-1 §9.9: head, hhea, loca,
    /// maxp, cvt, prep, glyf, hmtx, fpgm; cmap, name, post and OS/2 are small and some viewers
    /// look at them) and from a CFF-flavoured one (the CFF table instead of glyf and loca).
    /// </summary>
    internal static readonly IReadOnlySet<string> ForPdf = new HashSet<string>(StringComparer.Ordinal)
    {
        "head", "hhea", "maxp", "hmtx", "loca", "glyf", "cvt ", "fpgm", "prep",
        "cmap", "name", "post", "OS/2", "CFF ", "CFF2",
    };

    /// <summary>
    /// The program with only <see cref="ForPdf"/> tables, checksums and head.checkSumAdjustment
    /// written again. Returned unchanged when nothing is left out, or when it is not a single font
    /// (a collection, or not a font at all: the parser reports that later).
    /// </summary>
    public static byte[] KeepForPdf(byte[] program)
    {
        ArgumentNullException.ThrowIfNull(program);
        if (program.Length < 12)
        {
            return program;
        }

        uint version = BinaryPrimitives.ReadUInt32BigEndian(program);
        if (version is not (0x00010000 or 0x74727565 or 0x4F54544F)) // 1.0, 'true', 'OTTO'
        {
            return program;
        }

        int count = BinaryPrimitives.ReadUInt16BigEndian(program.AsSpan(4));
        if (12 + count * 16 > program.Length)
        {
            return program;
        }

        var kept = new List<(string Tag, int Offset, int Length)>();
        for (int i = 0; i < count; i++)
        {
            int rec = 12 + i * 16;
            string tag = Encoding.ASCII.GetString(program, rec, 4);
            long offset = BinaryPrimitives.ReadUInt32BigEndian(program.AsSpan(rec + 8));
            long length = BinaryPrimitives.ReadUInt32BigEndian(program.AsSpan(rec + 12));
            if (offset + length > program.Length)
            {
                return program; // corrupt: left for the parser to report
            }

            if (ForPdf.Contains(tag))
            {
                kept.Add((tag, (int)offset, (int)length));
            }
        }

        if (kept.Count == count)
        {
            return program;
        }

        kept.Sort((a, b) => string.CompareOrdinal(a.Tag, b.Tag));
        int dirLength = 12 + kept.Count * 16;
        int size = dirLength;
        foreach (var t in kept)
        {
            size += Padded(t.Length);
        }

        var result = new byte[size];
        BinaryPrimitives.WriteUInt32BigEndian(result, version);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(4), (ushort)kept.Count);
        int power = 1, log = 0;
        while (power * 2 <= kept.Count)
        {
            power *= 2;
            log++;
        }

        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(6), (ushort)(power * 16));
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(8), (ushort)log);
        BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(10), (ushort)(kept.Count * 16 - power * 16));

        int at = dirLength;
        int headAt = -1;
        for (int i = 0; i < kept.Count; i++)
        {
            var (tag, offset, length) = kept[i];
            program.AsSpan(offset, length).CopyTo(result.AsSpan(at));
            if (tag == "head" && length >= 12)
            {
                headAt = at;
                BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(at + 8), 0); // checkSumAdjustment, set below
            }

            int rec = 12 + i * 16;
            Encoding.ASCII.GetBytes(tag).CopyTo(result.AsSpan(rec));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(rec + 4), Checksum(result.AsSpan(at, Padded(length))));
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(rec + 8), (uint)at);
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(rec + 12), (uint)length);
            at += Padded(length);
        }

        if (headAt >= 0)
        {
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(headAt + 8), unchecked(0xB1B0AFBAu - Checksum(result)));
        }

        return result;
    }

    /// <summary>The sum of the big-endian 32-bit words (the data is padded to four bytes).</summary>
    internal static uint Checksum(ReadOnlySpan<byte> data)
    {
        uint sum = 0;
        int i = 0;
        for (; i + 4 <= data.Length; i += 4)
        {
            sum = unchecked(sum + BinaryPrimitives.ReadUInt32BigEndian(data[i..]));
        }

        if (i < data.Length)
        {
            Span<byte> last = stackalloc byte[4];
            data[i..].CopyTo(last);
            sum = unchecked(sum + BinaryPrimitives.ReadUInt32BigEndian(last));
        }

        return sum;
    }

    private static int Padded(int length) => (length + 3) & ~3;
}
