using System;
using System.Globalization;
using System.Text;

namespace RepoLegibility.Core.Pdf;

/// <summary>Formatting of PDF syntax tokens (ISO 32000-1 §7.3): numbers, names, strings.</summary>
internal static class PdfFormat
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>Real number with at most four decimals, invariant culture, never "-0" or exponent form.</summary>
    public static string Num(double value)
    {
        if (double.IsNaN(value) || double.IsInfinity(value))
            throw new ArgumentOutOfRangeException(nameof(value), "PDF numbers must be finite.");
        double r = Math.Round(value, 4, MidpointRounding.AwayFromZero);
        if (r == 0) return "0";
        return r.ToString("0.####", Inv);
    }

    public static string Int(long value) => value.ToString(Inv);

    /// <summary>Name object including the leading slash; delimiters and non-regular bytes as #XX (§7.3.5).</summary>
    public static string Name(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        var sb = new StringBuilder(name.Length + 1).Append('/');
        foreach (byte b in Encoding.UTF8.GetBytes(name))
        {
            bool regular = b >= 0x21 && b <= 0x7E && !"#()<>[]{}/%".Contains((char)b, StringComparison.Ordinal);
            if (regular) sb.Append((char)b);
            else sb.Append('#').Append(b.ToString("X2", Inv));
        }
        return sb.ToString();
    }

    /// <summary>Literal string for 7-bit ASCII content (§7.3.4.2); other bytes are written as octal escapes.</summary>
    public static string AsciiLiteral(string text)
    {
        var sb = new StringBuilder(text.Length + 2).Append('(');
        foreach (char c in text)
        {
            switch (c)
            {
                case '(': sb.Append("\\("); break;
                case ')': sb.Append("\\)"); break;
                case '\\': sb.Append("\\\\"); break;
                default:
                    if (c >= 0x20 && c < 0x7F) sb.Append(c);
                    else if (c <= 0xFF) sb.Append('\\').Append(Convert.ToString(c, 8).PadLeft(3, '0'));
                    else throw new ArgumentException("Only 8-bit characters can be written as a literal string.", nameof(text));
                    break;
            }
        }
        return sb.Append(')').ToString();
    }

    /// <summary>Text string (§7.9.2.2): ASCII as literal, anything else as UTF-16BE with BOM in hex.</summary>
    public static string TextString(string text)
    {
        bool ascii = true;
        foreach (char c in text) if (c < 0x20 || c > 0x7E) { ascii = false; break; }
        if (ascii) return AsciiLiteral(text);
        var bytes = new byte[2 + text.Length * 2];
        bytes[0] = 0xFE; bytes[1] = 0xFF;
        Encoding.BigEndianUnicode.GetBytes(text, 0, text.Length, bytes, 2);
        return "<" + Hex(bytes) + ">";
    }

    public static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes);

    /// <summary>Four-digit hex code for a 2-byte CID / glyph ID.</summary>
    public static string Hex4(int value) => value.ToString("X4", Inv);

    /// <summary>UTF-16BE hex of a string, as used in ToUnicode CMaps (§9.10.3).</summary>
    public static string Utf16Hex(string text) => Hex(Encoding.BigEndianUnicode.GetBytes(text));

    public static byte[] Bytes(string ascii) => Encoding.Latin1.GetBytes(ascii);
}
