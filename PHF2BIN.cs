///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 
//   ______          __            ____                            __  _____                 _       ___      __  ___         __                        __  _           _____       __      __  _                 
//  /_  __/__  _____/ /____  _____/ __ \________  ________  ____  / /_/ ___/____  ___  _____(_)___ _/ (_)____/ /_/   | __  __/ /_____  ____ ___  ____  / /_(_)   _____ / ___/____  / /_  __/ /_(_)___  ____  _____
//   / / / _ \/ ___/ __/ _ \/ ___/ /_/ / ___/ _ \/ ___/ _ \/ __ \/ __/\__ \/ __ \/ _ \/ ___/ / __ `/ / / ___/ __/ /| |/ / / / __/ __ \/ __ `__ \/ __ \/ __/ / | / / _ \\__ \/ __ \/ / / / / __/ / __ \/ __ \/ ___/
//  / / /  __(__  ) /_/  __/ /  / ____/ /  /  __(__  )  __/ / / / /_ ___/ / /_/ /  __/ /__/ / /_/ / / (__  ) /_/ ___ / /_/ / /_/ /_/ / / / / / / /_/ / /_/ /| |/ /  __/__/ / /_/ / / /_/ / /_/ / /_/ / / / (__  ) 
// /_/  \___/____/\__/\___/_/  /_/   /_/   \___/____/\___/_/ /_/\__//____/ .___/\___/\___/_/\__,_/_/_/____/\__/_/  |_\__,_/\__/\____/_/ /_/ /_/\____/\__/_/ |___/\___/____/\____/_/\__,_/\__/_/\____/_/ /_/____/  
//                                                                     /_/                                                                                                                                       
//  This is based off Roland's PHF2BIN work, see https://github.com/rollsch/PHF2BIN
//  Tested on FoA Orion module PHF files, confirmed working, this code is fromt the
//  Tester Engineering Suite v1.0.9-2026, made available open source for public use. 
//  See https://tester.engineering and https://testerpresent.com.au
//
//  Handles TWO distinct PHF families, auto-detected:
//
//   1. FORD IDS STRUCTURED PHF  (the common case: 8R29 Orion PCM/FDM, HCS12, MB90340,
//      6HP26, etc.).  A NUL-separated "KEY>VALUE" text header terminated by a lone "$",
//      followed by BINARY Intel-HEX download records:
//          3A  LL  AAAA(BE)  TT  [data×LL]  CC
//      types 00=data 01=EOF 02=ext-segment 04=ext-linear 03/05=start-addr (ignored).
//      CC = two's-complement sum (standard Intel-HEX). The header carries MODULE ID,
//      the part number, and FILE CHECKSUM = (sum of all data bytes) & 0xFFFF — which we
//      recompute and verify.  RE-verified against the sample corpus: every record CRC
//      valid and FILE CHECKSUM reproduced (0x2ACC / 0xF356 / 0xF7D7).
//
//   2. OAK FLAT-IMAGE PHF  (Falcon EEC-VI Spanish/Black/Green Oak).  A flat memory image
//      interleaved with inline block headers; de-interleaved via a data-driven profile
//      (marker → output size + magic + skip geometry + fill holes).  Port of the original
//      rollsch/PHF2BIN logic, now table-driven so new modules are data, not code.
//
//  Output is a flat BIN plus the parsed metadata; the IDS path also emits the sparse
//  address map so the caller can show the real load addresses (and export Intel-HEX/SREC).
//
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
using System;
using System.Collections.Generic;
using System.Text;
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
namespace TesterPresent.OBD2.FileFormats
{
    // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    public enum PhfFamily { Unknown, FordIdsHex, OakFlatImage }

    // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>One de-interleave profile for the oak flat-image family (data-driven).</summary>
    public sealed class OakProfile
    {
        public string[] Markers;      // ASCII markers to find in the first 0x100 bytes
        public string Name;
        public int OutputSize;
        public byte MagicByte10;      // magic header is 0x12 bytes, [0x10]=this, [0x11]=0x60
        public int BlockHdrSkip, BlockHdrEvery;      // skip N input bytes every M output bytes
        public int SubBlockHdrSkip, SubBlockHdrEvery;
        public (int Start, int End, byte Fill)[] Holes; // output ranges filled, not read from input
    }

    // ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    public sealed class PhfConvertResult
    {
        public bool Ok;
        public PhfFamily Family;
        public byte[] Bin = Array.Empty<byte>();
        public uint BaseAddress;      // IDS: lowest record address; oak: 0
        public uint EndAddress;
        public int RecordCount;
        public int BadRecordChecksums;
        public ushort? DeclaredChecksum;   // IDS FILE CHECKSUM
        public ushort? ComputedChecksum;
        public bool ChecksumOk;
        public string ModuleId = "";
        public string PartNumber = "";
        public string ModuleName = "";
        public string ProfileName = "";
        public Dictionary<string, string> Header = new Dictionary<string, string>();
        public string Detail = "";
        public string Error = "";
    }

    public static class PhfConverter
    {
        // ── oak profiles (the original three, now data) ──
        public static readonly OakProfile[] OakProfiles =
        {
            new OakProfile { Markers = new[]{"SPANISHOAK"}, Name = "Spanish Oak (Falcon EEC-VI)", OutputSize = 0x100000, MagicByte10 = 0x10,
                BlockHdrSkip = 8, BlockHdrEvery = 0x10000, SubBlockHdrSkip = 6, SubBlockHdrEvery = 0x20,
                Holes = new[]{ (0x8000, 0x10000, (byte)0xFF) } },
            new OakProfile { Markers = new[]{"BOAK"}, Name = "Black Oak", OutputSize = 0x180000, MagicByte10 = 0x30,
                BlockHdrSkip = 8, BlockHdrEvery = 0x10000, SubBlockHdrSkip = 6, SubBlockHdrEvery = 0x20,
                Holes = new[]{ (0x8000, 0x10000, (byte)0xFF) } },
            new OakProfile { Markers = new[]{"GOAK"}, Name = "Green Oak", OutputSize = 0x180000, MagicByte10 = 0x30,
                BlockHdrSkip = 8, BlockHdrEvery = 0x10000, SubBlockHdrSkip = 6, SubBlockHdrEvery = 0x20,
                Holes = new[]{ (0x8000, 0x10000, (byte)0xFF) } },
        };

        // ══════════════════════════════════════════════════════════════════════
        //  Entry point — auto-detect the family and convert
        // ══════════════════════════════════════════════════════════════════════

        public static PhfConvertResult Convert(byte[] phf)
        {
            var r = new PhfConvertResult();
            if (phf == null || phf.Length < 0x20) { r.Error = "file too small to be a PHF"; return r; }

            var oak = DetectOak(phf);
            if (LooksLikeIds(phf)) { r.Family = PhfFamily.FordIdsHex; return ConvertIds(phf, r); }
            if (oak != null) { r.Family = PhfFamily.OakFlatImage; return ConvertOak(phf, oak, r); }

            r.Family = PhfFamily.Unknown;
            r.Error = "unrecognised PHF: no Ford IDS 'MODULE ID>' header and no SPANISHOAK/BOAK/GOAK marker";
            return r;
        }

        public static PhfFamily Detect(byte[] phf)
        {
            if (phf == null || phf.Length < 0x20) return PhfFamily.Unknown;
            if (LooksLikeIds(phf)) return PhfFamily.FordIdsHex;
            return DetectOak(phf) != null ? PhfFamily.OakFlatImage : PhfFamily.Unknown;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  Ford IDS structured PHF  (binary Intel-HEX)
        // ══════════════════════════════════════════════════════════════════════

        private static bool LooksLikeIds(byte[] phf)
        {
            // The IDS text header lives in the first few KB. Match the long, distinctive field
            // NAMES without the '>' — some dialects write "MODULE ID >" (space before '>') and
            // "  EPROM PART NO." openers, so an exact "KEY>" substring misses them. These phrases
            // do not occur in an oak flat-image binary.
            int n = Math.Min(phf.Length, 0x4000);
            return IndexOfAscii(phf, "DOWNLOAD FORMAT", n) >= 0
                || IndexOfAscii(phf, "FILE CHECKSUM", n) >= 0
                || IndexOfAscii(phf, "APPLICATION>", n) >= 0
                || IndexOfAscii(phf, "MODULE ID>", n) >= 0;
        }

        private static PhfConvertResult ConvertIds(byte[] phf, PhfConvertResult r)
        {
            int dataStart = ParseIdsHeader(phf, r.Header);
            r.ModuleId = r.Header.TryGetValue("MODULE ID", out var mid) ? mid.Trim() : "";
            r.PartNumber = r.Header.TryGetValue("PRODUCTION MODULE PART NUMBER", out var pn) ? pn.Trim()
                          : (r.Header.TryGetValue("FILE NAME", out var fn) ? fn.Trim() : "");
            r.ModuleName = r.Header.TryGetValue("MODULE NAME", out var mn) ? mn.Trim() : "";
            if (r.Header.TryGetValue("FILE CHECKSUM", out var fc)) r.DeclaredChecksum = ParseHexU16(fc);

            // Two-pass parse of the binary Intel-HEX records — no dictionary (some images span
            // millions of addresses). Pass 1: validate + find the address extent; Pass 2: write
            // bytes straight into the sized, 0xFF-filled array.
            uint lo, hi;
            int records, bad;
            long dataSum;
            ScanIdsRecords(phf, dataStart, out lo, out hi, out records, out bad, out dataSum);

            if (records == 0 || hi < lo) { r.Error = "no data records decoded from the PHF"; return r; }

            r.RecordCount = records;
            r.BadRecordChecksums = bad;
            r.ComputedChecksum = (ushort)(dataSum & 0xFFFF);
            r.ChecksumOk = r.DeclaredChecksum == null || r.DeclaredChecksum == r.ComputedChecksum;

            long span = (long)hi - lo + 1;
            if (span <= 0 || span > 64L * 1024 * 1024) { r.Error = $"implausible address span {span} bytes (0x{lo:X}..0x{hi:X})"; return r; }

            var bin = new byte[span];
            for (int i = 0; i < bin.Length; i++) bin[i] = 0xFF;   // gaps = 0xFF (erased flash)
            WriteIdsRecords(phf, dataStart, lo, bin);

            r.Bin = bin;
            r.BaseAddress = lo;
            r.EndAddress = hi;
            r.Ok = true;
            r.Detail = $"Ford IDS PHF · module {r.ModuleId} · {records:N0} records ({bad} bad CRC) · "
                     + $"image 0x{lo:X}–0x{hi:X} ({span:N0} bytes) · FILE CHECKSUM "
                     + (r.DeclaredChecksum != null
                          ? $"0x{r.DeclaredChecksum:X4} " + (r.ChecksumOk ? "OK" : $"MISMATCH (computed 0x{r.ComputedChecksum:X4})")
                          : $"(none) computed 0x{r.ComputedChecksum:X4}");
            return r;
        }

        /// <summary>Parse the NUL-separated KEY&gt;VALUE header up to a lone "$"; return the data offset.</summary>
        private static int ParseIdsHeader(byte[] phf, Dictionary<string, string> header)
        {
            int p = 0;
            while (p < phf.Length)
            {
                int z = p; while (z < phf.Length && phf[z] != 0x00) z++;
                string field = Encoding.GetEncoding("latin1").GetString(phf, p, z - p);
                p = z + 1;                                  // step past the NUL
                string t = field.Trim();
                if (t == "$") return p;                     // header terminator
                int gt = field.IndexOf('>');
                if (gt > 0) header[field.Substring(0, gt).Trim()] = field.Substring(gt + 1);
                if (p >= phf.Length) break;
                // safety: the header lives in the first few KB; if we run past it without a '$', stop
                if (p > 0x4000) break;
            }
            return p;
        }

        /// <summary>Pass 1: validate record checksums, sum data bytes, find the min/max data address.</summary>
        private static void ScanIdsRecords(byte[] phf, int start, out uint lo, out uint hi,
                                           out int records, out int bad, out long dataSum)
        {
            lo = uint.MaxValue; hi = 0; records = 0; bad = 0; dataSum = 0;
            uint linBase = 0, segBase = 0;
            int p = start;
            while (p < phf.Length)
            {
                if (phf[p] != 0x3A) { p++; continue; }
                if (p + 5 > phf.Length) break;
                int ln = phf[p + 1], typ = phf[p + 4];
                uint addr = (uint)((phf[p + 2] << 8) | phf[p + 3]);
                int end = p + 5 + ln + 1;
                if (end > phf.Length) break;

                int sum = ln + phf[p + 2] + phf[p + 3] + typ;
                for (int k = 0; k < ln; k++) sum += phf[p + 5 + k];
                if ((byte)((0x100 - (sum & 0xFF)) & 0xFF) != phf[p + 5 + ln]) bad++;

                if (typ == 0x00)
                {
                    uint bas = linBase + segBase, a0 = bas + addr, a1 = a0 + (uint)(ln == 0 ? 0 : ln - 1);
                    if (ln > 0) { if (a0 < lo) lo = a0; if (a1 > hi) hi = a1; }
                    for (int k = 0; k < ln; k++) dataSum += phf[p + 5 + k];
                }
                else if (typ == 0x01) { records++; break; }
                else if (typ == 0x02) segBase = (uint)(((phf[p + 5] << 8) | phf[p + 6]) << 4);
                else if (typ == 0x04) linBase = (uint)(((phf[p + 5] << 8) | phf[p + 6]) << 16);
                records++;
                p = end;
            }
        }

        /// <summary>Pass 2: write every data record's bytes into bin at (address − lo).</summary>
        private static void WriteIdsRecords(byte[] phf, int start, uint lo, byte[] bin)
        {
            uint linBase = 0, segBase = 0;
            int p = start;
            while (p < phf.Length)
            {
                if (phf[p] != 0x3A) { p++; continue; }
                if (p + 5 > phf.Length) break;
                int ln = phf[p + 1], typ = phf[p + 4];
                uint addr = (uint)((phf[p + 2] << 8) | phf[p + 3]);
                int end = p + 5 + ln + 1;
                if (end > phf.Length) break;

                if (typ == 0x00)
                {
                    uint bas = linBase + segBase;
                    for (int k = 0; k < ln; k++)
                    {
                        long idx = (long)(bas + addr + (uint)k) - lo;
                        if (idx >= 0 && idx < bin.Length) bin[idx] = phf[p + 5 + k];
                    }
                }
                else if (typ == 0x01) break;
                else if (typ == 0x02) segBase = (uint)(((phf[p + 5] << 8) | phf[p + 6]) << 4);
                else if (typ == 0x04) linBase = (uint)(((phf[p + 5] << 8) | phf[p + 6]) << 16);
                p = end;
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        //  Oak flat-image PHF  (de-interleave)
        // ══════════════════════════════════════════════════════════════════════

        public static OakProfile DetectOak(byte[] phf)
        {
            if (phf == null || phf.Length < 0x100) return null;
            foreach (var pr in OakProfiles)
                foreach (var m in pr.Markers)
                    if (IndexOfAscii(phf, m, 0x100) >= 0) return pr;
            return null;
        }

        private static PhfConvertResult ConvertOak(byte[] phf, OakProfile prof, PhfConvertResult r)
        {
            r.ProfileName = prof.Name;
            var magic = new byte[0x12];
            magic[0x10] = prof.MagicByte10; magic[0x11] = 0x60;
            int magicOff = IndexOfBytes(phf, magic, 0);
            if (magicOff < 0) { r.Error = $"{prof.Name}: magic header (…{prof.MagicByte10:X2} 60) not found"; return r; }

            var outBytes = new byte[prof.OutputSize];
            for (int i = 0; i < outBytes.Length; i++) outBytes[i] = 0xFF;

            int outIdx = 0, inIdx = magicOff, padded = 0;
            while (inIdx < phf.Length && outIdx < outBytes.Length)
            {
                if (prof.BlockHdrEvery > 0 && outIdx % prof.BlockHdrEvery == 0 && outIdx != 0) inIdx += prof.BlockHdrSkip;
                if (outIdx >= outBytes.Length) break;

                bool inHole = false;
                if (prof.Holes != null)
                    foreach (var h in prof.Holes)
                        if (outIdx >= h.Start && outIdx < h.End) { outBytes[outIdx] = h.Fill; outIdx++; padded++; inHole = true; break; }
                if (inHole) continue;

                if (prof.SubBlockHdrEvery > 0 && outIdx % prof.SubBlockHdrEvery == 0 && outIdx != 0) inIdx += prof.SubBlockHdrSkip;
                if (outIdx >= outBytes.Length || inIdx >= phf.Length) break;

                outBytes[outIdx++] = phf[inIdx++];
            }

            r.Bin = outBytes;
            r.BaseAddress = 0;
            r.EndAddress = (uint)(prof.OutputSize - 1);
            r.Ok = true;
            r.Detail = $"{prof.Name} · magic @0x{magicOff:X} · {outIdx:N0}/{prof.OutputSize:N0} bytes "
                     + $"({outIdx - padded:N0} from PHF + {padded:N0} fill)";
            return r;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  Export helpers (feed a BIN back out as records)
        // ══════════════════════════════════════════════════════════════════════

        /// <summary>Emit a flat BIN as standard ASCII Intel-HEX (32-byte records, ext-linear addressing).</summary>
        public static string ToIntelHex(byte[] bin, uint baseAddr, int recLen = 0x20)
        {
            var sb = new StringBuilder();
            uint upper = 0xFFFFFFFF;
            for (int off = 0; off < bin.Length; off += recLen)
            {
                uint abs = baseAddr + (uint)off;
                uint hi = abs >> 16;
                if (hi != upper)
                {
                    upper = hi;
                    int s = 0x02 + (int)((hi >> 8) & 0xFF) + (int)(hi & 0xFF) + 0x04;
                    sb.Append($":02000004{hi:X4}{((0x100 - (s & 0xFF)) & 0xFF):X2}\n");
                }
                int ln = Math.Min(recLen, bin.Length - off);
                int sum = ln + (int)((abs >> 8) & 0xFF) + (int)(abs & 0xFF) + 0x00;
                var line = new StringBuilder($":{ln:X2}{(abs & 0xFFFF):X4}00");
                for (int k = 0; k < ln; k++) { byte b = bin[off + k]; sum += b; line.Append(b.ToString("X2")); }
                line.Append(((0x100 - (sum & 0xFF)) & 0xFF).ToString("X2"));
                sb.Append(line).Append('\n');
            }
            sb.Append(":00000001FF\n");
            return sb.ToString();
        }

        // ── byte helpers ──
        private static ushort? ParseHexU16(string s)
        {
            if (string.IsNullOrWhiteSpace(s)) return null;
            s = s.Trim();
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) s = s.Substring(2);
            return ushort.TryParse(s, System.Globalization.NumberStyles.HexNumber, null, out var v) ? v : (ushort?)null;
        }

        private static int IndexOfAscii(byte[] hay, string needle, int limit)
            => IndexOfBytes(hay, Encoding.ASCII.GetBytes(needle), 0, limit);

        private static int IndexOfBytes(byte[] hay, byte[] needle, int start, int limit = int.MaxValue)
        {
            if (hay == null || needle == null || needle.Length == 0) return -1;
            int max = Math.Min(hay.Length - needle.Length, limit - needle.Length);
            for (int i = start; i <= max; i++)
            {
                int k = 0;
                while (k < needle.Length && hay[i + k] == needle[k]) k++;
                if (k == needle.Length) return i;
            }
            return -1;
        }
    }
}
