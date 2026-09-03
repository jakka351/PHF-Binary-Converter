# PHF-Binary-Converter
Universal PHF to Binary converter based off rollsch/PHF2BIN
 
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
