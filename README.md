# PHF-Binary-Converter
Universal PHF to Binary converter based off rollsch/PHF2BIN

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
