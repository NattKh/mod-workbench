// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Per-element types for `sub_1411092E0`, the spawn-list payload shared
//! by `TerrainRegionAutoSpawnInfo` and `SpawningPoolAutoSpawnInfo`.
//!
//! The element reader `sub_1410FA2A0` reverse-engineers as fixed-shape
//! (despite original "polymorphic" docstring claims). Per element is a
//! 112-byte mem buffer with the wire layout:
//!   `CArray<PoolSplineEntry> + 2× CArray<u16> + 2× CArray<u32> +
//!    6× u32 + 6× u8 + u16`
//!
//! `PoolSplineEntry` (sub_1410F9F00, 72 mem bytes) is itself
//! `CArray<PoolSplineInnerEntry> + 9× u32 + [u32;4] + 3× u8 + u64`.
//!
//! `PoolSplineInnerEntry` (sub_1410F9DF0, 14 wire / 10 mem) is
//! 2× (u32→u16 hash + u16→u16 hash) + 2× u8.

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    /// `sub_1410F9DF0` per inner element. 14 wire bytes / 10 mem bytes.
    pub struct PoolSplineInnerEntry {
        pub raw_a: u32,    // sub_1410FF340 (u32 wire / u16 mem, qword_DA08)
        pub raw_b: u16,    // sub_1411003E0 (u16 wire / u16 mem, qword_12668)
        pub raw_c: u32,    // sub_1410FF340
        pub raw_d: u16,    // sub_1411003E0
        pub flag_a: u8,
        pub flag_b: u8,
    }
}

py_binary_struct! {
    /// `sub_1410F9F00` per element. 72 mem bytes per parent slot.
    pub struct PoolSplineEntry {
        pub inner_list: CArray<PoolSplineInnerEntry>,
        pub raw_a: u32,        // u32 wire → hash → u32 mem (qword_1ADD0)
        pub raw_b: u32,        // sub_141100740 (u32 wire / u16 mem)
        pub raw_c: u32,        // sub_1410FF5C0 (u32 wire / u16 mem)
        pub raw_d: u32,        // read_u32_lookup_DA30 (u32 wire / u16 mem)
        pub raw_e: u32,        // u32 wire → hash → u16 mem (qword_D9F8)
        pub raw_f: u32,        // raw u32 at mem +28
        pub raw_g: u32,        // raw u32 at mem +32
        pub raw_h: u32,        // raw u32 at mem +36
        pub raw_i: u32,        // raw u32 at mem +40
        pub block: [u32; 4],   // sub_14100CAB0 at mem +44 (4× u32)
        pub flag_a: u8,        // mem +60
        pub flag_b: u8,        // mem +61
        pub flag_c: u8,        // mem +62
        pub raw_qword: u64,    // mem +64
    }
}

py_binary_struct! {
    /// `sub_1410FA2A0` per element. 112 mem bytes (first 16 bytes are the
    /// CArray<PoolSplineEntry> Vec header).
    pub struct AutoSpawnEntry {
        pub spline_list: CArray<PoolSplineEntry>,    // sub_141109110
        pub list_a: CArray<u16>,                     // sub_1410FFAC0 (u16 wire / u16 mem)
        pub list_b: CArray<u16>,                     // sub_1410FFAC0
        pub list_c: CArray<u32>,                     // sub_1410FEF40 (u32 wire / u16 mem)
        pub list_d: CArray<u32>,                     // sub_1410FEF40
        pub raw_a: u32,
        pub raw_b: u32,
        pub raw_c: u32,
        pub raw_d: u32,
        pub raw_e: u32,
        pub raw_f: u32,
        pub flag_a: u8,
        pub flag_b: u8,
        pub flag_c: u8,
        pub flag_d: u8,
        pub flag_e: u8,
        pub flag_f: u8,
        pub final_u16: u16,
    }
}
