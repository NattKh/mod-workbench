// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! GameCondition tree case 8: pa::GlobalEffectConditionData.
//!
//! Hand-written from IDA decompile of sub_14114FF40.
//! Stream layout: [u32 effect_id][u8 byte_a (default 8)][u8 byte_b (default 6)]
//! Note: the f32 field at object+8 is zero-initialized from xmm0 in memory only —
//! NOT read from the stream.

use crate::py_binary_struct;

py_binary_struct! {
    pub struct GlobalEffectConditionData {
        pub effect_id: u32,
        pub byte_a: u8,
        pub byte_b: u8,
    }
}
