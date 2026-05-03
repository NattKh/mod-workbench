// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1.5 — typed prefix + Decoded|Raw fallback tail.
//!
//! Reader: `sub_1410E6FC0` in CrimsonDesert.exe (Win build). Massive
//! 7205-byte function, 100+ wire reads in the body. Fields 1-16 are
//! typed (joined with the prefix when the tail decodes successfully);
//! the 99.93% of vanilla entries that decode cleanly carry the rest as
//! `post_blob`. Field 17 (sub_1411125E0 → sub_141D7FF30 →
//! sub_141D80A90) is the next blocker: sub_141D80A90 is the
//! TriggerGamePlayEventHandlerData polymorphic ReflectObject dispatcher
//! (see STATUS.md "Deferred — ReflectObject reflection layer").
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u32 key                       (_key, mem a2+8)
//!   2. CString string_key            (_stringKey, mem a2+16)
//!   3. u8 is_blocked                 (_isBlocked, mem a2+24)
//!   4. CString prefab_path           (_prefabPath, mem a2+32)
//!   5. u32 gimmick_group_info        (_gimmickGroupInfo, sub_141104AE0
//!      → qword_145F11D70 lookup, mem a2+40)
//!   6. u16 breakable_object_info     (_breakableObjectInfo, inline u16 →
//!      qword_145F15960 lookup, wire u16, mem a2+42)
//!      ← TAIL STARTS HERE
//!   7. _gimmickInteractionOverrideDataList (sub_141118470 →
//!      CArray<COptional<144-byte item via sub_1410DF770>>; inner has 15
//!      wire reads incl. LocalizableString, CArray<{CStr hash + u32}>,
//!      sub_141100E90 CArray<32-byte item>, sub_141101AB0/sub_141103C30
//!      lookups, sub_141114FC0/sub_141E2C900 unknown helpers, mem a2+48)
//!   8. u8 _useInteractionUISocket    (mem a2+64)
//!   9. u8 _useSubPartForInteraction  (mem a2+65)
//!  10. _propertyList                 (sub_141101AB0, 16-byte CArray
//!      header at mem a2+72)
//!  11. u32 _gimmickNameHash          (mem a2+88)
//!  12. LocalizableString _gimmickName (mem a2+96)
//!  13. CString _emojiTextureID       (mem a2+128)
//!  14. CString _devMemo              (mem a2+136)
//!  15. sub_141104D20 (16 mem bytes)  (mem a2+144)
//!  16. sub_141102990 (16 mem bytes)  (mem a2+160)
//!  17. sub_1411125E0 (16 mem bytes)  (mem a2+176)
//!  18. _gimmickChartParameterList    (CArray of 16-byte items via
//!      sub_141C7F8B0; per element u32 + u8 + u32 + u8, mem a2+192)
//!  19. … 80+ more wire reads.
//!
//! Steps 1-16 are typed (joined with the prefix when Decoded). Field
//! 17 (sub_1411125E0) blocks further extension — see header note.
//!
//! ## GimmickInteractionOverrideData wire layout (sub_1410DF770)
//!
//! 144 mem bytes per element, 15 wire fields. Decompiled from Win-IDA
//! this session.
//!
//!   1. sub_1411026F0 — u16 lookup                    (mem +0)
//!   2. read_LocalizableString                        (mem +8, 32 b)
//!   3. u32 raw                                       (mem +40)
//!   4. CArray<{u32 hash + u32 raw}> (8-byte stride)  (mem +48, 16 b)
//!      — outer reads u32 count, then each element: sub_1410A9D40
//!      (CString-hash → u32) + u32 raw.
//!   5. sub_141114FC0 — CArray of 48-byte items via   (mem +64, 16 b)
//!      sub_1410DF4C0; per-element wire: u32 + CString-hash +
//!      CString + u32 + Vec3 + 3× u32. (Verified Win-IDA, 7 wire
//!      reads / 48 mem bytes.)
//!   6. sub_141E2C900 — `CArray<ConditionPair>` via   (mem +80, 16 b)
//!      `BareConditionPairCArray`. NO per-element COptional —
//!      bare ConditionPair stride. ← stream-mode GameCondition
//!      blocker starts here.
//!   7. sub_141100E90 — CArray of 32-byte items       (mem +96, 16 b)
//!      (28 wire bytes per element: f32 + 3× 8-byte clusters).
//!   8. sub_141101AB0 — `CArray<u32>`                 (mem +112, 16 b)
//!   9. sub_141103C30 — u32 lookup                    (mem +128)
//!  10. sub_141100370 — u16 lookup                    (mem +132)
//!  11. u8 flag                                       (mem +134)
//!  12. u8 flag                                       (mem +135)
//!  13. u8 flag                                       (mem +136)
//!  14. u8 flag                                       (mem +137)
//!  15. u8 flag                                       (mem +138)
//!
//! Outer wrapper (sub_141118470): `CArray<COptional<...>>` — u32
//! count + per-element u8 presence + (if present) heap-allocated
//! 144-byte GimmickInteractionOverrideData populated by
//! sub_1410DF770.

use crate::binary::*;
use crate::binary::variants::gimmick_interaction_override::GimmickInteractionOverrideCArray;
use crate::binary::variants::trigger_gameplay_event_handler_data::OptionalTriggerGamePlayEventHandlerData;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{Map, Value};
use std::io::{self, Write};

py_binary_struct! {
    /// `sub_141104D20` per-element. 8-byte mem stride; wire = 2× CString
    /// (each consumed via sub_1410A9D40 → u32 hash, packed into a qword).
    pub struct GimmickHashPair<'a> {
        pub hash_a: CString<'a>,
        pub hash_b: CString<'a>,
    }
}

py_binary_struct! {
    /// `sub_1410A9D40` wrapper. 4-byte mem stride; wire = CString.
    pub struct GimmickHashSingle<'a> {
        pub hash: CString<'a>,
    }
}

py_binary_struct! {
    /// Field 18 — `_gimmickChartParameterList` per-element.
    /// Win-IDA `sub_141C7F8B0`: 16-byte mem stride; wire = u32 + u8 + u32 + u8
    /// = 10 wire bytes per element. CArray<GimmickChartParameter>.
    pub struct GimmickChartParameter {
        pub a: u32,
        pub b: u8,
        pub c: u32,
        pub d: u8,
    }
}

/// Tail of GimmickInfo. When the field-7 CArray decode succeeds (and
/// the immediately-following stable scalar block parses cleanly) it
/// joins the typed prefix; the rest of the body (~85 fields) still
/// rides as `post_blob`. On any decode failure the entire post-prefix
/// region is captured as `Raw`.
#[derive(Debug)]
pub enum GimmickTail<'a> {
    Decoded {
        gimmick_interaction_override_list: GimmickInteractionOverrideCArray<'a>,
        use_interaction_ui_socket: u8,
        use_sub_part_for_interaction: u8,
        property_list: CArray<u32>,
        gimmick_name_hash: u32,
        gimmick_name: Box<LocalizableString<'a>>,
        emoji_texture_id: CString<'a>,
        dev_memo: CString<'a>,
        hash_pair_list: CArray<GimmickHashPair<'a>>,    // sub_141104D20
        hash_single_list: CArray<GimmickHashSingle<'a>>, // sub_141102990
        /// sub_1411125E0 — `CArray<COptional<TriggerGamePlayEventHandlerData>>`.
        /// Decoded when the typed reader cleanly consumes the bytes; falls
        /// back to leaving these bytes inside `post_blob` if any TGPEHD
        /// variant decode under/over-reads.
        trigger_event_handler_list: Option<CArray<OptionalTriggerGamePlayEventHandlerData<'a>>>,
        /// Field 18 — `_gimmickChartParameterList` (sub_141C7F8B0). 10 wire
        /// bytes per element (u32+u8+u32+u8). Best-effort typed; bytes
        /// remain in post_blob if decode under/over-reads.
        gimmick_chart_parameter_list: Option<CArray<GimmickChartParameter>>,
        /// Field 19 — empirically `CArray<u32>` (count=0 in 99.4% of vanilla
        /// entries; first u32 of post_blob after field 18 is 0x00000000).
        /// Only attempted if field 18 succeeded.
        field_19_u32_list: Option<CArray<u32>>,
        /// Field 20 — empirically `CArray<u32>` (mostly empty, but some
        /// entries have count=1 with item=0).
        field_20_u32_list: Option<CArray<u32>>,
        /// Field 21 — empirically `CArray<u32>` continuation. 98.8% empty.
        field_21_u32_list: Option<CArray<u32>>,
        /// Field 22 — empirically `CArray<u32>` continuation.
        field_22_u32_list: Option<CArray<u32>>,
        /// Field 23 — empirically `CArray<u32>` continuation; some
        /// entries have non-zero (possibly float-bit) values that may
        /// indicate this is actually a different type — defensive parse
        /// keeps it Option.
        field_23_u32_list: Option<CArray<u32>>,
        /// Field 24 — empirically `CArray<u32>` continuation OR a structured
        /// "emissive bind" record (63 entries) `{flag_a:u8, value_a:u32,
        /// flag_b:u8, name:CString, value_b:u32}` for material parameter
        /// bindings (e.g. "_emissiveProgressGauge"). When the structured
        /// record is detected (first byte = 0x01), it consumes those bytes
        /// and CArray<u32> attempt is skipped.
        field_24_u32_list: Option<CArray<u32>>,
        /// Structured emissive-bind record at field_24 position (mutually
        /// exclusive with field_24_u32_list).
        field_24_emissive_flag_a: Option<u8>,
        field_24_emissive_value_a: Option<u32>,
        field_24_emissive_flag_b: Option<u8>,
        field_24_emissive_name: Option<CString<'a>>,
        field_24_emissive_value_b: Option<u32>,
        /// Field 25 — empirically `CArray<u32>` continuation.
        field_25_u32_list: Option<CArray<u32>>,
        /// Field 26 — single u32 (probably a hash/key, NOT a CArray).
        /// Adding as CArray<u32> dropped typed-entry count 7318→121,
        /// confirming this is a different type.
        field_26_u32: Option<u32>,
        /// Field 27 — empirically `CArray<u32>` (most entries count=0,
        /// 106 entries count=1).
        field_27_u32_list: Option<CArray<u32>>,
        /// Field 28 — single u32 hash/key (7176 entries share value
        /// 0x150B14D0; clearly not a CArray count).
        field_28_u32: Option<u32>,
        /// Field 29 — empirically `CArray<u32>` continuation.
        field_29_u32_list: Option<CArray<u32>>,
        /// Field 30 — empirically `CArray<u32>` continuation.
        field_30_u32_list: Option<CArray<u32>>,
        /// Field 31 — empirically `CArray<u32>` continuation OR for 724
        /// entries a structured fixed-pattern record. When CArray fails,
        /// alt u32 chain (f31_alt_001..064) activates to consume bytes.
        field_31_u32_list: Option<CArray<u32>>,
        /// Field 31 alt — 64× chained u32s when CArray<u32> fails.
        f31_alt_001: Option<u32>, f31_alt_002: Option<u32>, f31_alt_003: Option<u32>, f31_alt_004: Option<u32>,
        f31_alt_005: Option<u32>, f31_alt_006: Option<u32>, f31_alt_007: Option<u32>, f31_alt_008: Option<u32>,
        f31_alt_009: Option<u32>, f31_alt_010: Option<u32>, f31_alt_011: Option<u32>, f31_alt_012: Option<u32>,
        f31_alt_013: Option<u32>, f31_alt_014: Option<u32>, f31_alt_015: Option<u32>, f31_alt_016: Option<u32>,
        f31_alt_017: Option<u32>, f31_alt_018: Option<u32>, f31_alt_019: Option<u32>, f31_alt_020: Option<u32>,
        f31_alt_021: Option<u32>, f31_alt_022: Option<u32>, f31_alt_023: Option<u32>, f31_alt_024: Option<u32>,
        f31_alt_025: Option<u32>, f31_alt_026: Option<u32>, f31_alt_027: Option<u32>, f31_alt_028: Option<u32>,
        f31_alt_029: Option<u32>, f31_alt_030: Option<u32>, f31_alt_031: Option<u32>, f31_alt_032: Option<u32>,
        f31_alt_033: Option<u32>, f31_alt_034: Option<u32>, f31_alt_035: Option<u32>, f31_alt_036: Option<u32>,
        f31_alt_037: Option<u32>, f31_alt_038: Option<u32>, f31_alt_039: Option<u32>, f31_alt_040: Option<u32>,
        f31_alt_041: Option<u32>, f31_alt_042: Option<u32>, f31_alt_043: Option<u32>, f31_alt_044: Option<u32>,
        f31_alt_045: Option<u32>, f31_alt_046: Option<u32>, f31_alt_047: Option<u32>, f31_alt_048: Option<u32>,
        f31_alt_049: Option<u32>, f31_alt_050: Option<u32>, f31_alt_051: Option<u32>, f31_alt_052: Option<u32>,
        f31_alt_053: Option<u32>, f31_alt_054: Option<u32>, f31_alt_055: Option<u32>, f31_alt_056: Option<u32>,
        f31_alt_057: Option<u32>, f31_alt_058: Option<u32>, f31_alt_059: Option<u32>, f31_alt_060: Option<u32>,
        f31_alt_061: Option<u32>, f31_alt_062: Option<u32>, f31_alt_063: Option<u32>, f31_alt_064: Option<u32>,
        /// f31_alt extension: 65-128
        f31_alt_065: Option<u32>, f31_alt_066: Option<u32>, f31_alt_067: Option<u32>, f31_alt_068: Option<u32>,
        f31_alt_069: Option<u32>, f31_alt_070: Option<u32>, f31_alt_071: Option<u32>, f31_alt_072: Option<u32>,
        f31_alt_073: Option<u32>, f31_alt_074: Option<u32>, f31_alt_075: Option<u32>, f31_alt_076: Option<u32>,
        f31_alt_077: Option<u32>, f31_alt_078: Option<u32>, f31_alt_079: Option<u32>, f31_alt_080: Option<u32>,
        f31_alt_081: Option<u32>, f31_alt_082: Option<u32>, f31_alt_083: Option<u32>, f31_alt_084: Option<u32>,
        f31_alt_085: Option<u32>, f31_alt_086: Option<u32>, f31_alt_087: Option<u32>, f31_alt_088: Option<u32>,
        f31_alt_089: Option<u32>, f31_alt_090: Option<u32>, f31_alt_091: Option<u32>, f31_alt_092: Option<u32>,
        f31_alt_093: Option<u32>, f31_alt_094: Option<u32>, f31_alt_095: Option<u32>, f31_alt_096: Option<u32>,
        f31_alt_097: Option<u32>, f31_alt_098: Option<u32>, f31_alt_099: Option<u32>, f31_alt_100: Option<u32>,
        f31_alt_101: Option<u32>, f31_alt_102: Option<u32>, f31_alt_103: Option<u32>, f31_alt_104: Option<u32>,
        f31_alt_105: Option<u32>, f31_alt_106: Option<u32>, f31_alt_107: Option<u32>, f31_alt_108: Option<u32>,
        f31_alt_109: Option<u32>, f31_alt_110: Option<u32>, f31_alt_111: Option<u32>, f31_alt_112: Option<u32>,
        f31_alt_113: Option<u32>, f31_alt_114: Option<u32>, f31_alt_115: Option<u32>, f31_alt_116: Option<u32>,
        f31_alt_117: Option<u32>, f31_alt_118: Option<u32>, f31_alt_119: Option<u32>, f31_alt_120: Option<u32>,
        f31_alt_121: Option<u32>, f31_alt_122: Option<u32>, f31_alt_123: Option<u32>, f31_alt_124: Option<u32>,
        f31_alt_125: Option<u32>, f31_alt_126: Option<u32>, f31_alt_127: Option<u32>, f31_alt_128: Option<u32>,
        f31_alt_129: Option<u32>, f31_alt_130: Option<u32>, f31_alt_131: Option<u32>, f31_alt_132: Option<u32>,
        f31_alt_133: Option<u32>, f31_alt_134: Option<u32>, f31_alt_135: Option<u32>, f31_alt_136: Option<u32>,
        f31_alt_137: Option<u32>, f31_alt_138: Option<u32>, f31_alt_139: Option<u32>, f31_alt_140: Option<u32>,
        f31_alt_141: Option<u32>, f31_alt_142: Option<u32>, f31_alt_143: Option<u32>, f31_alt_144: Option<u32>,
        f31_alt_145: Option<u32>, f31_alt_146: Option<u32>, f31_alt_147: Option<u32>, f31_alt_148: Option<u32>,
        f31_alt_149: Option<u32>, f31_alt_150: Option<u32>, f31_alt_151: Option<u32>, f31_alt_152: Option<u32>,
        f31_alt_153: Option<u32>, f31_alt_154: Option<u32>, f31_alt_155: Option<u32>, f31_alt_156: Option<u32>,
        f31_alt_157: Option<u32>, f31_alt_158: Option<u32>, f31_alt_159: Option<u32>, f31_alt_160: Option<u32>,
        f31_alt_161: Option<u32>, f31_alt_162: Option<u32>, f31_alt_163: Option<u32>, f31_alt_164: Option<u32>,
        f31_alt_165: Option<u32>, f31_alt_166: Option<u32>, f31_alt_167: Option<u32>, f31_alt_168: Option<u32>,
        f31_alt_169: Option<u32>, f31_alt_170: Option<u32>, f31_alt_171: Option<u32>, f31_alt_172: Option<u32>,
        f31_alt_173: Option<u32>, f31_alt_174: Option<u32>, f31_alt_175: Option<u32>, f31_alt_176: Option<u32>,
        f31_alt_177: Option<u32>, f31_alt_178: Option<u32>, f31_alt_179: Option<u32>, f31_alt_180: Option<u32>,
        f31_alt_181: Option<u32>, f31_alt_182: Option<u32>, f31_alt_183: Option<u32>, f31_alt_184: Option<u32>,
        f31_alt_185: Option<u32>, f31_alt_186: Option<u32>, f31_alt_187: Option<u32>, f31_alt_188: Option<u32>,
        f31_alt_189: Option<u32>, f31_alt_190: Option<u32>, f31_alt_191: Option<u32>, f31_alt_192: Option<u32>,
        f31_alt_193: Option<u32>, f31_alt_194: Option<u32>, f31_alt_195: Option<u32>, f31_alt_196: Option<u32>,
        f31_alt_197: Option<u32>, f31_alt_198: Option<u32>, f31_alt_199: Option<u32>, f31_alt_200: Option<u32>,
        f31_alt_201: Option<u32>, f31_alt_202: Option<u32>, f31_alt_203: Option<u32>, f31_alt_204: Option<u32>,
        f31_alt_205: Option<u32>, f31_alt_206: Option<u32>, f31_alt_207: Option<u32>, f31_alt_208: Option<u32>,
        f31_alt_209: Option<u32>, f31_alt_210: Option<u32>, f31_alt_211: Option<u32>, f31_alt_212: Option<u32>,
        f31_alt_213: Option<u32>, f31_alt_214: Option<u32>, f31_alt_215: Option<u32>, f31_alt_216: Option<u32>,
        f31_alt_217: Option<u32>, f31_alt_218: Option<u32>, f31_alt_219: Option<u32>, f31_alt_220: Option<u32>,
        f31_alt_221: Option<u32>, f31_alt_222: Option<u32>, f31_alt_223: Option<u32>, f31_alt_224: Option<u32>,
        f31_alt_225: Option<u32>, f31_alt_226: Option<u32>, f31_alt_227: Option<u32>, f31_alt_228: Option<u32>,
        f31_alt_229: Option<u32>, f31_alt_230: Option<u32>, f31_alt_231: Option<u32>, f31_alt_232: Option<u32>,
        f31_alt_233: Option<u32>, f31_alt_234: Option<u32>, f31_alt_235: Option<u32>, f31_alt_236: Option<u32>,
        f31_alt_237: Option<u32>, f31_alt_238: Option<u32>, f31_alt_239: Option<u32>, f31_alt_240: Option<u32>,
        f31_alt_241: Option<u32>, f31_alt_242: Option<u32>, f31_alt_243: Option<u32>, f31_alt_244: Option<u32>,
        f31_alt_245: Option<u32>, f31_alt_246: Option<u32>, f31_alt_247: Option<u32>, f31_alt_248: Option<u32>,
        f31_alt_249: Option<u32>, f31_alt_250: Option<u32>, f31_alt_251: Option<u32>, f31_alt_252: Option<u32>,
        f31_alt_253: Option<u32>, f31_alt_254: Option<u32>, f31_alt_255: Option<u32>, f31_alt_256: Option<u32>,
        /// Field 32 alt — 64× chained u32s when field_32 CArray<u32> fails
        /// (691 entries with XML content embedded as CString-prefixed text).
        f32_alt_001: Option<u32>, f32_alt_002: Option<u32>, f32_alt_003: Option<u32>, f32_alt_004: Option<u32>,
        f32_alt_005: Option<u32>, f32_alt_006: Option<u32>, f32_alt_007: Option<u32>, f32_alt_008: Option<u32>,
        f32_alt_009: Option<u32>, f32_alt_010: Option<u32>, f32_alt_011: Option<u32>, f32_alt_012: Option<u32>,
        f32_alt_013: Option<u32>, f32_alt_014: Option<u32>, f32_alt_015: Option<u32>, f32_alt_016: Option<u32>,
        f32_alt_017: Option<u32>, f32_alt_018: Option<u32>, f32_alt_019: Option<u32>, f32_alt_020: Option<u32>,
        f32_alt_021: Option<u32>, f32_alt_022: Option<u32>, f32_alt_023: Option<u32>, f32_alt_024: Option<u32>,
        f32_alt_025: Option<u32>, f32_alt_026: Option<u32>, f32_alt_027: Option<u32>, f32_alt_028: Option<u32>,
        f32_alt_029: Option<u32>, f32_alt_030: Option<u32>, f32_alt_031: Option<u32>, f32_alt_032: Option<u32>,
        f32_alt_033: Option<u32>, f32_alt_034: Option<u32>, f32_alt_035: Option<u32>, f32_alt_036: Option<u32>,
        f32_alt_037: Option<u32>, f32_alt_038: Option<u32>, f32_alt_039: Option<u32>, f32_alt_040: Option<u32>,
        f32_alt_041: Option<u32>, f32_alt_042: Option<u32>, f32_alt_043: Option<u32>, f32_alt_044: Option<u32>,
        f32_alt_045: Option<u32>, f32_alt_046: Option<u32>, f32_alt_047: Option<u32>, f32_alt_048: Option<u32>,
        f32_alt_049: Option<u32>, f32_alt_050: Option<u32>, f32_alt_051: Option<u32>, f32_alt_052: Option<u32>,
        f32_alt_053: Option<u32>, f32_alt_054: Option<u32>, f32_alt_055: Option<u32>, f32_alt_056: Option<u32>,
        f32_alt_057: Option<u32>, f32_alt_058: Option<u32>, f32_alt_059: Option<u32>, f32_alt_060: Option<u32>,
        f32_alt_061: Option<u32>, f32_alt_062: Option<u32>, f32_alt_063: Option<u32>, f32_alt_064: Option<u32>,
        f32_alt_065: Option<u32>, f32_alt_066: Option<u32>, f32_alt_067: Option<u32>, f32_alt_068: Option<u32>,
        f32_alt_069: Option<u32>, f32_alt_070: Option<u32>, f32_alt_071: Option<u32>, f32_alt_072: Option<u32>,
        f32_alt_073: Option<u32>, f32_alt_074: Option<u32>, f32_alt_075: Option<u32>, f32_alt_076: Option<u32>,
        f32_alt_077: Option<u32>, f32_alt_078: Option<u32>, f32_alt_079: Option<u32>, f32_alt_080: Option<u32>,
        f32_alt_081: Option<u32>, f32_alt_082: Option<u32>, f32_alt_083: Option<u32>, f32_alt_084: Option<u32>,
        f32_alt_085: Option<u32>, f32_alt_086: Option<u32>, f32_alt_087: Option<u32>, f32_alt_088: Option<u32>,
        f32_alt_089: Option<u32>, f32_alt_090: Option<u32>, f32_alt_091: Option<u32>, f32_alt_092: Option<u32>,
        f32_alt_093: Option<u32>, f32_alt_094: Option<u32>, f32_alt_095: Option<u32>, f32_alt_096: Option<u32>,
        f32_alt_097: Option<u32>, f32_alt_098: Option<u32>, f32_alt_099: Option<u32>, f32_alt_100: Option<u32>,
        f32_alt_101: Option<u32>, f32_alt_102: Option<u32>, f32_alt_103: Option<u32>, f32_alt_104: Option<u32>,
        f32_alt_105: Option<u32>, f32_alt_106: Option<u32>, f32_alt_107: Option<u32>, f32_alt_108: Option<u32>,
        f32_alt_109: Option<u32>, f32_alt_110: Option<u32>, f32_alt_111: Option<u32>, f32_alt_112: Option<u32>,
        f32_alt_113: Option<u32>, f32_alt_114: Option<u32>, f32_alt_115: Option<u32>, f32_alt_116: Option<u32>,
        f32_alt_117: Option<u32>, f32_alt_118: Option<u32>, f32_alt_119: Option<u32>, f32_alt_120: Option<u32>,
        f32_alt_121: Option<u32>, f32_alt_122: Option<u32>, f32_alt_123: Option<u32>, f32_alt_124: Option<u32>,
        f32_alt_125: Option<u32>, f32_alt_126: Option<u32>, f32_alt_127: Option<u32>, f32_alt_128: Option<u32>,
        f32_alt_129: Option<u32>, f32_alt_130: Option<u32>, f32_alt_131: Option<u32>, f32_alt_132: Option<u32>,
        f32_alt_133: Option<u32>, f32_alt_134: Option<u32>, f32_alt_135: Option<u32>, f32_alt_136: Option<u32>,
        f32_alt_137: Option<u32>, f32_alt_138: Option<u32>, f32_alt_139: Option<u32>, f32_alt_140: Option<u32>,
        f32_alt_141: Option<u32>, f32_alt_142: Option<u32>, f32_alt_143: Option<u32>, f32_alt_144: Option<u32>,
        f32_alt_145: Option<u32>, f32_alt_146: Option<u32>, f32_alt_147: Option<u32>, f32_alt_148: Option<u32>,
        f32_alt_149: Option<u32>, f32_alt_150: Option<u32>, f32_alt_151: Option<u32>, f32_alt_152: Option<u32>,
        f32_alt_153: Option<u32>, f32_alt_154: Option<u32>, f32_alt_155: Option<u32>, f32_alt_156: Option<u32>,
        f32_alt_157: Option<u32>, f32_alt_158: Option<u32>, f32_alt_159: Option<u32>, f32_alt_160: Option<u32>,
        f32_alt_161: Option<u32>, f32_alt_162: Option<u32>, f32_alt_163: Option<u32>, f32_alt_164: Option<u32>,
        f32_alt_165: Option<u32>, f32_alt_166: Option<u32>, f32_alt_167: Option<u32>, f32_alt_168: Option<u32>,
        f32_alt_169: Option<u32>, f32_alt_170: Option<u32>, f32_alt_171: Option<u32>, f32_alt_172: Option<u32>,
        f32_alt_173: Option<u32>, f32_alt_174: Option<u32>, f32_alt_175: Option<u32>, f32_alt_176: Option<u32>,
        f32_alt_177: Option<u32>, f32_alt_178: Option<u32>, f32_alt_179: Option<u32>, f32_alt_180: Option<u32>,
        f32_alt_181: Option<u32>, f32_alt_182: Option<u32>, f32_alt_183: Option<u32>, f32_alt_184: Option<u32>,
        f32_alt_185: Option<u32>, f32_alt_186: Option<u32>, f32_alt_187: Option<u32>, f32_alt_188: Option<u32>,
        f32_alt_189: Option<u32>, f32_alt_190: Option<u32>, f32_alt_191: Option<u32>, f32_alt_192: Option<u32>,
        /// Field 32 — empirically `CArray<u32>` continuation.
        field_32_u32_list: Option<CArray<u32>>,
        /// Field 33 — single u32 hash (6492 entries share 0x6c000000).
        field_33_u32: Option<u32>,
        /// Field 34 — single u32 hash (6102 entries share 0x00BCDE86 —
        /// likely a default reference shared across gimmicks).
        field_34_u32: Option<u32>,
        /// Field 35 — empirically `CArray<u32>` (6406/6411 have count=0).
        field_35_u32_list: Option<CArray<u32>>,
        /// Field 36 — single u32, flag-packed (6242 entries share
        /// `0x0001FF00`; pattern `0x00FF##00`).
        field_36_u32: Option<u32>,
        /// Field 37 — single u32 hash/value (6228 entries share `0xC39F0000`).
        field_37_u32: Option<u32>,
        /// Field 38 — single u32 (continuation hash).
        field_38_u32: Option<u32>,
        /// Field 39 — empirically `CArray<u32>` OR for 724 entries (565 with
        /// `0x00010200`, 159 with `0xdaa20000`), a structured fixed-pattern
        /// record. Alt u32 chain (f39_alt_001..064) activates when CArray fails.
        field_39_u32_list: Option<CArray<u32>>,
        /// Field 39 alt — 64× chained u32s when field_39 CArray<u32> fails.
        f39_alt_001: Option<u32>, f39_alt_002: Option<u32>, f39_alt_003: Option<u32>, f39_alt_004: Option<u32>,
        f39_alt_005: Option<u32>, f39_alt_006: Option<u32>, f39_alt_007: Option<u32>, f39_alt_008: Option<u32>,
        f39_alt_009: Option<u32>, f39_alt_010: Option<u32>, f39_alt_011: Option<u32>, f39_alt_012: Option<u32>,
        f39_alt_013: Option<u32>, f39_alt_014: Option<u32>, f39_alt_015: Option<u32>, f39_alt_016: Option<u32>,
        f39_alt_017: Option<u32>, f39_alt_018: Option<u32>, f39_alt_019: Option<u32>, f39_alt_020: Option<u32>,
        f39_alt_021: Option<u32>, f39_alt_022: Option<u32>, f39_alt_023: Option<u32>, f39_alt_024: Option<u32>,
        f39_alt_025: Option<u32>, f39_alt_026: Option<u32>, f39_alt_027: Option<u32>, f39_alt_028: Option<u32>,
        f39_alt_029: Option<u32>, f39_alt_030: Option<u32>, f39_alt_031: Option<u32>, f39_alt_032: Option<u32>,
        f39_alt_033: Option<u32>, f39_alt_034: Option<u32>, f39_alt_035: Option<u32>, f39_alt_036: Option<u32>,
        f39_alt_037: Option<u32>, f39_alt_038: Option<u32>, f39_alt_039: Option<u32>, f39_alt_040: Option<u32>,
        f39_alt_041: Option<u32>, f39_alt_042: Option<u32>, f39_alt_043: Option<u32>, f39_alt_044: Option<u32>,
        f39_alt_045: Option<u32>, f39_alt_046: Option<u32>, f39_alt_047: Option<u32>, f39_alt_048: Option<u32>,
        f39_alt_049: Option<u32>, f39_alt_050: Option<u32>, f39_alt_051: Option<u32>, f39_alt_052: Option<u32>,
        f39_alt_053: Option<u32>, f39_alt_054: Option<u32>, f39_alt_055: Option<u32>, f39_alt_056: Option<u32>,
        f39_alt_057: Option<u32>, f39_alt_058: Option<u32>, f39_alt_059: Option<u32>, f39_alt_060: Option<u32>,
        f39_alt_061: Option<u32>, f39_alt_062: Option<u32>, f39_alt_063: Option<u32>, f39_alt_064: Option<u32>,
        f39_alt_065: Option<u32>, f39_alt_066: Option<u32>, f39_alt_067: Option<u32>, f39_alt_068: Option<u32>,
        f39_alt_069: Option<u32>, f39_alt_070: Option<u32>, f39_alt_071: Option<u32>, f39_alt_072: Option<u32>,
        f39_alt_073: Option<u32>, f39_alt_074: Option<u32>, f39_alt_075: Option<u32>, f39_alt_076: Option<u32>,
        f39_alt_077: Option<u32>, f39_alt_078: Option<u32>, f39_alt_079: Option<u32>, f39_alt_080: Option<u32>,
        f39_alt_081: Option<u32>, f39_alt_082: Option<u32>, f39_alt_083: Option<u32>, f39_alt_084: Option<u32>,
        f39_alt_085: Option<u32>, f39_alt_086: Option<u32>, f39_alt_087: Option<u32>, f39_alt_088: Option<u32>,
        f39_alt_089: Option<u32>, f39_alt_090: Option<u32>, f39_alt_091: Option<u32>, f39_alt_092: Option<u32>,
        f39_alt_093: Option<u32>, f39_alt_094: Option<u32>, f39_alt_095: Option<u32>, f39_alt_096: Option<u32>,
        f39_alt_097: Option<u32>, f39_alt_098: Option<u32>, f39_alt_099: Option<u32>, f39_alt_100: Option<u32>,
        f39_alt_101: Option<u32>, f39_alt_102: Option<u32>, f39_alt_103: Option<u32>, f39_alt_104: Option<u32>,
        f39_alt_105: Option<u32>, f39_alt_106: Option<u32>, f39_alt_107: Option<u32>, f39_alt_108: Option<u32>,
        f39_alt_109: Option<u32>, f39_alt_110: Option<u32>, f39_alt_111: Option<u32>, f39_alt_112: Option<u32>,
        f39_alt_113: Option<u32>, f39_alt_114: Option<u32>, f39_alt_115: Option<u32>, f39_alt_116: Option<u32>,
        f39_alt_117: Option<u32>, f39_alt_118: Option<u32>, f39_alt_119: Option<u32>, f39_alt_120: Option<u32>,
        f39_alt_121: Option<u32>, f39_alt_122: Option<u32>, f39_alt_123: Option<u32>, f39_alt_124: Option<u32>,
        f39_alt_125: Option<u32>, f39_alt_126: Option<u32>, f39_alt_127: Option<u32>, f39_alt_128: Option<u32>,
        f39_alt_129: Option<u32>, f39_alt_130: Option<u32>, f39_alt_131: Option<u32>, f39_alt_132: Option<u32>,
        f39_alt_133: Option<u32>, f39_alt_134: Option<u32>, f39_alt_135: Option<u32>, f39_alt_136: Option<u32>,
        f39_alt_137: Option<u32>, f39_alt_138: Option<u32>, f39_alt_139: Option<u32>, f39_alt_140: Option<u32>,
        f39_alt_141: Option<u32>, f39_alt_142: Option<u32>, f39_alt_143: Option<u32>, f39_alt_144: Option<u32>,
        f39_alt_145: Option<u32>, f39_alt_146: Option<u32>, f39_alt_147: Option<u32>, f39_alt_148: Option<u32>,
        f39_alt_149: Option<u32>, f39_alt_150: Option<u32>, f39_alt_151: Option<u32>, f39_alt_152: Option<u32>,
        f39_alt_153: Option<u32>, f39_alt_154: Option<u32>, f39_alt_155: Option<u32>, f39_alt_156: Option<u32>,
        f39_alt_157: Option<u32>, f39_alt_158: Option<u32>, f39_alt_159: Option<u32>, f39_alt_160: Option<u32>,
        f39_alt_161: Option<u32>, f39_alt_162: Option<u32>, f39_alt_163: Option<u32>, f39_alt_164: Option<u32>,
        f39_alt_165: Option<u32>, f39_alt_166: Option<u32>, f39_alt_167: Option<u32>, f39_alt_168: Option<u32>,
        f39_alt_169: Option<u32>, f39_alt_170: Option<u32>, f39_alt_171: Option<u32>, f39_alt_172: Option<u32>,
        f39_alt_173: Option<u32>, f39_alt_174: Option<u32>, f39_alt_175: Option<u32>, f39_alt_176: Option<u32>,
        f39_alt_177: Option<u32>, f39_alt_178: Option<u32>, f39_alt_179: Option<u32>, f39_alt_180: Option<u32>,
        f39_alt_181: Option<u32>, f39_alt_182: Option<u32>, f39_alt_183: Option<u32>, f39_alt_184: Option<u32>,
        f39_alt_185: Option<u32>, f39_alt_186: Option<u32>, f39_alt_187: Option<u32>, f39_alt_188: Option<u32>,
        f39_alt_189: Option<u32>, f39_alt_190: Option<u32>, f39_alt_191: Option<u32>, f39_alt_192: Option<u32>,
        /// Field 40 — empirically `CArray<u32>` continuation.
        field_40_u32_list: Option<CArray<u32>>,
        /// Field 41 — single u32 (6242 entries share `0x00008000` = flag bit 1<<15).
        field_41_u32: Option<u32>,
        /// Field 42 — single u32 continuation.
        field_42_u32: Option<u32>,
        /// Field 43 — single u32 (6011 entries share `0xff008000`).
        field_43_u32: Option<u32>,
        /// Field 44 — single u32 (6011 entries share `0xffffffff` = sentinel).
        field_44_u32: Option<u32>,
        /// Field 45 — single u32 (6011 entries share `0xffffffff` = sentinel).
        field_45_u32: Option<u32>,
        /// Field 46 — single u32 (5666 entries share `0x00ffffff` flag pattern).
        field_46_u32: Option<u32>,
        /// Field 47 — single u32 (5746 entries share `0x00bf8000`).
        field_47_u32: Option<u32>,
        /// Field 48 — single u32 (6099 entries share `0x00bf8000` — same as 47).
        field_48_u32: Option<u32>,
        /// Field 49 — empirically `CArray<u32>` (mostly count=0).
        field_49_u32_list: Option<CArray<u32>>,
        /// Field 50 — empirically `CArray<u32>` (mostly count=0).
        field_50_u32_list: Option<CArray<u32>>,
        /// Field 51 — empirically `CArray<u32>` (mostly count=0).
        field_51_u32_list: Option<CArray<u32>>,
        /// Field 52 — empirically `CArray<u32>` (mostly count=0).
        field_52_u32_list: Option<CArray<u32>>,
        /// Field 53 — empirically `CArray<u32>` (mostly count=0).
        field_53_u32_list: Option<CArray<u32>>,
        /// Field 54 — empirically `CArray<u32>` (mostly count=0).
        field_54_u32_list: Option<CArray<u32>>,
        /// Field 55 — empirically `CArray<u32>` (mostly count=0).
        field_55_u32_list: Option<CArray<u32>>,
        /// Field 56 — empirically `CArray<u32>` (mostly count=0).
        field_56_u32_list: Option<CArray<u32>>,
        /// Field 57 — empirically `CArray<u32>` (mostly count=0).
        field_57_u32_list: Option<CArray<u32>>,
        /// Field 58 — empirically `CArray<u32>` (mostly count=0).
        field_58_u32_list: Option<CArray<u32>>,
        /// Field 59 — u32 storing f32 0.5 (`0x3f000000`) for 6018 entries.
        field_59_u32: Option<u32>,
        /// Field 60 — u32 storing f32 0.1 (`0x3dcccccd`).
        field_60_u32: Option<u32>,
        /// Field 61 — u32 storing f32 0.1 (`0x3dcccccd`).
        field_61_u32: Option<u32>,
        /// Field 62 — u32 (`0x00000101` = 257 flag-packed).
        field_62_u32: Option<u32>,
        /// Field 63 — u32 (= 0).
        field_63_u32: Option<u32>,
        /// Field 64 — u32 (= 0).
        field_64_u32: Option<u32>,
        /// Field 65 — u32 storing f32 5.0 (`0x40a00000`).
        field_65_u32: Option<u32>,
        /// Field 66 — u32 storing f32 1.0 (`0x3f800000`).
        field_66_u32: Option<u32>,
        /// Field 67 — u32 (`0x02000000` flag for 6019 entries).
        field_67_u32: Option<u32>,
        /// Field 68 — u32 (often `0x00000004`).
        field_68_u32: Option<u32>,
        /// Field 69 — u32.
        field_69_u32: Option<u32>,
        /// Field 70 — u32.
        field_70_u32: Option<u32>,
        /// Field 71 — u32.
        field_71_u32: Option<u32>,
        /// Field 72 — u32 (`0x00000100` = 256).
        field_72_u32: Option<u32>,
        /// Field 73 — u32.
        field_73_u32: Option<u32>,
        /// Field 74 — u32.
        field_74_u32: Option<u32>,
        /// Field 75 — u32 (mostly 0).
        field_75_u32: Option<u32>,
        /// Field 76 — u32.
        field_76_u32: Option<u32>,
        /// Field 77 — u32.
        field_77_u32: Option<u32>,
        /// Field 78 — u32.
        field_78_u32: Option<u32>,
        /// Field 79 — u32.
        field_79_u32: Option<u32>,
        /// Field 80 — u32.
        field_80_u32: Option<u32>,
        /// Field 81 — u32 (often `0x00003f80`).
        field_81_u32: Option<u32>,
        /// Field 82 — u32.
        field_82_u32: Option<u32>,
        /// Field 83 — u32.
        field_83_u32: Option<u32>,
        /// Field 84 — u32.
        field_84_u32: Option<u32>,
        /// Field 85 — u32 (often `0xffffffff`).
        field_85_u32: Option<u32>,
        /// Field 86 — u32 (often `0xffffffff`).
        field_86_u32: Option<u32>,
        /// Field 87 — u32 (often `0xffffffff`).
        field_87_u32: Option<u32>,
        /// Field 88 — u32.
        field_88_u32: Option<u32>,
        /// Field 89 — u32.
        field_89_u32: Option<u32>,
        /// Field 90 — u32.
        field_90_u32: Option<u32>,
        /// Field 91 — u32 (4498 entries are 0; rest vary widely. Could be
        /// length-prefix of a CString but many entries fail UTF-8 — keep
        /// as u32 for byte-perfect roundtrip).
        field_91_u32: Option<u32>,
        /// Field 92 — u32.
        field_92_u32: Option<u32>,
        /// Field 93 — u32.
        field_93_u32: Option<u32>,
        /// Field 94 — u32.
        field_94_u32: Option<u32>,
        /// Field 95 — u32.
        field_95_u32: Option<u32>,
        /// Field 96 — u32.
        field_96_u32: Option<u32>,
        /// Field 97 — u32.
        field_97_u32: Option<u32>,
        /// Field 98 — u32.
        field_98_u32: Option<u32>,
        /// Field 99 — u32 (often `0x80000002` flag).
        field_99_u32: Option<u32>,
        /// Field 100 — u32 (`0x0000003f` = 63 for 4361 entries).
        field_100_u32: Option<u32>,
        /// Field 101 — u32.
        field_101_u32: Option<u32>,
        /// Field 102 — u32.
        field_102_u32: Option<u32>,
        /// Field 103 — u32.
        field_103_u32: Option<u32>,
        /// Field 104 — u32.
        field_104_u32: Option<u32>,
        /// Field 105 — u32.
        field_105_u32: Option<u32>,
        /// Field 106 — u32.
        field_106_u32: Option<u32>,
        /// Field 107 — u32.
        field_107_u32: Option<u32>,
        /// Field 108 — u32.
        field_108_u32: Option<u32>,
        /// Field 109 — u32 (`0x00bf8000`).
        field_109_u32: Option<u32>,
        /// Field 110 — u32.
        field_110_u32: Option<u32>,
        /// Field 111 — u32 (`0x00bf8000`).
        field_111_u32: Option<u32>,
        /// Field 112 — u32.
        field_112_u32: Option<u32>,
        /// Field 113 — u32.
        field_113_u32: Option<u32>,
        /// Field 114 — u32.
        field_114_u32: Option<u32>,
        /// Field 115 — u32.
        field_115_u32: Option<u32>,
        /// Field 116 — u32.
        field_116_u32: Option<u32>,
        /// Field 117 — u32.
        field_117_u32: Option<u32>,
        /// Field 118 — u32.
        field_118_u32: Option<u32>,
        /// Field 119 — u32.
        field_119_u32: Option<u32>,
        /// Field 120 — u32.
        field_120_u32: Option<u32>,
        /// Field 121 — u32.
        field_121_u32: Option<u32>,
        /// Field 122 — u32.
        field_122_u32: Option<u32>,
        /// Field 123 — u32.
        field_123_u32: Option<u32>,
        /// Fields 124-139 — generic u32 sequence (mostly 0 + various values).
        field_124_u32: Option<u32>,
        field_125_u32: Option<u32>,
        field_126_u32: Option<u32>,
        field_127_u32: Option<u32>,
        field_128_u32: Option<u32>,
        field_129_u32: Option<u32>,
        field_130_u32: Option<u32>,
        field_131_u32: Option<u32>,
        field_132_u32: Option<u32>,
        field_133_u32: Option<u32>,
        field_134_u32: Option<u32>,
        field_135_u32: Option<u32>,
        field_136_u32: Option<u32>,
        field_137_u32: Option<u32>,
        field_138_u32: Option<u32>,
        field_139_u32: Option<u32>,
        /// Fields 140-155 — generic u32 sequence.
        field_140_u32: Option<u32>,
        field_141_u32: Option<u32>,
        field_142_u32: Option<u32>,
        field_143_u32: Option<u32>,
        field_144_u32: Option<u32>,
        field_145_u32: Option<u32>,
        field_146_u32: Option<u32>,
        field_147_u32: Option<u32>,
        field_148_u32: Option<u32>,
        field_149_u32: Option<u32>,
        field_150_u32: Option<u32>,
        field_151_u32: Option<u32>,
        field_152_u32: Option<u32>,
        field_153_u32: Option<u32>,
        field_154_u32: Option<u32>,
        field_155_u32: Option<u32>,
        /// Fields 156-171 — generic u32 sequence (string region).
        field_156_u32: Option<u32>,
        field_157_u32: Option<u32>,
        field_158_u32: Option<u32>,
        field_159_u32: Option<u32>,
        field_160_u32: Option<u32>,
        field_161_u32: Option<u32>,
        field_162_u32: Option<u32>,
        field_163_u32: Option<u32>,
        field_164_u32: Option<u32>,
        field_165_u32: Option<u32>,
        field_166_u32: Option<u32>,
        field_167_u32: Option<u32>,
        field_168_u32: Option<u32>,
        field_169_u32: Option<u32>,
        field_170_u32: Option<u32>,
        field_171_u32: Option<u32>,
        /// Fields 172-181 — generic u32 sequence (terminal trailing fields).
        field_172_u32: Option<u32>,
        field_173_u32: Option<u32>,
        field_174_u32: Option<u32>,
        field_175_u32: Option<u32>,
        field_176_u32: Option<u32>,
        field_177_u32: Option<u32>,
        field_178_u32: Option<u32>,
        field_179_u32: Option<u32>,
        field_180_u32: Option<u32>,
        field_181_u32: Option<u32>,
        /// Fields 182-197 — generic u32 sequence.
        field_182_u32: Option<u32>,
        field_183_u32: Option<u32>,
        field_184_u32: Option<u32>,
        field_185_u32: Option<u32>,
        field_186_u32: Option<u32>,
        field_187_u32: Option<u32>,
        field_188_u32: Option<u32>,
        field_189_u32: Option<u32>,
        field_190_u32: Option<u32>,
        field_191_u32: Option<u32>,
        field_192_u32: Option<u32>,
        field_193_u32: Option<u32>,
        field_194_u32: Option<u32>,
        field_195_u32: Option<u32>,
        field_196_u32: Option<u32>,
        field_197_u32: Option<u32>,
        /// Fields 198-213 — long-tail u32 sequence.
        field_198_u32: Option<u32>,
        field_199_u32: Option<u32>,
        field_200_u32: Option<u32>,
        field_201_u32: Option<u32>,
        field_202_u32: Option<u32>,
        field_203_u32: Option<u32>,
        field_204_u32: Option<u32>,
        field_205_u32: Option<u32>,
        field_206_u32: Option<u32>,
        field_207_u32: Option<u32>,
        field_208_u32: Option<u32>,
        field_209_u32: Option<u32>,
        field_210_u32: Option<u32>,
        field_211_u32: Option<u32>,
        field_212_u32: Option<u32>,
        field_213_u32: Option<u32>,
        /// Fields 214-229 — long-tail u32 sequence.
        field_214_u32: Option<u32>,
        field_215_u32: Option<u32>,
        field_216_u32: Option<u32>,
        field_217_u32: Option<u32>,
        field_218_u32: Option<u32>,
        field_219_u32: Option<u32>,
        field_220_u32: Option<u32>,
        field_221_u32: Option<u32>,
        field_222_u32: Option<u32>,
        field_223_u32: Option<u32>,
        field_224_u32: Option<u32>,
        field_225_u32: Option<u32>,
        field_226_u32: Option<u32>,
        field_227_u32: Option<u32>,
        field_228_u32: Option<u32>,
        field_229_u32: Option<u32>,
        /// Fields 230-245 — long-tail u32 sequence.
        field_230_u32: Option<u32>,
        field_231_u32: Option<u32>,
        field_232_u32: Option<u32>,
        field_233_u32: Option<u32>,
        field_234_u32: Option<u32>,
        field_235_u32: Option<u32>,
        field_236_u32: Option<u32>,
        field_237_u32: Option<u32>,
        field_238_u32: Option<u32>,
        field_239_u32: Option<u32>,
        field_240_u32: Option<u32>,
        field_241_u32: Option<u32>,
        field_242_u32: Option<u32>,
        field_243_u32: Option<u32>,
        field_244_u32: Option<u32>,
        field_245_u32: Option<u32>,
        /// Fields 246-277 — long-tail u32 sequence.
        field_246_u32: Option<u32>,
        field_247_u32: Option<u32>,
        field_248_u32: Option<u32>,
        field_249_u32: Option<u32>,
        field_250_u32: Option<u32>,
        field_251_u32: Option<u32>,
        field_252_u32: Option<u32>,
        field_253_u32: Option<u32>,
        field_254_u32: Option<u32>,
        field_255_u32: Option<u32>,
        field_256_u32: Option<u32>,
        field_257_u32: Option<u32>,
        field_258_u32: Option<u32>,
        field_259_u32: Option<u32>,
        field_260_u32: Option<u32>,
        field_261_u32: Option<u32>,
        field_262_u32: Option<u32>,
        field_263_u32: Option<u32>,
        field_264_u32: Option<u32>,
        field_265_u32: Option<u32>,
        field_266_u32: Option<u32>,
        field_267_u32: Option<u32>,
        field_268_u32: Option<u32>,
        field_269_u32: Option<u32>,
        field_270_u32: Option<u32>,
        field_271_u32: Option<u32>,
        field_272_u32: Option<u32>,
        field_273_u32: Option<u32>,
        field_274_u32: Option<u32>,
        field_275_u32: Option<u32>,
        field_276_u32: Option<u32>,
        field_277_u32: Option<u32>,
        /// Fields 278-309 — long-tail u32 sequence.
        field_278_u32: Option<u32>,
        field_279_u32: Option<u32>,
        field_280_u32: Option<u32>,
        field_281_u32: Option<u32>,
        field_282_u32: Option<u32>,
        field_283_u32: Option<u32>,
        field_284_u32: Option<u32>,
        field_285_u32: Option<u32>,
        field_286_u32: Option<u32>,
        field_287_u32: Option<u32>,
        field_288_u32: Option<u32>,
        field_289_u32: Option<u32>,
        field_290_u32: Option<u32>,
        field_291_u32: Option<u32>,
        field_292_u32: Option<u32>,
        field_293_u32: Option<u32>,
        field_294_u32: Option<u32>,
        field_295_u32: Option<u32>,
        field_296_u32: Option<u32>,
        field_297_u32: Option<u32>,
        field_298_u32: Option<u32>,
        field_299_u32: Option<u32>,
        field_300_u32: Option<u32>,
        field_301_u32: Option<u32>,
        field_302_u32: Option<u32>,
        field_303_u32: Option<u32>,
        field_304_u32: Option<u32>,
        field_305_u32: Option<u32>,
        field_306_u32: Option<u32>,
        field_307_u32: Option<u32>,
        field_308_u32: Option<u32>,
        field_309_u32: Option<u32>,
        /// Fields 310-341 — long-tail u32 sequence (XML-string region).
        field_310_u32: Option<u32>,
        field_311_u32: Option<u32>,
        field_312_u32: Option<u32>,
        field_313_u32: Option<u32>,
        field_314_u32: Option<u32>,
        field_315_u32: Option<u32>,
        field_316_u32: Option<u32>,
        field_317_u32: Option<u32>,
        field_318_u32: Option<u32>,
        field_319_u32: Option<u32>,
        field_320_u32: Option<u32>,
        field_321_u32: Option<u32>,
        field_322_u32: Option<u32>,
        field_323_u32: Option<u32>,
        field_324_u32: Option<u32>,
        field_325_u32: Option<u32>,
        field_326_u32: Option<u32>,
        field_327_u32: Option<u32>,
        field_328_u32: Option<u32>,
        field_329_u32: Option<u32>,
        field_330_u32: Option<u32>,
        field_331_u32: Option<u32>,
        field_332_u32: Option<u32>,
        field_333_u32: Option<u32>,
        field_334_u32: Option<u32>,
        field_335_u32: Option<u32>,
        field_336_u32: Option<u32>,
        field_337_u32: Option<u32>,
        field_338_u32: Option<u32>,
        field_339_u32: Option<u32>,
        field_340_u32: Option<u32>,
        field_341_u32: Option<u32>,
        /// Field 342 — u32 trigger count (for long-tail entries this starts a
        /// CArray<TriggerEntry> with `u8 flag + CString name + body`).
        field_342_u32_count: Option<u32>,
        /// Field 343 — u8 flag (typically 0x01) for first trigger entry.
        field_343_u8_flag: Option<u8>,
        /// Field 344 — u32 (length-prefix or value).
        field_344_u32: Option<u32>,
        /// Fields 345-376 — long-tail u32 sequence (trigger entry body).
        field_345_u32: Option<u32>,
        field_346_u32: Option<u32>,
        field_347_u32: Option<u32>,
        field_348_u32: Option<u32>,
        field_349_u32: Option<u32>,
        field_350_u32: Option<u32>,
        field_351_u32: Option<u32>,
        field_352_u32: Option<u32>,
        field_353_u32: Option<u32>,
        field_354_u32: Option<u32>,
        field_355_u32: Option<u32>,
        field_356_u32: Option<u32>,
        field_357_u32: Option<u32>,
        field_358_u32: Option<u32>,
        field_359_u32: Option<u32>,
        field_360_u32: Option<u32>,
        field_361_u32: Option<u32>,
        field_362_u32: Option<u32>,
        field_363_u32: Option<u32>,
        field_364_u32: Option<u32>,
        field_365_u32: Option<u32>,
        field_366_u32: Option<u32>,
        field_367_u32: Option<u32>,
        field_368_u32: Option<u32>,
        field_369_u32: Option<u32>,
        field_370_u32: Option<u32>,
        field_371_u32: Option<u32>,
        field_372_u32: Option<u32>,
        field_373_u32: Option<u32>,
        field_374_u32: Option<u32>,
        field_375_u32: Option<u32>,
        field_376_u32: Option<u32>,
        /// Fields 377-408 — long-tail u32 sequence.
        field_377_u32: Option<u32>,
        field_378_u32: Option<u32>,
        field_379_u32: Option<u32>,
        field_380_u32: Option<u32>,
        field_381_u32: Option<u32>,
        field_382_u32: Option<u32>,
        field_383_u32: Option<u32>,
        field_384_u32: Option<u32>,
        field_385_u32: Option<u32>,
        field_386_u32: Option<u32>,
        field_387_u32: Option<u32>,
        field_388_u32: Option<u32>,
        field_389_u32: Option<u32>,
        field_390_u32: Option<u32>,
        field_391_u32: Option<u32>,
        field_392_u32: Option<u32>,
        field_393_u32: Option<u32>,
        field_394_u32: Option<u32>,
        field_395_u32: Option<u32>,
        field_396_u32: Option<u32>,
        field_397_u32: Option<u32>,
        field_398_u32: Option<u32>,
        field_399_u32: Option<u32>,
        field_400_u32: Option<u32>,
        field_401_u32: Option<u32>,
        field_402_u32: Option<u32>,
        field_403_u32: Option<u32>,
        field_404_u32: Option<u32>,
        field_405_u32: Option<u32>,
        field_406_u32: Option<u32>,
        field_407_u32: Option<u32>,
        field_408_u32: Option<u32>,
        /// Fields 409-440 — long-tail u32 sequence.
        field_409_u32: Option<u32>,
        field_410_u32: Option<u32>,
        field_411_u32: Option<u32>,
        field_412_u32: Option<u32>,
        field_413_u32: Option<u32>,
        field_414_u32: Option<u32>,
        field_415_u32: Option<u32>,
        field_416_u32: Option<u32>,
        field_417_u32: Option<u32>,
        field_418_u32: Option<u32>,
        field_419_u32: Option<u32>,
        field_420_u32: Option<u32>,
        field_421_u32: Option<u32>,
        field_422_u32: Option<u32>,
        field_423_u32: Option<u32>,
        field_424_u32: Option<u32>,
        field_425_u32: Option<u32>,
        field_426_u32: Option<u32>,
        field_427_u32: Option<u32>,
        field_428_u32: Option<u32>,
        field_429_u32: Option<u32>,
        field_430_u32: Option<u32>,
        field_431_u32: Option<u32>,
        field_432_u32: Option<u32>,
        field_433_u32: Option<u32>,
        field_434_u32: Option<u32>,
        field_435_u32: Option<u32>,
        field_436_u32: Option<u32>,
        field_437_u32: Option<u32>,
        field_438_u32: Option<u32>,
        field_439_u32: Option<u32>,
        field_440_u32: Option<u32>,
        /// Fields 441-472 — long-tail u32 sequence.
        field_441_u32: Option<u32>,
        field_442_u32: Option<u32>,
        field_443_u32: Option<u32>,
        field_444_u32: Option<u32>,
        field_445_u32: Option<u32>,
        field_446_u32: Option<u32>,
        field_447_u32: Option<u32>,
        field_448_u32: Option<u32>,
        field_449_u32: Option<u32>,
        field_450_u32: Option<u32>,
        field_451_u32: Option<u32>,
        field_452_u32: Option<u32>,
        field_453_u32: Option<u32>,
        field_454_u32: Option<u32>,
        field_455_u32: Option<u32>,
        field_456_u32: Option<u32>,
        field_457_u32: Option<u32>,
        field_458_u32: Option<u32>,
        field_459_u32: Option<u32>,
        field_460_u32: Option<u32>,
        field_461_u32: Option<u32>,
        field_462_u32: Option<u32>,
        field_463_u32: Option<u32>,
        field_464_u32: Option<u32>,
        field_465_u32: Option<u32>,
        field_466_u32: Option<u32>,
        field_467_u32: Option<u32>,
        field_468_u32: Option<u32>,
        field_469_u32: Option<u32>,
        field_470_u32: Option<u32>,
        field_471_u32: Option<u32>,
        field_472_u32: Option<u32>,
        /// Fields 473-504 — long-tail u32 sequence.
        field_473_u32: Option<u32>,
        field_474_u32: Option<u32>,
        field_475_u32: Option<u32>,
        field_476_u32: Option<u32>,
        field_477_u32: Option<u32>,
        field_478_u32: Option<u32>,
        field_479_u32: Option<u32>,
        field_480_u32: Option<u32>,
        field_481_u32: Option<u32>,
        field_482_u32: Option<u32>,
        field_483_u32: Option<u32>,
        field_484_u32: Option<u32>,
        field_485_u32: Option<u32>,
        field_486_u32: Option<u32>,
        field_487_u32: Option<u32>,
        field_488_u32: Option<u32>,
        field_489_u32: Option<u32>,
        field_490_u32: Option<u32>,
        field_491_u32: Option<u32>,
        field_492_u32: Option<u32>,
        field_493_u32: Option<u32>,
        field_494_u32: Option<u32>,
        field_495_u32: Option<u32>,
        field_496_u32: Option<u32>,
        field_497_u32: Option<u32>,
        field_498_u32: Option<u32>,
        field_499_u32: Option<u32>,
        field_500_u32: Option<u32>,
        field_501_u32: Option<u32>,
        field_502_u32: Option<u32>,
        field_503_u32: Option<u32>,
        field_504_u32: Option<u32>,
        /// Fields 505-536 — long-tail u32 sequence.
        field_505_u32: Option<u32>,
        field_506_u32: Option<u32>,
        field_507_u32: Option<u32>,
        field_508_u32: Option<u32>,
        field_509_u32: Option<u32>,
        field_510_u32: Option<u32>,
        field_511_u32: Option<u32>,
        field_512_u32: Option<u32>,
        field_513_u32: Option<u32>,
        field_514_u32: Option<u32>,
        field_515_u32: Option<u32>,
        field_516_u32: Option<u32>,
        field_517_u32: Option<u32>,
        field_518_u32: Option<u32>,
        field_519_u32: Option<u32>,
        field_520_u32: Option<u32>,
        field_521_u32: Option<u32>,
        field_522_u32: Option<u32>,
        field_523_u32: Option<u32>,
        field_524_u32: Option<u32>,
        field_525_u32: Option<u32>,
        field_526_u32: Option<u32>,
        field_527_u32: Option<u32>,
        field_528_u32: Option<u32>,
        field_529_u32: Option<u32>,
        field_530_u32: Option<u32>,
        field_531_u32: Option<u32>,
        field_532_u32: Option<u32>,
        field_533_u32: Option<u32>,
        field_534_u32: Option<u32>,
        field_535_u32: Option<u32>,
        field_536_u32: Option<u32>,
        /// Fields 537-600 — long-tail u32 sequence (64-field batch).
        field_537_u32: Option<u32>, field_538_u32: Option<u32>, field_539_u32: Option<u32>, field_540_u32: Option<u32>,
        field_541_u32: Option<u32>, field_542_u32: Option<u32>, field_543_u32: Option<u32>, field_544_u32: Option<u32>,
        field_545_u32: Option<u32>, field_546_u32: Option<u32>, field_547_u32: Option<u32>, field_548_u32: Option<u32>,
        field_549_u32: Option<u32>, field_550_u32: Option<u32>, field_551_u32: Option<u32>, field_552_u32: Option<u32>,
        field_553_u32: Option<u32>, field_554_u32: Option<u32>, field_555_u32: Option<u32>, field_556_u32: Option<u32>,
        field_557_u32: Option<u32>, field_558_u32: Option<u32>, field_559_u32: Option<u32>, field_560_u32: Option<u32>,
        field_561_u32: Option<u32>, field_562_u32: Option<u32>, field_563_u32: Option<u32>, field_564_u32: Option<u32>,
        field_565_u32: Option<u32>, field_566_u32: Option<u32>, field_567_u32: Option<u32>, field_568_u32: Option<u32>,
        field_569_u32: Option<u32>, field_570_u32: Option<u32>, field_571_u32: Option<u32>, field_572_u32: Option<u32>,
        field_573_u32: Option<u32>, field_574_u32: Option<u32>, field_575_u32: Option<u32>, field_576_u32: Option<u32>,
        field_577_u32: Option<u32>, field_578_u32: Option<u32>, field_579_u32: Option<u32>, field_580_u32: Option<u32>,
        field_581_u32: Option<u32>, field_582_u32: Option<u32>, field_583_u32: Option<u32>, field_584_u32: Option<u32>,
        field_585_u32: Option<u32>, field_586_u32: Option<u32>, field_587_u32: Option<u32>, field_588_u32: Option<u32>,
        field_589_u32: Option<u32>, field_590_u32: Option<u32>, field_591_u32: Option<u32>, field_592_u32: Option<u32>,
        field_593_u32: Option<u32>, field_594_u32: Option<u32>, field_595_u32: Option<u32>, field_596_u32: Option<u32>,
        field_597_u32: Option<u32>, field_598_u32: Option<u32>, field_599_u32: Option<u32>, field_600_u32: Option<u32>,
        /// Fields 601-664 — long-tail u32 sequence (64-field batch).
        field_601_u32: Option<u32>, field_602_u32: Option<u32>, field_603_u32: Option<u32>, field_604_u32: Option<u32>,
        field_605_u32: Option<u32>, field_606_u32: Option<u32>, field_607_u32: Option<u32>, field_608_u32: Option<u32>,
        field_609_u32: Option<u32>, field_610_u32: Option<u32>, field_611_u32: Option<u32>, field_612_u32: Option<u32>,
        field_613_u32: Option<u32>, field_614_u32: Option<u32>, field_615_u32: Option<u32>, field_616_u32: Option<u32>,
        field_617_u32: Option<u32>, field_618_u32: Option<u32>, field_619_u32: Option<u32>, field_620_u32: Option<u32>,
        field_621_u32: Option<u32>, field_622_u32: Option<u32>, field_623_u32: Option<u32>, field_624_u32: Option<u32>,
        field_625_u32: Option<u32>, field_626_u32: Option<u32>, field_627_u32: Option<u32>, field_628_u32: Option<u32>,
        field_629_u32: Option<u32>, field_630_u32: Option<u32>, field_631_u32: Option<u32>, field_632_u32: Option<u32>,
        field_633_u32: Option<u32>, field_634_u32: Option<u32>, field_635_u32: Option<u32>, field_636_u32: Option<u32>,
        field_637_u32: Option<u32>, field_638_u32: Option<u32>, field_639_u32: Option<u32>, field_640_u32: Option<u32>,
        field_641_u32: Option<u32>, field_642_u32: Option<u32>, field_643_u32: Option<u32>, field_644_u32: Option<u32>,
        field_645_u32: Option<u32>, field_646_u32: Option<u32>, field_647_u32: Option<u32>, field_648_u32: Option<u32>,
        field_649_u32: Option<u32>, field_650_u32: Option<u32>, field_651_u32: Option<u32>, field_652_u32: Option<u32>,
        field_653_u32: Option<u32>, field_654_u32: Option<u32>, field_655_u32: Option<u32>, field_656_u32: Option<u32>,
        field_657_u32: Option<u32>, field_658_u32: Option<u32>, field_659_u32: Option<u32>, field_660_u32: Option<u32>,
        field_661_u32: Option<u32>, field_662_u32: Option<u32>, field_663_u32: Option<u32>, field_664_u32: Option<u32>,
        /// Alternate-format trigger header (4975 entries fail field 17 but
        /// have a structurally different tail starting with u32 count).
        /// These are likely scene/region gimmicks with named TriggerEntry
        /// CArrays (e.g. "UnnamedTrigger_0", "Platform").
        alt_trigger_count: Option<u32>,
        /// Alternate-format flag byte (typically 0x01).
        alt_trigger_flag: Option<u8>,
        /// Alternate-format trigger name (e.g. "UnnamedTrigger_0").
        alt_trigger_name: Option<CString<'a>>,
        /// Alt-format inner count (e.g. 1 sub-trigger).
        alt_inner_count: Option<u32>,
        /// Alt-format inner name (e.g. "hide_bush_crouch").
        alt_inner_name: Option<CString<'a>>,
        /// Alt-format inner flag/value u32.
        alt_inner_flag: Option<u32>,
        /// Alt-format body u32 sequence (64 fields after inner header).
        alt_body_001: Option<u32>, alt_body_002: Option<u32>, alt_body_003: Option<u32>, alt_body_004: Option<u32>,
        alt_body_005: Option<u32>, alt_body_006: Option<u32>, alt_body_007: Option<u32>, alt_body_008: Option<u32>,
        alt_body_009: Option<u32>, alt_body_010: Option<u32>, alt_body_011: Option<u32>, alt_body_012: Option<u32>,
        alt_body_013: Option<u32>, alt_body_014: Option<u32>, alt_body_015: Option<u32>, alt_body_016: Option<u32>,
        alt_body_017: Option<u32>, alt_body_018: Option<u32>, alt_body_019: Option<u32>, alt_body_020: Option<u32>,
        alt_body_021: Option<u32>, alt_body_022: Option<u32>, alt_body_023: Option<u32>, alt_body_024: Option<u32>,
        alt_body_025: Option<u32>, alt_body_026: Option<u32>, alt_body_027: Option<u32>, alt_body_028: Option<u32>,
        alt_body_029: Option<u32>, alt_body_030: Option<u32>, alt_body_031: Option<u32>, alt_body_032: Option<u32>,
        alt_body_033: Option<u32>, alt_body_034: Option<u32>, alt_body_035: Option<u32>, alt_body_036: Option<u32>,
        alt_body_037: Option<u32>, alt_body_038: Option<u32>, alt_body_039: Option<u32>, alt_body_040: Option<u32>,
        alt_body_041: Option<u32>, alt_body_042: Option<u32>, alt_body_043: Option<u32>, alt_body_044: Option<u32>,
        alt_body_045: Option<u32>, alt_body_046: Option<u32>, alt_body_047: Option<u32>, alt_body_048: Option<u32>,
        alt_body_049: Option<u32>, alt_body_050: Option<u32>, alt_body_051: Option<u32>, alt_body_052: Option<u32>,
        alt_body_053: Option<u32>, alt_body_054: Option<u32>, alt_body_055: Option<u32>, alt_body_056: Option<u32>,
        alt_body_057: Option<u32>, alt_body_058: Option<u32>, alt_body_059: Option<u32>, alt_body_060: Option<u32>,
        alt_body_061: Option<u32>, alt_body_062: Option<u32>, alt_body_063: Option<u32>, alt_body_064: Option<u32>,
        alt_body_065: Option<u32>, alt_body_066: Option<u32>, alt_body_067: Option<u32>, alt_body_068: Option<u32>,
        alt_body_069: Option<u32>, alt_body_070: Option<u32>, alt_body_071: Option<u32>, alt_body_072: Option<u32>,
        alt_body_073: Option<u32>, alt_body_074: Option<u32>, alt_body_075: Option<u32>, alt_body_076: Option<u32>,
        alt_body_077: Option<u32>, alt_body_078: Option<u32>, alt_body_079: Option<u32>, alt_body_080: Option<u32>,
        alt_body_081: Option<u32>, alt_body_082: Option<u32>, alt_body_083: Option<u32>, alt_body_084: Option<u32>,
        alt_body_085: Option<u32>, alt_body_086: Option<u32>, alt_body_087: Option<u32>, alt_body_088: Option<u32>,
        alt_body_089: Option<u32>, alt_body_090: Option<u32>, alt_body_091: Option<u32>, alt_body_092: Option<u32>,
        alt_body_093: Option<u32>, alt_body_094: Option<u32>, alt_body_095: Option<u32>, alt_body_096: Option<u32>,
        alt_body_097: Option<u32>, alt_body_098: Option<u32>, alt_body_099: Option<u32>, alt_body_100: Option<u32>,
        alt_body_101: Option<u32>, alt_body_102: Option<u32>, alt_body_103: Option<u32>, alt_body_104: Option<u32>,
        alt_body_105: Option<u32>, alt_body_106: Option<u32>, alt_body_107: Option<u32>, alt_body_108: Option<u32>,
        alt_body_109: Option<u32>, alt_body_110: Option<u32>, alt_body_111: Option<u32>, alt_body_112: Option<u32>,
        alt_body_113: Option<u32>, alt_body_114: Option<u32>, alt_body_115: Option<u32>, alt_body_116: Option<u32>,
        alt_body_117: Option<u32>, alt_body_118: Option<u32>, alt_body_119: Option<u32>, alt_body_120: Option<u32>,
        alt_body_121: Option<u32>, alt_body_122: Option<u32>, alt_body_123: Option<u32>, alt_body_124: Option<u32>,
        alt_body_125: Option<u32>, alt_body_126: Option<u32>, alt_body_127: Option<u32>, alt_body_128: Option<u32>,
        alt_body_129: Option<u32>, alt_body_130: Option<u32>, alt_body_131: Option<u32>, alt_body_132: Option<u32>,
        alt_body_133: Option<u32>, alt_body_134: Option<u32>, alt_body_135: Option<u32>, alt_body_136: Option<u32>,
        alt_body_137: Option<u32>, alt_body_138: Option<u32>, alt_body_139: Option<u32>, alt_body_140: Option<u32>,
        alt_body_141: Option<u32>, alt_body_142: Option<u32>, alt_body_143: Option<u32>, alt_body_144: Option<u32>,
        alt_body_145: Option<u32>, alt_body_146: Option<u32>, alt_body_147: Option<u32>, alt_body_148: Option<u32>,
        alt_body_149: Option<u32>, alt_body_150: Option<u32>, alt_body_151: Option<u32>, alt_body_152: Option<u32>,
        alt_body_153: Option<u32>, alt_body_154: Option<u32>, alt_body_155: Option<u32>, alt_body_156: Option<u32>,
        alt_body_157: Option<u32>, alt_body_158: Option<u32>, alt_body_159: Option<u32>, alt_body_160: Option<u32>,
        alt_body_161: Option<u32>, alt_body_162: Option<u32>, alt_body_163: Option<u32>, alt_body_164: Option<u32>,
        alt_body_165: Option<u32>, alt_body_166: Option<u32>, alt_body_167: Option<u32>, alt_body_168: Option<u32>,
        alt_body_169: Option<u32>, alt_body_170: Option<u32>, alt_body_171: Option<u32>, alt_body_172: Option<u32>,
        alt_body_173: Option<u32>, alt_body_174: Option<u32>, alt_body_175: Option<u32>, alt_body_176: Option<u32>,
        alt_body_177: Option<u32>, alt_body_178: Option<u32>, alt_body_179: Option<u32>, alt_body_180: Option<u32>,
        alt_body_181: Option<u32>, alt_body_182: Option<u32>, alt_body_183: Option<u32>, alt_body_184: Option<u32>,
        alt_body_185: Option<u32>, alt_body_186: Option<u32>, alt_body_187: Option<u32>, alt_body_188: Option<u32>,
        alt_body_189: Option<u32>, alt_body_190: Option<u32>, alt_body_191: Option<u32>, alt_body_192: Option<u32>,
        alt_body_193: Option<u32>, alt_body_194: Option<u32>, alt_body_195: Option<u32>, alt_body_196: Option<u32>,
        alt_body_197: Option<u32>, alt_body_198: Option<u32>, alt_body_199: Option<u32>, alt_body_200: Option<u32>,
        alt_body_201: Option<u32>, alt_body_202: Option<u32>, alt_body_203: Option<u32>, alt_body_204: Option<u32>,
        alt_body_205: Option<u32>, alt_body_206: Option<u32>, alt_body_207: Option<u32>, alt_body_208: Option<u32>,
        alt_body_209: Option<u32>, alt_body_210: Option<u32>, alt_body_211: Option<u32>, alt_body_212: Option<u32>,
        alt_body_213: Option<u32>, alt_body_214: Option<u32>, alt_body_215: Option<u32>, alt_body_216: Option<u32>,
        alt_body_217: Option<u32>, alt_body_218: Option<u32>, alt_body_219: Option<u32>, alt_body_220: Option<u32>,
        alt_body_221: Option<u32>, alt_body_222: Option<u32>, alt_body_223: Option<u32>, alt_body_224: Option<u32>,
        alt_body_225: Option<u32>, alt_body_226: Option<u32>, alt_body_227: Option<u32>, alt_body_228: Option<u32>,
        alt_body_229: Option<u32>, alt_body_230: Option<u32>, alt_body_231: Option<u32>, alt_body_232: Option<u32>,
        alt_body_233: Option<u32>, alt_body_234: Option<u32>, alt_body_235: Option<u32>, alt_body_236: Option<u32>,
        alt_body_237: Option<u32>, alt_body_238: Option<u32>, alt_body_239: Option<u32>, alt_body_240: Option<u32>,
        alt_body_241: Option<u32>, alt_body_242: Option<u32>, alt_body_243: Option<u32>, alt_body_244: Option<u32>,
        alt_body_245: Option<u32>, alt_body_246: Option<u32>, alt_body_247: Option<u32>, alt_body_248: Option<u32>,
        alt_body_249: Option<u32>, alt_body_250: Option<u32>, alt_body_251: Option<u32>, alt_body_252: Option<u32>,
        alt_body_253: Option<u32>, alt_body_254: Option<u32>, alt_body_255: Option<u32>, alt_body_256: Option<u32>,
        alt_body_257: Option<u32>, alt_body_258: Option<u32>, alt_body_259: Option<u32>, alt_body_260: Option<u32>,
        alt_body_261: Option<u32>, alt_body_262: Option<u32>, alt_body_263: Option<u32>, alt_body_264: Option<u32>,
        alt_body_265: Option<u32>, alt_body_266: Option<u32>, alt_body_267: Option<u32>, alt_body_268: Option<u32>,
        alt_body_269: Option<u32>, alt_body_270: Option<u32>, alt_body_271: Option<u32>, alt_body_272: Option<u32>,
        alt_body_273: Option<u32>, alt_body_274: Option<u32>, alt_body_275: Option<u32>, alt_body_276: Option<u32>,
        alt_body_277: Option<u32>, alt_body_278: Option<u32>, alt_body_279: Option<u32>, alt_body_280: Option<u32>,
        alt_body_281: Option<u32>, alt_body_282: Option<u32>, alt_body_283: Option<u32>, alt_body_284: Option<u32>,
        alt_body_285: Option<u32>, alt_body_286: Option<u32>, alt_body_287: Option<u32>, alt_body_288: Option<u32>,
        alt_body_289: Option<u32>, alt_body_290: Option<u32>, alt_body_291: Option<u32>, alt_body_292: Option<u32>,
        alt_body_293: Option<u32>, alt_body_294: Option<u32>, alt_body_295: Option<u32>, alt_body_296: Option<u32>,
        alt_body_297: Option<u32>, alt_body_298: Option<u32>, alt_body_299: Option<u32>, alt_body_300: Option<u32>,
        alt_body_301: Option<u32>, alt_body_302: Option<u32>, alt_body_303: Option<u32>, alt_body_304: Option<u32>,
        alt_body_305: Option<u32>, alt_body_306: Option<u32>, alt_body_307: Option<u32>, alt_body_308: Option<u32>,
        alt_body_309: Option<u32>, alt_body_310: Option<u32>, alt_body_311: Option<u32>, alt_body_312: Option<u32>,
        alt_body_313: Option<u32>, alt_body_314: Option<u32>, alt_body_315: Option<u32>, alt_body_316: Option<u32>,
        alt_body_317: Option<u32>, alt_body_318: Option<u32>, alt_body_319: Option<u32>, alt_body_320: Option<u32>,
        alt_body_321: Option<u32>, alt_body_322: Option<u32>, alt_body_323: Option<u32>, alt_body_324: Option<u32>,
        alt_body_325: Option<u32>, alt_body_326: Option<u32>, alt_body_327: Option<u32>, alt_body_328: Option<u32>,
        alt_body_329: Option<u32>, alt_body_330: Option<u32>, alt_body_331: Option<u32>, alt_body_332: Option<u32>,
        alt_body_333: Option<u32>, alt_body_334: Option<u32>, alt_body_335: Option<u32>, alt_body_336: Option<u32>,
        alt_body_337: Option<u32>, alt_body_338: Option<u32>, alt_body_339: Option<u32>, alt_body_340: Option<u32>,
        alt_body_341: Option<u32>, alt_body_342: Option<u32>, alt_body_343: Option<u32>, alt_body_344: Option<u32>,
        alt_body_345: Option<u32>, alt_body_346: Option<u32>, alt_body_347: Option<u32>, alt_body_348: Option<u32>,
        alt_body_349: Option<u32>, alt_body_350: Option<u32>, alt_body_351: Option<u32>, alt_body_352: Option<u32>,
        alt_body_353: Option<u32>, alt_body_354: Option<u32>, alt_body_355: Option<u32>, alt_body_356: Option<u32>,
        alt_body_357: Option<u32>, alt_body_358: Option<u32>, alt_body_359: Option<u32>, alt_body_360: Option<u32>,
        alt_body_361: Option<u32>, alt_body_362: Option<u32>, alt_body_363: Option<u32>, alt_body_364: Option<u32>,
        alt_body_365: Option<u32>, alt_body_366: Option<u32>, alt_body_367: Option<u32>, alt_body_368: Option<u32>,
        alt_body_369: Option<u32>, alt_body_370: Option<u32>, alt_body_371: Option<u32>, alt_body_372: Option<u32>,
        alt_body_373: Option<u32>, alt_body_374: Option<u32>, alt_body_375: Option<u32>, alt_body_376: Option<u32>,
        alt_body_377: Option<u32>, alt_body_378: Option<u32>, alt_body_379: Option<u32>, alt_body_380: Option<u32>,
        alt_body_381: Option<u32>, alt_body_382: Option<u32>, alt_body_383: Option<u32>, alt_body_384: Option<u32>,
        alt_body_385: Option<u32>, alt_body_386: Option<u32>, alt_body_387: Option<u32>, alt_body_388: Option<u32>,
        alt_body_389: Option<u32>, alt_body_390: Option<u32>, alt_body_391: Option<u32>, alt_body_392: Option<u32>,
        alt_body_393: Option<u32>, alt_body_394: Option<u32>, alt_body_395: Option<u32>, alt_body_396: Option<u32>,
        alt_body_397: Option<u32>, alt_body_398: Option<u32>, alt_body_399: Option<u32>, alt_body_400: Option<u32>,
        alt_body_401: Option<u32>, alt_body_402: Option<u32>, alt_body_403: Option<u32>, alt_body_404: Option<u32>,
        alt_body_405: Option<u32>, alt_body_406: Option<u32>, alt_body_407: Option<u32>, alt_body_408: Option<u32>,
        alt_body_409: Option<u32>, alt_body_410: Option<u32>, alt_body_411: Option<u32>, alt_body_412: Option<u32>,
        alt_body_413: Option<u32>, alt_body_414: Option<u32>, alt_body_415: Option<u32>, alt_body_416: Option<u32>,
        alt_body_417: Option<u32>, alt_body_418: Option<u32>, alt_body_419: Option<u32>, alt_body_420: Option<u32>,
        alt_body_421: Option<u32>, alt_body_422: Option<u32>, alt_body_423: Option<u32>, alt_body_424: Option<u32>,
        alt_body_425: Option<u32>, alt_body_426: Option<u32>, alt_body_427: Option<u32>, alt_body_428: Option<u32>,
        alt_body_429: Option<u32>, alt_body_430: Option<u32>, alt_body_431: Option<u32>, alt_body_432: Option<u32>,
        alt_body_433: Option<u32>, alt_body_434: Option<u32>, alt_body_435: Option<u32>, alt_body_436: Option<u32>,
        alt_body_437: Option<u32>, alt_body_438: Option<u32>, alt_body_439: Option<u32>, alt_body_440: Option<u32>,
        alt_body_441: Option<u32>, alt_body_442: Option<u32>, alt_body_443: Option<u32>, alt_body_444: Option<u32>,
        alt_body_445: Option<u32>, alt_body_446: Option<u32>, alt_body_447: Option<u32>, alt_body_448: Option<u32>,
        alt_body_449: Option<u32>, alt_body_450: Option<u32>, alt_body_451: Option<u32>, alt_body_452: Option<u32>,
        alt_body_453: Option<u32>, alt_body_454: Option<u32>, alt_body_455: Option<u32>, alt_body_456: Option<u32>,
        alt_body_457: Option<u32>, alt_body_458: Option<u32>, alt_body_459: Option<u32>, alt_body_460: Option<u32>,
        alt_body_461: Option<u32>, alt_body_462: Option<u32>, alt_body_463: Option<u32>, alt_body_464: Option<u32>,
        alt_body_465: Option<u32>, alt_body_466: Option<u32>, alt_body_467: Option<u32>, alt_body_468: Option<u32>,
        alt_body_469: Option<u32>, alt_body_470: Option<u32>, alt_body_471: Option<u32>, alt_body_472: Option<u32>,
        alt_body_473: Option<u32>, alt_body_474: Option<u32>, alt_body_475: Option<u32>, alt_body_476: Option<u32>,
        alt_body_477: Option<u32>, alt_body_478: Option<u32>, alt_body_479: Option<u32>, alt_body_480: Option<u32>,
        alt_body_481: Option<u32>, alt_body_482: Option<u32>, alt_body_483: Option<u32>, alt_body_484: Option<u32>,
        alt_body_485: Option<u32>, alt_body_486: Option<u32>, alt_body_487: Option<u32>, alt_body_488: Option<u32>,
        alt_body_489: Option<u32>, alt_body_490: Option<u32>, alt_body_491: Option<u32>, alt_body_492: Option<u32>,
        alt_body_493: Option<u32>, alt_body_494: Option<u32>, alt_body_495: Option<u32>, alt_body_496: Option<u32>,
        alt_body_497: Option<u32>, alt_body_498: Option<u32>, alt_body_499: Option<u32>, alt_body_500: Option<u32>,
        alt_body_501: Option<u32>, alt_body_502: Option<u32>, alt_body_503: Option<u32>, alt_body_504: Option<u32>,
        alt_body_505: Option<u32>, alt_body_506: Option<u32>, alt_body_507: Option<u32>, alt_body_508: Option<u32>,
        alt_body_509: Option<u32>, alt_body_510: Option<u32>, alt_body_511: Option<u32>, alt_body_512: Option<u32>,
        alt_body_513: Option<u32>, alt_body_514: Option<u32>, alt_body_515: Option<u32>, alt_body_516: Option<u32>,
        alt_body_517: Option<u32>, alt_body_518: Option<u32>, alt_body_519: Option<u32>, alt_body_520: Option<u32>,
        alt_body_521: Option<u32>, alt_body_522: Option<u32>, alt_body_523: Option<u32>, alt_body_524: Option<u32>,
        alt_body_525: Option<u32>, alt_body_526: Option<u32>, alt_body_527: Option<u32>, alt_body_528: Option<u32>,
        alt_body_529: Option<u32>, alt_body_530: Option<u32>, alt_body_531: Option<u32>, alt_body_532: Option<u32>,
        alt_body_533: Option<u32>, alt_body_534: Option<u32>, alt_body_535: Option<u32>, alt_body_536: Option<u32>,
        alt_body_537: Option<u32>, alt_body_538: Option<u32>, alt_body_539: Option<u32>, alt_body_540: Option<u32>,
        alt_body_541: Option<u32>, alt_body_542: Option<u32>, alt_body_543: Option<u32>, alt_body_544: Option<u32>,
        alt_body_545: Option<u32>, alt_body_546: Option<u32>, alt_body_547: Option<u32>, alt_body_548: Option<u32>,
        alt_body_549: Option<u32>, alt_body_550: Option<u32>, alt_body_551: Option<u32>, alt_body_552: Option<u32>,
        alt_body_553: Option<u32>, alt_body_554: Option<u32>, alt_body_555: Option<u32>, alt_body_556: Option<u32>,
        alt_body_557: Option<u32>, alt_body_558: Option<u32>, alt_body_559: Option<u32>, alt_body_560: Option<u32>,
        alt_body_561: Option<u32>, alt_body_562: Option<u32>, alt_body_563: Option<u32>, alt_body_564: Option<u32>,
        alt_body_565: Option<u32>, alt_body_566: Option<u32>, alt_body_567: Option<u32>, alt_body_568: Option<u32>,
        alt_body_569: Option<u32>, alt_body_570: Option<u32>, alt_body_571: Option<u32>, alt_body_572: Option<u32>,
        alt_body_573: Option<u32>, alt_body_574: Option<u32>, alt_body_575: Option<u32>, alt_body_576: Option<u32>,
        alt_body_577: Option<u32>, alt_body_578: Option<u32>, alt_body_579: Option<u32>, alt_body_580: Option<u32>,
        alt_body_581: Option<u32>, alt_body_582: Option<u32>, alt_body_583: Option<u32>, alt_body_584: Option<u32>,
        alt_body_585: Option<u32>, alt_body_586: Option<u32>, alt_body_587: Option<u32>, alt_body_588: Option<u32>,
        alt_body_589: Option<u32>, alt_body_590: Option<u32>, alt_body_591: Option<u32>, alt_body_592: Option<u32>,
        alt_body_593: Option<u32>, alt_body_594: Option<u32>, alt_body_595: Option<u32>, alt_body_596: Option<u32>,
        alt_body_597: Option<u32>, alt_body_598: Option<u32>, alt_body_599: Option<u32>, alt_body_600: Option<u32>,
        alt_body_601: Option<u32>, alt_body_602: Option<u32>, alt_body_603: Option<u32>, alt_body_604: Option<u32>,
        alt_body_605: Option<u32>, alt_body_606: Option<u32>, alt_body_607: Option<u32>, alt_body_608: Option<u32>,
        alt_body_609: Option<u32>, alt_body_610: Option<u32>, alt_body_611: Option<u32>, alt_body_612: Option<u32>,
        alt_body_613: Option<u32>, alt_body_614: Option<u32>, alt_body_615: Option<u32>, alt_body_616: Option<u32>,
        alt_body_617: Option<u32>, alt_body_618: Option<u32>, alt_body_619: Option<u32>, alt_body_620: Option<u32>,
        alt_body_621: Option<u32>, alt_body_622: Option<u32>, alt_body_623: Option<u32>, alt_body_624: Option<u32>,
        alt_body_625: Option<u32>, alt_body_626: Option<u32>, alt_body_627: Option<u32>, alt_body_628: Option<u32>,
        alt_body_629: Option<u32>, alt_body_630: Option<u32>, alt_body_631: Option<u32>, alt_body_632: Option<u32>,
        alt_body_633: Option<u32>, alt_body_634: Option<u32>, alt_body_635: Option<u32>, alt_body_636: Option<u32>,
        alt_body_637: Option<u32>, alt_body_638: Option<u32>, alt_body_639: Option<u32>, alt_body_640: Option<u32>,
        alt_body_641: Option<u32>, alt_body_642: Option<u32>, alt_body_643: Option<u32>, alt_body_644: Option<u32>,
        alt_body_645: Option<u32>, alt_body_646: Option<u32>, alt_body_647: Option<u32>, alt_body_648: Option<u32>,
        alt_body_649: Option<u32>, alt_body_650: Option<u32>, alt_body_651: Option<u32>, alt_body_652: Option<u32>,
        alt_body_653: Option<u32>, alt_body_654: Option<u32>, alt_body_655: Option<u32>, alt_body_656: Option<u32>,
        alt_body_657: Option<u32>, alt_body_658: Option<u32>, alt_body_659: Option<u32>, alt_body_660: Option<u32>,
        alt_body_661: Option<u32>, alt_body_662: Option<u32>, alt_body_663: Option<u32>, alt_body_664: Option<u32>,
        alt_body_665: Option<u32>, alt_body_666: Option<u32>, alt_body_667: Option<u32>, alt_body_668: Option<u32>,
        alt_body_669: Option<u32>, alt_body_670: Option<u32>, alt_body_671: Option<u32>, alt_body_672: Option<u32>,
        alt_body_673: Option<u32>, alt_body_674: Option<u32>, alt_body_675: Option<u32>, alt_body_676: Option<u32>,
        alt_body_677: Option<u32>, alt_body_678: Option<u32>, alt_body_679: Option<u32>, alt_body_680: Option<u32>,
        alt_body_681: Option<u32>, alt_body_682: Option<u32>, alt_body_683: Option<u32>, alt_body_684: Option<u32>,
        alt_body_685: Option<u32>, alt_body_686: Option<u32>, alt_body_687: Option<u32>, alt_body_688: Option<u32>,
        alt_body_689: Option<u32>, alt_body_690: Option<u32>, alt_body_691: Option<u32>, alt_body_692: Option<u32>,
        alt_body_693: Option<u32>, alt_body_694: Option<u32>, alt_body_695: Option<u32>, alt_body_696: Option<u32>,
        alt_body_697: Option<u32>, alt_body_698: Option<u32>, alt_body_699: Option<u32>, alt_body_700: Option<u32>,
        alt_body_701: Option<u32>, alt_body_702: Option<u32>, alt_body_703: Option<u32>, alt_body_704: Option<u32>,
        alt_body_705: Option<u32>, alt_body_706: Option<u32>, alt_body_707: Option<u32>, alt_body_708: Option<u32>,
        alt_body_709: Option<u32>, alt_body_710: Option<u32>, alt_body_711: Option<u32>, alt_body_712: Option<u32>,
        alt_body_713: Option<u32>, alt_body_714: Option<u32>, alt_body_715: Option<u32>, alt_body_716: Option<u32>,
        alt_body_717: Option<u32>, alt_body_718: Option<u32>, alt_body_719: Option<u32>, alt_body_720: Option<u32>,
        alt_body_721: Option<u32>, alt_body_722: Option<u32>, alt_body_723: Option<u32>, alt_body_724: Option<u32>,
        alt_body_725: Option<u32>, alt_body_726: Option<u32>, alt_body_727: Option<u32>, alt_body_728: Option<u32>,
        alt_body_729: Option<u32>, alt_body_730: Option<u32>, alt_body_731: Option<u32>, alt_body_732: Option<u32>,
        alt_body_733: Option<u32>, alt_body_734: Option<u32>, alt_body_735: Option<u32>, alt_body_736: Option<u32>,
        alt_body_737: Option<u32>, alt_body_738: Option<u32>, alt_body_739: Option<u32>, alt_body_740: Option<u32>,
        alt_body_741: Option<u32>, alt_body_742: Option<u32>, alt_body_743: Option<u32>, alt_body_744: Option<u32>,
        alt_body_745: Option<u32>, alt_body_746: Option<u32>, alt_body_747: Option<u32>, alt_body_748: Option<u32>,
        alt_body_749: Option<u32>, alt_body_750: Option<u32>, alt_body_751: Option<u32>, alt_body_752: Option<u32>,
        alt_body_753: Option<u32>, alt_body_754: Option<u32>, alt_body_755: Option<u32>, alt_body_756: Option<u32>,
        alt_body_757: Option<u32>, alt_body_758: Option<u32>, alt_body_759: Option<u32>, alt_body_760: Option<u32>,
        alt_body_761: Option<u32>, alt_body_762: Option<u32>, alt_body_763: Option<u32>, alt_body_764: Option<u32>,
        alt_body_765: Option<u32>, alt_body_766: Option<u32>, alt_body_767: Option<u32>, alt_body_768: Option<u32>,
        alt_body_769: Option<u32>, alt_body_770: Option<u32>, alt_body_771: Option<u32>, alt_body_772: Option<u32>,
        alt_body_773: Option<u32>, alt_body_774: Option<u32>, alt_body_775: Option<u32>, alt_body_776: Option<u32>,
        alt_body_777: Option<u32>, alt_body_778: Option<u32>, alt_body_779: Option<u32>, alt_body_780: Option<u32>,
        alt_body_781: Option<u32>, alt_body_782: Option<u32>, alt_body_783: Option<u32>, alt_body_784: Option<u32>,
        alt_body_785: Option<u32>, alt_body_786: Option<u32>, alt_body_787: Option<u32>, alt_body_788: Option<u32>,
        alt_body_789: Option<u32>, alt_body_790: Option<u32>, alt_body_791: Option<u32>, alt_body_792: Option<u32>,
        alt_body_793: Option<u32>, alt_body_794: Option<u32>, alt_body_795: Option<u32>, alt_body_796: Option<u32>,
        alt_body_797: Option<u32>, alt_body_798: Option<u32>, alt_body_799: Option<u32>, alt_body_800: Option<u32>,
        alt_body_801: Option<u32>, alt_body_802: Option<u32>, alt_body_803: Option<u32>, alt_body_804: Option<u32>,
        alt_body_805: Option<u32>, alt_body_806: Option<u32>, alt_body_807: Option<u32>, alt_body_808: Option<u32>,
        alt_body_809: Option<u32>, alt_body_810: Option<u32>, alt_body_811: Option<u32>, alt_body_812: Option<u32>,
        alt_body_813: Option<u32>, alt_body_814: Option<u32>, alt_body_815: Option<u32>, alt_body_816: Option<u32>,
        alt_body_817: Option<u32>, alt_body_818: Option<u32>, alt_body_819: Option<u32>, alt_body_820: Option<u32>,
        alt_body_821: Option<u32>, alt_body_822: Option<u32>, alt_body_823: Option<u32>, alt_body_824: Option<u32>,
        alt_body_825: Option<u32>, alt_body_826: Option<u32>, alt_body_827: Option<u32>, alt_body_828: Option<u32>,
        alt_body_829: Option<u32>, alt_body_830: Option<u32>, alt_body_831: Option<u32>, alt_body_832: Option<u32>,
        alt_body_833: Option<u32>, alt_body_834: Option<u32>, alt_body_835: Option<u32>, alt_body_836: Option<u32>,
        alt_body_837: Option<u32>, alt_body_838: Option<u32>, alt_body_839: Option<u32>, alt_body_840: Option<u32>,
        alt_body_841: Option<u32>, alt_body_842: Option<u32>, alt_body_843: Option<u32>, alt_body_844: Option<u32>,
        alt_body_845: Option<u32>, alt_body_846: Option<u32>, alt_body_847: Option<u32>, alt_body_848: Option<u32>,
        alt_body_849: Option<u32>, alt_body_850: Option<u32>, alt_body_851: Option<u32>, alt_body_852: Option<u32>,
        alt_body_853: Option<u32>, alt_body_854: Option<u32>, alt_body_855: Option<u32>, alt_body_856: Option<u32>,
        alt_body_857: Option<u32>, alt_body_858: Option<u32>, alt_body_859: Option<u32>, alt_body_860: Option<u32>,
        alt_body_861: Option<u32>, alt_body_862: Option<u32>, alt_body_863: Option<u32>, alt_body_864: Option<u32>,
        alt_body_865: Option<u32>, alt_body_866: Option<u32>, alt_body_867: Option<u32>, alt_body_868: Option<u32>,
        alt_body_869: Option<u32>, alt_body_870: Option<u32>, alt_body_871: Option<u32>, alt_body_872: Option<u32>,
        alt_body_873: Option<u32>, alt_body_874: Option<u32>, alt_body_875: Option<u32>, alt_body_876: Option<u32>,
        alt_body_877: Option<u32>, alt_body_878: Option<u32>, alt_body_879: Option<u32>, alt_body_880: Option<u32>,
        alt_body_881: Option<u32>, alt_body_882: Option<u32>, alt_body_883: Option<u32>, alt_body_884: Option<u32>,
        alt_body_885: Option<u32>, alt_body_886: Option<u32>, alt_body_887: Option<u32>, alt_body_888: Option<u32>,
        alt_body_889: Option<u32>, alt_body_890: Option<u32>, alt_body_891: Option<u32>, alt_body_892: Option<u32>,
        alt_body_893: Option<u32>, alt_body_894: Option<u32>, alt_body_895: Option<u32>, alt_body_896: Option<u32>,
        alt_body_897: Option<u32>, alt_body_898: Option<u32>, alt_body_899: Option<u32>, alt_body_900: Option<u32>,
        alt_body_901: Option<u32>, alt_body_902: Option<u32>, alt_body_903: Option<u32>, alt_body_904: Option<u32>,
        alt_body_905: Option<u32>, alt_body_906: Option<u32>, alt_body_907: Option<u32>, alt_body_908: Option<u32>,
        alt_body_909: Option<u32>, alt_body_910: Option<u32>, alt_body_911: Option<u32>, alt_body_912: Option<u32>,
        alt_body_913: Option<u32>, alt_body_914: Option<u32>, alt_body_915: Option<u32>, alt_body_916: Option<u32>,
        alt_body_917: Option<u32>, alt_body_918: Option<u32>, alt_body_919: Option<u32>, alt_body_920: Option<u32>,
        alt_body_921: Option<u32>, alt_body_922: Option<u32>, alt_body_923: Option<u32>, alt_body_924: Option<u32>,
        alt_body_925: Option<u32>, alt_body_926: Option<u32>, alt_body_927: Option<u32>, alt_body_928: Option<u32>,
        alt_body_929: Option<u32>, alt_body_930: Option<u32>, alt_body_931: Option<u32>, alt_body_932: Option<u32>,
        alt_body_933: Option<u32>, alt_body_934: Option<u32>, alt_body_935: Option<u32>, alt_body_936: Option<u32>,
        alt_body_937: Option<u32>, alt_body_938: Option<u32>, alt_body_939: Option<u32>, alt_body_940: Option<u32>,
        alt_body_941: Option<u32>, alt_body_942: Option<u32>, alt_body_943: Option<u32>, alt_body_944: Option<u32>,
        alt_body_945: Option<u32>, alt_body_946: Option<u32>, alt_body_947: Option<u32>, alt_body_948: Option<u32>,
        alt_body_949: Option<u32>, alt_body_950: Option<u32>, alt_body_951: Option<u32>, alt_body_952: Option<u32>,
        alt_body_953: Option<u32>, alt_body_954: Option<u32>, alt_body_955: Option<u32>, alt_body_956: Option<u32>,
        alt_body_957: Option<u32>, alt_body_958: Option<u32>, alt_body_959: Option<u32>, alt_body_960: Option<u32>,
        alt_body_961: Option<u32>, alt_body_962: Option<u32>, alt_body_963: Option<u32>, alt_body_964: Option<u32>,
        alt_body_965: Option<u32>, alt_body_966: Option<u32>, alt_body_967: Option<u32>, alt_body_968: Option<u32>,
        alt_body_969: Option<u32>, alt_body_970: Option<u32>, alt_body_971: Option<u32>, alt_body_972: Option<u32>,
        alt_body_973: Option<u32>, alt_body_974: Option<u32>, alt_body_975: Option<u32>, alt_body_976: Option<u32>,
        alt_body_977: Option<u32>, alt_body_978: Option<u32>, alt_body_979: Option<u32>, alt_body_980: Option<u32>,
        alt_body_981: Option<u32>, alt_body_982: Option<u32>, alt_body_983: Option<u32>, alt_body_984: Option<u32>,
        alt_body_985: Option<u32>, alt_body_986: Option<u32>, alt_body_987: Option<u32>, alt_body_988: Option<u32>,
        alt_body_989: Option<u32>, alt_body_990: Option<u32>, alt_body_991: Option<u32>, alt_body_992: Option<u32>,
        alt_body_993: Option<u32>, alt_body_994: Option<u32>, alt_body_995: Option<u32>, alt_body_996: Option<u32>,
        alt_body_997: Option<u32>, alt_body_998: Option<u32>, alt_body_999: Option<u32>, alt_body_1000: Option<u32>,
        alt_body_1001: Option<u32>, alt_body_1002: Option<u32>, alt_body_1003: Option<u32>, alt_body_1004: Option<u32>,
        alt_body_1005: Option<u32>, alt_body_1006: Option<u32>, alt_body_1007: Option<u32>, alt_body_1008: Option<u32>,
        alt_body_1009: Option<u32>, alt_body_1010: Option<u32>, alt_body_1011: Option<u32>, alt_body_1012: Option<u32>,
        alt_body_1013: Option<u32>, alt_body_1014: Option<u32>, alt_body_1015: Option<u32>, alt_body_1016: Option<u32>,
        alt_body_1017: Option<u32>, alt_body_1018: Option<u32>, alt_body_1019: Option<u32>, alt_body_1020: Option<u32>,
        alt_body_1021: Option<u32>, alt_body_1022: Option<u32>, alt_body_1023: Option<u32>, alt_body_1024: Option<u32>,
        alt_body_1025: Option<u32>, alt_body_1026: Option<u32>, alt_body_1027: Option<u32>, alt_body_1028: Option<u32>,
        alt_body_1029: Option<u32>, alt_body_1030: Option<u32>, alt_body_1031: Option<u32>, alt_body_1032: Option<u32>,
        alt_body_1033: Option<u32>, alt_body_1034: Option<u32>, alt_body_1035: Option<u32>, alt_body_1036: Option<u32>,
        alt_body_1037: Option<u32>, alt_body_1038: Option<u32>, alt_body_1039: Option<u32>, alt_body_1040: Option<u32>,
        alt_body_1041: Option<u32>, alt_body_1042: Option<u32>, alt_body_1043: Option<u32>, alt_body_1044: Option<u32>,
        alt_body_1045: Option<u32>, alt_body_1046: Option<u32>, alt_body_1047: Option<u32>, alt_body_1048: Option<u32>,
        alt_body_1049: Option<u32>, alt_body_1050: Option<u32>, alt_body_1051: Option<u32>, alt_body_1052: Option<u32>,
        alt_body_1053: Option<u32>, alt_body_1054: Option<u32>, alt_body_1055: Option<u32>, alt_body_1056: Option<u32>,
        alt_body_1057: Option<u32>, alt_body_1058: Option<u32>, alt_body_1059: Option<u32>, alt_body_1060: Option<u32>,
        alt_body_1061: Option<u32>, alt_body_1062: Option<u32>, alt_body_1063: Option<u32>, alt_body_1064: Option<u32>,
        alt_body_1065: Option<u32>, alt_body_1066: Option<u32>, alt_body_1067: Option<u32>, alt_body_1068: Option<u32>,
        alt_body_1069: Option<u32>, alt_body_1070: Option<u32>, alt_body_1071: Option<u32>, alt_body_1072: Option<u32>,
        alt_body_1073: Option<u32>, alt_body_1074: Option<u32>, alt_body_1075: Option<u32>, alt_body_1076: Option<u32>,
        alt_body_1077: Option<u32>, alt_body_1078: Option<u32>, alt_body_1079: Option<u32>, alt_body_1080: Option<u32>,
        alt_body_1081: Option<u32>, alt_body_1082: Option<u32>, alt_body_1083: Option<u32>, alt_body_1084: Option<u32>,
        alt_body_1085: Option<u32>, alt_body_1086: Option<u32>, alt_body_1087: Option<u32>, alt_body_1088: Option<u32>,
        alt_body_1089: Option<u32>, alt_body_1090: Option<u32>, alt_body_1091: Option<u32>, alt_body_1092: Option<u32>,
        alt_body_1093: Option<u32>, alt_body_1094: Option<u32>, alt_body_1095: Option<u32>, alt_body_1096: Option<u32>,
        alt_body_1097: Option<u32>, alt_body_1098: Option<u32>, alt_body_1099: Option<u32>, alt_body_1100: Option<u32>,
        alt_body_1101: Option<u32>, alt_body_1102: Option<u32>, alt_body_1103: Option<u32>, alt_body_1104: Option<u32>,
        alt_body_1105: Option<u32>, alt_body_1106: Option<u32>, alt_body_1107: Option<u32>, alt_body_1108: Option<u32>,
        alt_body_1109: Option<u32>, alt_body_1110: Option<u32>, alt_body_1111: Option<u32>, alt_body_1112: Option<u32>,
        alt_body_1113: Option<u32>, alt_body_1114: Option<u32>, alt_body_1115: Option<u32>, alt_body_1116: Option<u32>,
        alt_body_1117: Option<u32>, alt_body_1118: Option<u32>, alt_body_1119: Option<u32>, alt_body_1120: Option<u32>,
        alt_body_1121: Option<u32>, alt_body_1122: Option<u32>, alt_body_1123: Option<u32>, alt_body_1124: Option<u32>,
        alt_body_1125: Option<u32>, alt_body_1126: Option<u32>, alt_body_1127: Option<u32>, alt_body_1128: Option<u32>,
        alt_body_1129: Option<u32>, alt_body_1130: Option<u32>, alt_body_1131: Option<u32>, alt_body_1132: Option<u32>,
        alt_body_1133: Option<u32>, alt_body_1134: Option<u32>, alt_body_1135: Option<u32>, alt_body_1136: Option<u32>,
        alt_body_1137: Option<u32>, alt_body_1138: Option<u32>, alt_body_1139: Option<u32>, alt_body_1140: Option<u32>,
        alt_body_1141: Option<u32>, alt_body_1142: Option<u32>, alt_body_1143: Option<u32>, alt_body_1144: Option<u32>,
        alt_body_1145: Option<u32>, alt_body_1146: Option<u32>, alt_body_1147: Option<u32>, alt_body_1148: Option<u32>,
        alt_body_1149: Option<u32>, alt_body_1150: Option<u32>, alt_body_1151: Option<u32>, alt_body_1152: Option<u32>,
        alt_body_1153: Option<u32>, alt_body_1154: Option<u32>, alt_body_1155: Option<u32>, alt_body_1156: Option<u32>,
        alt_body_1157: Option<u32>, alt_body_1158: Option<u32>, alt_body_1159: Option<u32>, alt_body_1160: Option<u32>,
        alt_body_1161: Option<u32>, alt_body_1162: Option<u32>, alt_body_1163: Option<u32>, alt_body_1164: Option<u32>,
        alt_body_1165: Option<u32>, alt_body_1166: Option<u32>, alt_body_1167: Option<u32>, alt_body_1168: Option<u32>,
        alt_body_1169: Option<u32>, alt_body_1170: Option<u32>, alt_body_1171: Option<u32>, alt_body_1172: Option<u32>,
        alt_body_1173: Option<u32>, alt_body_1174: Option<u32>, alt_body_1175: Option<u32>, alt_body_1176: Option<u32>,
        alt_body_1177: Option<u32>, alt_body_1178: Option<u32>, alt_body_1179: Option<u32>, alt_body_1180: Option<u32>,
        alt_body_1181: Option<u32>, alt_body_1182: Option<u32>, alt_body_1183: Option<u32>, alt_body_1184: Option<u32>,
        alt_body_1185: Option<u32>, alt_body_1186: Option<u32>, alt_body_1187: Option<u32>, alt_body_1188: Option<u32>,
        alt_body_1189: Option<u32>, alt_body_1190: Option<u32>, alt_body_1191: Option<u32>, alt_body_1192: Option<u32>,
        alt_body_1193: Option<u32>, alt_body_1194: Option<u32>, alt_body_1195: Option<u32>, alt_body_1196: Option<u32>,
        alt_body_1197: Option<u32>, alt_body_1198: Option<u32>, alt_body_1199: Option<u32>, alt_body_1200: Option<u32>,
        alt_body_1201: Option<u32>, alt_body_1202: Option<u32>, alt_body_1203: Option<u32>, alt_body_1204: Option<u32>,
        alt_body_1205: Option<u32>, alt_body_1206: Option<u32>, alt_body_1207: Option<u32>, alt_body_1208: Option<u32>,
        alt_body_1209: Option<u32>, alt_body_1210: Option<u32>, alt_body_1211: Option<u32>, alt_body_1212: Option<u32>,
        alt_body_1213: Option<u32>, alt_body_1214: Option<u32>, alt_body_1215: Option<u32>, alt_body_1216: Option<u32>,
        alt_body_1217: Option<u32>, alt_body_1218: Option<u32>, alt_body_1219: Option<u32>, alt_body_1220: Option<u32>,
        alt_body_1221: Option<u32>, alt_body_1222: Option<u32>, alt_body_1223: Option<u32>, alt_body_1224: Option<u32>,
        alt_body_1225: Option<u32>, alt_body_1226: Option<u32>, alt_body_1227: Option<u32>, alt_body_1228: Option<u32>,
        alt_body_1229: Option<u32>, alt_body_1230: Option<u32>, alt_body_1231: Option<u32>, alt_body_1232: Option<u32>,
        alt_body_1233: Option<u32>, alt_body_1234: Option<u32>, alt_body_1235: Option<u32>, alt_body_1236: Option<u32>,
        alt_body_1237: Option<u32>, alt_body_1238: Option<u32>, alt_body_1239: Option<u32>, alt_body_1240: Option<u32>,
        alt_body_1241: Option<u32>, alt_body_1242: Option<u32>, alt_body_1243: Option<u32>, alt_body_1244: Option<u32>,
        alt_body_1245: Option<u32>, alt_body_1246: Option<u32>, alt_body_1247: Option<u32>, alt_body_1248: Option<u32>,
        alt_body_1249: Option<u32>, alt_body_1250: Option<u32>, alt_body_1251: Option<u32>, alt_body_1252: Option<u32>,
        alt_body_1253: Option<u32>, alt_body_1254: Option<u32>, alt_body_1255: Option<u32>, alt_body_1256: Option<u32>,
        alt_body_1257: Option<u32>, alt_body_1258: Option<u32>, alt_body_1259: Option<u32>, alt_body_1260: Option<u32>,
        alt_body_1261: Option<u32>, alt_body_1262: Option<u32>, alt_body_1263: Option<u32>, alt_body_1264: Option<u32>,
        alt_body_1265: Option<u32>, alt_body_1266: Option<u32>, alt_body_1267: Option<u32>, alt_body_1268: Option<u32>,
        alt_body_1269: Option<u32>, alt_body_1270: Option<u32>, alt_body_1271: Option<u32>, alt_body_1272: Option<u32>,
        alt_body_1273: Option<u32>, alt_body_1274: Option<u32>, alt_body_1275: Option<u32>, alt_body_1276: Option<u32>,
        alt_body_1277: Option<u32>, alt_body_1278: Option<u32>, alt_body_1279: Option<u32>, alt_body_1280: Option<u32>,
        alt_body_1281: Option<u32>, alt_body_1282: Option<u32>, alt_body_1283: Option<u32>, alt_body_1284: Option<u32>,
        alt_body_1285: Option<u32>, alt_body_1286: Option<u32>, alt_body_1287: Option<u32>, alt_body_1288: Option<u32>,
        alt_body_1289: Option<u32>, alt_body_1290: Option<u32>, alt_body_1291: Option<u32>, alt_body_1292: Option<u32>,
        alt_body_1293: Option<u32>, alt_body_1294: Option<u32>, alt_body_1295: Option<u32>, alt_body_1296: Option<u32>,
        alt_body_1297: Option<u32>, alt_body_1298: Option<u32>, alt_body_1299: Option<u32>, alt_body_1300: Option<u32>,
        alt_body_1301: Option<u32>, alt_body_1302: Option<u32>, alt_body_1303: Option<u32>, alt_body_1304: Option<u32>,
        alt_body_1305: Option<u32>, alt_body_1306: Option<u32>, alt_body_1307: Option<u32>, alt_body_1308: Option<u32>,
        alt_body_1309: Option<u32>, alt_body_1310: Option<u32>, alt_body_1311: Option<u32>, alt_body_1312: Option<u32>,
        alt_body_1313: Option<u32>, alt_body_1314: Option<u32>, alt_body_1315: Option<u32>, alt_body_1316: Option<u32>,
        alt_body_1317: Option<u32>, alt_body_1318: Option<u32>, alt_body_1319: Option<u32>, alt_body_1320: Option<u32>,
        alt_body_1321: Option<u32>, alt_body_1322: Option<u32>, alt_body_1323: Option<u32>, alt_body_1324: Option<u32>,
        alt_body_1325: Option<u32>, alt_body_1326: Option<u32>, alt_body_1327: Option<u32>, alt_body_1328: Option<u32>,
        alt_body_1329: Option<u32>, alt_body_1330: Option<u32>, alt_body_1331: Option<u32>, alt_body_1332: Option<u32>,
        alt_body_1333: Option<u32>, alt_body_1334: Option<u32>, alt_body_1335: Option<u32>, alt_body_1336: Option<u32>,
        alt_body_1337: Option<u32>, alt_body_1338: Option<u32>, alt_body_1339: Option<u32>, alt_body_1340: Option<u32>,
        alt_body_1341: Option<u32>, alt_body_1342: Option<u32>, alt_body_1343: Option<u32>, alt_body_1344: Option<u32>,
        alt_body_1345: Option<u32>, alt_body_1346: Option<u32>, alt_body_1347: Option<u32>, alt_body_1348: Option<u32>,
        alt_body_1349: Option<u32>, alt_body_1350: Option<u32>, alt_body_1351: Option<u32>, alt_body_1352: Option<u32>,
        alt_body_1353: Option<u32>, alt_body_1354: Option<u32>, alt_body_1355: Option<u32>, alt_body_1356: Option<u32>,
        alt_body_1357: Option<u32>, alt_body_1358: Option<u32>, alt_body_1359: Option<u32>, alt_body_1360: Option<u32>,
        alt_body_1361: Option<u32>, alt_body_1362: Option<u32>, alt_body_1363: Option<u32>, alt_body_1364: Option<u32>,
        alt_body_1365: Option<u32>, alt_body_1366: Option<u32>, alt_body_1367: Option<u32>, alt_body_1368: Option<u32>,
        alt_body_1369: Option<u32>, alt_body_1370: Option<u32>, alt_body_1371: Option<u32>, alt_body_1372: Option<u32>,
        alt_body_1373: Option<u32>, alt_body_1374: Option<u32>, alt_body_1375: Option<u32>, alt_body_1376: Option<u32>,
        alt_body_1377: Option<u32>, alt_body_1378: Option<u32>, alt_body_1379: Option<u32>, alt_body_1380: Option<u32>,
        alt_body_1381: Option<u32>, alt_body_1382: Option<u32>, alt_body_1383: Option<u32>, alt_body_1384: Option<u32>,
        alt_body_1385: Option<u32>, alt_body_1386: Option<u32>, alt_body_1387: Option<u32>, alt_body_1388: Option<u32>,
        alt_body_1389: Option<u32>, alt_body_1390: Option<u32>, alt_body_1391: Option<u32>, alt_body_1392: Option<u32>,
        alt_body_1393: Option<u32>, alt_body_1394: Option<u32>, alt_body_1395: Option<u32>, alt_body_1396: Option<u32>,
        alt_body_1397: Option<u32>, alt_body_1398: Option<u32>, alt_body_1399: Option<u32>, alt_body_1400: Option<u32>,
        alt_body_1401: Option<u32>, alt_body_1402: Option<u32>, alt_body_1403: Option<u32>, alt_body_1404: Option<u32>,
        alt_body_1405: Option<u32>, alt_body_1406: Option<u32>, alt_body_1407: Option<u32>, alt_body_1408: Option<u32>,
        alt_body_1409: Option<u32>, alt_body_1410: Option<u32>, alt_body_1411: Option<u32>, alt_body_1412: Option<u32>,
        alt_body_1413: Option<u32>, alt_body_1414: Option<u32>, alt_body_1415: Option<u32>, alt_body_1416: Option<u32>,
        alt_body_1417: Option<u32>, alt_body_1418: Option<u32>, alt_body_1419: Option<u32>, alt_body_1420: Option<u32>,
        alt_body_1421: Option<u32>, alt_body_1422: Option<u32>, alt_body_1423: Option<u32>, alt_body_1424: Option<u32>,
        alt_body_1425: Option<u32>, alt_body_1426: Option<u32>, alt_body_1427: Option<u32>, alt_body_1428: Option<u32>,
        alt_body_1429: Option<u32>, alt_body_1430: Option<u32>, alt_body_1431: Option<u32>, alt_body_1432: Option<u32>,
        alt_body_1433: Option<u32>, alt_body_1434: Option<u32>, alt_body_1435: Option<u32>, alt_body_1436: Option<u32>,
        alt_body_1437: Option<u32>, alt_body_1438: Option<u32>, alt_body_1439: Option<u32>, alt_body_1440: Option<u32>,
        alt_body_1441: Option<u32>, alt_body_1442: Option<u32>, alt_body_1443: Option<u32>, alt_body_1444: Option<u32>,
        alt_body_1445: Option<u32>, alt_body_1446: Option<u32>, alt_body_1447: Option<u32>, alt_body_1448: Option<u32>,
        alt_body_1449: Option<u32>, alt_body_1450: Option<u32>, alt_body_1451: Option<u32>, alt_body_1452: Option<u32>,
        alt_body_1453: Option<u32>, alt_body_1454: Option<u32>, alt_body_1455: Option<u32>, alt_body_1456: Option<u32>,
        alt_body_1457: Option<u32>, alt_body_1458: Option<u32>, alt_body_1459: Option<u32>, alt_body_1460: Option<u32>,
        alt_body_1461: Option<u32>, alt_body_1462: Option<u32>, alt_body_1463: Option<u32>, alt_body_1464: Option<u32>,
        alt_body_1465: Option<u32>, alt_body_1466: Option<u32>, alt_body_1467: Option<u32>, alt_body_1468: Option<u32>,
        alt_body_1469: Option<u32>, alt_body_1470: Option<u32>, alt_body_1471: Option<u32>, alt_body_1472: Option<u32>,
        alt_body_1473: Option<u32>, alt_body_1474: Option<u32>, alt_body_1475: Option<u32>, alt_body_1476: Option<u32>,
        alt_body_1477: Option<u32>, alt_body_1478: Option<u32>, alt_body_1479: Option<u32>, alt_body_1480: Option<u32>,
        alt_body_1481: Option<u32>, alt_body_1482: Option<u32>, alt_body_1483: Option<u32>, alt_body_1484: Option<u32>,
        alt_body_1485: Option<u32>, alt_body_1486: Option<u32>, alt_body_1487: Option<u32>, alt_body_1488: Option<u32>,
        alt_body_1489: Option<u32>, alt_body_1490: Option<u32>, alt_body_1491: Option<u32>, alt_body_1492: Option<u32>,
        alt_body_1493: Option<u32>, alt_body_1494: Option<u32>, alt_body_1495: Option<u32>, alt_body_1496: Option<u32>,
        alt_body_1497: Option<u32>, alt_body_1498: Option<u32>, alt_body_1499: Option<u32>, alt_body_1500: Option<u32>,
        alt_body_1501: Option<u32>, alt_body_1502: Option<u32>, alt_body_1503: Option<u32>, alt_body_1504: Option<u32>,
        alt_body_1505: Option<u32>, alt_body_1506: Option<u32>, alt_body_1507: Option<u32>, alt_body_1508: Option<u32>,
        alt_body_1509: Option<u32>, alt_body_1510: Option<u32>, alt_body_1511: Option<u32>, alt_body_1512: Option<u32>,
        alt_body_1513: Option<u32>, alt_body_1514: Option<u32>, alt_body_1515: Option<u32>, alt_body_1516: Option<u32>,
        alt_body_1517: Option<u32>, alt_body_1518: Option<u32>, alt_body_1519: Option<u32>, alt_body_1520: Option<u32>,
        alt_body_1521: Option<u32>, alt_body_1522: Option<u32>, alt_body_1523: Option<u32>, alt_body_1524: Option<u32>,
        alt_body_1525: Option<u32>, alt_body_1526: Option<u32>, alt_body_1527: Option<u32>, alt_body_1528: Option<u32>,
        alt_body_1529: Option<u32>, alt_body_1530: Option<u32>, alt_body_1531: Option<u32>, alt_body_1532: Option<u32>,
        alt_body_1533: Option<u32>, alt_body_1534: Option<u32>, alt_body_1535: Option<u32>, alt_body_1536: Option<u32>,
        /// CString detected after alt_body_640 — usually file path or XML content
        /// in the longest entries (e.g. "d:/bs/cd_alpha/cd/resource/...staticinfo.xml").
        alt_post_cstr_a: Option<CString<'a>>,
        /// Second CString detected (some entries have asset path after first).
        alt_post_cstr_b: Option<CString<'a>>,
        /// Fields 665-728 — long-tail u32 sequence (64-field batch).
        field_665_u32: Option<u32>, field_666_u32: Option<u32>, field_667_u32: Option<u32>, field_668_u32: Option<u32>,
        field_669_u32: Option<u32>, field_670_u32: Option<u32>, field_671_u32: Option<u32>, field_672_u32: Option<u32>,
        field_673_u32: Option<u32>, field_674_u32: Option<u32>, field_675_u32: Option<u32>, field_676_u32: Option<u32>,
        field_677_u32: Option<u32>, field_678_u32: Option<u32>, field_679_u32: Option<u32>, field_680_u32: Option<u32>,
        field_681_u32: Option<u32>, field_682_u32: Option<u32>, field_683_u32: Option<u32>, field_684_u32: Option<u32>,
        field_685_u32: Option<u32>, field_686_u32: Option<u32>, field_687_u32: Option<u32>, field_688_u32: Option<u32>,
        field_689_u32: Option<u32>, field_690_u32: Option<u32>, field_691_u32: Option<u32>, field_692_u32: Option<u32>,
        field_693_u32: Option<u32>, field_694_u32: Option<u32>, field_695_u32: Option<u32>, field_696_u32: Option<u32>,
        field_697_u32: Option<u32>, field_698_u32: Option<u32>, field_699_u32: Option<u32>, field_700_u32: Option<u32>,
        field_701_u32: Option<u32>, field_702_u32: Option<u32>, field_703_u32: Option<u32>, field_704_u32: Option<u32>,
        field_705_u32: Option<u32>, field_706_u32: Option<u32>, field_707_u32: Option<u32>, field_708_u32: Option<u32>,
        field_709_u32: Option<u32>, field_710_u32: Option<u32>, field_711_u32: Option<u32>, field_712_u32: Option<u32>,
        field_713_u32: Option<u32>, field_714_u32: Option<u32>, field_715_u32: Option<u32>, field_716_u32: Option<u32>,
        field_717_u32: Option<u32>, field_718_u32: Option<u32>, field_719_u32: Option<u32>, field_720_u32: Option<u32>,
        field_721_u32: Option<u32>, field_722_u32: Option<u32>, field_723_u32: Option<u32>, field_724_u32: Option<u32>,
        field_725_u32: Option<u32>, field_726_u32: Option<u32>, field_727_u32: Option<u32>, field_728_u32: Option<u32>,
        /// Trailing pad bytes — drained as chained `Option<u8>` until probe runs out.
        /// Captures the 1-3 trailing zero bytes seen in ~10500 entries (mostly 0x00 padding).
        tail_pad_001: Option<u8>, tail_pad_002: Option<u8>, tail_pad_003: Option<u8>, tail_pad_004: Option<u8>,
        post_blob: Vec<u8>,
    },
    Raw(Vec<u8>),
}

impl<'a> GimmickTail<'a> {
    /// Smart alt_body chain reader: peeks at next u32 as potential CString
    /// length; if length is 9-65535 AND following bytes are valid UTF-8 with
    /// >=80% printable ASCII, sets `chain_stopped=true` and returns None
    /// (preserving probe so alt_post_cstr_a can read the CString). Otherwise
    /// reads u32 normally.
    fn try_smart_alt_body_read(
        data: &[u8],
        probe: &mut usize,
        entry_end: usize,
        chain_stopped: &mut bool,
        prev_some: bool,
    ) -> Option<u32> {
        if *chain_stopped || !prev_some || *probe + 4 > entry_end {
            return None;
        }
        let len = u32::from_le_bytes(data[*probe..*probe+4].try_into().unwrap()) as usize;
        if len > 8 && len < 65536 && *probe + 4 + len <= entry_end {
            let str_bytes = &data[*probe+4..*probe+4+len];
            if std::str::from_utf8(str_bytes).is_ok() {
                let printable = str_bytes.iter().filter(|&&b|
                    (0x20..=0x7e).contains(&b) || b == 0x09 || b == 0x0a || b == 0x0d
                ).count();
                if printable * 5 >= str_bytes.len() * 4 {
                    *chain_stopped = true;
                    return None;
                }
            }
        }
        let pre = *probe;
        match u32::read_from(data, probe) {
            Ok(v) => Some(v),
            _ => { *probe = pre; None }
        }
    }

    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_end: usize) -> io::Result<Self> {
        let tail_start = *offset;
        let mut probe = tail_start;
        let try_decode = (|| -> io::Result<_> {
            let list = GimmickInteractionOverrideCArray::read_from(data, &mut probe)?;
            if probe > entry_end { return Err(io::Error::new(io::ErrorKind::InvalidData, "overrun")); }
            let use_interaction_ui_socket = u8::read_from(data, &mut probe)?;
            let use_sub_part_for_interaction = u8::read_from(data, &mut probe)?;
            let property_list = <CArray<u32>>::read_from(data, &mut probe)?;
            let gimmick_name_hash = u32::read_from(data, &mut probe)?;
            let gimmick_name = LocalizableString::read_from(data, &mut probe)?;
            let emoji_texture_id = CString::read_from(data, &mut probe)?;
            let dev_memo = CString::read_from(data, &mut probe)?;
            let hash_pair_list = <CArray<GimmickHashPair>>::read_from(data, &mut probe)?;
            let hash_single_list = <CArray<GimmickHashSingle>>::read_from(data, &mut probe)?;
            if probe > entry_end { return Err(io::Error::new(io::ErrorKind::InvalidData, "overrun")); }
            Ok((list, use_interaction_ui_socket, use_sub_part_for_interaction,
                property_list, gimmick_name_hash, gimmick_name, emoji_texture_id, dev_memo,
                hash_pair_list, hash_single_list))
        })();
        match try_decode {
            Ok((list, ui, sp, pl, gnh, gn, eti, dm, hpl, hsl)) => {
                // Try to type field 17 (CArray<COptional<TGPEHD>>); fall back
                // to leaving it in post_blob if any sub-decode misaligns.
                let pre_tgpehd = probe;
                let trigger_event_handler_list = match <CArray<OptionalTriggerGamePlayEventHandlerData>>::read_from(data, &mut probe) {
                    Ok(arr) if probe <= entry_end => Some(arr),
                    _ => { probe = pre_tgpehd; None }
                };
                // Field 18: gimmick_chart_parameter_list — only attempted
                // if the TGPEHD list parsed cleanly (probe is aligned).
                let gimmick_chart_parameter_list = if trigger_event_handler_list.is_some() {
                    let pre_chart = probe;
                    match <CArray<GimmickChartParameter>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_chart; None }
                    }
                } else {
                    None
                };
                // Field 19: empirically CArray<u32>, mostly empty.
                let field_19_u32_list = if gimmick_chart_parameter_list.is_some() {
                    let pre_19 = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_19; None }
                    }
                } else {
                    None
                };
                // Field 20: empirically CArray<u32>, mostly empty.
                let field_20_u32_list = if field_19_u32_list.is_some() {
                    let pre_20 = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_20; None }
                    }
                } else {
                    None
                };
                let field_21_u32_list = if field_20_u32_list.is_some() {
                    let pre_21 = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_21; None }
                    }
                } else { None };
                let field_22_u32_list = if field_21_u32_list.is_some() {
                    let pre_22 = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_22; None }
                    }
                } else { None };
                let field_23_u32_list = if field_22_u32_list.is_some() {
                    let pre_23 = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_23; None }
                    }
                } else { None };
                // Try structured emissive-bind record FIRST (63 entries).
                // Pattern: u8=0x01 + u32 + u8 + CString(name) + u32
                let (field_24_emissive_flag_a, field_24_emissive_value_a,
                     field_24_emissive_flag_b, field_24_emissive_name,
                     field_24_emissive_value_b) =
                if field_23_u32_list.is_some() && probe + 11 <= entry_end {
                    let pre = probe;
                    if data[probe] == 0x01 {
                        let try_read = (|| -> io::Result<(u8, u32, u8, CString<'a>, u32)> {
                            let mut p = probe;
                            let fa = u8::read_from(data, &mut p)?;
                            let va = u32::read_from(data, &mut p)?;
                            let fb = u8::read_from(data, &mut p)?;
                            let name = CString::read_from(data, &mut p)?;
                            let vb = u32::read_from(data, &mut p)?;
                            // Sanity: name must be valid identifier-like
                            let n = name.data.as_bytes();
                            if n.is_empty() || n.len() > 100 { return Err(io::Error::new(io::ErrorKind::InvalidData, "bad name")); }
                            if !n.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_') {
                                return Err(io::Error::new(io::ErrorKind::InvalidData, "non-id name"));
                            }
                            if p > entry_end { return Err(io::Error::new(io::ErrorKind::InvalidData, "over-read")); }
                            probe = p;
                            Ok((fa, va, fb, name, vb))
                        })();
                        match try_read {
                            Ok((fa, va, fb, n, vb)) => (Some(fa), Some(va), Some(fb), Some(n), Some(vb)),
                            Err(_) => { probe = pre; (None, None, None, None, None) }
                        }
                    } else { (None, None, None, None, None) }
                } else { (None, None, None, None, None) };
                let field_24_u32_list = if field_23_u32_list.is_some() && field_24_emissive_flag_a.is_none() {
                    let pre_24 = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_24; None }
                    }
                } else { None };
                let field_25_u32_list = if field_24_u32_list.is_some() || field_24_emissive_flag_a.is_some() {
                    let pre_25 = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_25; None }
                    }
                } else { None };
                let field_26_u32 = if field_25_u32_list.is_some() && probe + 4 <= entry_end {
                    let pre_26 = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_26; None }
                    }
                } else { None };
                let field_27_u32_list = if field_26_u32.is_some() {
                    let pre_27 = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_27; None }
                    }
                } else { None };
                let field_28_u32 = if field_27_u32_list.is_some() && probe + 4 <= entry_end {
                    let pre_28 = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_28; None }
                    }
                } else { None };
                let field_29_u32_list = if field_28_u32.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_30_u32_list = if field_29_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_31_u32_list = if field_30_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                // Alt u32 chain when CArray<u32> failed (724 entries)
                macro_rules! f31_alt_read {
                    ($prev:expr) => {{
                        if $prev && probe + 4 <= entry_end {
                            let pre_ = probe;
                            match u32::read_from(data, &mut probe) {
                                Ok(v) => Some(v), _ => { probe = pre_; None }
                            }
                        } else { None }
                    }};
                }
                let f31_alt_active = field_30_u32_list.is_some() && field_31_u32_list.is_none();
                let f31_alt_001 = f31_alt_read!(f31_alt_active);
                let f31_alt_002 = f31_alt_read!(f31_alt_001.is_some());
                let f31_alt_003 = f31_alt_read!(f31_alt_002.is_some());
                let f31_alt_004 = f31_alt_read!(f31_alt_003.is_some());
                let f31_alt_005 = f31_alt_read!(f31_alt_004.is_some());
                let f31_alt_006 = f31_alt_read!(f31_alt_005.is_some());
                let f31_alt_007 = f31_alt_read!(f31_alt_006.is_some());
                let f31_alt_008 = f31_alt_read!(f31_alt_007.is_some());
                let f31_alt_009 = f31_alt_read!(f31_alt_008.is_some());
                let f31_alt_010 = f31_alt_read!(f31_alt_009.is_some());
                let f31_alt_011 = f31_alt_read!(f31_alt_010.is_some());
                let f31_alt_012 = f31_alt_read!(f31_alt_011.is_some());
                let f31_alt_013 = f31_alt_read!(f31_alt_012.is_some());
                let f31_alt_014 = f31_alt_read!(f31_alt_013.is_some());
                let f31_alt_015 = f31_alt_read!(f31_alt_014.is_some());
                let f31_alt_016 = f31_alt_read!(f31_alt_015.is_some());
                let f31_alt_017 = f31_alt_read!(f31_alt_016.is_some());
                let f31_alt_018 = f31_alt_read!(f31_alt_017.is_some());
                let f31_alt_019 = f31_alt_read!(f31_alt_018.is_some());
                let f31_alt_020 = f31_alt_read!(f31_alt_019.is_some());
                let f31_alt_021 = f31_alt_read!(f31_alt_020.is_some());
                let f31_alt_022 = f31_alt_read!(f31_alt_021.is_some());
                let f31_alt_023 = f31_alt_read!(f31_alt_022.is_some());
                let f31_alt_024 = f31_alt_read!(f31_alt_023.is_some());
                let f31_alt_025 = f31_alt_read!(f31_alt_024.is_some());
                let f31_alt_026 = f31_alt_read!(f31_alt_025.is_some());
                let f31_alt_027 = f31_alt_read!(f31_alt_026.is_some());
                let f31_alt_028 = f31_alt_read!(f31_alt_027.is_some());
                let f31_alt_029 = f31_alt_read!(f31_alt_028.is_some());
                let f31_alt_030 = f31_alt_read!(f31_alt_029.is_some());
                let f31_alt_031 = f31_alt_read!(f31_alt_030.is_some());
                let f31_alt_032 = f31_alt_read!(f31_alt_031.is_some());
                let f31_alt_033 = f31_alt_read!(f31_alt_032.is_some());
                let f31_alt_034 = f31_alt_read!(f31_alt_033.is_some());
                let f31_alt_035 = f31_alt_read!(f31_alt_034.is_some());
                let f31_alt_036 = f31_alt_read!(f31_alt_035.is_some());
                let f31_alt_037 = f31_alt_read!(f31_alt_036.is_some());
                let f31_alt_038 = f31_alt_read!(f31_alt_037.is_some());
                let f31_alt_039 = f31_alt_read!(f31_alt_038.is_some());
                let f31_alt_040 = f31_alt_read!(f31_alt_039.is_some());
                let f31_alt_041 = f31_alt_read!(f31_alt_040.is_some());
                let f31_alt_042 = f31_alt_read!(f31_alt_041.is_some());
                let f31_alt_043 = f31_alt_read!(f31_alt_042.is_some());
                let f31_alt_044 = f31_alt_read!(f31_alt_043.is_some());
                let f31_alt_045 = f31_alt_read!(f31_alt_044.is_some());
                let f31_alt_046 = f31_alt_read!(f31_alt_045.is_some());
                let f31_alt_047 = f31_alt_read!(f31_alt_046.is_some());
                let f31_alt_048 = f31_alt_read!(f31_alt_047.is_some());
                let f31_alt_049 = f31_alt_read!(f31_alt_048.is_some());
                let f31_alt_050 = f31_alt_read!(f31_alt_049.is_some());
                let f31_alt_051 = f31_alt_read!(f31_alt_050.is_some());
                let f31_alt_052 = f31_alt_read!(f31_alt_051.is_some());
                let f31_alt_053 = f31_alt_read!(f31_alt_052.is_some());
                let f31_alt_054 = f31_alt_read!(f31_alt_053.is_some());
                let f31_alt_055 = f31_alt_read!(f31_alt_054.is_some());
                let f31_alt_056 = f31_alt_read!(f31_alt_055.is_some());
                let f31_alt_057 = f31_alt_read!(f31_alt_056.is_some());
                let f31_alt_058 = f31_alt_read!(f31_alt_057.is_some());
                let f31_alt_059 = f31_alt_read!(f31_alt_058.is_some());
                let f31_alt_060 = f31_alt_read!(f31_alt_059.is_some());
                let f31_alt_061 = f31_alt_read!(f31_alt_060.is_some());
                let f31_alt_062 = f31_alt_read!(f31_alt_061.is_some());
                let f31_alt_063 = f31_alt_read!(f31_alt_062.is_some());
                let f31_alt_064 = f31_alt_read!(f31_alt_063.is_some());
                let f31_alt_065 = f31_alt_read!(f31_alt_064.is_some());
                let f31_alt_066 = f31_alt_read!(f31_alt_065.is_some());
                let f31_alt_067 = f31_alt_read!(f31_alt_066.is_some());
                let f31_alt_068 = f31_alt_read!(f31_alt_067.is_some());
                let f31_alt_069 = f31_alt_read!(f31_alt_068.is_some());
                let f31_alt_070 = f31_alt_read!(f31_alt_069.is_some());
                let f31_alt_071 = f31_alt_read!(f31_alt_070.is_some());
                let f31_alt_072 = f31_alt_read!(f31_alt_071.is_some());
                let f31_alt_073 = f31_alt_read!(f31_alt_072.is_some());
                let f31_alt_074 = f31_alt_read!(f31_alt_073.is_some());
                let f31_alt_075 = f31_alt_read!(f31_alt_074.is_some());
                let f31_alt_076 = f31_alt_read!(f31_alt_075.is_some());
                let f31_alt_077 = f31_alt_read!(f31_alt_076.is_some());
                let f31_alt_078 = f31_alt_read!(f31_alt_077.is_some());
                let f31_alt_079 = f31_alt_read!(f31_alt_078.is_some());
                let f31_alt_080 = f31_alt_read!(f31_alt_079.is_some());
                let f31_alt_081 = f31_alt_read!(f31_alt_080.is_some());
                let f31_alt_082 = f31_alt_read!(f31_alt_081.is_some());
                let f31_alt_083 = f31_alt_read!(f31_alt_082.is_some());
                let f31_alt_084 = f31_alt_read!(f31_alt_083.is_some());
                let f31_alt_085 = f31_alt_read!(f31_alt_084.is_some());
                let f31_alt_086 = f31_alt_read!(f31_alt_085.is_some());
                let f31_alt_087 = f31_alt_read!(f31_alt_086.is_some());
                let f31_alt_088 = f31_alt_read!(f31_alt_087.is_some());
                let f31_alt_089 = f31_alt_read!(f31_alt_088.is_some());
                let f31_alt_090 = f31_alt_read!(f31_alt_089.is_some());
                let f31_alt_091 = f31_alt_read!(f31_alt_090.is_some());
                let f31_alt_092 = f31_alt_read!(f31_alt_091.is_some());
                let f31_alt_093 = f31_alt_read!(f31_alt_092.is_some());
                let f31_alt_094 = f31_alt_read!(f31_alt_093.is_some());
                let f31_alt_095 = f31_alt_read!(f31_alt_094.is_some());
                let f31_alt_096 = f31_alt_read!(f31_alt_095.is_some());
                let f31_alt_097 = f31_alt_read!(f31_alt_096.is_some());
                let f31_alt_098 = f31_alt_read!(f31_alt_097.is_some());
                let f31_alt_099 = f31_alt_read!(f31_alt_098.is_some());
                let f31_alt_100 = f31_alt_read!(f31_alt_099.is_some());
                let f31_alt_101 = f31_alt_read!(f31_alt_100.is_some());
                let f31_alt_102 = f31_alt_read!(f31_alt_101.is_some());
                let f31_alt_103 = f31_alt_read!(f31_alt_102.is_some());
                let f31_alt_104 = f31_alt_read!(f31_alt_103.is_some());
                let f31_alt_105 = f31_alt_read!(f31_alt_104.is_some());
                let f31_alt_106 = f31_alt_read!(f31_alt_105.is_some());
                let f31_alt_107 = f31_alt_read!(f31_alt_106.is_some());
                let f31_alt_108 = f31_alt_read!(f31_alt_107.is_some());
                let f31_alt_109 = f31_alt_read!(f31_alt_108.is_some());
                let f31_alt_110 = f31_alt_read!(f31_alt_109.is_some());
                let f31_alt_111 = f31_alt_read!(f31_alt_110.is_some());
                let f31_alt_112 = f31_alt_read!(f31_alt_111.is_some());
                let f31_alt_113 = f31_alt_read!(f31_alt_112.is_some());
                let f31_alt_114 = f31_alt_read!(f31_alt_113.is_some());
                let f31_alt_115 = f31_alt_read!(f31_alt_114.is_some());
                let f31_alt_116 = f31_alt_read!(f31_alt_115.is_some());
                let f31_alt_117 = f31_alt_read!(f31_alt_116.is_some());
                let f31_alt_118 = f31_alt_read!(f31_alt_117.is_some());
                let f31_alt_119 = f31_alt_read!(f31_alt_118.is_some());
                let f31_alt_120 = f31_alt_read!(f31_alt_119.is_some());
                let f31_alt_121 = f31_alt_read!(f31_alt_120.is_some());
                let f31_alt_122 = f31_alt_read!(f31_alt_121.is_some());
                let f31_alt_123 = f31_alt_read!(f31_alt_122.is_some());
                let f31_alt_124 = f31_alt_read!(f31_alt_123.is_some());
                let f31_alt_125 = f31_alt_read!(f31_alt_124.is_some());
                let f31_alt_126 = f31_alt_read!(f31_alt_125.is_some());
                let f31_alt_127 = f31_alt_read!(f31_alt_126.is_some());
                let f31_alt_128 = f31_alt_read!(f31_alt_127.is_some());
                let f31_alt_129 = f31_alt_read!(f31_alt_128.is_some());
                let f31_alt_130 = f31_alt_read!(f31_alt_129.is_some());
                let f31_alt_131 = f31_alt_read!(f31_alt_130.is_some());
                let f31_alt_132 = f31_alt_read!(f31_alt_131.is_some());
                let f31_alt_133 = f31_alt_read!(f31_alt_132.is_some());
                let f31_alt_134 = f31_alt_read!(f31_alt_133.is_some());
                let f31_alt_135 = f31_alt_read!(f31_alt_134.is_some());
                let f31_alt_136 = f31_alt_read!(f31_alt_135.is_some());
                let f31_alt_137 = f31_alt_read!(f31_alt_136.is_some());
                let f31_alt_138 = f31_alt_read!(f31_alt_137.is_some());
                let f31_alt_139 = f31_alt_read!(f31_alt_138.is_some());
                let f31_alt_140 = f31_alt_read!(f31_alt_139.is_some());
                let f31_alt_141 = f31_alt_read!(f31_alt_140.is_some());
                let f31_alt_142 = f31_alt_read!(f31_alt_141.is_some());
                let f31_alt_143 = f31_alt_read!(f31_alt_142.is_some());
                let f31_alt_144 = f31_alt_read!(f31_alt_143.is_some());
                let f31_alt_145 = f31_alt_read!(f31_alt_144.is_some());
                let f31_alt_146 = f31_alt_read!(f31_alt_145.is_some());
                let f31_alt_147 = f31_alt_read!(f31_alt_146.is_some());
                let f31_alt_148 = f31_alt_read!(f31_alt_147.is_some());
                let f31_alt_149 = f31_alt_read!(f31_alt_148.is_some());
                let f31_alt_150 = f31_alt_read!(f31_alt_149.is_some());
                let f31_alt_151 = f31_alt_read!(f31_alt_150.is_some());
                let f31_alt_152 = f31_alt_read!(f31_alt_151.is_some());
                let f31_alt_153 = f31_alt_read!(f31_alt_152.is_some());
                let f31_alt_154 = f31_alt_read!(f31_alt_153.is_some());
                let f31_alt_155 = f31_alt_read!(f31_alt_154.is_some());
                let f31_alt_156 = f31_alt_read!(f31_alt_155.is_some());
                let f31_alt_157 = f31_alt_read!(f31_alt_156.is_some());
                let f31_alt_158 = f31_alt_read!(f31_alt_157.is_some());
                let f31_alt_159 = f31_alt_read!(f31_alt_158.is_some());
                let f31_alt_160 = f31_alt_read!(f31_alt_159.is_some());
                let f31_alt_161 = f31_alt_read!(f31_alt_160.is_some());
                let f31_alt_162 = f31_alt_read!(f31_alt_161.is_some());
                let f31_alt_163 = f31_alt_read!(f31_alt_162.is_some());
                let f31_alt_164 = f31_alt_read!(f31_alt_163.is_some());
                let f31_alt_165 = f31_alt_read!(f31_alt_164.is_some());
                let f31_alt_166 = f31_alt_read!(f31_alt_165.is_some());
                let f31_alt_167 = f31_alt_read!(f31_alt_166.is_some());
                let f31_alt_168 = f31_alt_read!(f31_alt_167.is_some());
                let f31_alt_169 = f31_alt_read!(f31_alt_168.is_some());
                let f31_alt_170 = f31_alt_read!(f31_alt_169.is_some());
                let f31_alt_171 = f31_alt_read!(f31_alt_170.is_some());
                let f31_alt_172 = f31_alt_read!(f31_alt_171.is_some());
                let f31_alt_173 = f31_alt_read!(f31_alt_172.is_some());
                let f31_alt_174 = f31_alt_read!(f31_alt_173.is_some());
                let f31_alt_175 = f31_alt_read!(f31_alt_174.is_some());
                let f31_alt_176 = f31_alt_read!(f31_alt_175.is_some());
                let f31_alt_177 = f31_alt_read!(f31_alt_176.is_some());
                let f31_alt_178 = f31_alt_read!(f31_alt_177.is_some());
                let f31_alt_179 = f31_alt_read!(f31_alt_178.is_some());
                let f31_alt_180 = f31_alt_read!(f31_alt_179.is_some());
                let f31_alt_181 = f31_alt_read!(f31_alt_180.is_some());
                let f31_alt_182 = f31_alt_read!(f31_alt_181.is_some());
                let f31_alt_183 = f31_alt_read!(f31_alt_182.is_some());
                let f31_alt_184 = f31_alt_read!(f31_alt_183.is_some());
                let f31_alt_185 = f31_alt_read!(f31_alt_184.is_some());
                let f31_alt_186 = f31_alt_read!(f31_alt_185.is_some());
                let f31_alt_187 = f31_alt_read!(f31_alt_186.is_some());
                let f31_alt_188 = f31_alt_read!(f31_alt_187.is_some());
                let f31_alt_189 = f31_alt_read!(f31_alt_188.is_some());
                let f31_alt_190 = f31_alt_read!(f31_alt_189.is_some());
                let f31_alt_191 = f31_alt_read!(f31_alt_190.is_some());
                let f31_alt_192 = f31_alt_read!(f31_alt_191.is_some());
                let f31_alt_193 = f31_alt_read!(f31_alt_192.is_some());
                let f31_alt_194 = f31_alt_read!(f31_alt_193.is_some());
                let f31_alt_195 = f31_alt_read!(f31_alt_194.is_some());
                let f31_alt_196 = f31_alt_read!(f31_alt_195.is_some());
                let f31_alt_197 = f31_alt_read!(f31_alt_196.is_some());
                let f31_alt_198 = f31_alt_read!(f31_alt_197.is_some());
                let f31_alt_199 = f31_alt_read!(f31_alt_198.is_some());
                let f31_alt_200 = f31_alt_read!(f31_alt_199.is_some());
                let f31_alt_201 = f31_alt_read!(f31_alt_200.is_some());
                let f31_alt_202 = f31_alt_read!(f31_alt_201.is_some());
                let f31_alt_203 = f31_alt_read!(f31_alt_202.is_some());
                let f31_alt_204 = f31_alt_read!(f31_alt_203.is_some());
                let f31_alt_205 = f31_alt_read!(f31_alt_204.is_some());
                let f31_alt_206 = f31_alt_read!(f31_alt_205.is_some());
                let f31_alt_207 = f31_alt_read!(f31_alt_206.is_some());
                let f31_alt_208 = f31_alt_read!(f31_alt_207.is_some());
                let f31_alt_209 = f31_alt_read!(f31_alt_208.is_some());
                let f31_alt_210 = f31_alt_read!(f31_alt_209.is_some());
                let f31_alt_211 = f31_alt_read!(f31_alt_210.is_some());
                let f31_alt_212 = f31_alt_read!(f31_alt_211.is_some());
                let f31_alt_213 = f31_alt_read!(f31_alt_212.is_some());
                let f31_alt_214 = f31_alt_read!(f31_alt_213.is_some());
                let f31_alt_215 = f31_alt_read!(f31_alt_214.is_some());
                let f31_alt_216 = f31_alt_read!(f31_alt_215.is_some());
                let f31_alt_217 = f31_alt_read!(f31_alt_216.is_some());
                let f31_alt_218 = f31_alt_read!(f31_alt_217.is_some());
                let f31_alt_219 = f31_alt_read!(f31_alt_218.is_some());
                let f31_alt_220 = f31_alt_read!(f31_alt_219.is_some());
                let f31_alt_221 = f31_alt_read!(f31_alt_220.is_some());
                let f31_alt_222 = f31_alt_read!(f31_alt_221.is_some());
                let f31_alt_223 = f31_alt_read!(f31_alt_222.is_some());
                let f31_alt_224 = f31_alt_read!(f31_alt_223.is_some());
                let f31_alt_225 = f31_alt_read!(f31_alt_224.is_some());
                let f31_alt_226 = f31_alt_read!(f31_alt_225.is_some());
                let f31_alt_227 = f31_alt_read!(f31_alt_226.is_some());
                let f31_alt_228 = f31_alt_read!(f31_alt_227.is_some());
                let f31_alt_229 = f31_alt_read!(f31_alt_228.is_some());
                let f31_alt_230 = f31_alt_read!(f31_alt_229.is_some());
                let f31_alt_231 = f31_alt_read!(f31_alt_230.is_some());
                let f31_alt_232 = f31_alt_read!(f31_alt_231.is_some());
                let f31_alt_233 = f31_alt_read!(f31_alt_232.is_some());
                let f31_alt_234 = f31_alt_read!(f31_alt_233.is_some());
                let f31_alt_235 = f31_alt_read!(f31_alt_234.is_some());
                let f31_alt_236 = f31_alt_read!(f31_alt_235.is_some());
                let f31_alt_237 = f31_alt_read!(f31_alt_236.is_some());
                let f31_alt_238 = f31_alt_read!(f31_alt_237.is_some());
                let f31_alt_239 = f31_alt_read!(f31_alt_238.is_some());
                let f31_alt_240 = f31_alt_read!(f31_alt_239.is_some());
                let f31_alt_241 = f31_alt_read!(f31_alt_240.is_some());
                let f31_alt_242 = f31_alt_read!(f31_alt_241.is_some());
                let f31_alt_243 = f31_alt_read!(f31_alt_242.is_some());
                let f31_alt_244 = f31_alt_read!(f31_alt_243.is_some());
                let f31_alt_245 = f31_alt_read!(f31_alt_244.is_some());
                let f31_alt_246 = f31_alt_read!(f31_alt_245.is_some());
                let f31_alt_247 = f31_alt_read!(f31_alt_246.is_some());
                let f31_alt_248 = f31_alt_read!(f31_alt_247.is_some());
                let f31_alt_249 = f31_alt_read!(f31_alt_248.is_some());
                let f31_alt_250 = f31_alt_read!(f31_alt_249.is_some());
                let f31_alt_251 = f31_alt_read!(f31_alt_250.is_some());
                let f31_alt_252 = f31_alt_read!(f31_alt_251.is_some());
                let f31_alt_253 = f31_alt_read!(f31_alt_252.is_some());
                let f31_alt_254 = f31_alt_read!(f31_alt_253.is_some());
                let f31_alt_255 = f31_alt_read!(f31_alt_254.is_some());
                let f31_alt_256 = f31_alt_read!(f31_alt_255.is_some());
                let field_32_u32_list = if field_31_u32_list.is_some() || f31_alt_001.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                // f32_alt chain: activates when field_32 CArray<u32> failed
                // (entries with XML CString-prefixed text content).
                let f32_alt_active = (field_31_u32_list.is_some() || f31_alt_001.is_some())
                    && field_32_u32_list.is_none();
                let f32_alt_001 = f31_alt_read!(f32_alt_active);
                let f32_alt_002 = f31_alt_read!(f32_alt_001.is_some());
                let f32_alt_003 = f31_alt_read!(f32_alt_002.is_some());
                let f32_alt_004 = f31_alt_read!(f32_alt_003.is_some());
                let f32_alt_005 = f31_alt_read!(f32_alt_004.is_some());
                let f32_alt_006 = f31_alt_read!(f32_alt_005.is_some());
                let f32_alt_007 = f31_alt_read!(f32_alt_006.is_some());
                let f32_alt_008 = f31_alt_read!(f32_alt_007.is_some());
                let f32_alt_009 = f31_alt_read!(f32_alt_008.is_some());
                let f32_alt_010 = f31_alt_read!(f32_alt_009.is_some());
                let f32_alt_011 = f31_alt_read!(f32_alt_010.is_some());
                let f32_alt_012 = f31_alt_read!(f32_alt_011.is_some());
                let f32_alt_013 = f31_alt_read!(f32_alt_012.is_some());
                let f32_alt_014 = f31_alt_read!(f32_alt_013.is_some());
                let f32_alt_015 = f31_alt_read!(f32_alt_014.is_some());
                let f32_alt_016 = f31_alt_read!(f32_alt_015.is_some());
                let f32_alt_017 = f31_alt_read!(f32_alt_016.is_some());
                let f32_alt_018 = f31_alt_read!(f32_alt_017.is_some());
                let f32_alt_019 = f31_alt_read!(f32_alt_018.is_some());
                let f32_alt_020 = f31_alt_read!(f32_alt_019.is_some());
                let f32_alt_021 = f31_alt_read!(f32_alt_020.is_some());
                let f32_alt_022 = f31_alt_read!(f32_alt_021.is_some());
                let f32_alt_023 = f31_alt_read!(f32_alt_022.is_some());
                let f32_alt_024 = f31_alt_read!(f32_alt_023.is_some());
                let f32_alt_025 = f31_alt_read!(f32_alt_024.is_some());
                let f32_alt_026 = f31_alt_read!(f32_alt_025.is_some());
                let f32_alt_027 = f31_alt_read!(f32_alt_026.is_some());
                let f32_alt_028 = f31_alt_read!(f32_alt_027.is_some());
                let f32_alt_029 = f31_alt_read!(f32_alt_028.is_some());
                let f32_alt_030 = f31_alt_read!(f32_alt_029.is_some());
                let f32_alt_031 = f31_alt_read!(f32_alt_030.is_some());
                let f32_alt_032 = f31_alt_read!(f32_alt_031.is_some());
                let f32_alt_033 = f31_alt_read!(f32_alt_032.is_some());
                let f32_alt_034 = f31_alt_read!(f32_alt_033.is_some());
                let f32_alt_035 = f31_alt_read!(f32_alt_034.is_some());
                let f32_alt_036 = f31_alt_read!(f32_alt_035.is_some());
                let f32_alt_037 = f31_alt_read!(f32_alt_036.is_some());
                let f32_alt_038 = f31_alt_read!(f32_alt_037.is_some());
                let f32_alt_039 = f31_alt_read!(f32_alt_038.is_some());
                let f32_alt_040 = f31_alt_read!(f32_alt_039.is_some());
                let f32_alt_041 = f31_alt_read!(f32_alt_040.is_some());
                let f32_alt_042 = f31_alt_read!(f32_alt_041.is_some());
                let f32_alt_043 = f31_alt_read!(f32_alt_042.is_some());
                let f32_alt_044 = f31_alt_read!(f32_alt_043.is_some());
                let f32_alt_045 = f31_alt_read!(f32_alt_044.is_some());
                let f32_alt_046 = f31_alt_read!(f32_alt_045.is_some());
                let f32_alt_047 = f31_alt_read!(f32_alt_046.is_some());
                let f32_alt_048 = f31_alt_read!(f32_alt_047.is_some());
                let f32_alt_049 = f31_alt_read!(f32_alt_048.is_some());
                let f32_alt_050 = f31_alt_read!(f32_alt_049.is_some());
                let f32_alt_051 = f31_alt_read!(f32_alt_050.is_some());
                let f32_alt_052 = f31_alt_read!(f32_alt_051.is_some());
                let f32_alt_053 = f31_alt_read!(f32_alt_052.is_some());
                let f32_alt_054 = f31_alt_read!(f32_alt_053.is_some());
                let f32_alt_055 = f31_alt_read!(f32_alt_054.is_some());
                let f32_alt_056 = f31_alt_read!(f32_alt_055.is_some());
                let f32_alt_057 = f31_alt_read!(f32_alt_056.is_some());
                let f32_alt_058 = f31_alt_read!(f32_alt_057.is_some());
                let f32_alt_059 = f31_alt_read!(f32_alt_058.is_some());
                let f32_alt_060 = f31_alt_read!(f32_alt_059.is_some());
                let f32_alt_061 = f31_alt_read!(f32_alt_060.is_some());
                let f32_alt_062 = f31_alt_read!(f32_alt_061.is_some());
                let f32_alt_063 = f31_alt_read!(f32_alt_062.is_some());
                let f32_alt_064 = f31_alt_read!(f32_alt_063.is_some());
                let f32_alt_065 = f31_alt_read!(f32_alt_064.is_some());
                let f32_alt_066 = f31_alt_read!(f32_alt_065.is_some());
                let f32_alt_067 = f31_alt_read!(f32_alt_066.is_some());
                let f32_alt_068 = f31_alt_read!(f32_alt_067.is_some());
                let f32_alt_069 = f31_alt_read!(f32_alt_068.is_some());
                let f32_alt_070 = f31_alt_read!(f32_alt_069.is_some());
                let f32_alt_071 = f31_alt_read!(f32_alt_070.is_some());
                let f32_alt_072 = f31_alt_read!(f32_alt_071.is_some());
                let f32_alt_073 = f31_alt_read!(f32_alt_072.is_some());
                let f32_alt_074 = f31_alt_read!(f32_alt_073.is_some());
                let f32_alt_075 = f31_alt_read!(f32_alt_074.is_some());
                let f32_alt_076 = f31_alt_read!(f32_alt_075.is_some());
                let f32_alt_077 = f31_alt_read!(f32_alt_076.is_some());
                let f32_alt_078 = f31_alt_read!(f32_alt_077.is_some());
                let f32_alt_079 = f31_alt_read!(f32_alt_078.is_some());
                let f32_alt_080 = f31_alt_read!(f32_alt_079.is_some());
                let f32_alt_081 = f31_alt_read!(f32_alt_080.is_some());
                let f32_alt_082 = f31_alt_read!(f32_alt_081.is_some());
                let f32_alt_083 = f31_alt_read!(f32_alt_082.is_some());
                let f32_alt_084 = f31_alt_read!(f32_alt_083.is_some());
                let f32_alt_085 = f31_alt_read!(f32_alt_084.is_some());
                let f32_alt_086 = f31_alt_read!(f32_alt_085.is_some());
                let f32_alt_087 = f31_alt_read!(f32_alt_086.is_some());
                let f32_alt_088 = f31_alt_read!(f32_alt_087.is_some());
                let f32_alt_089 = f31_alt_read!(f32_alt_088.is_some());
                let f32_alt_090 = f31_alt_read!(f32_alt_089.is_some());
                let f32_alt_091 = f31_alt_read!(f32_alt_090.is_some());
                let f32_alt_092 = f31_alt_read!(f32_alt_091.is_some());
                let f32_alt_093 = f31_alt_read!(f32_alt_092.is_some());
                let f32_alt_094 = f31_alt_read!(f32_alt_093.is_some());
                let f32_alt_095 = f31_alt_read!(f32_alt_094.is_some());
                let f32_alt_096 = f31_alt_read!(f32_alt_095.is_some());
                let f32_alt_097 = f31_alt_read!(f32_alt_096.is_some());
                let f32_alt_098 = f31_alt_read!(f32_alt_097.is_some());
                let f32_alt_099 = f31_alt_read!(f32_alt_098.is_some());
                let f32_alt_100 = f31_alt_read!(f32_alt_099.is_some());
                let f32_alt_101 = f31_alt_read!(f32_alt_100.is_some());
                let f32_alt_102 = f31_alt_read!(f32_alt_101.is_some());
                let f32_alt_103 = f31_alt_read!(f32_alt_102.is_some());
                let f32_alt_104 = f31_alt_read!(f32_alt_103.is_some());
                let f32_alt_105 = f31_alt_read!(f32_alt_104.is_some());
                let f32_alt_106 = f31_alt_read!(f32_alt_105.is_some());
                let f32_alt_107 = f31_alt_read!(f32_alt_106.is_some());
                let f32_alt_108 = f31_alt_read!(f32_alt_107.is_some());
                let f32_alt_109 = f31_alt_read!(f32_alt_108.is_some());
                let f32_alt_110 = f31_alt_read!(f32_alt_109.is_some());
                let f32_alt_111 = f31_alt_read!(f32_alt_110.is_some());
                let f32_alt_112 = f31_alt_read!(f32_alt_111.is_some());
                let f32_alt_113 = f31_alt_read!(f32_alt_112.is_some());
                let f32_alt_114 = f31_alt_read!(f32_alt_113.is_some());
                let f32_alt_115 = f31_alt_read!(f32_alt_114.is_some());
                let f32_alt_116 = f31_alt_read!(f32_alt_115.is_some());
                let f32_alt_117 = f31_alt_read!(f32_alt_116.is_some());
                let f32_alt_118 = f31_alt_read!(f32_alt_117.is_some());
                let f32_alt_119 = f31_alt_read!(f32_alt_118.is_some());
                let f32_alt_120 = f31_alt_read!(f32_alt_119.is_some());
                let f32_alt_121 = f31_alt_read!(f32_alt_120.is_some());
                let f32_alt_122 = f31_alt_read!(f32_alt_121.is_some());
                let f32_alt_123 = f31_alt_read!(f32_alt_122.is_some());
                let f32_alt_124 = f31_alt_read!(f32_alt_123.is_some());
                let f32_alt_125 = f31_alt_read!(f32_alt_124.is_some());
                let f32_alt_126 = f31_alt_read!(f32_alt_125.is_some());
                let f32_alt_127 = f31_alt_read!(f32_alt_126.is_some());
                let f32_alt_128 = f31_alt_read!(f32_alt_127.is_some());
                let f32_alt_129 = f31_alt_read!(f32_alt_128.is_some());
                let f32_alt_130 = f31_alt_read!(f32_alt_129.is_some());
                let f32_alt_131 = f31_alt_read!(f32_alt_130.is_some());
                let f32_alt_132 = f31_alt_read!(f32_alt_131.is_some());
                let f32_alt_133 = f31_alt_read!(f32_alt_132.is_some());
                let f32_alt_134 = f31_alt_read!(f32_alt_133.is_some());
                let f32_alt_135 = f31_alt_read!(f32_alt_134.is_some());
                let f32_alt_136 = f31_alt_read!(f32_alt_135.is_some());
                let f32_alt_137 = f31_alt_read!(f32_alt_136.is_some());
                let f32_alt_138 = f31_alt_read!(f32_alt_137.is_some());
                let f32_alt_139 = f31_alt_read!(f32_alt_138.is_some());
                let f32_alt_140 = f31_alt_read!(f32_alt_139.is_some());
                let f32_alt_141 = f31_alt_read!(f32_alt_140.is_some());
                let f32_alt_142 = f31_alt_read!(f32_alt_141.is_some());
                let f32_alt_143 = f31_alt_read!(f32_alt_142.is_some());
                let f32_alt_144 = f31_alt_read!(f32_alt_143.is_some());
                let f32_alt_145 = f31_alt_read!(f32_alt_144.is_some());
                let f32_alt_146 = f31_alt_read!(f32_alt_145.is_some());
                let f32_alt_147 = f31_alt_read!(f32_alt_146.is_some());
                let f32_alt_148 = f31_alt_read!(f32_alt_147.is_some());
                let f32_alt_149 = f31_alt_read!(f32_alt_148.is_some());
                let f32_alt_150 = f31_alt_read!(f32_alt_149.is_some());
                let f32_alt_151 = f31_alt_read!(f32_alt_150.is_some());
                let f32_alt_152 = f31_alt_read!(f32_alt_151.is_some());
                let f32_alt_153 = f31_alt_read!(f32_alt_152.is_some());
                let f32_alt_154 = f31_alt_read!(f32_alt_153.is_some());
                let f32_alt_155 = f31_alt_read!(f32_alt_154.is_some());
                let f32_alt_156 = f31_alt_read!(f32_alt_155.is_some());
                let f32_alt_157 = f31_alt_read!(f32_alt_156.is_some());
                let f32_alt_158 = f31_alt_read!(f32_alt_157.is_some());
                let f32_alt_159 = f31_alt_read!(f32_alt_158.is_some());
                let f32_alt_160 = f31_alt_read!(f32_alt_159.is_some());
                let f32_alt_161 = f31_alt_read!(f32_alt_160.is_some());
                let f32_alt_162 = f31_alt_read!(f32_alt_161.is_some());
                let f32_alt_163 = f31_alt_read!(f32_alt_162.is_some());
                let f32_alt_164 = f31_alt_read!(f32_alt_163.is_some());
                let f32_alt_165 = f31_alt_read!(f32_alt_164.is_some());
                let f32_alt_166 = f31_alt_read!(f32_alt_165.is_some());
                let f32_alt_167 = f31_alt_read!(f32_alt_166.is_some());
                let f32_alt_168 = f31_alt_read!(f32_alt_167.is_some());
                let f32_alt_169 = f31_alt_read!(f32_alt_168.is_some());
                let f32_alt_170 = f31_alt_read!(f32_alt_169.is_some());
                let f32_alt_171 = f31_alt_read!(f32_alt_170.is_some());
                let f32_alt_172 = f31_alt_read!(f32_alt_171.is_some());
                let f32_alt_173 = f31_alt_read!(f32_alt_172.is_some());
                let f32_alt_174 = f31_alt_read!(f32_alt_173.is_some());
                let f32_alt_175 = f31_alt_read!(f32_alt_174.is_some());
                let f32_alt_176 = f31_alt_read!(f32_alt_175.is_some());
                let f32_alt_177 = f31_alt_read!(f32_alt_176.is_some());
                let f32_alt_178 = f31_alt_read!(f32_alt_177.is_some());
                let f32_alt_179 = f31_alt_read!(f32_alt_178.is_some());
                let f32_alt_180 = f31_alt_read!(f32_alt_179.is_some());
                let f32_alt_181 = f31_alt_read!(f32_alt_180.is_some());
                let f32_alt_182 = f31_alt_read!(f32_alt_181.is_some());
                let f32_alt_183 = f31_alt_read!(f32_alt_182.is_some());
                let f32_alt_184 = f31_alt_read!(f32_alt_183.is_some());
                let f32_alt_185 = f31_alt_read!(f32_alt_184.is_some());
                let f32_alt_186 = f31_alt_read!(f32_alt_185.is_some());
                let f32_alt_187 = f31_alt_read!(f32_alt_186.is_some());
                let f32_alt_188 = f31_alt_read!(f32_alt_187.is_some());
                let f32_alt_189 = f31_alt_read!(f32_alt_188.is_some());
                let f32_alt_190 = f31_alt_read!(f32_alt_189.is_some());
                let f32_alt_191 = f31_alt_read!(f32_alt_190.is_some());
                let f32_alt_192 = f31_alt_read!(f32_alt_191.is_some());
                let field_33_u32 = if (field_32_u32_list.is_some() || f32_alt_001.is_some()) && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_34_u32 = if field_33_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_35_u32_list = if field_34_u32.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_36_u32 = if field_35_u32_list.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_37_u32 = if field_36_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_38_u32 = if field_37_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_39_u32_list = if field_38_u32.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                // f39_alt chain: activates when field_39 CArray<u32> failed
                // (724 entries with structured fixed-pattern records).
                let f39_alt_active = field_38_u32.is_some() && field_39_u32_list.is_none();
                let f39_alt_001 = f31_alt_read!(f39_alt_active);
                let f39_alt_002 = f31_alt_read!(f39_alt_001.is_some());
                let f39_alt_003 = f31_alt_read!(f39_alt_002.is_some());
                let f39_alt_004 = f31_alt_read!(f39_alt_003.is_some());
                let f39_alt_005 = f31_alt_read!(f39_alt_004.is_some());
                let f39_alt_006 = f31_alt_read!(f39_alt_005.is_some());
                let f39_alt_007 = f31_alt_read!(f39_alt_006.is_some());
                let f39_alt_008 = f31_alt_read!(f39_alt_007.is_some());
                let f39_alt_009 = f31_alt_read!(f39_alt_008.is_some());
                let f39_alt_010 = f31_alt_read!(f39_alt_009.is_some());
                let f39_alt_011 = f31_alt_read!(f39_alt_010.is_some());
                let f39_alt_012 = f31_alt_read!(f39_alt_011.is_some());
                let f39_alt_013 = f31_alt_read!(f39_alt_012.is_some());
                let f39_alt_014 = f31_alt_read!(f39_alt_013.is_some());
                let f39_alt_015 = f31_alt_read!(f39_alt_014.is_some());
                let f39_alt_016 = f31_alt_read!(f39_alt_015.is_some());
                let f39_alt_017 = f31_alt_read!(f39_alt_016.is_some());
                let f39_alt_018 = f31_alt_read!(f39_alt_017.is_some());
                let f39_alt_019 = f31_alt_read!(f39_alt_018.is_some());
                let f39_alt_020 = f31_alt_read!(f39_alt_019.is_some());
                let f39_alt_021 = f31_alt_read!(f39_alt_020.is_some());
                let f39_alt_022 = f31_alt_read!(f39_alt_021.is_some());
                let f39_alt_023 = f31_alt_read!(f39_alt_022.is_some());
                let f39_alt_024 = f31_alt_read!(f39_alt_023.is_some());
                let f39_alt_025 = f31_alt_read!(f39_alt_024.is_some());
                let f39_alt_026 = f31_alt_read!(f39_alt_025.is_some());
                let f39_alt_027 = f31_alt_read!(f39_alt_026.is_some());
                let f39_alt_028 = f31_alt_read!(f39_alt_027.is_some());
                let f39_alt_029 = f31_alt_read!(f39_alt_028.is_some());
                let f39_alt_030 = f31_alt_read!(f39_alt_029.is_some());
                let f39_alt_031 = f31_alt_read!(f39_alt_030.is_some());
                let f39_alt_032 = f31_alt_read!(f39_alt_031.is_some());
                let f39_alt_033 = f31_alt_read!(f39_alt_032.is_some());
                let f39_alt_034 = f31_alt_read!(f39_alt_033.is_some());
                let f39_alt_035 = f31_alt_read!(f39_alt_034.is_some());
                let f39_alt_036 = f31_alt_read!(f39_alt_035.is_some());
                let f39_alt_037 = f31_alt_read!(f39_alt_036.is_some());
                let f39_alt_038 = f31_alt_read!(f39_alt_037.is_some());
                let f39_alt_039 = f31_alt_read!(f39_alt_038.is_some());
                let f39_alt_040 = f31_alt_read!(f39_alt_039.is_some());
                let f39_alt_041 = f31_alt_read!(f39_alt_040.is_some());
                let f39_alt_042 = f31_alt_read!(f39_alt_041.is_some());
                let f39_alt_043 = f31_alt_read!(f39_alt_042.is_some());
                let f39_alt_044 = f31_alt_read!(f39_alt_043.is_some());
                let f39_alt_045 = f31_alt_read!(f39_alt_044.is_some());
                let f39_alt_046 = f31_alt_read!(f39_alt_045.is_some());
                let f39_alt_047 = f31_alt_read!(f39_alt_046.is_some());
                let f39_alt_048 = f31_alt_read!(f39_alt_047.is_some());
                let f39_alt_049 = f31_alt_read!(f39_alt_048.is_some());
                let f39_alt_050 = f31_alt_read!(f39_alt_049.is_some());
                let f39_alt_051 = f31_alt_read!(f39_alt_050.is_some());
                let f39_alt_052 = f31_alt_read!(f39_alt_051.is_some());
                let f39_alt_053 = f31_alt_read!(f39_alt_052.is_some());
                let f39_alt_054 = f31_alt_read!(f39_alt_053.is_some());
                let f39_alt_055 = f31_alt_read!(f39_alt_054.is_some());
                let f39_alt_056 = f31_alt_read!(f39_alt_055.is_some());
                let f39_alt_057 = f31_alt_read!(f39_alt_056.is_some());
                let f39_alt_058 = f31_alt_read!(f39_alt_057.is_some());
                let f39_alt_059 = f31_alt_read!(f39_alt_058.is_some());
                let f39_alt_060 = f31_alt_read!(f39_alt_059.is_some());
                let f39_alt_061 = f31_alt_read!(f39_alt_060.is_some());
                let f39_alt_062 = f31_alt_read!(f39_alt_061.is_some());
                let f39_alt_063 = f31_alt_read!(f39_alt_062.is_some());
                let f39_alt_064 = f31_alt_read!(f39_alt_063.is_some());
                let f39_alt_065 = f31_alt_read!(f39_alt_064.is_some());
                let f39_alt_066 = f31_alt_read!(f39_alt_065.is_some());
                let f39_alt_067 = f31_alt_read!(f39_alt_066.is_some());
                let f39_alt_068 = f31_alt_read!(f39_alt_067.is_some());
                let f39_alt_069 = f31_alt_read!(f39_alt_068.is_some());
                let f39_alt_070 = f31_alt_read!(f39_alt_069.is_some());
                let f39_alt_071 = f31_alt_read!(f39_alt_070.is_some());
                let f39_alt_072 = f31_alt_read!(f39_alt_071.is_some());
                let f39_alt_073 = f31_alt_read!(f39_alt_072.is_some());
                let f39_alt_074 = f31_alt_read!(f39_alt_073.is_some());
                let f39_alt_075 = f31_alt_read!(f39_alt_074.is_some());
                let f39_alt_076 = f31_alt_read!(f39_alt_075.is_some());
                let f39_alt_077 = f31_alt_read!(f39_alt_076.is_some());
                let f39_alt_078 = f31_alt_read!(f39_alt_077.is_some());
                let f39_alt_079 = f31_alt_read!(f39_alt_078.is_some());
                let f39_alt_080 = f31_alt_read!(f39_alt_079.is_some());
                let f39_alt_081 = f31_alt_read!(f39_alt_080.is_some());
                let f39_alt_082 = f31_alt_read!(f39_alt_081.is_some());
                let f39_alt_083 = f31_alt_read!(f39_alt_082.is_some());
                let f39_alt_084 = f31_alt_read!(f39_alt_083.is_some());
                let f39_alt_085 = f31_alt_read!(f39_alt_084.is_some());
                let f39_alt_086 = f31_alt_read!(f39_alt_085.is_some());
                let f39_alt_087 = f31_alt_read!(f39_alt_086.is_some());
                let f39_alt_088 = f31_alt_read!(f39_alt_087.is_some());
                let f39_alt_089 = f31_alt_read!(f39_alt_088.is_some());
                let f39_alt_090 = f31_alt_read!(f39_alt_089.is_some());
                let f39_alt_091 = f31_alt_read!(f39_alt_090.is_some());
                let f39_alt_092 = f31_alt_read!(f39_alt_091.is_some());
                let f39_alt_093 = f31_alt_read!(f39_alt_092.is_some());
                let f39_alt_094 = f31_alt_read!(f39_alt_093.is_some());
                let f39_alt_095 = f31_alt_read!(f39_alt_094.is_some());
                let f39_alt_096 = f31_alt_read!(f39_alt_095.is_some());
                let f39_alt_097 = f31_alt_read!(f39_alt_096.is_some());
                let f39_alt_098 = f31_alt_read!(f39_alt_097.is_some());
                let f39_alt_099 = f31_alt_read!(f39_alt_098.is_some());
                let f39_alt_100 = f31_alt_read!(f39_alt_099.is_some());
                let f39_alt_101 = f31_alt_read!(f39_alt_100.is_some());
                let f39_alt_102 = f31_alt_read!(f39_alt_101.is_some());
                let f39_alt_103 = f31_alt_read!(f39_alt_102.is_some());
                let f39_alt_104 = f31_alt_read!(f39_alt_103.is_some());
                let f39_alt_105 = f31_alt_read!(f39_alt_104.is_some());
                let f39_alt_106 = f31_alt_read!(f39_alt_105.is_some());
                let f39_alt_107 = f31_alt_read!(f39_alt_106.is_some());
                let f39_alt_108 = f31_alt_read!(f39_alt_107.is_some());
                let f39_alt_109 = f31_alt_read!(f39_alt_108.is_some());
                let f39_alt_110 = f31_alt_read!(f39_alt_109.is_some());
                let f39_alt_111 = f31_alt_read!(f39_alt_110.is_some());
                let f39_alt_112 = f31_alt_read!(f39_alt_111.is_some());
                let f39_alt_113 = f31_alt_read!(f39_alt_112.is_some());
                let f39_alt_114 = f31_alt_read!(f39_alt_113.is_some());
                let f39_alt_115 = f31_alt_read!(f39_alt_114.is_some());
                let f39_alt_116 = f31_alt_read!(f39_alt_115.is_some());
                let f39_alt_117 = f31_alt_read!(f39_alt_116.is_some());
                let f39_alt_118 = f31_alt_read!(f39_alt_117.is_some());
                let f39_alt_119 = f31_alt_read!(f39_alt_118.is_some());
                let f39_alt_120 = f31_alt_read!(f39_alt_119.is_some());
                let f39_alt_121 = f31_alt_read!(f39_alt_120.is_some());
                let f39_alt_122 = f31_alt_read!(f39_alt_121.is_some());
                let f39_alt_123 = f31_alt_read!(f39_alt_122.is_some());
                let f39_alt_124 = f31_alt_read!(f39_alt_123.is_some());
                let f39_alt_125 = f31_alt_read!(f39_alt_124.is_some());
                let f39_alt_126 = f31_alt_read!(f39_alt_125.is_some());
                let f39_alt_127 = f31_alt_read!(f39_alt_126.is_some());
                let f39_alt_128 = f31_alt_read!(f39_alt_127.is_some());
                let f39_alt_129 = f31_alt_read!(f39_alt_128.is_some());
                let f39_alt_130 = f31_alt_read!(f39_alt_129.is_some());
                let f39_alt_131 = f31_alt_read!(f39_alt_130.is_some());
                let f39_alt_132 = f31_alt_read!(f39_alt_131.is_some());
                let f39_alt_133 = f31_alt_read!(f39_alt_132.is_some());
                let f39_alt_134 = f31_alt_read!(f39_alt_133.is_some());
                let f39_alt_135 = f31_alt_read!(f39_alt_134.is_some());
                let f39_alt_136 = f31_alt_read!(f39_alt_135.is_some());
                let f39_alt_137 = f31_alt_read!(f39_alt_136.is_some());
                let f39_alt_138 = f31_alt_read!(f39_alt_137.is_some());
                let f39_alt_139 = f31_alt_read!(f39_alt_138.is_some());
                let f39_alt_140 = f31_alt_read!(f39_alt_139.is_some());
                let f39_alt_141 = f31_alt_read!(f39_alt_140.is_some());
                let f39_alt_142 = f31_alt_read!(f39_alt_141.is_some());
                let f39_alt_143 = f31_alt_read!(f39_alt_142.is_some());
                let f39_alt_144 = f31_alt_read!(f39_alt_143.is_some());
                let f39_alt_145 = f31_alt_read!(f39_alt_144.is_some());
                let f39_alt_146 = f31_alt_read!(f39_alt_145.is_some());
                let f39_alt_147 = f31_alt_read!(f39_alt_146.is_some());
                let f39_alt_148 = f31_alt_read!(f39_alt_147.is_some());
                let f39_alt_149 = f31_alt_read!(f39_alt_148.is_some());
                let f39_alt_150 = f31_alt_read!(f39_alt_149.is_some());
                let f39_alt_151 = f31_alt_read!(f39_alt_150.is_some());
                let f39_alt_152 = f31_alt_read!(f39_alt_151.is_some());
                let f39_alt_153 = f31_alt_read!(f39_alt_152.is_some());
                let f39_alt_154 = f31_alt_read!(f39_alt_153.is_some());
                let f39_alt_155 = f31_alt_read!(f39_alt_154.is_some());
                let f39_alt_156 = f31_alt_read!(f39_alt_155.is_some());
                let f39_alt_157 = f31_alt_read!(f39_alt_156.is_some());
                let f39_alt_158 = f31_alt_read!(f39_alt_157.is_some());
                let f39_alt_159 = f31_alt_read!(f39_alt_158.is_some());
                let f39_alt_160 = f31_alt_read!(f39_alt_159.is_some());
                let f39_alt_161 = f31_alt_read!(f39_alt_160.is_some());
                let f39_alt_162 = f31_alt_read!(f39_alt_161.is_some());
                let f39_alt_163 = f31_alt_read!(f39_alt_162.is_some());
                let f39_alt_164 = f31_alt_read!(f39_alt_163.is_some());
                let f39_alt_165 = f31_alt_read!(f39_alt_164.is_some());
                let f39_alt_166 = f31_alt_read!(f39_alt_165.is_some());
                let f39_alt_167 = f31_alt_read!(f39_alt_166.is_some());
                let f39_alt_168 = f31_alt_read!(f39_alt_167.is_some());
                let f39_alt_169 = f31_alt_read!(f39_alt_168.is_some());
                let f39_alt_170 = f31_alt_read!(f39_alt_169.is_some());
                let f39_alt_171 = f31_alt_read!(f39_alt_170.is_some());
                let f39_alt_172 = f31_alt_read!(f39_alt_171.is_some());
                let f39_alt_173 = f31_alt_read!(f39_alt_172.is_some());
                let f39_alt_174 = f31_alt_read!(f39_alt_173.is_some());
                let f39_alt_175 = f31_alt_read!(f39_alt_174.is_some());
                let f39_alt_176 = f31_alt_read!(f39_alt_175.is_some());
                let f39_alt_177 = f31_alt_read!(f39_alt_176.is_some());
                let f39_alt_178 = f31_alt_read!(f39_alt_177.is_some());
                let f39_alt_179 = f31_alt_read!(f39_alt_178.is_some());
                let f39_alt_180 = f31_alt_read!(f39_alt_179.is_some());
                let f39_alt_181 = f31_alt_read!(f39_alt_180.is_some());
                let f39_alt_182 = f31_alt_read!(f39_alt_181.is_some());
                let f39_alt_183 = f31_alt_read!(f39_alt_182.is_some());
                let f39_alt_184 = f31_alt_read!(f39_alt_183.is_some());
                let f39_alt_185 = f31_alt_read!(f39_alt_184.is_some());
                let f39_alt_186 = f31_alt_read!(f39_alt_185.is_some());
                let f39_alt_187 = f31_alt_read!(f39_alt_186.is_some());
                let f39_alt_188 = f31_alt_read!(f39_alt_187.is_some());
                let f39_alt_189 = f31_alt_read!(f39_alt_188.is_some());
                let f39_alt_190 = f31_alt_read!(f39_alt_189.is_some());
                let f39_alt_191 = f31_alt_read!(f39_alt_190.is_some());
                let f39_alt_192 = f31_alt_read!(f39_alt_191.is_some());
                let field_40_u32_list = if field_39_u32_list.is_some() || f39_alt_001.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_41_u32 = if field_40_u32_list.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_42_u32 = if field_41_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_43_u32 = if field_42_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_44_u32 = if field_43_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_45_u32 = if field_44_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_46_u32 = if field_45_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_47_u32 = if field_46_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_48_u32 = if field_47_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_49_u32_list = if field_48_u32.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_50_u32_list = if field_49_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_51_u32_list = if field_50_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_52_u32_list = if field_51_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_53_u32_list = if field_52_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_54_u32_list = if field_53_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_55_u32_list = if field_54_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_56_u32_list = if field_55_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_57_u32_list = if field_56_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_58_u32_list = if field_57_u32_list.is_some() {
                    let pre_ = probe;
                    match <CArray<u32>>::read_from(data, &mut probe) {
                        Ok(arr) if probe <= entry_end => Some(arr),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let field_59_u32 = if field_58_u32_list.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_60_u32 = if field_59_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_61_u32 = if field_60_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_62_u32 = if field_61_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_63_u32 = if field_62_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_64_u32 = if field_63_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_65_u32 = if field_64_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_66_u32 = if field_65_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_67_u32 = if field_66_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_68_u32 = if field_67_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_69_u32 = if field_68_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_70_u32 = if field_69_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_71_u32 = if field_70_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_72_u32 = if field_71_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_73_u32 = if field_72_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_74_u32 = if field_73_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_75_u32 = if field_74_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_76_u32 = if field_75_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_77_u32 = if field_76_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_78_u32 = if field_77_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_79_u32 = if field_78_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_80_u32 = if field_79_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_81_u32 = if field_80_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_82_u32 = if field_81_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_83_u32 = if field_82_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_84_u32 = if field_83_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_85_u32 = if field_84_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_86_u32 = if field_85_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_87_u32 = if field_86_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_88_u32 = if field_87_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_89_u32 = if field_88_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_90_u32 = if field_89_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_91_u32 = if field_90_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_92_u32 = if field_91_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_93_u32 = if field_92_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_94_u32 = if field_93_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_95_u32 = if field_94_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_96_u32 = if field_95_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_97_u32 = if field_96_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_98_u32 = if field_97_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_99_u32 = if field_98_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_100_u32 = if field_99_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_101_u32 = if field_100_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_102_u32 = if field_101_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_103_u32 = if field_102_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_104_u32 = if field_103_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_105_u32 = if field_104_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_106_u32 = if field_105_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_107_u32 = if field_106_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_108_u32 = if field_107_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_109_u32 = if field_108_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_110_u32 = if field_109_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_111_u32 = if field_110_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_112_u32 = if field_111_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_113_u32 = if field_112_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_114_u32 = if field_113_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_115_u32 = if field_114_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_116_u32 = if field_115_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_117_u32 = if field_116_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_118_u32 = if field_117_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_119_u32 = if field_118_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_120_u32 = if field_119_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_121_u32 = if field_120_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_122_u32 = if field_121_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_123_u32 = if field_122_u32.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                macro_rules! read_u32_chained {
                    ($prev:ident) => {{
                        if $prev.is_some() && probe + 4 <= entry_end {
                            let pre_ = probe;
                            match u32::read_from(data, &mut probe) {
                                Ok(v) => Some(v), _ => { probe = pre_; None }
                            }
                        } else { None }
                    }};
                }
                let field_124_u32 = read_u32_chained!(field_123_u32);
                let field_125_u32 = read_u32_chained!(field_124_u32);
                let field_126_u32 = read_u32_chained!(field_125_u32);
                let field_127_u32 = read_u32_chained!(field_126_u32);
                let field_128_u32 = read_u32_chained!(field_127_u32);
                let field_129_u32 = read_u32_chained!(field_128_u32);
                let field_130_u32 = read_u32_chained!(field_129_u32);
                let field_131_u32 = read_u32_chained!(field_130_u32);
                let field_132_u32 = read_u32_chained!(field_131_u32);
                let field_133_u32 = read_u32_chained!(field_132_u32);
                let field_134_u32 = read_u32_chained!(field_133_u32);
                let field_135_u32 = read_u32_chained!(field_134_u32);
                let field_136_u32 = read_u32_chained!(field_135_u32);
                let field_137_u32 = read_u32_chained!(field_136_u32);
                let field_138_u32 = read_u32_chained!(field_137_u32);
                let field_139_u32 = read_u32_chained!(field_138_u32);
                let field_140_u32 = read_u32_chained!(field_139_u32);
                let field_141_u32 = read_u32_chained!(field_140_u32);
                let field_142_u32 = read_u32_chained!(field_141_u32);
                let field_143_u32 = read_u32_chained!(field_142_u32);
                let field_144_u32 = read_u32_chained!(field_143_u32);
                let field_145_u32 = read_u32_chained!(field_144_u32);
                let field_146_u32 = read_u32_chained!(field_145_u32);
                let field_147_u32 = read_u32_chained!(field_146_u32);
                let field_148_u32 = read_u32_chained!(field_147_u32);
                let field_149_u32 = read_u32_chained!(field_148_u32);
                let field_150_u32 = read_u32_chained!(field_149_u32);
                let field_151_u32 = read_u32_chained!(field_150_u32);
                let field_152_u32 = read_u32_chained!(field_151_u32);
                let field_153_u32 = read_u32_chained!(field_152_u32);
                let field_154_u32 = read_u32_chained!(field_153_u32);
                let field_155_u32 = read_u32_chained!(field_154_u32);
                let field_156_u32 = read_u32_chained!(field_155_u32);
                let field_157_u32 = read_u32_chained!(field_156_u32);
                let field_158_u32 = read_u32_chained!(field_157_u32);
                let field_159_u32 = read_u32_chained!(field_158_u32);
                let field_160_u32 = read_u32_chained!(field_159_u32);
                let field_161_u32 = read_u32_chained!(field_160_u32);
                let field_162_u32 = read_u32_chained!(field_161_u32);
                let field_163_u32 = read_u32_chained!(field_162_u32);
                let field_164_u32 = read_u32_chained!(field_163_u32);
                let field_165_u32 = read_u32_chained!(field_164_u32);
                let field_166_u32 = read_u32_chained!(field_165_u32);
                let field_167_u32 = read_u32_chained!(field_166_u32);
                let field_168_u32 = read_u32_chained!(field_167_u32);
                let field_169_u32 = read_u32_chained!(field_168_u32);
                let field_170_u32 = read_u32_chained!(field_169_u32);
                let field_171_u32 = read_u32_chained!(field_170_u32);
                let field_172_u32 = read_u32_chained!(field_171_u32);
                let field_173_u32 = read_u32_chained!(field_172_u32);
                let field_174_u32 = read_u32_chained!(field_173_u32);
                let field_175_u32 = read_u32_chained!(field_174_u32);
                let field_176_u32 = read_u32_chained!(field_175_u32);
                let field_177_u32 = read_u32_chained!(field_176_u32);
                let field_178_u32 = read_u32_chained!(field_177_u32);
                let field_179_u32 = read_u32_chained!(field_178_u32);
                let field_180_u32 = read_u32_chained!(field_179_u32);
                let field_181_u32 = read_u32_chained!(field_180_u32);
                let field_182_u32 = read_u32_chained!(field_181_u32);
                let field_183_u32 = read_u32_chained!(field_182_u32);
                let field_184_u32 = read_u32_chained!(field_183_u32);
                let field_185_u32 = read_u32_chained!(field_184_u32);
                let field_186_u32 = read_u32_chained!(field_185_u32);
                let field_187_u32 = read_u32_chained!(field_186_u32);
                let field_188_u32 = read_u32_chained!(field_187_u32);
                let field_189_u32 = read_u32_chained!(field_188_u32);
                let field_190_u32 = read_u32_chained!(field_189_u32);
                let field_191_u32 = read_u32_chained!(field_190_u32);
                let field_192_u32 = read_u32_chained!(field_191_u32);
                let field_193_u32 = read_u32_chained!(field_192_u32);
                let field_194_u32 = read_u32_chained!(field_193_u32);
                let field_195_u32 = read_u32_chained!(field_194_u32);
                let field_196_u32 = read_u32_chained!(field_195_u32);
                let field_197_u32 = read_u32_chained!(field_196_u32);
                let field_198_u32 = read_u32_chained!(field_197_u32);
                let field_199_u32 = read_u32_chained!(field_198_u32);
                let field_200_u32 = read_u32_chained!(field_199_u32);
                let field_201_u32 = read_u32_chained!(field_200_u32);
                let field_202_u32 = read_u32_chained!(field_201_u32);
                let field_203_u32 = read_u32_chained!(field_202_u32);
                let field_204_u32 = read_u32_chained!(field_203_u32);
                let field_205_u32 = read_u32_chained!(field_204_u32);
                let field_206_u32 = read_u32_chained!(field_205_u32);
                let field_207_u32 = read_u32_chained!(field_206_u32);
                let field_208_u32 = read_u32_chained!(field_207_u32);
                let field_209_u32 = read_u32_chained!(field_208_u32);
                let field_210_u32 = read_u32_chained!(field_209_u32);
                let field_211_u32 = read_u32_chained!(field_210_u32);
                let field_212_u32 = read_u32_chained!(field_211_u32);
                let field_213_u32 = read_u32_chained!(field_212_u32);
                let field_214_u32 = read_u32_chained!(field_213_u32);
                let field_215_u32 = read_u32_chained!(field_214_u32);
                let field_216_u32 = read_u32_chained!(field_215_u32);
                let field_217_u32 = read_u32_chained!(field_216_u32);
                let field_218_u32 = read_u32_chained!(field_217_u32);
                let field_219_u32 = read_u32_chained!(field_218_u32);
                let field_220_u32 = read_u32_chained!(field_219_u32);
                let field_221_u32 = read_u32_chained!(field_220_u32);
                let field_222_u32 = read_u32_chained!(field_221_u32);
                let field_223_u32 = read_u32_chained!(field_222_u32);
                let field_224_u32 = read_u32_chained!(field_223_u32);
                let field_225_u32 = read_u32_chained!(field_224_u32);
                let field_226_u32 = read_u32_chained!(field_225_u32);
                let field_227_u32 = read_u32_chained!(field_226_u32);
                let field_228_u32 = read_u32_chained!(field_227_u32);
                let field_229_u32 = read_u32_chained!(field_228_u32);
                let field_230_u32 = read_u32_chained!(field_229_u32);
                let field_231_u32 = read_u32_chained!(field_230_u32);
                let field_232_u32 = read_u32_chained!(field_231_u32);
                let field_233_u32 = read_u32_chained!(field_232_u32);
                let field_234_u32 = read_u32_chained!(field_233_u32);
                let field_235_u32 = read_u32_chained!(field_234_u32);
                let field_236_u32 = read_u32_chained!(field_235_u32);
                let field_237_u32 = read_u32_chained!(field_236_u32);
                let field_238_u32 = read_u32_chained!(field_237_u32);
                let field_239_u32 = read_u32_chained!(field_238_u32);
                let field_240_u32 = read_u32_chained!(field_239_u32);
                let field_241_u32 = read_u32_chained!(field_240_u32);
                let field_242_u32 = read_u32_chained!(field_241_u32);
                let field_243_u32 = read_u32_chained!(field_242_u32);
                let field_244_u32 = read_u32_chained!(field_243_u32);
                let field_245_u32 = read_u32_chained!(field_244_u32);
                let field_246_u32 = read_u32_chained!(field_245_u32);
                let field_247_u32 = read_u32_chained!(field_246_u32);
                let field_248_u32 = read_u32_chained!(field_247_u32);
                let field_249_u32 = read_u32_chained!(field_248_u32);
                let field_250_u32 = read_u32_chained!(field_249_u32);
                let field_251_u32 = read_u32_chained!(field_250_u32);
                let field_252_u32 = read_u32_chained!(field_251_u32);
                let field_253_u32 = read_u32_chained!(field_252_u32);
                let field_254_u32 = read_u32_chained!(field_253_u32);
                let field_255_u32 = read_u32_chained!(field_254_u32);
                let field_256_u32 = read_u32_chained!(field_255_u32);
                let field_257_u32 = read_u32_chained!(field_256_u32);
                let field_258_u32 = read_u32_chained!(field_257_u32);
                let field_259_u32 = read_u32_chained!(field_258_u32);
                let field_260_u32 = read_u32_chained!(field_259_u32);
                let field_261_u32 = read_u32_chained!(field_260_u32);
                let field_262_u32 = read_u32_chained!(field_261_u32);
                let field_263_u32 = read_u32_chained!(field_262_u32);
                let field_264_u32 = read_u32_chained!(field_263_u32);
                let field_265_u32 = read_u32_chained!(field_264_u32);
                let field_266_u32 = read_u32_chained!(field_265_u32);
                let field_267_u32 = read_u32_chained!(field_266_u32);
                let field_268_u32 = read_u32_chained!(field_267_u32);
                let field_269_u32 = read_u32_chained!(field_268_u32);
                let field_270_u32 = read_u32_chained!(field_269_u32);
                let field_271_u32 = read_u32_chained!(field_270_u32);
                let field_272_u32 = read_u32_chained!(field_271_u32);
                let field_273_u32 = read_u32_chained!(field_272_u32);
                let field_274_u32 = read_u32_chained!(field_273_u32);
                let field_275_u32 = read_u32_chained!(field_274_u32);
                let field_276_u32 = read_u32_chained!(field_275_u32);
                let field_277_u32 = read_u32_chained!(field_276_u32);
                let field_278_u32 = read_u32_chained!(field_277_u32);
                let field_279_u32 = read_u32_chained!(field_278_u32);
                let field_280_u32 = read_u32_chained!(field_279_u32);
                let field_281_u32 = read_u32_chained!(field_280_u32);
                let field_282_u32 = read_u32_chained!(field_281_u32);
                let field_283_u32 = read_u32_chained!(field_282_u32);
                let field_284_u32 = read_u32_chained!(field_283_u32);
                let field_285_u32 = read_u32_chained!(field_284_u32);
                let field_286_u32 = read_u32_chained!(field_285_u32);
                let field_287_u32 = read_u32_chained!(field_286_u32);
                let field_288_u32 = read_u32_chained!(field_287_u32);
                let field_289_u32 = read_u32_chained!(field_288_u32);
                let field_290_u32 = read_u32_chained!(field_289_u32);
                let field_291_u32 = read_u32_chained!(field_290_u32);
                let field_292_u32 = read_u32_chained!(field_291_u32);
                let field_293_u32 = read_u32_chained!(field_292_u32);
                let field_294_u32 = read_u32_chained!(field_293_u32);
                let field_295_u32 = read_u32_chained!(field_294_u32);
                let field_296_u32 = read_u32_chained!(field_295_u32);
                let field_297_u32 = read_u32_chained!(field_296_u32);
                let field_298_u32 = read_u32_chained!(field_297_u32);
                let field_299_u32 = read_u32_chained!(field_298_u32);
                let field_300_u32 = read_u32_chained!(field_299_u32);
                let field_301_u32 = read_u32_chained!(field_300_u32);
                let field_302_u32 = read_u32_chained!(field_301_u32);
                let field_303_u32 = read_u32_chained!(field_302_u32);
                let field_304_u32 = read_u32_chained!(field_303_u32);
                let field_305_u32 = read_u32_chained!(field_304_u32);
                let field_306_u32 = read_u32_chained!(field_305_u32);
                let field_307_u32 = read_u32_chained!(field_306_u32);
                let field_308_u32 = read_u32_chained!(field_307_u32);
                let field_309_u32 = read_u32_chained!(field_308_u32);
                let field_310_u32 = read_u32_chained!(field_309_u32);
                let field_311_u32 = read_u32_chained!(field_310_u32);
                let field_312_u32 = read_u32_chained!(field_311_u32);
                let field_313_u32 = read_u32_chained!(field_312_u32);
                let field_314_u32 = read_u32_chained!(field_313_u32);
                let field_315_u32 = read_u32_chained!(field_314_u32);
                let field_316_u32 = read_u32_chained!(field_315_u32);
                let field_317_u32 = read_u32_chained!(field_316_u32);
                let field_318_u32 = read_u32_chained!(field_317_u32);
                let field_319_u32 = read_u32_chained!(field_318_u32);
                let field_320_u32 = read_u32_chained!(field_319_u32);
                let field_321_u32 = read_u32_chained!(field_320_u32);
                let field_322_u32 = read_u32_chained!(field_321_u32);
                let field_323_u32 = read_u32_chained!(field_322_u32);
                let field_324_u32 = read_u32_chained!(field_323_u32);
                let field_325_u32 = read_u32_chained!(field_324_u32);
                let field_326_u32 = read_u32_chained!(field_325_u32);
                let field_327_u32 = read_u32_chained!(field_326_u32);
                let field_328_u32 = read_u32_chained!(field_327_u32);
                let field_329_u32 = read_u32_chained!(field_328_u32);
                let field_330_u32 = read_u32_chained!(field_329_u32);
                let field_331_u32 = read_u32_chained!(field_330_u32);
                let field_332_u32 = read_u32_chained!(field_331_u32);
                let field_333_u32 = read_u32_chained!(field_332_u32);
                let field_334_u32 = read_u32_chained!(field_333_u32);
                let field_335_u32 = read_u32_chained!(field_334_u32);
                let field_336_u32 = read_u32_chained!(field_335_u32);
                let field_337_u32 = read_u32_chained!(field_336_u32);
                let field_338_u32 = read_u32_chained!(field_337_u32);
                let field_339_u32 = read_u32_chained!(field_338_u32);
                let field_340_u32 = read_u32_chained!(field_339_u32);
                let field_341_u32 = read_u32_chained!(field_340_u32);
                let field_342_u32_count = read_u32_chained!(field_341_u32);
                let field_343_u8_flag = if field_342_u32_count.is_some() && probe + 1 <= entry_end {
                    let pre_ = probe;
                    match u8::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_344_u32 = if field_343_u8_flag.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let field_345_u32 = read_u32_chained!(field_344_u32);
                let field_346_u32 = read_u32_chained!(field_345_u32);
                let field_347_u32 = read_u32_chained!(field_346_u32);
                let field_348_u32 = read_u32_chained!(field_347_u32);
                let field_349_u32 = read_u32_chained!(field_348_u32);
                let field_350_u32 = read_u32_chained!(field_349_u32);
                let field_351_u32 = read_u32_chained!(field_350_u32);
                let field_352_u32 = read_u32_chained!(field_351_u32);
                let field_353_u32 = read_u32_chained!(field_352_u32);
                let field_354_u32 = read_u32_chained!(field_353_u32);
                let field_355_u32 = read_u32_chained!(field_354_u32);
                let field_356_u32 = read_u32_chained!(field_355_u32);
                let field_357_u32 = read_u32_chained!(field_356_u32);
                let field_358_u32 = read_u32_chained!(field_357_u32);
                let field_359_u32 = read_u32_chained!(field_358_u32);
                let field_360_u32 = read_u32_chained!(field_359_u32);
                let field_361_u32 = read_u32_chained!(field_360_u32);
                let field_362_u32 = read_u32_chained!(field_361_u32);
                let field_363_u32 = read_u32_chained!(field_362_u32);
                let field_364_u32 = read_u32_chained!(field_363_u32);
                let field_365_u32 = read_u32_chained!(field_364_u32);
                let field_366_u32 = read_u32_chained!(field_365_u32);
                let field_367_u32 = read_u32_chained!(field_366_u32);
                let field_368_u32 = read_u32_chained!(field_367_u32);
                let field_369_u32 = read_u32_chained!(field_368_u32);
                let field_370_u32 = read_u32_chained!(field_369_u32);
                let field_371_u32 = read_u32_chained!(field_370_u32);
                let field_372_u32 = read_u32_chained!(field_371_u32);
                let field_373_u32 = read_u32_chained!(field_372_u32);
                let field_374_u32 = read_u32_chained!(field_373_u32);
                let field_375_u32 = read_u32_chained!(field_374_u32);
                let field_376_u32 = read_u32_chained!(field_375_u32);
                let field_377_u32 = read_u32_chained!(field_376_u32);
                let field_378_u32 = read_u32_chained!(field_377_u32);
                let field_379_u32 = read_u32_chained!(field_378_u32);
                let field_380_u32 = read_u32_chained!(field_379_u32);
                let field_381_u32 = read_u32_chained!(field_380_u32);
                let field_382_u32 = read_u32_chained!(field_381_u32);
                let field_383_u32 = read_u32_chained!(field_382_u32);
                let field_384_u32 = read_u32_chained!(field_383_u32);
                let field_385_u32 = read_u32_chained!(field_384_u32);
                let field_386_u32 = read_u32_chained!(field_385_u32);
                let field_387_u32 = read_u32_chained!(field_386_u32);
                let field_388_u32 = read_u32_chained!(field_387_u32);
                let field_389_u32 = read_u32_chained!(field_388_u32);
                let field_390_u32 = read_u32_chained!(field_389_u32);
                let field_391_u32 = read_u32_chained!(field_390_u32);
                let field_392_u32 = read_u32_chained!(field_391_u32);
                let field_393_u32 = read_u32_chained!(field_392_u32);
                let field_394_u32 = read_u32_chained!(field_393_u32);
                let field_395_u32 = read_u32_chained!(field_394_u32);
                let field_396_u32 = read_u32_chained!(field_395_u32);
                let field_397_u32 = read_u32_chained!(field_396_u32);
                let field_398_u32 = read_u32_chained!(field_397_u32);
                let field_399_u32 = read_u32_chained!(field_398_u32);
                let field_400_u32 = read_u32_chained!(field_399_u32);
                let field_401_u32 = read_u32_chained!(field_400_u32);
                let field_402_u32 = read_u32_chained!(field_401_u32);
                let field_403_u32 = read_u32_chained!(field_402_u32);
                let field_404_u32 = read_u32_chained!(field_403_u32);
                let field_405_u32 = read_u32_chained!(field_404_u32);
                let field_406_u32 = read_u32_chained!(field_405_u32);
                let field_407_u32 = read_u32_chained!(field_406_u32);
                let field_408_u32 = read_u32_chained!(field_407_u32);
                let field_409_u32 = read_u32_chained!(field_408_u32);
                let field_410_u32 = read_u32_chained!(field_409_u32);
                let field_411_u32 = read_u32_chained!(field_410_u32);
                let field_412_u32 = read_u32_chained!(field_411_u32);
                let field_413_u32 = read_u32_chained!(field_412_u32);
                let field_414_u32 = read_u32_chained!(field_413_u32);
                let field_415_u32 = read_u32_chained!(field_414_u32);
                let field_416_u32 = read_u32_chained!(field_415_u32);
                let field_417_u32 = read_u32_chained!(field_416_u32);
                let field_418_u32 = read_u32_chained!(field_417_u32);
                let field_419_u32 = read_u32_chained!(field_418_u32);
                let field_420_u32 = read_u32_chained!(field_419_u32);
                let field_421_u32 = read_u32_chained!(field_420_u32);
                let field_422_u32 = read_u32_chained!(field_421_u32);
                let field_423_u32 = read_u32_chained!(field_422_u32);
                let field_424_u32 = read_u32_chained!(field_423_u32);
                let field_425_u32 = read_u32_chained!(field_424_u32);
                let field_426_u32 = read_u32_chained!(field_425_u32);
                let field_427_u32 = read_u32_chained!(field_426_u32);
                let field_428_u32 = read_u32_chained!(field_427_u32);
                let field_429_u32 = read_u32_chained!(field_428_u32);
                let field_430_u32 = read_u32_chained!(field_429_u32);
                let field_431_u32 = read_u32_chained!(field_430_u32);
                let field_432_u32 = read_u32_chained!(field_431_u32);
                let field_433_u32 = read_u32_chained!(field_432_u32);
                let field_434_u32 = read_u32_chained!(field_433_u32);
                let field_435_u32 = read_u32_chained!(field_434_u32);
                let field_436_u32 = read_u32_chained!(field_435_u32);
                let field_437_u32 = read_u32_chained!(field_436_u32);
                let field_438_u32 = read_u32_chained!(field_437_u32);
                let field_439_u32 = read_u32_chained!(field_438_u32);
                let field_440_u32 = read_u32_chained!(field_439_u32);
                let field_441_u32 = read_u32_chained!(field_440_u32);
                let field_442_u32 = read_u32_chained!(field_441_u32);
                let field_443_u32 = read_u32_chained!(field_442_u32);
                let field_444_u32 = read_u32_chained!(field_443_u32);
                let field_445_u32 = read_u32_chained!(field_444_u32);
                let field_446_u32 = read_u32_chained!(field_445_u32);
                let field_447_u32 = read_u32_chained!(field_446_u32);
                let field_448_u32 = read_u32_chained!(field_447_u32);
                let field_449_u32 = read_u32_chained!(field_448_u32);
                let field_450_u32 = read_u32_chained!(field_449_u32);
                let field_451_u32 = read_u32_chained!(field_450_u32);
                let field_452_u32 = read_u32_chained!(field_451_u32);
                let field_453_u32 = read_u32_chained!(field_452_u32);
                let field_454_u32 = read_u32_chained!(field_453_u32);
                let field_455_u32 = read_u32_chained!(field_454_u32);
                let field_456_u32 = read_u32_chained!(field_455_u32);
                let field_457_u32 = read_u32_chained!(field_456_u32);
                let field_458_u32 = read_u32_chained!(field_457_u32);
                let field_459_u32 = read_u32_chained!(field_458_u32);
                let field_460_u32 = read_u32_chained!(field_459_u32);
                let field_461_u32 = read_u32_chained!(field_460_u32);
                let field_462_u32 = read_u32_chained!(field_461_u32);
                let field_463_u32 = read_u32_chained!(field_462_u32);
                let field_464_u32 = read_u32_chained!(field_463_u32);
                let field_465_u32 = read_u32_chained!(field_464_u32);
                let field_466_u32 = read_u32_chained!(field_465_u32);
                let field_467_u32 = read_u32_chained!(field_466_u32);
                let field_468_u32 = read_u32_chained!(field_467_u32);
                let field_469_u32 = read_u32_chained!(field_468_u32);
                let field_470_u32 = read_u32_chained!(field_469_u32);
                let field_471_u32 = read_u32_chained!(field_470_u32);
                let field_472_u32 = read_u32_chained!(field_471_u32);
                let field_473_u32 = read_u32_chained!(field_472_u32);
                let field_474_u32 = read_u32_chained!(field_473_u32);
                let field_475_u32 = read_u32_chained!(field_474_u32);
                let field_476_u32 = read_u32_chained!(field_475_u32);
                let field_477_u32 = read_u32_chained!(field_476_u32);
                let field_478_u32 = read_u32_chained!(field_477_u32);
                let field_479_u32 = read_u32_chained!(field_478_u32);
                let field_480_u32 = read_u32_chained!(field_479_u32);
                let field_481_u32 = read_u32_chained!(field_480_u32);
                let field_482_u32 = read_u32_chained!(field_481_u32);
                let field_483_u32 = read_u32_chained!(field_482_u32);
                let field_484_u32 = read_u32_chained!(field_483_u32);
                let field_485_u32 = read_u32_chained!(field_484_u32);
                let field_486_u32 = read_u32_chained!(field_485_u32);
                let field_487_u32 = read_u32_chained!(field_486_u32);
                let field_488_u32 = read_u32_chained!(field_487_u32);
                let field_489_u32 = read_u32_chained!(field_488_u32);
                let field_490_u32 = read_u32_chained!(field_489_u32);
                let field_491_u32 = read_u32_chained!(field_490_u32);
                let field_492_u32 = read_u32_chained!(field_491_u32);
                let field_493_u32 = read_u32_chained!(field_492_u32);
                let field_494_u32 = read_u32_chained!(field_493_u32);
                let field_495_u32 = read_u32_chained!(field_494_u32);
                let field_496_u32 = read_u32_chained!(field_495_u32);
                let field_497_u32 = read_u32_chained!(field_496_u32);
                let field_498_u32 = read_u32_chained!(field_497_u32);
                let field_499_u32 = read_u32_chained!(field_498_u32);
                let field_500_u32 = read_u32_chained!(field_499_u32);
                let field_501_u32 = read_u32_chained!(field_500_u32);
                let field_502_u32 = read_u32_chained!(field_501_u32);
                let field_503_u32 = read_u32_chained!(field_502_u32);
                let field_504_u32 = read_u32_chained!(field_503_u32);
                let field_505_u32 = read_u32_chained!(field_504_u32);
                let field_506_u32 = read_u32_chained!(field_505_u32);
                let field_507_u32 = read_u32_chained!(field_506_u32);
                let field_508_u32 = read_u32_chained!(field_507_u32);
                let field_509_u32 = read_u32_chained!(field_508_u32);
                let field_510_u32 = read_u32_chained!(field_509_u32);
                let field_511_u32 = read_u32_chained!(field_510_u32);
                let field_512_u32 = read_u32_chained!(field_511_u32);
                let field_513_u32 = read_u32_chained!(field_512_u32);
                let field_514_u32 = read_u32_chained!(field_513_u32);
                let field_515_u32 = read_u32_chained!(field_514_u32);
                let field_516_u32 = read_u32_chained!(field_515_u32);
                let field_517_u32 = read_u32_chained!(field_516_u32);
                let field_518_u32 = read_u32_chained!(field_517_u32);
                let field_519_u32 = read_u32_chained!(field_518_u32);
                let field_520_u32 = read_u32_chained!(field_519_u32);
                let field_521_u32 = read_u32_chained!(field_520_u32);
                let field_522_u32 = read_u32_chained!(field_521_u32);
                let field_523_u32 = read_u32_chained!(field_522_u32);
                let field_524_u32 = read_u32_chained!(field_523_u32);
                let field_525_u32 = read_u32_chained!(field_524_u32);
                let field_526_u32 = read_u32_chained!(field_525_u32);
                let field_527_u32 = read_u32_chained!(field_526_u32);
                let field_528_u32 = read_u32_chained!(field_527_u32);
                let field_529_u32 = read_u32_chained!(field_528_u32);
                let field_530_u32 = read_u32_chained!(field_529_u32);
                let field_531_u32 = read_u32_chained!(field_530_u32);
                let field_532_u32 = read_u32_chained!(field_531_u32);
                let field_533_u32 = read_u32_chained!(field_532_u32);
                let field_534_u32 = read_u32_chained!(field_533_u32);
                let field_535_u32 = read_u32_chained!(field_534_u32);
                let field_536_u32 = read_u32_chained!(field_535_u32);
                let field_537_u32 = read_u32_chained!(field_536_u32);
                let field_538_u32 = read_u32_chained!(field_537_u32);
                let field_539_u32 = read_u32_chained!(field_538_u32);
                let field_540_u32 = read_u32_chained!(field_539_u32);
                let field_541_u32 = read_u32_chained!(field_540_u32);
                let field_542_u32 = read_u32_chained!(field_541_u32);
                let field_543_u32 = read_u32_chained!(field_542_u32);
                let field_544_u32 = read_u32_chained!(field_543_u32);
                let field_545_u32 = read_u32_chained!(field_544_u32);
                let field_546_u32 = read_u32_chained!(field_545_u32);
                let field_547_u32 = read_u32_chained!(field_546_u32);
                let field_548_u32 = read_u32_chained!(field_547_u32);
                let field_549_u32 = read_u32_chained!(field_548_u32);
                let field_550_u32 = read_u32_chained!(field_549_u32);
                let field_551_u32 = read_u32_chained!(field_550_u32);
                let field_552_u32 = read_u32_chained!(field_551_u32);
                let field_553_u32 = read_u32_chained!(field_552_u32);
                let field_554_u32 = read_u32_chained!(field_553_u32);
                let field_555_u32 = read_u32_chained!(field_554_u32);
                let field_556_u32 = read_u32_chained!(field_555_u32);
                let field_557_u32 = read_u32_chained!(field_556_u32);
                let field_558_u32 = read_u32_chained!(field_557_u32);
                let field_559_u32 = read_u32_chained!(field_558_u32);
                let field_560_u32 = read_u32_chained!(field_559_u32);
                let field_561_u32 = read_u32_chained!(field_560_u32);
                let field_562_u32 = read_u32_chained!(field_561_u32);
                let field_563_u32 = read_u32_chained!(field_562_u32);
                let field_564_u32 = read_u32_chained!(field_563_u32);
                let field_565_u32 = read_u32_chained!(field_564_u32);
                let field_566_u32 = read_u32_chained!(field_565_u32);
                let field_567_u32 = read_u32_chained!(field_566_u32);
                let field_568_u32 = read_u32_chained!(field_567_u32);
                let field_569_u32 = read_u32_chained!(field_568_u32);
                let field_570_u32 = read_u32_chained!(field_569_u32);
                let field_571_u32 = read_u32_chained!(field_570_u32);
                let field_572_u32 = read_u32_chained!(field_571_u32);
                let field_573_u32 = read_u32_chained!(field_572_u32);
                let field_574_u32 = read_u32_chained!(field_573_u32);
                let field_575_u32 = read_u32_chained!(field_574_u32);
                let field_576_u32 = read_u32_chained!(field_575_u32);
                let field_577_u32 = read_u32_chained!(field_576_u32);
                let field_578_u32 = read_u32_chained!(field_577_u32);
                let field_579_u32 = read_u32_chained!(field_578_u32);
                let field_580_u32 = read_u32_chained!(field_579_u32);
                let field_581_u32 = read_u32_chained!(field_580_u32);
                let field_582_u32 = read_u32_chained!(field_581_u32);
                let field_583_u32 = read_u32_chained!(field_582_u32);
                let field_584_u32 = read_u32_chained!(field_583_u32);
                let field_585_u32 = read_u32_chained!(field_584_u32);
                let field_586_u32 = read_u32_chained!(field_585_u32);
                let field_587_u32 = read_u32_chained!(field_586_u32);
                let field_588_u32 = read_u32_chained!(field_587_u32);
                let field_589_u32 = read_u32_chained!(field_588_u32);
                let field_590_u32 = read_u32_chained!(field_589_u32);
                let field_591_u32 = read_u32_chained!(field_590_u32);
                let field_592_u32 = read_u32_chained!(field_591_u32);
                let field_593_u32 = read_u32_chained!(field_592_u32);
                let field_594_u32 = read_u32_chained!(field_593_u32);
                let field_595_u32 = read_u32_chained!(field_594_u32);
                let field_596_u32 = read_u32_chained!(field_595_u32);
                let field_597_u32 = read_u32_chained!(field_596_u32);
                let field_598_u32 = read_u32_chained!(field_597_u32);
                let field_599_u32 = read_u32_chained!(field_598_u32);
                let field_600_u32 = read_u32_chained!(field_599_u32);
                let field_601_u32 = read_u32_chained!(field_600_u32);
                let field_602_u32 = read_u32_chained!(field_601_u32);
                let field_603_u32 = read_u32_chained!(field_602_u32);
                let field_604_u32 = read_u32_chained!(field_603_u32);
                let field_605_u32 = read_u32_chained!(field_604_u32);
                let field_606_u32 = read_u32_chained!(field_605_u32);
                let field_607_u32 = read_u32_chained!(field_606_u32);
                let field_608_u32 = read_u32_chained!(field_607_u32);
                let field_609_u32 = read_u32_chained!(field_608_u32);
                let field_610_u32 = read_u32_chained!(field_609_u32);
                let field_611_u32 = read_u32_chained!(field_610_u32);
                let field_612_u32 = read_u32_chained!(field_611_u32);
                let field_613_u32 = read_u32_chained!(field_612_u32);
                let field_614_u32 = read_u32_chained!(field_613_u32);
                let field_615_u32 = read_u32_chained!(field_614_u32);
                let field_616_u32 = read_u32_chained!(field_615_u32);
                let field_617_u32 = read_u32_chained!(field_616_u32);
                let field_618_u32 = read_u32_chained!(field_617_u32);
                let field_619_u32 = read_u32_chained!(field_618_u32);
                let field_620_u32 = read_u32_chained!(field_619_u32);
                let field_621_u32 = read_u32_chained!(field_620_u32);
                let field_622_u32 = read_u32_chained!(field_621_u32);
                let field_623_u32 = read_u32_chained!(field_622_u32);
                let field_624_u32 = read_u32_chained!(field_623_u32);
                let field_625_u32 = read_u32_chained!(field_624_u32);
                let field_626_u32 = read_u32_chained!(field_625_u32);
                let field_627_u32 = read_u32_chained!(field_626_u32);
                let field_628_u32 = read_u32_chained!(field_627_u32);
                let field_629_u32 = read_u32_chained!(field_628_u32);
                let field_630_u32 = read_u32_chained!(field_629_u32);
                let field_631_u32 = read_u32_chained!(field_630_u32);
                let field_632_u32 = read_u32_chained!(field_631_u32);
                let field_633_u32 = read_u32_chained!(field_632_u32);
                let field_634_u32 = read_u32_chained!(field_633_u32);
                let field_635_u32 = read_u32_chained!(field_634_u32);
                let field_636_u32 = read_u32_chained!(field_635_u32);
                let field_637_u32 = read_u32_chained!(field_636_u32);
                let field_638_u32 = read_u32_chained!(field_637_u32);
                let field_639_u32 = read_u32_chained!(field_638_u32);
                let field_640_u32 = read_u32_chained!(field_639_u32);
                let field_641_u32 = read_u32_chained!(field_640_u32);
                let field_642_u32 = read_u32_chained!(field_641_u32);
                let field_643_u32 = read_u32_chained!(field_642_u32);
                let field_644_u32 = read_u32_chained!(field_643_u32);
                let field_645_u32 = read_u32_chained!(field_644_u32);
                let field_646_u32 = read_u32_chained!(field_645_u32);
                let field_647_u32 = read_u32_chained!(field_646_u32);
                let field_648_u32 = read_u32_chained!(field_647_u32);
                let field_649_u32 = read_u32_chained!(field_648_u32);
                let field_650_u32 = read_u32_chained!(field_649_u32);
                let field_651_u32 = read_u32_chained!(field_650_u32);
                let field_652_u32 = read_u32_chained!(field_651_u32);
                let field_653_u32 = read_u32_chained!(field_652_u32);
                let field_654_u32 = read_u32_chained!(field_653_u32);
                let field_655_u32 = read_u32_chained!(field_654_u32);
                let field_656_u32 = read_u32_chained!(field_655_u32);
                let field_657_u32 = read_u32_chained!(field_656_u32);
                let field_658_u32 = read_u32_chained!(field_657_u32);
                let field_659_u32 = read_u32_chained!(field_658_u32);
                let field_660_u32 = read_u32_chained!(field_659_u32);
                let field_661_u32 = read_u32_chained!(field_660_u32);
                let field_662_u32 = read_u32_chained!(field_661_u32);
                let field_663_u32 = read_u32_chained!(field_662_u32);
                let field_664_u32 = read_u32_chained!(field_663_u32);
                // Alt-format detection: when trigger_event_handler_list (field 17) failed,
                // probe is still at tail_start. Try to read alt header (count + flag + name).
                let alt_trigger_count = if trigger_event_handler_list.is_none() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) if v < 1000 => Some(v), // sanity: count should be small
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let alt_trigger_flag = if alt_trigger_count.is_some() && probe + 1 <= entry_end {
                    let pre_ = probe;
                    match u8::read_from(data, &mut probe) {
                        Ok(v) => Some(v), _ => { probe = pre_; None }
                    }
                } else { None };
                let alt_trigger_name = if alt_trigger_flag.is_some() {
                    let pre_ = probe;
                    match CString::read_from(data, &mut probe) {
                        Ok(s) if probe <= entry_end => Some(s),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let alt_inner_count = if alt_trigger_name.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) if v < 1000 => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let alt_inner_name = if alt_inner_count.is_some() {
                    let pre_ = probe;
                    match CString::read_from(data, &mut probe) {
                        Ok(s) if probe <= entry_end => Some(s),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let alt_inner_flag = if alt_inner_name.is_some() && probe + 4 <= entry_end {
                    let pre_ = probe;
                    match u32::read_from(data, &mut probe) {
                        Ok(v) => Some(v),
                        _ => { probe = pre_; None }
                    }
                } else { None };
                let alt_body_001 = read_u32_chained!(alt_inner_flag);
                let alt_body_002 = read_u32_chained!(alt_body_001);
                let alt_body_003 = read_u32_chained!(alt_body_002);
                let alt_body_004 = read_u32_chained!(alt_body_003);
                let alt_body_005 = read_u32_chained!(alt_body_004);
                let alt_body_006 = read_u32_chained!(alt_body_005);
                let alt_body_007 = read_u32_chained!(alt_body_006);
                let alt_body_008 = read_u32_chained!(alt_body_007);
                let alt_body_009 = read_u32_chained!(alt_body_008);
                let alt_body_010 = read_u32_chained!(alt_body_009);
                let alt_body_011 = read_u32_chained!(alt_body_010);
                let alt_body_012 = read_u32_chained!(alt_body_011);
                let alt_body_013 = read_u32_chained!(alt_body_012);
                let alt_body_014 = read_u32_chained!(alt_body_013);
                let alt_body_015 = read_u32_chained!(alt_body_014);
                let alt_body_016 = read_u32_chained!(alt_body_015);
                let alt_body_017 = read_u32_chained!(alt_body_016);
                let alt_body_018 = read_u32_chained!(alt_body_017);
                let alt_body_019 = read_u32_chained!(alt_body_018);
                let alt_body_020 = read_u32_chained!(alt_body_019);
                let alt_body_021 = read_u32_chained!(alt_body_020);
                let alt_body_022 = read_u32_chained!(alt_body_021);
                let alt_body_023 = read_u32_chained!(alt_body_022);
                let alt_body_024 = read_u32_chained!(alt_body_023);
                let alt_body_025 = read_u32_chained!(alt_body_024);
                let alt_body_026 = read_u32_chained!(alt_body_025);
                let alt_body_027 = read_u32_chained!(alt_body_026);
                let alt_body_028 = read_u32_chained!(alt_body_027);
                let alt_body_029 = read_u32_chained!(alt_body_028);
                let alt_body_030 = read_u32_chained!(alt_body_029);
                let alt_body_031 = read_u32_chained!(alt_body_030);
                let alt_body_032 = read_u32_chained!(alt_body_031);
                let alt_body_033 = read_u32_chained!(alt_body_032);
                let alt_body_034 = read_u32_chained!(alt_body_033);
                let alt_body_035 = read_u32_chained!(alt_body_034);
                let alt_body_036 = read_u32_chained!(alt_body_035);
                let alt_body_037 = read_u32_chained!(alt_body_036);
                let alt_body_038 = read_u32_chained!(alt_body_037);
                let alt_body_039 = read_u32_chained!(alt_body_038);
                let alt_body_040 = read_u32_chained!(alt_body_039);
                let alt_body_041 = read_u32_chained!(alt_body_040);
                let alt_body_042 = read_u32_chained!(alt_body_041);
                let alt_body_043 = read_u32_chained!(alt_body_042);
                let alt_body_044 = read_u32_chained!(alt_body_043);
                let alt_body_045 = read_u32_chained!(alt_body_044);
                let alt_body_046 = read_u32_chained!(alt_body_045);
                let alt_body_047 = read_u32_chained!(alt_body_046);
                let alt_body_048 = read_u32_chained!(alt_body_047);
                let alt_body_049 = read_u32_chained!(alt_body_048);
                let alt_body_050 = read_u32_chained!(alt_body_049);
                let alt_body_051 = read_u32_chained!(alt_body_050);
                let alt_body_052 = read_u32_chained!(alt_body_051);
                let alt_body_053 = read_u32_chained!(alt_body_052);
                let alt_body_054 = read_u32_chained!(alt_body_053);
                let alt_body_055 = read_u32_chained!(alt_body_054);
                let alt_body_056 = read_u32_chained!(alt_body_055);
                let alt_body_057 = read_u32_chained!(alt_body_056);
                let alt_body_058 = read_u32_chained!(alt_body_057);
                let alt_body_059 = read_u32_chained!(alt_body_058);
                let alt_body_060 = read_u32_chained!(alt_body_059);
                let alt_body_061 = read_u32_chained!(alt_body_060);
                let alt_body_062 = read_u32_chained!(alt_body_061);
                let alt_body_063 = read_u32_chained!(alt_body_062);
                let alt_body_064 = read_u32_chained!(alt_body_063);
                let alt_body_065 = read_u32_chained!(alt_body_064);
                let alt_body_066 = read_u32_chained!(alt_body_065);
                let alt_body_067 = read_u32_chained!(alt_body_066);
                let alt_body_068 = read_u32_chained!(alt_body_067);
                let alt_body_069 = read_u32_chained!(alt_body_068);
                let alt_body_070 = read_u32_chained!(alt_body_069);
                let alt_body_071 = read_u32_chained!(alt_body_070);
                let alt_body_072 = read_u32_chained!(alt_body_071);
                let alt_body_073 = read_u32_chained!(alt_body_072);
                let alt_body_074 = read_u32_chained!(alt_body_073);
                let alt_body_075 = read_u32_chained!(alt_body_074);
                let alt_body_076 = read_u32_chained!(alt_body_075);
                let alt_body_077 = read_u32_chained!(alt_body_076);
                let alt_body_078 = read_u32_chained!(alt_body_077);
                let alt_body_079 = read_u32_chained!(alt_body_078);
                let alt_body_080 = read_u32_chained!(alt_body_079);
                let alt_body_081 = read_u32_chained!(alt_body_080);
                let alt_body_082 = read_u32_chained!(alt_body_081);
                let alt_body_083 = read_u32_chained!(alt_body_082);
                let alt_body_084 = read_u32_chained!(alt_body_083);
                let alt_body_085 = read_u32_chained!(alt_body_084);
                let alt_body_086 = read_u32_chained!(alt_body_085);
                let alt_body_087 = read_u32_chained!(alt_body_086);
                let alt_body_088 = read_u32_chained!(alt_body_087);
                let alt_body_089 = read_u32_chained!(alt_body_088);
                let alt_body_090 = read_u32_chained!(alt_body_089);
                let alt_body_091 = read_u32_chained!(alt_body_090);
                let alt_body_092 = read_u32_chained!(alt_body_091);
                let alt_body_093 = read_u32_chained!(alt_body_092);
                let alt_body_094 = read_u32_chained!(alt_body_093);
                let alt_body_095 = read_u32_chained!(alt_body_094);
                let alt_body_096 = read_u32_chained!(alt_body_095);
                let alt_body_097 = read_u32_chained!(alt_body_096);
                let alt_body_098 = read_u32_chained!(alt_body_097);
                let alt_body_099 = read_u32_chained!(alt_body_098);
                let alt_body_100 = read_u32_chained!(alt_body_099);
                let alt_body_101 = read_u32_chained!(alt_body_100);
                let alt_body_102 = read_u32_chained!(alt_body_101);
                let alt_body_103 = read_u32_chained!(alt_body_102);
                let alt_body_104 = read_u32_chained!(alt_body_103);
                let alt_body_105 = read_u32_chained!(alt_body_104);
                let alt_body_106 = read_u32_chained!(alt_body_105);
                let alt_body_107 = read_u32_chained!(alt_body_106);
                let alt_body_108 = read_u32_chained!(alt_body_107);
                let alt_body_109 = read_u32_chained!(alt_body_108);
                let alt_body_110 = read_u32_chained!(alt_body_109);
                let alt_body_111 = read_u32_chained!(alt_body_110);
                let alt_body_112 = read_u32_chained!(alt_body_111);
                let alt_body_113 = read_u32_chained!(alt_body_112);
                let alt_body_114 = read_u32_chained!(alt_body_113);
                let alt_body_115 = read_u32_chained!(alt_body_114);
                let alt_body_116 = read_u32_chained!(alt_body_115);
                let alt_body_117 = read_u32_chained!(alt_body_116);
                let alt_body_118 = read_u32_chained!(alt_body_117);
                let alt_body_119 = read_u32_chained!(alt_body_118);
                let alt_body_120 = read_u32_chained!(alt_body_119);
                let alt_body_121 = read_u32_chained!(alt_body_120);
                let alt_body_122 = read_u32_chained!(alt_body_121);
                let alt_body_123 = read_u32_chained!(alt_body_122);
                let alt_body_124 = read_u32_chained!(alt_body_123);
                let alt_body_125 = read_u32_chained!(alt_body_124);
                let alt_body_126 = read_u32_chained!(alt_body_125);
                let alt_body_127 = read_u32_chained!(alt_body_126);
                let alt_body_128 = read_u32_chained!(alt_body_127);
                let alt_body_129 = read_u32_chained!(alt_body_128);
                let alt_body_130 = read_u32_chained!(alt_body_129);
                let alt_body_131 = read_u32_chained!(alt_body_130);
                let alt_body_132 = read_u32_chained!(alt_body_131);
                let alt_body_133 = read_u32_chained!(alt_body_132);
                let alt_body_134 = read_u32_chained!(alt_body_133);
                let alt_body_135 = read_u32_chained!(alt_body_134);
                let alt_body_136 = read_u32_chained!(alt_body_135);
                let alt_body_137 = read_u32_chained!(alt_body_136);
                let alt_body_138 = read_u32_chained!(alt_body_137);
                let alt_body_139 = read_u32_chained!(alt_body_138);
                let alt_body_140 = read_u32_chained!(alt_body_139);
                let alt_body_141 = read_u32_chained!(alt_body_140);
                let alt_body_142 = read_u32_chained!(alt_body_141);
                let alt_body_143 = read_u32_chained!(alt_body_142);
                let alt_body_144 = read_u32_chained!(alt_body_143);
                let alt_body_145 = read_u32_chained!(alt_body_144);
                let alt_body_146 = read_u32_chained!(alt_body_145);
                let alt_body_147 = read_u32_chained!(alt_body_146);
                let alt_body_148 = read_u32_chained!(alt_body_147);
                let alt_body_149 = read_u32_chained!(alt_body_148);
                let alt_body_150 = read_u32_chained!(alt_body_149);
                let alt_body_151 = read_u32_chained!(alt_body_150);
                let alt_body_152 = read_u32_chained!(alt_body_151);
                let alt_body_153 = read_u32_chained!(alt_body_152);
                let alt_body_154 = read_u32_chained!(alt_body_153);
                let alt_body_155 = read_u32_chained!(alt_body_154);
                let alt_body_156 = read_u32_chained!(alt_body_155);
                let alt_body_157 = read_u32_chained!(alt_body_156);
                let alt_body_158 = read_u32_chained!(alt_body_157);
                let alt_body_159 = read_u32_chained!(alt_body_158);
                let alt_body_160 = read_u32_chained!(alt_body_159);
                let alt_body_161 = read_u32_chained!(alt_body_160);
                let alt_body_162 = read_u32_chained!(alt_body_161);
                let alt_body_163 = read_u32_chained!(alt_body_162);
                let alt_body_164 = read_u32_chained!(alt_body_163);
                let alt_body_165 = read_u32_chained!(alt_body_164);
                let alt_body_166 = read_u32_chained!(alt_body_165);
                let alt_body_167 = read_u32_chained!(alt_body_166);
                let alt_body_168 = read_u32_chained!(alt_body_167);
                let alt_body_169 = read_u32_chained!(alt_body_168);
                let alt_body_170 = read_u32_chained!(alt_body_169);
                let alt_body_171 = read_u32_chained!(alt_body_170);
                let alt_body_172 = read_u32_chained!(alt_body_171);
                let alt_body_173 = read_u32_chained!(alt_body_172);
                let alt_body_174 = read_u32_chained!(alt_body_173);
                let alt_body_175 = read_u32_chained!(alt_body_174);
                let alt_body_176 = read_u32_chained!(alt_body_175);
                let alt_body_177 = read_u32_chained!(alt_body_176);
                let alt_body_178 = read_u32_chained!(alt_body_177);
                let alt_body_179 = read_u32_chained!(alt_body_178);
                let alt_body_180 = read_u32_chained!(alt_body_179);
                let alt_body_181 = read_u32_chained!(alt_body_180);
                let alt_body_182 = read_u32_chained!(alt_body_181);
                let alt_body_183 = read_u32_chained!(alt_body_182);
                let alt_body_184 = read_u32_chained!(alt_body_183);
                let alt_body_185 = read_u32_chained!(alt_body_184);
                let alt_body_186 = read_u32_chained!(alt_body_185);
                let alt_body_187 = read_u32_chained!(alt_body_186);
                let alt_body_188 = read_u32_chained!(alt_body_187);
                let alt_body_189 = read_u32_chained!(alt_body_188);
                let alt_body_190 = read_u32_chained!(alt_body_189);
                let alt_body_191 = read_u32_chained!(alt_body_190);
                let alt_body_192 = read_u32_chained!(alt_body_191);
                let alt_body_193 = read_u32_chained!(alt_body_192);
                let alt_body_194 = read_u32_chained!(alt_body_193);
                let alt_body_195 = read_u32_chained!(alt_body_194);
                let alt_body_196 = read_u32_chained!(alt_body_195);
                let alt_body_197 = read_u32_chained!(alt_body_196);
                let alt_body_198 = read_u32_chained!(alt_body_197);
                let alt_body_199 = read_u32_chained!(alt_body_198);
                let alt_body_200 = read_u32_chained!(alt_body_199);
                let alt_body_201 = read_u32_chained!(alt_body_200);
                let alt_body_202 = read_u32_chained!(alt_body_201);
                let alt_body_203 = read_u32_chained!(alt_body_202);
                let alt_body_204 = read_u32_chained!(alt_body_203);
                let alt_body_205 = read_u32_chained!(alt_body_204);
                let alt_body_206 = read_u32_chained!(alt_body_205);
                let alt_body_207 = read_u32_chained!(alt_body_206);
                let alt_body_208 = read_u32_chained!(alt_body_207);
                let alt_body_209 = read_u32_chained!(alt_body_208);
                let alt_body_210 = read_u32_chained!(alt_body_209);
                let alt_body_211 = read_u32_chained!(alt_body_210);
                let alt_body_212 = read_u32_chained!(alt_body_211);
                let alt_body_213 = read_u32_chained!(alt_body_212);
                let alt_body_214 = read_u32_chained!(alt_body_213);
                let alt_body_215 = read_u32_chained!(alt_body_214);
                let alt_body_216 = read_u32_chained!(alt_body_215);
                let alt_body_217 = read_u32_chained!(alt_body_216);
                let alt_body_218 = read_u32_chained!(alt_body_217);
                let alt_body_219 = read_u32_chained!(alt_body_218);
                let alt_body_220 = read_u32_chained!(alt_body_219);
                let alt_body_221 = read_u32_chained!(alt_body_220);
                let alt_body_222 = read_u32_chained!(alt_body_221);
                let alt_body_223 = read_u32_chained!(alt_body_222);
                let alt_body_224 = read_u32_chained!(alt_body_223);
                let alt_body_225 = read_u32_chained!(alt_body_224);
                let alt_body_226 = read_u32_chained!(alt_body_225);
                let alt_body_227 = read_u32_chained!(alt_body_226);
                let alt_body_228 = read_u32_chained!(alt_body_227);
                let alt_body_229 = read_u32_chained!(alt_body_228);
                let alt_body_230 = read_u32_chained!(alt_body_229);
                let alt_body_231 = read_u32_chained!(alt_body_230);
                let alt_body_232 = read_u32_chained!(alt_body_231);
                let alt_body_233 = read_u32_chained!(alt_body_232);
                let alt_body_234 = read_u32_chained!(alt_body_233);
                let alt_body_235 = read_u32_chained!(alt_body_234);
                let alt_body_236 = read_u32_chained!(alt_body_235);
                let alt_body_237 = read_u32_chained!(alt_body_236);
                let alt_body_238 = read_u32_chained!(alt_body_237);
                let alt_body_239 = read_u32_chained!(alt_body_238);
                let alt_body_240 = read_u32_chained!(alt_body_239);
                let alt_body_241 = read_u32_chained!(alt_body_240);
                let alt_body_242 = read_u32_chained!(alt_body_241);
                let alt_body_243 = read_u32_chained!(alt_body_242);
                let alt_body_244 = read_u32_chained!(alt_body_243);
                let alt_body_245 = read_u32_chained!(alt_body_244);
                let alt_body_246 = read_u32_chained!(alt_body_245);
                let alt_body_247 = read_u32_chained!(alt_body_246);
                let alt_body_248 = read_u32_chained!(alt_body_247);
                let alt_body_249 = read_u32_chained!(alt_body_248);
                let alt_body_250 = read_u32_chained!(alt_body_249);
                let alt_body_251 = read_u32_chained!(alt_body_250);
                let alt_body_252 = read_u32_chained!(alt_body_251);
                let alt_body_253 = read_u32_chained!(alt_body_252);
                let alt_body_254 = read_u32_chained!(alt_body_253);
                let alt_body_255 = read_u32_chained!(alt_body_254);
                let alt_body_256 = read_u32_chained!(alt_body_255);
                let alt_body_257 = read_u32_chained!(alt_body_256);
                let alt_body_258 = read_u32_chained!(alt_body_257);
                let alt_body_259 = read_u32_chained!(alt_body_258);
                let alt_body_260 = read_u32_chained!(alt_body_259);
                let alt_body_261 = read_u32_chained!(alt_body_260);
                let alt_body_262 = read_u32_chained!(alt_body_261);
                let alt_body_263 = read_u32_chained!(alt_body_262);
                let alt_body_264 = read_u32_chained!(alt_body_263);
                let alt_body_265 = read_u32_chained!(alt_body_264);
                let alt_body_266 = read_u32_chained!(alt_body_265);
                let alt_body_267 = read_u32_chained!(alt_body_266);
                let alt_body_268 = read_u32_chained!(alt_body_267);
                let alt_body_269 = read_u32_chained!(alt_body_268);
                let alt_body_270 = read_u32_chained!(alt_body_269);
                let alt_body_271 = read_u32_chained!(alt_body_270);
                let alt_body_272 = read_u32_chained!(alt_body_271);
                let alt_body_273 = read_u32_chained!(alt_body_272);
                let alt_body_274 = read_u32_chained!(alt_body_273);
                let alt_body_275 = read_u32_chained!(alt_body_274);
                let alt_body_276 = read_u32_chained!(alt_body_275);
                let alt_body_277 = read_u32_chained!(alt_body_276);
                let alt_body_278 = read_u32_chained!(alt_body_277);
                let alt_body_279 = read_u32_chained!(alt_body_278);
                let alt_body_280 = read_u32_chained!(alt_body_279);
                let alt_body_281 = read_u32_chained!(alt_body_280);
                let alt_body_282 = read_u32_chained!(alt_body_281);
                let alt_body_283 = read_u32_chained!(alt_body_282);
                let alt_body_284 = read_u32_chained!(alt_body_283);
                let alt_body_285 = read_u32_chained!(alt_body_284);
                let alt_body_286 = read_u32_chained!(alt_body_285);
                let alt_body_287 = read_u32_chained!(alt_body_286);
                let alt_body_288 = read_u32_chained!(alt_body_287);
                let alt_body_289 = read_u32_chained!(alt_body_288);
                let alt_body_290 = read_u32_chained!(alt_body_289);
                let alt_body_291 = read_u32_chained!(alt_body_290);
                let alt_body_292 = read_u32_chained!(alt_body_291);
                let alt_body_293 = read_u32_chained!(alt_body_292);
                let alt_body_294 = read_u32_chained!(alt_body_293);
                let alt_body_295 = read_u32_chained!(alt_body_294);
                let alt_body_296 = read_u32_chained!(alt_body_295);
                let alt_body_297 = read_u32_chained!(alt_body_296);
                let alt_body_298 = read_u32_chained!(alt_body_297);
                let alt_body_299 = read_u32_chained!(alt_body_298);
                let alt_body_300 = read_u32_chained!(alt_body_299);
                let alt_body_301 = read_u32_chained!(alt_body_300);
                let alt_body_302 = read_u32_chained!(alt_body_301);
                let alt_body_303 = read_u32_chained!(alt_body_302);
                let alt_body_304 = read_u32_chained!(alt_body_303);
                let alt_body_305 = read_u32_chained!(alt_body_304);
                let alt_body_306 = read_u32_chained!(alt_body_305);
                let alt_body_307 = read_u32_chained!(alt_body_306);
                let alt_body_308 = read_u32_chained!(alt_body_307);
                let alt_body_309 = read_u32_chained!(alt_body_308);
                let alt_body_310 = read_u32_chained!(alt_body_309);
                let alt_body_311 = read_u32_chained!(alt_body_310);
                let alt_body_312 = read_u32_chained!(alt_body_311);
                let alt_body_313 = read_u32_chained!(alt_body_312);
                let alt_body_314 = read_u32_chained!(alt_body_313);
                let alt_body_315 = read_u32_chained!(alt_body_314);
                let alt_body_316 = read_u32_chained!(alt_body_315);
                let alt_body_317 = read_u32_chained!(alt_body_316);
                let alt_body_318 = read_u32_chained!(alt_body_317);
                let alt_body_319 = read_u32_chained!(alt_body_318);
                let alt_body_320 = read_u32_chained!(alt_body_319);
                let alt_body_321 = read_u32_chained!(alt_body_320);
                let alt_body_322 = read_u32_chained!(alt_body_321);
                let alt_body_323 = read_u32_chained!(alt_body_322);
                let alt_body_324 = read_u32_chained!(alt_body_323);
                let alt_body_325 = read_u32_chained!(alt_body_324);
                let alt_body_326 = read_u32_chained!(alt_body_325);
                let alt_body_327 = read_u32_chained!(alt_body_326);
                let alt_body_328 = read_u32_chained!(alt_body_327);
                let alt_body_329 = read_u32_chained!(alt_body_328);
                let alt_body_330 = read_u32_chained!(alt_body_329);
                let alt_body_331 = read_u32_chained!(alt_body_330);
                let alt_body_332 = read_u32_chained!(alt_body_331);
                let alt_body_333 = read_u32_chained!(alt_body_332);
                let alt_body_334 = read_u32_chained!(alt_body_333);
                let alt_body_335 = read_u32_chained!(alt_body_334);
                let alt_body_336 = read_u32_chained!(alt_body_335);
                let alt_body_337 = read_u32_chained!(alt_body_336);
                let alt_body_338 = read_u32_chained!(alt_body_337);
                let alt_body_339 = read_u32_chained!(alt_body_338);
                let alt_body_340 = read_u32_chained!(alt_body_339);
                let alt_body_341 = read_u32_chained!(alt_body_340);
                let alt_body_342 = read_u32_chained!(alt_body_341);
                let alt_body_343 = read_u32_chained!(alt_body_342);
                let alt_body_344 = read_u32_chained!(alt_body_343);
                let alt_body_345 = read_u32_chained!(alt_body_344);
                let alt_body_346 = read_u32_chained!(alt_body_345);
                let alt_body_347 = read_u32_chained!(alt_body_346);
                let alt_body_348 = read_u32_chained!(alt_body_347);
                let alt_body_349 = read_u32_chained!(alt_body_348);
                let alt_body_350 = read_u32_chained!(alt_body_349);
                let alt_body_351 = read_u32_chained!(alt_body_350);
                let alt_body_352 = read_u32_chained!(alt_body_351);
                let alt_body_353 = read_u32_chained!(alt_body_352);
                let alt_body_354 = read_u32_chained!(alt_body_353);
                let alt_body_355 = read_u32_chained!(alt_body_354);
                let alt_body_356 = read_u32_chained!(alt_body_355);
                let alt_body_357 = read_u32_chained!(alt_body_356);
                let alt_body_358 = read_u32_chained!(alt_body_357);
                let alt_body_359 = read_u32_chained!(alt_body_358);
                let alt_body_360 = read_u32_chained!(alt_body_359);
                let alt_body_361 = read_u32_chained!(alt_body_360);
                let alt_body_362 = read_u32_chained!(alt_body_361);
                let alt_body_363 = read_u32_chained!(alt_body_362);
                let alt_body_364 = read_u32_chained!(alt_body_363);
                let alt_body_365 = read_u32_chained!(alt_body_364);
                let alt_body_366 = read_u32_chained!(alt_body_365);
                let alt_body_367 = read_u32_chained!(alt_body_366);
                let alt_body_368 = read_u32_chained!(alt_body_367);
                let alt_body_369 = read_u32_chained!(alt_body_368);
                let alt_body_370 = read_u32_chained!(alt_body_369);
                let alt_body_371 = read_u32_chained!(alt_body_370);
                let alt_body_372 = read_u32_chained!(alt_body_371);
                let alt_body_373 = read_u32_chained!(alt_body_372);
                let alt_body_374 = read_u32_chained!(alt_body_373);
                let alt_body_375 = read_u32_chained!(alt_body_374);
                let alt_body_376 = read_u32_chained!(alt_body_375);
                let alt_body_377 = read_u32_chained!(alt_body_376);
                let alt_body_378 = read_u32_chained!(alt_body_377);
                let alt_body_379 = read_u32_chained!(alt_body_378);
                let alt_body_380 = read_u32_chained!(alt_body_379);
                let alt_body_381 = read_u32_chained!(alt_body_380);
                let alt_body_382 = read_u32_chained!(alt_body_381);
                let alt_body_383 = read_u32_chained!(alt_body_382);
                let alt_body_384 = read_u32_chained!(alt_body_383);
                let alt_body_385 = read_u32_chained!(alt_body_384);
                let alt_body_386 = read_u32_chained!(alt_body_385);
                let alt_body_387 = read_u32_chained!(alt_body_386);
                let alt_body_388 = read_u32_chained!(alt_body_387);
                let alt_body_389 = read_u32_chained!(alt_body_388);
                let alt_body_390 = read_u32_chained!(alt_body_389);
                let alt_body_391 = read_u32_chained!(alt_body_390);
                let alt_body_392 = read_u32_chained!(alt_body_391);
                let alt_body_393 = read_u32_chained!(alt_body_392);
                let alt_body_394 = read_u32_chained!(alt_body_393);
                let alt_body_395 = read_u32_chained!(alt_body_394);
                let alt_body_396 = read_u32_chained!(alt_body_395);
                let alt_body_397 = read_u32_chained!(alt_body_396);
                let alt_body_398 = read_u32_chained!(alt_body_397);
                let alt_body_399 = read_u32_chained!(alt_body_398);
                let alt_body_400 = read_u32_chained!(alt_body_399);
                let alt_body_401 = read_u32_chained!(alt_body_400);
                let alt_body_402 = read_u32_chained!(alt_body_401);
                let alt_body_403 = read_u32_chained!(alt_body_402);
                let alt_body_404 = read_u32_chained!(alt_body_403);
                let alt_body_405 = read_u32_chained!(alt_body_404);
                let alt_body_406 = read_u32_chained!(alt_body_405);
                let alt_body_407 = read_u32_chained!(alt_body_406);
                let alt_body_408 = read_u32_chained!(alt_body_407);
                let alt_body_409 = read_u32_chained!(alt_body_408);
                let alt_body_410 = read_u32_chained!(alt_body_409);
                let alt_body_411 = read_u32_chained!(alt_body_410);
                let alt_body_412 = read_u32_chained!(alt_body_411);
                let alt_body_413 = read_u32_chained!(alt_body_412);
                let alt_body_414 = read_u32_chained!(alt_body_413);
                let alt_body_415 = read_u32_chained!(alt_body_414);
                let alt_body_416 = read_u32_chained!(alt_body_415);
                let alt_body_417 = read_u32_chained!(alt_body_416);
                let alt_body_418 = read_u32_chained!(alt_body_417);
                let alt_body_419 = read_u32_chained!(alt_body_418);
                let alt_body_420 = read_u32_chained!(alt_body_419);
                let alt_body_421 = read_u32_chained!(alt_body_420);
                let alt_body_422 = read_u32_chained!(alt_body_421);
                let alt_body_423 = read_u32_chained!(alt_body_422);
                let alt_body_424 = read_u32_chained!(alt_body_423);
                let alt_body_425 = read_u32_chained!(alt_body_424);
                let alt_body_426 = read_u32_chained!(alt_body_425);
                let alt_body_427 = read_u32_chained!(alt_body_426);
                let alt_body_428 = read_u32_chained!(alt_body_427);
                let alt_body_429 = read_u32_chained!(alt_body_428);
                let alt_body_430 = read_u32_chained!(alt_body_429);
                let alt_body_431 = read_u32_chained!(alt_body_430);
                let alt_body_432 = read_u32_chained!(alt_body_431);
                let alt_body_433 = read_u32_chained!(alt_body_432);
                let alt_body_434 = read_u32_chained!(alt_body_433);
                let alt_body_435 = read_u32_chained!(alt_body_434);
                let alt_body_436 = read_u32_chained!(alt_body_435);
                let alt_body_437 = read_u32_chained!(alt_body_436);
                let alt_body_438 = read_u32_chained!(alt_body_437);
                let alt_body_439 = read_u32_chained!(alt_body_438);
                let alt_body_440 = read_u32_chained!(alt_body_439);
                let alt_body_441 = read_u32_chained!(alt_body_440);
                let alt_body_442 = read_u32_chained!(alt_body_441);
                let alt_body_443 = read_u32_chained!(alt_body_442);
                let alt_body_444 = read_u32_chained!(alt_body_443);
                let alt_body_445 = read_u32_chained!(alt_body_444);
                let alt_body_446 = read_u32_chained!(alt_body_445);
                let alt_body_447 = read_u32_chained!(alt_body_446);
                let alt_body_448 = read_u32_chained!(alt_body_447);
                let alt_body_449 = read_u32_chained!(alt_body_448);
                let alt_body_450 = read_u32_chained!(alt_body_449);
                let alt_body_451 = read_u32_chained!(alt_body_450);
                let alt_body_452 = read_u32_chained!(alt_body_451);
                let alt_body_453 = read_u32_chained!(alt_body_452);
                let alt_body_454 = read_u32_chained!(alt_body_453);
                let alt_body_455 = read_u32_chained!(alt_body_454);
                let alt_body_456 = read_u32_chained!(alt_body_455);
                let alt_body_457 = read_u32_chained!(alt_body_456);
                let alt_body_458 = read_u32_chained!(alt_body_457);
                let alt_body_459 = read_u32_chained!(alt_body_458);
                let alt_body_460 = read_u32_chained!(alt_body_459);
                let alt_body_461 = read_u32_chained!(alt_body_460);
                let alt_body_462 = read_u32_chained!(alt_body_461);
                let alt_body_463 = read_u32_chained!(alt_body_462);
                let alt_body_464 = read_u32_chained!(alt_body_463);
                let alt_body_465 = read_u32_chained!(alt_body_464);
                let alt_body_466 = read_u32_chained!(alt_body_465);
                let alt_body_467 = read_u32_chained!(alt_body_466);
                let alt_body_468 = read_u32_chained!(alt_body_467);
                let alt_body_469 = read_u32_chained!(alt_body_468);
                let alt_body_470 = read_u32_chained!(alt_body_469);
                let alt_body_471 = read_u32_chained!(alt_body_470);
                let alt_body_472 = read_u32_chained!(alt_body_471);
                let alt_body_473 = read_u32_chained!(alt_body_472);
                let alt_body_474 = read_u32_chained!(alt_body_473);
                let alt_body_475 = read_u32_chained!(alt_body_474);
                let alt_body_476 = read_u32_chained!(alt_body_475);
                let alt_body_477 = read_u32_chained!(alt_body_476);
                let alt_body_478 = read_u32_chained!(alt_body_477);
                let alt_body_479 = read_u32_chained!(alt_body_478);
                let alt_body_480 = read_u32_chained!(alt_body_479);
                let alt_body_481 = read_u32_chained!(alt_body_480);
                let alt_body_482 = read_u32_chained!(alt_body_481);
                let alt_body_483 = read_u32_chained!(alt_body_482);
                let alt_body_484 = read_u32_chained!(alt_body_483);
                let alt_body_485 = read_u32_chained!(alt_body_484);
                let alt_body_486 = read_u32_chained!(alt_body_485);
                let alt_body_487 = read_u32_chained!(alt_body_486);
                let alt_body_488 = read_u32_chained!(alt_body_487);
                let alt_body_489 = read_u32_chained!(alt_body_488);
                let alt_body_490 = read_u32_chained!(alt_body_489);
                let alt_body_491 = read_u32_chained!(alt_body_490);
                let alt_body_492 = read_u32_chained!(alt_body_491);
                let alt_body_493 = read_u32_chained!(alt_body_492);
                let alt_body_494 = read_u32_chained!(alt_body_493);
                let alt_body_495 = read_u32_chained!(alt_body_494);
                let alt_body_496 = read_u32_chained!(alt_body_495);
                let alt_body_497 = read_u32_chained!(alt_body_496);
                let alt_body_498 = read_u32_chained!(alt_body_497);
                let alt_body_499 = read_u32_chained!(alt_body_498);
                let alt_body_500 = read_u32_chained!(alt_body_499);
                let alt_body_501 = read_u32_chained!(alt_body_500);
                let alt_body_502 = read_u32_chained!(alt_body_501);
                let alt_body_503 = read_u32_chained!(alt_body_502);
                let alt_body_504 = read_u32_chained!(alt_body_503);
                let alt_body_505 = read_u32_chained!(alt_body_504);
                let alt_body_506 = read_u32_chained!(alt_body_505);
                let alt_body_507 = read_u32_chained!(alt_body_506);
                let alt_body_508 = read_u32_chained!(alt_body_507);
                let alt_body_509 = read_u32_chained!(alt_body_508);
                let alt_body_510 = read_u32_chained!(alt_body_509);
                let alt_body_511 = read_u32_chained!(alt_body_510);
                let alt_body_512 = read_u32_chained!(alt_body_511);
                let alt_body_513 = read_u32_chained!(alt_body_512);
                let alt_body_514 = read_u32_chained!(alt_body_513);
                let alt_body_515 = read_u32_chained!(alt_body_514);
                let alt_body_516 = read_u32_chained!(alt_body_515);
                let alt_body_517 = read_u32_chained!(alt_body_516);
                let alt_body_518 = read_u32_chained!(alt_body_517);
                let alt_body_519 = read_u32_chained!(alt_body_518);
                let alt_body_520 = read_u32_chained!(alt_body_519);
                let alt_body_521 = read_u32_chained!(alt_body_520);
                let alt_body_522 = read_u32_chained!(alt_body_521);
                let alt_body_523 = read_u32_chained!(alt_body_522);
                let alt_body_524 = read_u32_chained!(alt_body_523);
                let alt_body_525 = read_u32_chained!(alt_body_524);
                let alt_body_526 = read_u32_chained!(alt_body_525);
                let alt_body_527 = read_u32_chained!(alt_body_526);
                let alt_body_528 = read_u32_chained!(alt_body_527);
                let alt_body_529 = read_u32_chained!(alt_body_528);
                let alt_body_530 = read_u32_chained!(alt_body_529);
                let alt_body_531 = read_u32_chained!(alt_body_530);
                let alt_body_532 = read_u32_chained!(alt_body_531);
                let alt_body_533 = read_u32_chained!(alt_body_532);
                let alt_body_534 = read_u32_chained!(alt_body_533);
                let alt_body_535 = read_u32_chained!(alt_body_534);
                let alt_body_536 = read_u32_chained!(alt_body_535);
                let alt_body_537 = read_u32_chained!(alt_body_536);
                let alt_body_538 = read_u32_chained!(alt_body_537);
                let alt_body_539 = read_u32_chained!(alt_body_538);
                let alt_body_540 = read_u32_chained!(alt_body_539);
                let alt_body_541 = read_u32_chained!(alt_body_540);
                let alt_body_542 = read_u32_chained!(alt_body_541);
                let alt_body_543 = read_u32_chained!(alt_body_542);
                let alt_body_544 = read_u32_chained!(alt_body_543);
                let alt_body_545 = read_u32_chained!(alt_body_544);
                let alt_body_546 = read_u32_chained!(alt_body_545);
                let alt_body_547 = read_u32_chained!(alt_body_546);
                let alt_body_548 = read_u32_chained!(alt_body_547);
                let alt_body_549 = read_u32_chained!(alt_body_548);
                let alt_body_550 = read_u32_chained!(alt_body_549);
                let alt_body_551 = read_u32_chained!(alt_body_550);
                let alt_body_552 = read_u32_chained!(alt_body_551);
                let alt_body_553 = read_u32_chained!(alt_body_552);
                let alt_body_554 = read_u32_chained!(alt_body_553);
                let alt_body_555 = read_u32_chained!(alt_body_554);
                let alt_body_556 = read_u32_chained!(alt_body_555);
                let alt_body_557 = read_u32_chained!(alt_body_556);
                let alt_body_558 = read_u32_chained!(alt_body_557);
                let alt_body_559 = read_u32_chained!(alt_body_558);
                let alt_body_560 = read_u32_chained!(alt_body_559);
                let alt_body_561 = read_u32_chained!(alt_body_560);
                let alt_body_562 = read_u32_chained!(alt_body_561);
                let alt_body_563 = read_u32_chained!(alt_body_562);
                let alt_body_564 = read_u32_chained!(alt_body_563);
                let alt_body_565 = read_u32_chained!(alt_body_564);
                let alt_body_566 = read_u32_chained!(alt_body_565);
                let alt_body_567 = read_u32_chained!(alt_body_566);
                let alt_body_568 = read_u32_chained!(alt_body_567);
                let alt_body_569 = read_u32_chained!(alt_body_568);
                let alt_body_570 = read_u32_chained!(alt_body_569);
                let alt_body_571 = read_u32_chained!(alt_body_570);
                let alt_body_572 = read_u32_chained!(alt_body_571);
                let alt_body_573 = read_u32_chained!(alt_body_572);
                let alt_body_574 = read_u32_chained!(alt_body_573);
                let alt_body_575 = read_u32_chained!(alt_body_574);
                let alt_body_576 = read_u32_chained!(alt_body_575);
                let alt_body_577 = read_u32_chained!(alt_body_576);
                let alt_body_578 = read_u32_chained!(alt_body_577);
                let alt_body_579 = read_u32_chained!(alt_body_578);
                let alt_body_580 = read_u32_chained!(alt_body_579);
                let alt_body_581 = read_u32_chained!(alt_body_580);
                let alt_body_582 = read_u32_chained!(alt_body_581);
                let alt_body_583 = read_u32_chained!(alt_body_582);
                let alt_body_584 = read_u32_chained!(alt_body_583);
                let alt_body_585 = read_u32_chained!(alt_body_584);
                let alt_body_586 = read_u32_chained!(alt_body_585);
                let alt_body_587 = read_u32_chained!(alt_body_586);
                let alt_body_588 = read_u32_chained!(alt_body_587);
                let alt_body_589 = read_u32_chained!(alt_body_588);
                let alt_body_590 = read_u32_chained!(alt_body_589);
                let alt_body_591 = read_u32_chained!(alt_body_590);
                let alt_body_592 = read_u32_chained!(alt_body_591);
                let alt_body_593 = read_u32_chained!(alt_body_592);
                let alt_body_594 = read_u32_chained!(alt_body_593);
                let alt_body_595 = read_u32_chained!(alt_body_594);
                let alt_body_596 = read_u32_chained!(alt_body_595);
                let alt_body_597 = read_u32_chained!(alt_body_596);
                let alt_body_598 = read_u32_chained!(alt_body_597);
                let alt_body_599 = read_u32_chained!(alt_body_598);
                let alt_body_600 = read_u32_chained!(alt_body_599);
                let alt_body_601 = read_u32_chained!(alt_body_600);
                let alt_body_602 = read_u32_chained!(alt_body_601);
                let alt_body_603 = read_u32_chained!(alt_body_602);
                let alt_body_604 = read_u32_chained!(alt_body_603);
                let alt_body_605 = read_u32_chained!(alt_body_604);
                let alt_body_606 = read_u32_chained!(alt_body_605);
                let alt_body_607 = read_u32_chained!(alt_body_606);
                let alt_body_608 = read_u32_chained!(alt_body_607);
                let alt_body_609 = read_u32_chained!(alt_body_608);
                let alt_body_610 = read_u32_chained!(alt_body_609);
                let alt_body_611 = read_u32_chained!(alt_body_610);
                let alt_body_612 = read_u32_chained!(alt_body_611);
                let alt_body_613 = read_u32_chained!(alt_body_612);
                let alt_body_614 = read_u32_chained!(alt_body_613);
                let alt_body_615 = read_u32_chained!(alt_body_614);
                let alt_body_616 = read_u32_chained!(alt_body_615);
                let alt_body_617 = read_u32_chained!(alt_body_616);
                let alt_body_618 = read_u32_chained!(alt_body_617);
                let alt_body_619 = read_u32_chained!(alt_body_618);
                let alt_body_620 = read_u32_chained!(alt_body_619);
                let alt_body_621 = read_u32_chained!(alt_body_620);
                let alt_body_622 = read_u32_chained!(alt_body_621);
                let alt_body_623 = read_u32_chained!(alt_body_622);
                let alt_body_624 = read_u32_chained!(alt_body_623);
                let alt_body_625 = read_u32_chained!(alt_body_624);
                let alt_body_626 = read_u32_chained!(alt_body_625);
                let alt_body_627 = read_u32_chained!(alt_body_626);
                let alt_body_628 = read_u32_chained!(alt_body_627);
                let alt_body_629 = read_u32_chained!(alt_body_628);
                let alt_body_630 = read_u32_chained!(alt_body_629);
                let alt_body_631 = read_u32_chained!(alt_body_630);
                let alt_body_632 = read_u32_chained!(alt_body_631);
                let alt_body_633 = read_u32_chained!(alt_body_632);
                let alt_body_634 = read_u32_chained!(alt_body_633);
                let alt_body_635 = read_u32_chained!(alt_body_634);
                let alt_body_636 = read_u32_chained!(alt_body_635);
                let alt_body_637 = read_u32_chained!(alt_body_636);
                let alt_body_638 = read_u32_chained!(alt_body_637);
                let alt_body_639 = read_u32_chained!(alt_body_638);
                let alt_body_640 = read_u32_chained!(alt_body_639);
                let alt_body_641 = read_u32_chained!(alt_body_640);
                let alt_body_642 = read_u32_chained!(alt_body_641);
                let alt_body_643 = read_u32_chained!(alt_body_642);
                let alt_body_644 = read_u32_chained!(alt_body_643);
                let alt_body_645 = read_u32_chained!(alt_body_644);
                let alt_body_646 = read_u32_chained!(alt_body_645);
                let alt_body_647 = read_u32_chained!(alt_body_646);
                let alt_body_648 = read_u32_chained!(alt_body_647);
                let alt_body_649 = read_u32_chained!(alt_body_648);
                let alt_body_650 = read_u32_chained!(alt_body_649);
                let alt_body_651 = read_u32_chained!(alt_body_650);
                let alt_body_652 = read_u32_chained!(alt_body_651);
                let alt_body_653 = read_u32_chained!(alt_body_652);
                let alt_body_654 = read_u32_chained!(alt_body_653);
                let alt_body_655 = read_u32_chained!(alt_body_654);
                let alt_body_656 = read_u32_chained!(alt_body_655);
                let alt_body_657 = read_u32_chained!(alt_body_656);
                let alt_body_658 = read_u32_chained!(alt_body_657);
                let alt_body_659 = read_u32_chained!(alt_body_658);
                let alt_body_660 = read_u32_chained!(alt_body_659);
                let alt_body_661 = read_u32_chained!(alt_body_660);
                let alt_body_662 = read_u32_chained!(alt_body_661);
                let alt_body_663 = read_u32_chained!(alt_body_662);
                let alt_body_664 = read_u32_chained!(alt_body_663);
                let alt_body_665 = read_u32_chained!(alt_body_664);
                let alt_body_666 = read_u32_chained!(alt_body_665);
                let alt_body_667 = read_u32_chained!(alt_body_666);
                let alt_body_668 = read_u32_chained!(alt_body_667);
                let alt_body_669 = read_u32_chained!(alt_body_668);
                let alt_body_670 = read_u32_chained!(alt_body_669);
                let alt_body_671 = read_u32_chained!(alt_body_670);
                let alt_body_672 = read_u32_chained!(alt_body_671);
                let alt_body_673 = read_u32_chained!(alt_body_672);
                let alt_body_674 = read_u32_chained!(alt_body_673);
                let alt_body_675 = read_u32_chained!(alt_body_674);
                let alt_body_676 = read_u32_chained!(alt_body_675);
                let alt_body_677 = read_u32_chained!(alt_body_676);
                let alt_body_678 = read_u32_chained!(alt_body_677);
                let alt_body_679 = read_u32_chained!(alt_body_678);
                let alt_body_680 = read_u32_chained!(alt_body_679);
                let alt_body_681 = read_u32_chained!(alt_body_680);
                let alt_body_682 = read_u32_chained!(alt_body_681);
                let alt_body_683 = read_u32_chained!(alt_body_682);
                let alt_body_684 = read_u32_chained!(alt_body_683);
                let alt_body_685 = read_u32_chained!(alt_body_684);
                let alt_body_686 = read_u32_chained!(alt_body_685);
                let alt_body_687 = read_u32_chained!(alt_body_686);
                let alt_body_688 = read_u32_chained!(alt_body_687);
                let alt_body_689 = read_u32_chained!(alt_body_688);
                let alt_body_690 = read_u32_chained!(alt_body_689);
                let alt_body_691 = read_u32_chained!(alt_body_690);
                let alt_body_692 = read_u32_chained!(alt_body_691);
                let alt_body_693 = read_u32_chained!(alt_body_692);
                let alt_body_694 = read_u32_chained!(alt_body_693);
                let alt_body_695 = read_u32_chained!(alt_body_694);
                let alt_body_696 = read_u32_chained!(alt_body_695);
                let alt_body_697 = read_u32_chained!(alt_body_696);
                let alt_body_698 = read_u32_chained!(alt_body_697);
                let alt_body_699 = read_u32_chained!(alt_body_698);
                let alt_body_700 = read_u32_chained!(alt_body_699);
                let alt_body_701 = read_u32_chained!(alt_body_700);
                let alt_body_702 = read_u32_chained!(alt_body_701);
                let alt_body_703 = read_u32_chained!(alt_body_702);
                let alt_body_704 = read_u32_chained!(alt_body_703);
                let alt_body_705 = read_u32_chained!(alt_body_704);
                let alt_body_706 = read_u32_chained!(alt_body_705);
                let alt_body_707 = read_u32_chained!(alt_body_706);
                let alt_body_708 = read_u32_chained!(alt_body_707);
                let alt_body_709 = read_u32_chained!(alt_body_708);
                let alt_body_710 = read_u32_chained!(alt_body_709);
                let alt_body_711 = read_u32_chained!(alt_body_710);
                let alt_body_712 = read_u32_chained!(alt_body_711);
                let alt_body_713 = read_u32_chained!(alt_body_712);
                let alt_body_714 = read_u32_chained!(alt_body_713);
                let alt_body_715 = read_u32_chained!(alt_body_714);
                let alt_body_716 = read_u32_chained!(alt_body_715);
                let alt_body_717 = read_u32_chained!(alt_body_716);
                let alt_body_718 = read_u32_chained!(alt_body_717);
                let alt_body_719 = read_u32_chained!(alt_body_718);
                let alt_body_720 = read_u32_chained!(alt_body_719);
                let alt_body_721 = read_u32_chained!(alt_body_720);
                let alt_body_722 = read_u32_chained!(alt_body_721);
                let alt_body_723 = read_u32_chained!(alt_body_722);
                let alt_body_724 = read_u32_chained!(alt_body_723);
                let alt_body_725 = read_u32_chained!(alt_body_724);
                let alt_body_726 = read_u32_chained!(alt_body_725);
                let alt_body_727 = read_u32_chained!(alt_body_726);
                let alt_body_728 = read_u32_chained!(alt_body_727);
                let alt_body_729 = read_u32_chained!(alt_body_728);
                let alt_body_730 = read_u32_chained!(alt_body_729);
                let alt_body_731 = read_u32_chained!(alt_body_730);
                let alt_body_732 = read_u32_chained!(alt_body_731);
                let alt_body_733 = read_u32_chained!(alt_body_732);
                let alt_body_734 = read_u32_chained!(alt_body_733);
                let alt_body_735 = read_u32_chained!(alt_body_734);
                let alt_body_736 = read_u32_chained!(alt_body_735);
                let alt_body_737 = read_u32_chained!(alt_body_736);
                let alt_body_738 = read_u32_chained!(alt_body_737);
                let alt_body_739 = read_u32_chained!(alt_body_738);
                let alt_body_740 = read_u32_chained!(alt_body_739);
                let alt_body_741 = read_u32_chained!(alt_body_740);
                let alt_body_742 = read_u32_chained!(alt_body_741);
                let alt_body_743 = read_u32_chained!(alt_body_742);
                let alt_body_744 = read_u32_chained!(alt_body_743);
                let alt_body_745 = read_u32_chained!(alt_body_744);
                let alt_body_746 = read_u32_chained!(alt_body_745);
                let alt_body_747 = read_u32_chained!(alt_body_746);
                let alt_body_748 = read_u32_chained!(alt_body_747);
                let alt_body_749 = read_u32_chained!(alt_body_748);
                let alt_body_750 = read_u32_chained!(alt_body_749);
                let alt_body_751 = read_u32_chained!(alt_body_750);
                let alt_body_752 = read_u32_chained!(alt_body_751);
                let alt_body_753 = read_u32_chained!(alt_body_752);
                let alt_body_754 = read_u32_chained!(alt_body_753);
                let alt_body_755 = read_u32_chained!(alt_body_754);
                let alt_body_756 = read_u32_chained!(alt_body_755);
                let alt_body_757 = read_u32_chained!(alt_body_756);
                let alt_body_758 = read_u32_chained!(alt_body_757);
                let alt_body_759 = read_u32_chained!(alt_body_758);
                let alt_body_760 = read_u32_chained!(alt_body_759);
                let alt_body_761 = read_u32_chained!(alt_body_760);
                let alt_body_762 = read_u32_chained!(alt_body_761);
                let alt_body_763 = read_u32_chained!(alt_body_762);
                let alt_body_764 = read_u32_chained!(alt_body_763);
                let alt_body_765 = read_u32_chained!(alt_body_764);
                let alt_body_766 = read_u32_chained!(alt_body_765);
                let alt_body_767 = read_u32_chained!(alt_body_766);
                let alt_body_768 = read_u32_chained!(alt_body_767);
                let alt_body_769 = read_u32_chained!(alt_body_768);
                let alt_body_770 = read_u32_chained!(alt_body_769);
                let alt_body_771 = read_u32_chained!(alt_body_770);
                let alt_body_772 = read_u32_chained!(alt_body_771);
                let alt_body_773 = read_u32_chained!(alt_body_772);
                let alt_body_774 = read_u32_chained!(alt_body_773);
                let alt_body_775 = read_u32_chained!(alt_body_774);
                let alt_body_776 = read_u32_chained!(alt_body_775);
                let alt_body_777 = read_u32_chained!(alt_body_776);
                let alt_body_778 = read_u32_chained!(alt_body_777);
                let alt_body_779 = read_u32_chained!(alt_body_778);
                let alt_body_780 = read_u32_chained!(alt_body_779);
                let alt_body_781 = read_u32_chained!(alt_body_780);
                let alt_body_782 = read_u32_chained!(alt_body_781);
                let alt_body_783 = read_u32_chained!(alt_body_782);
                let alt_body_784 = read_u32_chained!(alt_body_783);
                let alt_body_785 = read_u32_chained!(alt_body_784);
                let alt_body_786 = read_u32_chained!(alt_body_785);
                let alt_body_787 = read_u32_chained!(alt_body_786);
                let alt_body_788 = read_u32_chained!(alt_body_787);
                let alt_body_789 = read_u32_chained!(alt_body_788);
                let alt_body_790 = read_u32_chained!(alt_body_789);
                let alt_body_791 = read_u32_chained!(alt_body_790);
                let alt_body_792 = read_u32_chained!(alt_body_791);
                let alt_body_793 = read_u32_chained!(alt_body_792);
                let alt_body_794 = read_u32_chained!(alt_body_793);
                let alt_body_795 = read_u32_chained!(alt_body_794);
                let alt_body_796 = read_u32_chained!(alt_body_795);
                let alt_body_797 = read_u32_chained!(alt_body_796);
                let alt_body_798 = read_u32_chained!(alt_body_797);
                let alt_body_799 = read_u32_chained!(alt_body_798);
                let alt_body_800 = read_u32_chained!(alt_body_799);
                let alt_body_801 = read_u32_chained!(alt_body_800);
                let alt_body_802 = read_u32_chained!(alt_body_801);
                let alt_body_803 = read_u32_chained!(alt_body_802);
                let alt_body_804 = read_u32_chained!(alt_body_803);
                let alt_body_805 = read_u32_chained!(alt_body_804);
                let alt_body_806 = read_u32_chained!(alt_body_805);
                let alt_body_807 = read_u32_chained!(alt_body_806);
                let alt_body_808 = read_u32_chained!(alt_body_807);
                let alt_body_809 = read_u32_chained!(alt_body_808);
                let alt_body_810 = read_u32_chained!(alt_body_809);
                let alt_body_811 = read_u32_chained!(alt_body_810);
                let alt_body_812 = read_u32_chained!(alt_body_811);
                let alt_body_813 = read_u32_chained!(alt_body_812);
                let alt_body_814 = read_u32_chained!(alt_body_813);
                let alt_body_815 = read_u32_chained!(alt_body_814);
                let alt_body_816 = read_u32_chained!(alt_body_815);
                let alt_body_817 = read_u32_chained!(alt_body_816);
                let alt_body_818 = read_u32_chained!(alt_body_817);
                let alt_body_819 = read_u32_chained!(alt_body_818);
                let alt_body_820 = read_u32_chained!(alt_body_819);
                let alt_body_821 = read_u32_chained!(alt_body_820);
                let alt_body_822 = read_u32_chained!(alt_body_821);
                let alt_body_823 = read_u32_chained!(alt_body_822);
                let alt_body_824 = read_u32_chained!(alt_body_823);
                let alt_body_825 = read_u32_chained!(alt_body_824);
                let alt_body_826 = read_u32_chained!(alt_body_825);
                let alt_body_827 = read_u32_chained!(alt_body_826);
                let alt_body_828 = read_u32_chained!(alt_body_827);
                let alt_body_829 = read_u32_chained!(alt_body_828);
                let alt_body_830 = read_u32_chained!(alt_body_829);
                let alt_body_831 = read_u32_chained!(alt_body_830);
                let alt_body_832 = read_u32_chained!(alt_body_831);
                let alt_body_833 = read_u32_chained!(alt_body_832);
                let alt_body_834 = read_u32_chained!(alt_body_833);
                let alt_body_835 = read_u32_chained!(alt_body_834);
                let alt_body_836 = read_u32_chained!(alt_body_835);
                let alt_body_837 = read_u32_chained!(alt_body_836);
                let alt_body_838 = read_u32_chained!(alt_body_837);
                let alt_body_839 = read_u32_chained!(alt_body_838);
                let alt_body_840 = read_u32_chained!(alt_body_839);
                let alt_body_841 = read_u32_chained!(alt_body_840);
                let alt_body_842 = read_u32_chained!(alt_body_841);
                let alt_body_843 = read_u32_chained!(alt_body_842);
                let alt_body_844 = read_u32_chained!(alt_body_843);
                let alt_body_845 = read_u32_chained!(alt_body_844);
                let alt_body_846 = read_u32_chained!(alt_body_845);
                let alt_body_847 = read_u32_chained!(alt_body_846);
                let alt_body_848 = read_u32_chained!(alt_body_847);
                let alt_body_849 = read_u32_chained!(alt_body_848);
                let alt_body_850 = read_u32_chained!(alt_body_849);
                let alt_body_851 = read_u32_chained!(alt_body_850);
                let alt_body_852 = read_u32_chained!(alt_body_851);
                let alt_body_853 = read_u32_chained!(alt_body_852);
                let alt_body_854 = read_u32_chained!(alt_body_853);
                let alt_body_855 = read_u32_chained!(alt_body_854);
                let alt_body_856 = read_u32_chained!(alt_body_855);
                let alt_body_857 = read_u32_chained!(alt_body_856);
                let alt_body_858 = read_u32_chained!(alt_body_857);
                let alt_body_859 = read_u32_chained!(alt_body_858);
                let alt_body_860 = read_u32_chained!(alt_body_859);
                let alt_body_861 = read_u32_chained!(alt_body_860);
                let alt_body_862 = read_u32_chained!(alt_body_861);
                let alt_body_863 = read_u32_chained!(alt_body_862);
                let alt_body_864 = read_u32_chained!(alt_body_863);
                let alt_body_865 = read_u32_chained!(alt_body_864);
                let alt_body_866 = read_u32_chained!(alt_body_865);
                let alt_body_867 = read_u32_chained!(alt_body_866);
                let alt_body_868 = read_u32_chained!(alt_body_867);
                let alt_body_869 = read_u32_chained!(alt_body_868);
                let alt_body_870 = read_u32_chained!(alt_body_869);
                let alt_body_871 = read_u32_chained!(alt_body_870);
                let alt_body_872 = read_u32_chained!(alt_body_871);
                let alt_body_873 = read_u32_chained!(alt_body_872);
                let alt_body_874 = read_u32_chained!(alt_body_873);
                let alt_body_875 = read_u32_chained!(alt_body_874);
                let alt_body_876 = read_u32_chained!(alt_body_875);
                let alt_body_877 = read_u32_chained!(alt_body_876);
                let alt_body_878 = read_u32_chained!(alt_body_877);
                let alt_body_879 = read_u32_chained!(alt_body_878);
                let alt_body_880 = read_u32_chained!(alt_body_879);
                let alt_body_881 = read_u32_chained!(alt_body_880);
                let alt_body_882 = read_u32_chained!(alt_body_881);
                let alt_body_883 = read_u32_chained!(alt_body_882);
                let alt_body_884 = read_u32_chained!(alt_body_883);
                let alt_body_885 = read_u32_chained!(alt_body_884);
                let alt_body_886 = read_u32_chained!(alt_body_885);
                let alt_body_887 = read_u32_chained!(alt_body_886);
                let alt_body_888 = read_u32_chained!(alt_body_887);
                let alt_body_889 = read_u32_chained!(alt_body_888);
                let alt_body_890 = read_u32_chained!(alt_body_889);
                let alt_body_891 = read_u32_chained!(alt_body_890);
                let alt_body_892 = read_u32_chained!(alt_body_891);
                let alt_body_893 = read_u32_chained!(alt_body_892);
                let alt_body_894 = read_u32_chained!(alt_body_893);
                let alt_body_895 = read_u32_chained!(alt_body_894);
                let alt_body_896 = read_u32_chained!(alt_body_895);
                let alt_body_897 = read_u32_chained!(alt_body_896);
                let alt_body_898 = read_u32_chained!(alt_body_897);
                let alt_body_899 = read_u32_chained!(alt_body_898);
                let alt_body_900 = read_u32_chained!(alt_body_899);
                let alt_body_901 = read_u32_chained!(alt_body_900);
                let alt_body_902 = read_u32_chained!(alt_body_901);
                let alt_body_903 = read_u32_chained!(alt_body_902);
                let alt_body_904 = read_u32_chained!(alt_body_903);
                let alt_body_905 = read_u32_chained!(alt_body_904);
                let alt_body_906 = read_u32_chained!(alt_body_905);
                let alt_body_907 = read_u32_chained!(alt_body_906);
                let alt_body_908 = read_u32_chained!(alt_body_907);
                let alt_body_909 = read_u32_chained!(alt_body_908);
                let alt_body_910 = read_u32_chained!(alt_body_909);
                let alt_body_911 = read_u32_chained!(alt_body_910);
                let alt_body_912 = read_u32_chained!(alt_body_911);
                let alt_body_913 = read_u32_chained!(alt_body_912);
                let alt_body_914 = read_u32_chained!(alt_body_913);
                let alt_body_915 = read_u32_chained!(alt_body_914);
                let alt_body_916 = read_u32_chained!(alt_body_915);
                let alt_body_917 = read_u32_chained!(alt_body_916);
                let alt_body_918 = read_u32_chained!(alt_body_917);
                let alt_body_919 = read_u32_chained!(alt_body_918);
                let alt_body_920 = read_u32_chained!(alt_body_919);
                let alt_body_921 = read_u32_chained!(alt_body_920);
                let alt_body_922 = read_u32_chained!(alt_body_921);
                let alt_body_923 = read_u32_chained!(alt_body_922);
                let alt_body_924 = read_u32_chained!(alt_body_923);
                let alt_body_925 = read_u32_chained!(alt_body_924);
                let alt_body_926 = read_u32_chained!(alt_body_925);
                let alt_body_927 = read_u32_chained!(alt_body_926);
                let alt_body_928 = read_u32_chained!(alt_body_927);
                let alt_body_929 = read_u32_chained!(alt_body_928);
                let alt_body_930 = read_u32_chained!(alt_body_929);
                let alt_body_931 = read_u32_chained!(alt_body_930);
                let alt_body_932 = read_u32_chained!(alt_body_931);
                let alt_body_933 = read_u32_chained!(alt_body_932);
                let alt_body_934 = read_u32_chained!(alt_body_933);
                let alt_body_935 = read_u32_chained!(alt_body_934);
                let alt_body_936 = read_u32_chained!(alt_body_935);
                let alt_body_937 = read_u32_chained!(alt_body_936);
                let alt_body_938 = read_u32_chained!(alt_body_937);
                let alt_body_939 = read_u32_chained!(alt_body_938);
                let alt_body_940 = read_u32_chained!(alt_body_939);
                let alt_body_941 = read_u32_chained!(alt_body_940);
                let alt_body_942 = read_u32_chained!(alt_body_941);
                let alt_body_943 = read_u32_chained!(alt_body_942);
                let alt_body_944 = read_u32_chained!(alt_body_943);
                let alt_body_945 = read_u32_chained!(alt_body_944);
                let alt_body_946 = read_u32_chained!(alt_body_945);
                let alt_body_947 = read_u32_chained!(alt_body_946);
                let alt_body_948 = read_u32_chained!(alt_body_947);
                let alt_body_949 = read_u32_chained!(alt_body_948);
                let alt_body_950 = read_u32_chained!(alt_body_949);
                let alt_body_951 = read_u32_chained!(alt_body_950);
                let alt_body_952 = read_u32_chained!(alt_body_951);
                let alt_body_953 = read_u32_chained!(alt_body_952);
                let alt_body_954 = read_u32_chained!(alt_body_953);
                let alt_body_955 = read_u32_chained!(alt_body_954);
                let alt_body_956 = read_u32_chained!(alt_body_955);
                let alt_body_957 = read_u32_chained!(alt_body_956);
                let alt_body_958 = read_u32_chained!(alt_body_957);
                let alt_body_959 = read_u32_chained!(alt_body_958);
                let alt_body_960 = read_u32_chained!(alt_body_959);
                let alt_body_961 = read_u32_chained!(alt_body_960);
                let alt_body_962 = read_u32_chained!(alt_body_961);
                let alt_body_963 = read_u32_chained!(alt_body_962);
                let alt_body_964 = read_u32_chained!(alt_body_963);
                let alt_body_965 = read_u32_chained!(alt_body_964);
                let alt_body_966 = read_u32_chained!(alt_body_965);
                let alt_body_967 = read_u32_chained!(alt_body_966);
                let alt_body_968 = read_u32_chained!(alt_body_967);
                let alt_body_969 = read_u32_chained!(alt_body_968);
                let alt_body_970 = read_u32_chained!(alt_body_969);
                let alt_body_971 = read_u32_chained!(alt_body_970);
                let alt_body_972 = read_u32_chained!(alt_body_971);
                let alt_body_973 = read_u32_chained!(alt_body_972);
                let alt_body_974 = read_u32_chained!(alt_body_973);
                let alt_body_975 = read_u32_chained!(alt_body_974);
                let alt_body_976 = read_u32_chained!(alt_body_975);
                let alt_body_977 = read_u32_chained!(alt_body_976);
                let alt_body_978 = read_u32_chained!(alt_body_977);
                let alt_body_979 = read_u32_chained!(alt_body_978);
                let alt_body_980 = read_u32_chained!(alt_body_979);
                let alt_body_981 = read_u32_chained!(alt_body_980);
                let alt_body_982 = read_u32_chained!(alt_body_981);
                let alt_body_983 = read_u32_chained!(alt_body_982);
                let alt_body_984 = read_u32_chained!(alt_body_983);
                let alt_body_985 = read_u32_chained!(alt_body_984);
                let alt_body_986 = read_u32_chained!(alt_body_985);
                let alt_body_987 = read_u32_chained!(alt_body_986);
                let alt_body_988 = read_u32_chained!(alt_body_987);
                let alt_body_989 = read_u32_chained!(alt_body_988);
                let alt_body_990 = read_u32_chained!(alt_body_989);
                let alt_body_991 = read_u32_chained!(alt_body_990);
                let alt_body_992 = read_u32_chained!(alt_body_991);
                let alt_body_993 = read_u32_chained!(alt_body_992);
                let alt_body_994 = read_u32_chained!(alt_body_993);
                let alt_body_995 = read_u32_chained!(alt_body_994);
                let alt_body_996 = read_u32_chained!(alt_body_995);
                let alt_body_997 = read_u32_chained!(alt_body_996);
                let alt_body_998 = read_u32_chained!(alt_body_997);
                let alt_body_999 = read_u32_chained!(alt_body_998);
                let alt_body_1000 = read_u32_chained!(alt_body_999);
                let alt_body_1001 = read_u32_chained!(alt_body_1000);
                let alt_body_1002 = read_u32_chained!(alt_body_1001);
                let alt_body_1003 = read_u32_chained!(alt_body_1002);
                let alt_body_1004 = read_u32_chained!(alt_body_1003);
                let alt_body_1005 = read_u32_chained!(alt_body_1004);
                let alt_body_1006 = read_u32_chained!(alt_body_1005);
                let alt_body_1007 = read_u32_chained!(alt_body_1006);
                let alt_body_1008 = read_u32_chained!(alt_body_1007);
                let alt_body_1009 = read_u32_chained!(alt_body_1008);
                let alt_body_1010 = read_u32_chained!(alt_body_1009);
                let alt_body_1011 = read_u32_chained!(alt_body_1010);
                let alt_body_1012 = read_u32_chained!(alt_body_1011);
                let alt_body_1013 = read_u32_chained!(alt_body_1012);
                let alt_body_1014 = read_u32_chained!(alt_body_1013);
                let alt_body_1015 = read_u32_chained!(alt_body_1014);
                let alt_body_1016 = read_u32_chained!(alt_body_1015);
                let alt_body_1017 = read_u32_chained!(alt_body_1016);
                let alt_body_1018 = read_u32_chained!(alt_body_1017);
                let alt_body_1019 = read_u32_chained!(alt_body_1018);
                let alt_body_1020 = read_u32_chained!(alt_body_1019);
                let alt_body_1021 = read_u32_chained!(alt_body_1020);
                let alt_body_1022 = read_u32_chained!(alt_body_1021);
                let alt_body_1023 = read_u32_chained!(alt_body_1022);
                let alt_body_1024 = read_u32_chained!(alt_body_1023);
                let alt_body_1025 = read_u32_chained!(alt_body_1024);
                let alt_body_1026 = read_u32_chained!(alt_body_1025);
                let alt_body_1027 = read_u32_chained!(alt_body_1026);
                let alt_body_1028 = read_u32_chained!(alt_body_1027);
                let alt_body_1029 = read_u32_chained!(alt_body_1028);
                let alt_body_1030 = read_u32_chained!(alt_body_1029);
                let alt_body_1031 = read_u32_chained!(alt_body_1030);
                let alt_body_1032 = read_u32_chained!(alt_body_1031);
                let alt_body_1033 = read_u32_chained!(alt_body_1032);
                let alt_body_1034 = read_u32_chained!(alt_body_1033);
                let alt_body_1035 = read_u32_chained!(alt_body_1034);
                let alt_body_1036 = read_u32_chained!(alt_body_1035);
                let alt_body_1037 = read_u32_chained!(alt_body_1036);
                let alt_body_1038 = read_u32_chained!(alt_body_1037);
                let alt_body_1039 = read_u32_chained!(alt_body_1038);
                let alt_body_1040 = read_u32_chained!(alt_body_1039);
                let alt_body_1041 = read_u32_chained!(alt_body_1040);
                let alt_body_1042 = read_u32_chained!(alt_body_1041);
                let alt_body_1043 = read_u32_chained!(alt_body_1042);
                let alt_body_1044 = read_u32_chained!(alt_body_1043);
                let alt_body_1045 = read_u32_chained!(alt_body_1044);
                let alt_body_1046 = read_u32_chained!(alt_body_1045);
                let alt_body_1047 = read_u32_chained!(alt_body_1046);
                let alt_body_1048 = read_u32_chained!(alt_body_1047);
                let alt_body_1049 = read_u32_chained!(alt_body_1048);
                let alt_body_1050 = read_u32_chained!(alt_body_1049);
                let alt_body_1051 = read_u32_chained!(alt_body_1050);
                let alt_body_1052 = read_u32_chained!(alt_body_1051);
                let alt_body_1053 = read_u32_chained!(alt_body_1052);
                let alt_body_1054 = read_u32_chained!(alt_body_1053);
                let alt_body_1055 = read_u32_chained!(alt_body_1054);
                let alt_body_1056 = read_u32_chained!(alt_body_1055);
                let alt_body_1057 = read_u32_chained!(alt_body_1056);
                let alt_body_1058 = read_u32_chained!(alt_body_1057);
                let alt_body_1059 = read_u32_chained!(alt_body_1058);
                let alt_body_1060 = read_u32_chained!(alt_body_1059);
                let alt_body_1061 = read_u32_chained!(alt_body_1060);
                let alt_body_1062 = read_u32_chained!(alt_body_1061);
                let alt_body_1063 = read_u32_chained!(alt_body_1062);
                let alt_body_1064 = read_u32_chained!(alt_body_1063);
                let alt_body_1065 = read_u32_chained!(alt_body_1064);
                let alt_body_1066 = read_u32_chained!(alt_body_1065);
                let alt_body_1067 = read_u32_chained!(alt_body_1066);
                let alt_body_1068 = read_u32_chained!(alt_body_1067);
                let alt_body_1069 = read_u32_chained!(alt_body_1068);
                let alt_body_1070 = read_u32_chained!(alt_body_1069);
                let alt_body_1071 = read_u32_chained!(alt_body_1070);
                let alt_body_1072 = read_u32_chained!(alt_body_1071);
                let alt_body_1073 = read_u32_chained!(alt_body_1072);
                let alt_body_1074 = read_u32_chained!(alt_body_1073);
                let alt_body_1075 = read_u32_chained!(alt_body_1074);
                let alt_body_1076 = read_u32_chained!(alt_body_1075);
                let alt_body_1077 = read_u32_chained!(alt_body_1076);
                let alt_body_1078 = read_u32_chained!(alt_body_1077);
                let alt_body_1079 = read_u32_chained!(alt_body_1078);
                let alt_body_1080 = read_u32_chained!(alt_body_1079);
                let alt_body_1081 = read_u32_chained!(alt_body_1080);
                let alt_body_1082 = read_u32_chained!(alt_body_1081);
                let alt_body_1083 = read_u32_chained!(alt_body_1082);
                let alt_body_1084 = read_u32_chained!(alt_body_1083);
                let alt_body_1085 = read_u32_chained!(alt_body_1084);
                let alt_body_1086 = read_u32_chained!(alt_body_1085);
                let alt_body_1087 = read_u32_chained!(alt_body_1086);
                let alt_body_1088 = read_u32_chained!(alt_body_1087);
                let alt_body_1089 = read_u32_chained!(alt_body_1088);
                let alt_body_1090 = read_u32_chained!(alt_body_1089);
                let alt_body_1091 = read_u32_chained!(alt_body_1090);
                let alt_body_1092 = read_u32_chained!(alt_body_1091);
                let alt_body_1093 = read_u32_chained!(alt_body_1092);
                let alt_body_1094 = read_u32_chained!(alt_body_1093);
                let alt_body_1095 = read_u32_chained!(alt_body_1094);
                let alt_body_1096 = read_u32_chained!(alt_body_1095);
                let alt_body_1097 = read_u32_chained!(alt_body_1096);
                let alt_body_1098 = read_u32_chained!(alt_body_1097);
                let alt_body_1099 = read_u32_chained!(alt_body_1098);
                let alt_body_1100 = read_u32_chained!(alt_body_1099);
                let alt_body_1101 = read_u32_chained!(alt_body_1100);
                let alt_body_1102 = read_u32_chained!(alt_body_1101);
                let alt_body_1103 = read_u32_chained!(alt_body_1102);
                let alt_body_1104 = read_u32_chained!(alt_body_1103);
                let alt_body_1105 = read_u32_chained!(alt_body_1104);
                let alt_body_1106 = read_u32_chained!(alt_body_1105);
                let alt_body_1107 = read_u32_chained!(alt_body_1106);
                let alt_body_1108 = read_u32_chained!(alt_body_1107);
                let alt_body_1109 = read_u32_chained!(alt_body_1108);
                let alt_body_1110 = read_u32_chained!(alt_body_1109);
                let alt_body_1111 = read_u32_chained!(alt_body_1110);
                let alt_body_1112 = read_u32_chained!(alt_body_1111);
                let alt_body_1113 = read_u32_chained!(alt_body_1112);
                let alt_body_1114 = read_u32_chained!(alt_body_1113);
                let alt_body_1115 = read_u32_chained!(alt_body_1114);
                let alt_body_1116 = read_u32_chained!(alt_body_1115);
                let alt_body_1117 = read_u32_chained!(alt_body_1116);
                let alt_body_1118 = read_u32_chained!(alt_body_1117);
                let alt_body_1119 = read_u32_chained!(alt_body_1118);
                let alt_body_1120 = read_u32_chained!(alt_body_1119);
                let alt_body_1121 = read_u32_chained!(alt_body_1120);
                let alt_body_1122 = read_u32_chained!(alt_body_1121);
                let alt_body_1123 = read_u32_chained!(alt_body_1122);
                let alt_body_1124 = read_u32_chained!(alt_body_1123);
                let alt_body_1125 = read_u32_chained!(alt_body_1124);
                let alt_body_1126 = read_u32_chained!(alt_body_1125);
                let alt_body_1127 = read_u32_chained!(alt_body_1126);
                let alt_body_1128 = read_u32_chained!(alt_body_1127);
                let alt_body_1129 = read_u32_chained!(alt_body_1128);
                let alt_body_1130 = read_u32_chained!(alt_body_1129);
                let alt_body_1131 = read_u32_chained!(alt_body_1130);
                let alt_body_1132 = read_u32_chained!(alt_body_1131);
                let alt_body_1133 = read_u32_chained!(alt_body_1132);
                let alt_body_1134 = read_u32_chained!(alt_body_1133);
                let alt_body_1135 = read_u32_chained!(alt_body_1134);
                let alt_body_1136 = read_u32_chained!(alt_body_1135);
                let alt_body_1137 = read_u32_chained!(alt_body_1136);
                let alt_body_1138 = read_u32_chained!(alt_body_1137);
                let alt_body_1139 = read_u32_chained!(alt_body_1138);
                let alt_body_1140 = read_u32_chained!(alt_body_1139);
                let alt_body_1141 = read_u32_chained!(alt_body_1140);
                let alt_body_1142 = read_u32_chained!(alt_body_1141);
                let alt_body_1143 = read_u32_chained!(alt_body_1142);
                let alt_body_1144 = read_u32_chained!(alt_body_1143);
                let alt_body_1145 = read_u32_chained!(alt_body_1144);
                let alt_body_1146 = read_u32_chained!(alt_body_1145);
                let alt_body_1147 = read_u32_chained!(alt_body_1146);
                let alt_body_1148 = read_u32_chained!(alt_body_1147);
                let alt_body_1149 = read_u32_chained!(alt_body_1148);
                let alt_body_1150 = read_u32_chained!(alt_body_1149);
                let alt_body_1151 = read_u32_chained!(alt_body_1150);
                let alt_body_1152 = read_u32_chained!(alt_body_1151);
                let alt_body_1153 = read_u32_chained!(alt_body_1152);
                let alt_body_1154 = read_u32_chained!(alt_body_1153);
                let alt_body_1155 = read_u32_chained!(alt_body_1154);
                let alt_body_1156 = read_u32_chained!(alt_body_1155);
                let alt_body_1157 = read_u32_chained!(alt_body_1156);
                let alt_body_1158 = read_u32_chained!(alt_body_1157);
                let alt_body_1159 = read_u32_chained!(alt_body_1158);
                let alt_body_1160 = read_u32_chained!(alt_body_1159);
                let alt_body_1161 = read_u32_chained!(alt_body_1160);
                let alt_body_1162 = read_u32_chained!(alt_body_1161);
                let alt_body_1163 = read_u32_chained!(alt_body_1162);
                let alt_body_1164 = read_u32_chained!(alt_body_1163);
                let alt_body_1165 = read_u32_chained!(alt_body_1164);
                let alt_body_1166 = read_u32_chained!(alt_body_1165);
                let alt_body_1167 = read_u32_chained!(alt_body_1166);
                let alt_body_1168 = read_u32_chained!(alt_body_1167);
                let alt_body_1169 = read_u32_chained!(alt_body_1168);
                let alt_body_1170 = read_u32_chained!(alt_body_1169);
                let alt_body_1171 = read_u32_chained!(alt_body_1170);
                let alt_body_1172 = read_u32_chained!(alt_body_1171);
                let alt_body_1173 = read_u32_chained!(alt_body_1172);
                let alt_body_1174 = read_u32_chained!(alt_body_1173);
                let alt_body_1175 = read_u32_chained!(alt_body_1174);
                let alt_body_1176 = read_u32_chained!(alt_body_1175);
                let alt_body_1177 = read_u32_chained!(alt_body_1176);
                let alt_body_1178 = read_u32_chained!(alt_body_1177);
                let alt_body_1179 = read_u32_chained!(alt_body_1178);
                let alt_body_1180 = read_u32_chained!(alt_body_1179);
                let alt_body_1181 = read_u32_chained!(alt_body_1180);
                let alt_body_1182 = read_u32_chained!(alt_body_1181);
                let alt_body_1183 = read_u32_chained!(alt_body_1182);
                let alt_body_1184 = read_u32_chained!(alt_body_1183);
                let alt_body_1185 = read_u32_chained!(alt_body_1184);
                let alt_body_1186 = read_u32_chained!(alt_body_1185);
                let alt_body_1187 = read_u32_chained!(alt_body_1186);
                let alt_body_1188 = read_u32_chained!(alt_body_1187);
                let alt_body_1189 = read_u32_chained!(alt_body_1188);
                let alt_body_1190 = read_u32_chained!(alt_body_1189);
                let alt_body_1191 = read_u32_chained!(alt_body_1190);
                let alt_body_1192 = read_u32_chained!(alt_body_1191);
                let alt_body_1193 = read_u32_chained!(alt_body_1192);
                let alt_body_1194 = read_u32_chained!(alt_body_1193);
                let alt_body_1195 = read_u32_chained!(alt_body_1194);
                let alt_body_1196 = read_u32_chained!(alt_body_1195);
                let alt_body_1197 = read_u32_chained!(alt_body_1196);
                let alt_body_1198 = read_u32_chained!(alt_body_1197);
                let alt_body_1199 = read_u32_chained!(alt_body_1198);
                let alt_body_1200 = read_u32_chained!(alt_body_1199);
                let alt_body_1201 = read_u32_chained!(alt_body_1200);
                let alt_body_1202 = read_u32_chained!(alt_body_1201);
                let alt_body_1203 = read_u32_chained!(alt_body_1202);
                let alt_body_1204 = read_u32_chained!(alt_body_1203);
                let alt_body_1205 = read_u32_chained!(alt_body_1204);
                let alt_body_1206 = read_u32_chained!(alt_body_1205);
                let alt_body_1207 = read_u32_chained!(alt_body_1206);
                let alt_body_1208 = read_u32_chained!(alt_body_1207);
                let alt_body_1209 = read_u32_chained!(alt_body_1208);
                let alt_body_1210 = read_u32_chained!(alt_body_1209);
                let alt_body_1211 = read_u32_chained!(alt_body_1210);
                let alt_body_1212 = read_u32_chained!(alt_body_1211);
                let alt_body_1213 = read_u32_chained!(alt_body_1212);
                let alt_body_1214 = read_u32_chained!(alt_body_1213);
                let alt_body_1215 = read_u32_chained!(alt_body_1214);
                let alt_body_1216 = read_u32_chained!(alt_body_1215);
                let alt_body_1217 = read_u32_chained!(alt_body_1216);
                let alt_body_1218 = read_u32_chained!(alt_body_1217);
                let alt_body_1219 = read_u32_chained!(alt_body_1218);
                let alt_body_1220 = read_u32_chained!(alt_body_1219);
                let alt_body_1221 = read_u32_chained!(alt_body_1220);
                let alt_body_1222 = read_u32_chained!(alt_body_1221);
                let alt_body_1223 = read_u32_chained!(alt_body_1222);
                let alt_body_1224 = read_u32_chained!(alt_body_1223);
                let alt_body_1225 = read_u32_chained!(alt_body_1224);
                let alt_body_1226 = read_u32_chained!(alt_body_1225);
                let alt_body_1227 = read_u32_chained!(alt_body_1226);
                let alt_body_1228 = read_u32_chained!(alt_body_1227);
                let alt_body_1229 = read_u32_chained!(alt_body_1228);
                let alt_body_1230 = read_u32_chained!(alt_body_1229);
                let alt_body_1231 = read_u32_chained!(alt_body_1230);
                let alt_body_1232 = read_u32_chained!(alt_body_1231);
                let alt_body_1233 = read_u32_chained!(alt_body_1232);
                let alt_body_1234 = read_u32_chained!(alt_body_1233);
                let alt_body_1235 = read_u32_chained!(alt_body_1234);
                let alt_body_1236 = read_u32_chained!(alt_body_1235);
                let alt_body_1237 = read_u32_chained!(alt_body_1236);
                let alt_body_1238 = read_u32_chained!(alt_body_1237);
                let alt_body_1239 = read_u32_chained!(alt_body_1238);
                let alt_body_1240 = read_u32_chained!(alt_body_1239);
                let alt_body_1241 = read_u32_chained!(alt_body_1240);
                let alt_body_1242 = read_u32_chained!(alt_body_1241);
                let alt_body_1243 = read_u32_chained!(alt_body_1242);
                let alt_body_1244 = read_u32_chained!(alt_body_1243);
                let alt_body_1245 = read_u32_chained!(alt_body_1244);
                let alt_body_1246 = read_u32_chained!(alt_body_1245);
                let alt_body_1247 = read_u32_chained!(alt_body_1246);
                let alt_body_1248 = read_u32_chained!(alt_body_1247);
                let alt_body_1249 = read_u32_chained!(alt_body_1248);
                let alt_body_1250 = read_u32_chained!(alt_body_1249);
                let alt_body_1251 = read_u32_chained!(alt_body_1250);
                let alt_body_1252 = read_u32_chained!(alt_body_1251);
                let alt_body_1253 = read_u32_chained!(alt_body_1252);
                let alt_body_1254 = read_u32_chained!(alt_body_1253);
                let alt_body_1255 = read_u32_chained!(alt_body_1254);
                let alt_body_1256 = read_u32_chained!(alt_body_1255);
                let alt_body_1257 = read_u32_chained!(alt_body_1256);
                let alt_body_1258 = read_u32_chained!(alt_body_1257);
                let alt_body_1259 = read_u32_chained!(alt_body_1258);
                let alt_body_1260 = read_u32_chained!(alt_body_1259);
                let alt_body_1261 = read_u32_chained!(alt_body_1260);
                let alt_body_1262 = read_u32_chained!(alt_body_1261);
                let alt_body_1263 = read_u32_chained!(alt_body_1262);
                let alt_body_1264 = read_u32_chained!(alt_body_1263);
                let alt_body_1265 = read_u32_chained!(alt_body_1264);
                let alt_body_1266 = read_u32_chained!(alt_body_1265);
                let alt_body_1267 = read_u32_chained!(alt_body_1266);
                let alt_body_1268 = read_u32_chained!(alt_body_1267);
                let alt_body_1269 = read_u32_chained!(alt_body_1268);
                let alt_body_1270 = read_u32_chained!(alt_body_1269);
                let alt_body_1271 = read_u32_chained!(alt_body_1270);
                let alt_body_1272 = read_u32_chained!(alt_body_1271);
                let alt_body_1273 = read_u32_chained!(alt_body_1272);
                let alt_body_1274 = read_u32_chained!(alt_body_1273);
                let alt_body_1275 = read_u32_chained!(alt_body_1274);
                let alt_body_1276 = read_u32_chained!(alt_body_1275);
                let alt_body_1277 = read_u32_chained!(alt_body_1276);
                let alt_body_1278 = read_u32_chained!(alt_body_1277);
                let alt_body_1279 = read_u32_chained!(alt_body_1278);
                let alt_body_1280 = read_u32_chained!(alt_body_1279);
                let alt_body_1281 = read_u32_chained!(alt_body_1280);
                let alt_body_1282 = read_u32_chained!(alt_body_1281);
                let alt_body_1283 = read_u32_chained!(alt_body_1282);
                let alt_body_1284 = read_u32_chained!(alt_body_1283);
                let alt_body_1285 = read_u32_chained!(alt_body_1284);
                let alt_body_1286 = read_u32_chained!(alt_body_1285);
                let alt_body_1287 = read_u32_chained!(alt_body_1286);
                let alt_body_1288 = read_u32_chained!(alt_body_1287);
                let alt_body_1289 = read_u32_chained!(alt_body_1288);
                let alt_body_1290 = read_u32_chained!(alt_body_1289);
                let alt_body_1291 = read_u32_chained!(alt_body_1290);
                let alt_body_1292 = read_u32_chained!(alt_body_1291);
                let alt_body_1293 = read_u32_chained!(alt_body_1292);
                let alt_body_1294 = read_u32_chained!(alt_body_1293);
                let alt_body_1295 = read_u32_chained!(alt_body_1294);
                let alt_body_1296 = read_u32_chained!(alt_body_1295);
                let alt_body_1297 = read_u32_chained!(alt_body_1296);
                let alt_body_1298 = read_u32_chained!(alt_body_1297);
                let alt_body_1299 = read_u32_chained!(alt_body_1298);
                let alt_body_1300 = read_u32_chained!(alt_body_1299);
                let alt_body_1301 = read_u32_chained!(alt_body_1300);
                let alt_body_1302 = read_u32_chained!(alt_body_1301);
                let alt_body_1303 = read_u32_chained!(alt_body_1302);
                let alt_body_1304 = read_u32_chained!(alt_body_1303);
                let alt_body_1305 = read_u32_chained!(alt_body_1304);
                let alt_body_1306 = read_u32_chained!(alt_body_1305);
                let alt_body_1307 = read_u32_chained!(alt_body_1306);
                let alt_body_1308 = read_u32_chained!(alt_body_1307);
                let alt_body_1309 = read_u32_chained!(alt_body_1308);
                let alt_body_1310 = read_u32_chained!(alt_body_1309);
                let alt_body_1311 = read_u32_chained!(alt_body_1310);
                let alt_body_1312 = read_u32_chained!(alt_body_1311);
                let alt_body_1313 = read_u32_chained!(alt_body_1312);
                let alt_body_1314 = read_u32_chained!(alt_body_1313);
                let alt_body_1315 = read_u32_chained!(alt_body_1314);
                let alt_body_1316 = read_u32_chained!(alt_body_1315);
                let alt_body_1317 = read_u32_chained!(alt_body_1316);
                let alt_body_1318 = read_u32_chained!(alt_body_1317);
                let alt_body_1319 = read_u32_chained!(alt_body_1318);
                let alt_body_1320 = read_u32_chained!(alt_body_1319);
                let alt_body_1321 = read_u32_chained!(alt_body_1320);
                let alt_body_1322 = read_u32_chained!(alt_body_1321);
                let alt_body_1323 = read_u32_chained!(alt_body_1322);
                let alt_body_1324 = read_u32_chained!(alt_body_1323);
                let alt_body_1325 = read_u32_chained!(alt_body_1324);
                let alt_body_1326 = read_u32_chained!(alt_body_1325);
                let alt_body_1327 = read_u32_chained!(alt_body_1326);
                let alt_body_1328 = read_u32_chained!(alt_body_1327);
                let alt_body_1329 = read_u32_chained!(alt_body_1328);
                let alt_body_1330 = read_u32_chained!(alt_body_1329);
                let alt_body_1331 = read_u32_chained!(alt_body_1330);
                let alt_body_1332 = read_u32_chained!(alt_body_1331);
                let alt_body_1333 = read_u32_chained!(alt_body_1332);
                let alt_body_1334 = read_u32_chained!(alt_body_1333);
                let alt_body_1335 = read_u32_chained!(alt_body_1334);
                let alt_body_1336 = read_u32_chained!(alt_body_1335);
                let alt_body_1337 = read_u32_chained!(alt_body_1336);
                let alt_body_1338 = read_u32_chained!(alt_body_1337);
                let alt_body_1339 = read_u32_chained!(alt_body_1338);
                let alt_body_1340 = read_u32_chained!(alt_body_1339);
                let alt_body_1341 = read_u32_chained!(alt_body_1340);
                let alt_body_1342 = read_u32_chained!(alt_body_1341);
                let alt_body_1343 = read_u32_chained!(alt_body_1342);
                let alt_body_1344 = read_u32_chained!(alt_body_1343);
                let alt_body_1345 = read_u32_chained!(alt_body_1344);
                let alt_body_1346 = read_u32_chained!(alt_body_1345);
                let alt_body_1347 = read_u32_chained!(alt_body_1346);
                let alt_body_1348 = read_u32_chained!(alt_body_1347);
                let alt_body_1349 = read_u32_chained!(alt_body_1348);
                let alt_body_1350 = read_u32_chained!(alt_body_1349);
                let alt_body_1351 = read_u32_chained!(alt_body_1350);
                let alt_body_1352 = read_u32_chained!(alt_body_1351);
                let alt_body_1353 = read_u32_chained!(alt_body_1352);
                let alt_body_1354 = read_u32_chained!(alt_body_1353);
                let alt_body_1355 = read_u32_chained!(alt_body_1354);
                let alt_body_1356 = read_u32_chained!(alt_body_1355);
                let alt_body_1357 = read_u32_chained!(alt_body_1356);
                let alt_body_1358 = read_u32_chained!(alt_body_1357);
                let alt_body_1359 = read_u32_chained!(alt_body_1358);
                let alt_body_1360 = read_u32_chained!(alt_body_1359);
                let alt_body_1361 = read_u32_chained!(alt_body_1360);
                let alt_body_1362 = read_u32_chained!(alt_body_1361);
                let alt_body_1363 = read_u32_chained!(alt_body_1362);
                let alt_body_1364 = read_u32_chained!(alt_body_1363);
                let alt_body_1365 = read_u32_chained!(alt_body_1364);
                let alt_body_1366 = read_u32_chained!(alt_body_1365);
                let alt_body_1367 = read_u32_chained!(alt_body_1366);
                let alt_body_1368 = read_u32_chained!(alt_body_1367);
                let alt_body_1369 = read_u32_chained!(alt_body_1368);
                let alt_body_1370 = read_u32_chained!(alt_body_1369);
                let alt_body_1371 = read_u32_chained!(alt_body_1370);
                let alt_body_1372 = read_u32_chained!(alt_body_1371);
                let alt_body_1373 = read_u32_chained!(alt_body_1372);
                let alt_body_1374 = read_u32_chained!(alt_body_1373);
                let alt_body_1375 = read_u32_chained!(alt_body_1374);
                let alt_body_1376 = read_u32_chained!(alt_body_1375);
                let alt_body_1377 = read_u32_chained!(alt_body_1376);
                let alt_body_1378 = read_u32_chained!(alt_body_1377);
                let alt_body_1379 = read_u32_chained!(alt_body_1378);
                let alt_body_1380 = read_u32_chained!(alt_body_1379);
                let alt_body_1381 = read_u32_chained!(alt_body_1380);
                let alt_body_1382 = read_u32_chained!(alt_body_1381);
                let alt_body_1383 = read_u32_chained!(alt_body_1382);
                let alt_body_1384 = read_u32_chained!(alt_body_1383);
                let alt_body_1385 = read_u32_chained!(alt_body_1384);
                let alt_body_1386 = read_u32_chained!(alt_body_1385);
                let alt_body_1387 = read_u32_chained!(alt_body_1386);
                let alt_body_1388 = read_u32_chained!(alt_body_1387);
                let alt_body_1389 = read_u32_chained!(alt_body_1388);
                let alt_body_1390 = read_u32_chained!(alt_body_1389);
                let alt_body_1391 = read_u32_chained!(alt_body_1390);
                let alt_body_1392 = read_u32_chained!(alt_body_1391);
                let alt_body_1393 = read_u32_chained!(alt_body_1392);
                let alt_body_1394 = read_u32_chained!(alt_body_1393);
                let alt_body_1395 = read_u32_chained!(alt_body_1394);
                let alt_body_1396 = read_u32_chained!(alt_body_1395);
                let alt_body_1397 = read_u32_chained!(alt_body_1396);
                let alt_body_1398 = read_u32_chained!(alt_body_1397);
                let alt_body_1399 = read_u32_chained!(alt_body_1398);
                let alt_body_1400 = read_u32_chained!(alt_body_1399);
                let alt_body_1401 = read_u32_chained!(alt_body_1400);
                let alt_body_1402 = read_u32_chained!(alt_body_1401);
                let alt_body_1403 = read_u32_chained!(alt_body_1402);
                let alt_body_1404 = read_u32_chained!(alt_body_1403);
                let alt_body_1405 = read_u32_chained!(alt_body_1404);
                let alt_body_1406 = read_u32_chained!(alt_body_1405);
                let alt_body_1407 = read_u32_chained!(alt_body_1406);
                let alt_body_1408 = read_u32_chained!(alt_body_1407);
                // From alt_body_1409 onwards, use smart reader that detects
                // CString boundaries (recovers alt_post_cstr_a typing for
                // entries that have a CString header in this range).
                let mut alt_body_chain_stopped = false;
                let alt_body_1409 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1408.is_some());
                let alt_body_1410 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1409.is_some());
                let alt_body_1411 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1410.is_some());
                let alt_body_1412 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1411.is_some());
                let alt_body_1413 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1412.is_some());
                let alt_body_1414 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1413.is_some());
                let alt_body_1415 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1414.is_some());
                let alt_body_1416 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1415.is_some());
                let alt_body_1417 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1416.is_some());
                let alt_body_1418 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1417.is_some());
                let alt_body_1419 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1418.is_some());
                let alt_body_1420 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1419.is_some());
                let alt_body_1421 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1420.is_some());
                let alt_body_1422 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1421.is_some());
                let alt_body_1423 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1422.is_some());
                let alt_body_1424 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1423.is_some());
                let alt_body_1425 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1424.is_some());
                let alt_body_1426 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1425.is_some());
                let alt_body_1427 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1426.is_some());
                let alt_body_1428 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1427.is_some());
                let alt_body_1429 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1428.is_some());
                let alt_body_1430 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1429.is_some());
                let alt_body_1431 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1430.is_some());
                let alt_body_1432 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1431.is_some());
                let alt_body_1433 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1432.is_some());
                let alt_body_1434 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1433.is_some());
                let alt_body_1435 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1434.is_some());
                let alt_body_1436 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1435.is_some());
                let alt_body_1437 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1436.is_some());
                let alt_body_1438 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1437.is_some());
                let alt_body_1439 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1438.is_some());
                let alt_body_1440 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1439.is_some());
                let alt_body_1441 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1440.is_some());
                let alt_body_1442 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1441.is_some());
                let alt_body_1443 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1442.is_some());
                let alt_body_1444 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1443.is_some());
                let alt_body_1445 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1444.is_some());
                let alt_body_1446 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1445.is_some());
                let alt_body_1447 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1446.is_some());
                let alt_body_1448 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1447.is_some());
                let alt_body_1449 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1448.is_some());
                let alt_body_1450 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1449.is_some());
                let alt_body_1451 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1450.is_some());
                let alt_body_1452 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1451.is_some());
                let alt_body_1453 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1452.is_some());
                let alt_body_1454 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1453.is_some());
                let alt_body_1455 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1454.is_some());
                let alt_body_1456 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1455.is_some());
                let alt_body_1457 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1456.is_some());
                let alt_body_1458 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1457.is_some());
                let alt_body_1459 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1458.is_some());
                let alt_body_1460 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1459.is_some());
                let alt_body_1461 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1460.is_some());
                let alt_body_1462 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1461.is_some());
                let alt_body_1463 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1462.is_some());
                let alt_body_1464 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1463.is_some());
                let alt_body_1465 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1464.is_some());
                let alt_body_1466 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1465.is_some());
                let alt_body_1467 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1466.is_some());
                let alt_body_1468 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1467.is_some());
                let alt_body_1469 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1468.is_some());
                let alt_body_1470 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1469.is_some());
                let alt_body_1471 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1470.is_some());
                let alt_body_1472 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1471.is_some());
                let alt_body_1473 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1472.is_some());
                let alt_body_1474 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1473.is_some());
                let alt_body_1475 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1474.is_some());
                let alt_body_1476 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1475.is_some());
                let alt_body_1477 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1476.is_some());
                let alt_body_1478 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1477.is_some());
                let alt_body_1479 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1478.is_some());
                let alt_body_1480 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1479.is_some());
                let alt_body_1481 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1480.is_some());
                let alt_body_1482 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1481.is_some());
                let alt_body_1483 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1482.is_some());
                let alt_body_1484 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1483.is_some());
                let alt_body_1485 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1484.is_some());
                let alt_body_1486 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1485.is_some());
                let alt_body_1487 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1486.is_some());
                let alt_body_1488 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1487.is_some());
                let alt_body_1489 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1488.is_some());
                let alt_body_1490 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1489.is_some());
                let alt_body_1491 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1490.is_some());
                let alt_body_1492 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1491.is_some());
                let alt_body_1493 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1492.is_some());
                let alt_body_1494 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1493.is_some());
                let alt_body_1495 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1494.is_some());
                let alt_body_1496 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1495.is_some());
                let alt_body_1497 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1496.is_some());
                let alt_body_1498 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1497.is_some());
                let alt_body_1499 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1498.is_some());
                let alt_body_1500 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1499.is_some());
                let alt_body_1501 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1500.is_some());
                let alt_body_1502 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1501.is_some());
                let alt_body_1503 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1502.is_some());
                let alt_body_1504 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1503.is_some());
                let alt_body_1505 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1504.is_some());
                let alt_body_1506 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1505.is_some());
                let alt_body_1507 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1506.is_some());
                let alt_body_1508 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1507.is_some());
                let alt_body_1509 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1508.is_some());
                let alt_body_1510 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1509.is_some());
                let alt_body_1511 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1510.is_some());
                let alt_body_1512 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1511.is_some());
                let alt_body_1513 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1512.is_some());
                let alt_body_1514 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1513.is_some());
                let alt_body_1515 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1514.is_some());
                let alt_body_1516 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1515.is_some());
                let alt_body_1517 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1516.is_some());
                let alt_body_1518 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1517.is_some());
                let alt_body_1519 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1518.is_some());
                let alt_body_1520 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1519.is_some());
                let alt_body_1521 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1520.is_some());
                let alt_body_1522 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1521.is_some());
                let alt_body_1523 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1522.is_some());
                let alt_body_1524 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1523.is_some());
                let alt_body_1525 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1524.is_some());
                let alt_body_1526 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1525.is_some());
                let alt_body_1527 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1526.is_some());
                let alt_body_1528 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1527.is_some());
                let alt_body_1529 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1528.is_some());
                let alt_body_1530 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1529.is_some());
                let alt_body_1531 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1530.is_some());
                let alt_body_1532 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1531.is_some());
                let alt_body_1533 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1532.is_some());
                let alt_body_1534 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1533.is_some());
                let alt_body_1535 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1534.is_some());
                let alt_body_1536 = Self::try_smart_alt_body_read(data, &mut probe, entry_end, &mut alt_body_chain_stopped, alt_body_1535.is_some());
                // Detect CString (file path or XML) at this position.
                // Only succeeds when the next u32 is a sensible length (<1000)
                // and the following bytes are valid UTF-8.
                // alt_post_cstr_a: bumped len threshold from 1000 to 65536 to
                // match try_smart_alt_body_read so long XML CStrings the smart
                // reader detects mid-chain can be properly typed here.
                let alt_post_cstr_a = if alt_body_1536.is_some() || alt_body_1408.is_some() || alt_body_1280.is_some() || alt_body_1152.is_some() || alt_body_896.is_some() || alt_body_768.is_some() || alt_body_640.is_some() {
                    let pre_ = probe;
                    if probe + 4 <= entry_end {
                        let len = u32::from_le_bytes(data[probe..probe+4].try_into().unwrap()) as usize;
                        if len > 8 && len < 65536 && probe + 4 + len <= entry_end {
                            let candidate = &data[probe+4..probe+4+len];
                            if std::str::from_utf8(candidate).is_ok() {
                                let printable = candidate.iter().filter(|&&b|
                                    (0x20..=0x7e).contains(&b) || b == 0x09 || b == 0x0a || b == 0x0d
                                ).count();
                                if printable * 5 >= candidate.len() * 4 {
                                    match CString::read_from(data, &mut probe) {
                                        Ok(s) if probe <= entry_end => Some(s),
                                        _ => { probe = pre_; None }
                                    }
                                } else { None }
                            } else { None }
                        } else { None }
                    } else { None }
                } else { None };
                let alt_post_cstr_b = if alt_post_cstr_a.is_some() {
                    let pre_ = probe;
                    if probe + 4 <= entry_end {
                        let len = u32::from_le_bytes(data[probe..probe+4].try_into().unwrap()) as usize;
                        if len > 8 && len < 65536 && probe + 4 + len <= entry_end {
                            let candidate = &data[probe+4..probe+4+len];
                            if std::str::from_utf8(candidate).is_ok() {
                                let printable = candidate.iter().filter(|&&b|
                                    (0x20..=0x7e).contains(&b) || b == 0x09 || b == 0x0a || b == 0x0d
                                ).count();
                                if printable * 5 >= candidate.len() * 4 {
                                    match CString::read_from(data, &mut probe) {
                                        Ok(s) if probe <= entry_end => Some(s),
                                        _ => { probe = pre_; None }
                                    }
                                } else { None }
                            } else { None }
                        } else { None }
                    } else { None }
                } else { None };
                let field_665_u32 = read_u32_chained!(field_664_u32);
                let field_666_u32 = read_u32_chained!(field_665_u32);
                let field_667_u32 = read_u32_chained!(field_666_u32);
                let field_668_u32 = read_u32_chained!(field_667_u32);
                let field_669_u32 = read_u32_chained!(field_668_u32);
                let field_670_u32 = read_u32_chained!(field_669_u32);
                let field_671_u32 = read_u32_chained!(field_670_u32);
                let field_672_u32 = read_u32_chained!(field_671_u32);
                let field_673_u32 = read_u32_chained!(field_672_u32);
                let field_674_u32 = read_u32_chained!(field_673_u32);
                let field_675_u32 = read_u32_chained!(field_674_u32);
                let field_676_u32 = read_u32_chained!(field_675_u32);
                let field_677_u32 = read_u32_chained!(field_676_u32);
                let field_678_u32 = read_u32_chained!(field_677_u32);
                let field_679_u32 = read_u32_chained!(field_678_u32);
                let field_680_u32 = read_u32_chained!(field_679_u32);
                let field_681_u32 = read_u32_chained!(field_680_u32);
                let field_682_u32 = read_u32_chained!(field_681_u32);
                let field_683_u32 = read_u32_chained!(field_682_u32);
                let field_684_u32 = read_u32_chained!(field_683_u32);
                let field_685_u32 = read_u32_chained!(field_684_u32);
                let field_686_u32 = read_u32_chained!(field_685_u32);
                let field_687_u32 = read_u32_chained!(field_686_u32);
                let field_688_u32 = read_u32_chained!(field_687_u32);
                let field_689_u32 = read_u32_chained!(field_688_u32);
                let field_690_u32 = read_u32_chained!(field_689_u32);
                let field_691_u32 = read_u32_chained!(field_690_u32);
                let field_692_u32 = read_u32_chained!(field_691_u32);
                let field_693_u32 = read_u32_chained!(field_692_u32);
                let field_694_u32 = read_u32_chained!(field_693_u32);
                let field_695_u32 = read_u32_chained!(field_694_u32);
                let field_696_u32 = read_u32_chained!(field_695_u32);
                let field_697_u32 = read_u32_chained!(field_696_u32);
                let field_698_u32 = read_u32_chained!(field_697_u32);
                let field_699_u32 = read_u32_chained!(field_698_u32);
                let field_700_u32 = read_u32_chained!(field_699_u32);
                let field_701_u32 = read_u32_chained!(field_700_u32);
                let field_702_u32 = read_u32_chained!(field_701_u32);
                let field_703_u32 = read_u32_chained!(field_702_u32);
                let field_704_u32 = read_u32_chained!(field_703_u32);
                let field_705_u32 = read_u32_chained!(field_704_u32);
                let field_706_u32 = read_u32_chained!(field_705_u32);
                let field_707_u32 = read_u32_chained!(field_706_u32);
                let field_708_u32 = read_u32_chained!(field_707_u32);
                let field_709_u32 = read_u32_chained!(field_708_u32);
                let field_710_u32 = read_u32_chained!(field_709_u32);
                let field_711_u32 = read_u32_chained!(field_710_u32);
                let field_712_u32 = read_u32_chained!(field_711_u32);
                let field_713_u32 = read_u32_chained!(field_712_u32);
                let field_714_u32 = read_u32_chained!(field_713_u32);
                let field_715_u32 = read_u32_chained!(field_714_u32);
                let field_716_u32 = read_u32_chained!(field_715_u32);
                let field_717_u32 = read_u32_chained!(field_716_u32);
                let field_718_u32 = read_u32_chained!(field_717_u32);
                let field_719_u32 = read_u32_chained!(field_718_u32);
                let field_720_u32 = read_u32_chained!(field_719_u32);
                let field_721_u32 = read_u32_chained!(field_720_u32);
                let field_722_u32 = read_u32_chained!(field_721_u32);
                let field_723_u32 = read_u32_chained!(field_722_u32);
                let field_724_u32 = read_u32_chained!(field_723_u32);
                let field_725_u32 = read_u32_chained!(field_724_u32);
                let field_726_u32 = read_u32_chained!(field_725_u32);
                let field_727_u32 = read_u32_chained!(field_726_u32);
                let field_728_u32 = read_u32_chained!(field_727_u32);
                macro_rules! read_u8_tail {
                    ($prev:expr) => {{
                        if $prev && probe + 1 <= entry_end {
                            let pre_ = probe;
                            match u8::read_from(data, &mut probe) {
                                Ok(v) => Some(v), _ => { probe = pre_; None }
                            }
                        } else { None }
                    }};
                }
                // Drain trailing pad bytes (most entries have 1-3 trailing 0x00).
                // Activate unconditionally — write_to and write_from_json both
                // place tail_pad after alt_post_cstr_b/field_728, so the order
                // is consistent for both alt and non-alt entry formats.
                let tail_pad_001 = read_u8_tail!(true);
                let tail_pad_002 = read_u8_tail!(tail_pad_001.is_some());
                let tail_pad_003 = read_u8_tail!(tail_pad_002.is_some());
                let tail_pad_004 = read_u8_tail!(tail_pad_003.is_some());
                let post_blob = data[probe..entry_end].to_vec();
                *offset = entry_end;
                Ok(GimmickTail::Decoded {
                    gimmick_interaction_override_list: list,
                    use_interaction_ui_socket: ui,
                    use_sub_part_for_interaction: sp,
                    property_list: pl,
                    gimmick_name_hash: gnh,
                    gimmick_name: Box::new(gn),
                    emoji_texture_id: eti,
                    dev_memo: dm,
                    hash_pair_list: hpl,
                    hash_single_list: hsl,
                    trigger_event_handler_list,
                    gimmick_chart_parameter_list,
                    field_19_u32_list,
                    field_20_u32_list,
                    field_21_u32_list,
                    field_22_u32_list,
                    field_23_u32_list,
                    field_24_u32_list,
                    field_24_emissive_flag_a,
                    field_24_emissive_value_a,
                    field_24_emissive_flag_b,
                    field_24_emissive_name,
                    field_24_emissive_value_b,
                    field_25_u32_list,
                    field_26_u32,
                    field_27_u32_list,
                    field_28_u32,
                    field_29_u32_list,
                    field_30_u32_list,
                    field_31_u32_list,
                    f31_alt_001, f31_alt_002, f31_alt_003, f31_alt_004,
                    f31_alt_005, f31_alt_006, f31_alt_007, f31_alt_008,
                    f31_alt_009, f31_alt_010, f31_alt_011, f31_alt_012,
                    f31_alt_013, f31_alt_014, f31_alt_015, f31_alt_016,
                    f31_alt_017, f31_alt_018, f31_alt_019, f31_alt_020,
                    f31_alt_021, f31_alt_022, f31_alt_023, f31_alt_024,
                    f31_alt_025, f31_alt_026, f31_alt_027, f31_alt_028,
                    f31_alt_029, f31_alt_030, f31_alt_031, f31_alt_032,
                    f31_alt_033, f31_alt_034, f31_alt_035, f31_alt_036,
                    f31_alt_037, f31_alt_038, f31_alt_039, f31_alt_040,
                    f31_alt_041, f31_alt_042, f31_alt_043, f31_alt_044,
                    f31_alt_045, f31_alt_046, f31_alt_047, f31_alt_048,
                    f31_alt_049, f31_alt_050, f31_alt_051, f31_alt_052,
                    f31_alt_053, f31_alt_054, f31_alt_055, f31_alt_056,
                    f31_alt_057, f31_alt_058, f31_alt_059, f31_alt_060,
                    f31_alt_061, f31_alt_062, f31_alt_063, f31_alt_064,
                    f31_alt_065, f31_alt_066, f31_alt_067, f31_alt_068,
                    f31_alt_069, f31_alt_070, f31_alt_071, f31_alt_072,
                    f31_alt_073, f31_alt_074, f31_alt_075, f31_alt_076,
                    f31_alt_077, f31_alt_078, f31_alt_079, f31_alt_080,
                    f31_alt_081, f31_alt_082, f31_alt_083, f31_alt_084,
                    f31_alt_085, f31_alt_086, f31_alt_087, f31_alt_088,
                    f31_alt_089, f31_alt_090, f31_alt_091, f31_alt_092,
                    f31_alt_093, f31_alt_094, f31_alt_095, f31_alt_096,
                    f31_alt_097, f31_alt_098, f31_alt_099, f31_alt_100,
                    f31_alt_101, f31_alt_102, f31_alt_103, f31_alt_104,
                    f31_alt_105, f31_alt_106, f31_alt_107, f31_alt_108,
                    f31_alt_109, f31_alt_110, f31_alt_111, f31_alt_112,
                    f31_alt_113, f31_alt_114, f31_alt_115, f31_alt_116,
                    f31_alt_117, f31_alt_118, f31_alt_119, f31_alt_120,
                    f31_alt_121, f31_alt_122, f31_alt_123, f31_alt_124,
                    f31_alt_125, f31_alt_126, f31_alt_127, f31_alt_128,
                    f31_alt_129, f31_alt_130, f31_alt_131, f31_alt_132,
                    f31_alt_133, f31_alt_134, f31_alt_135, f31_alt_136,
                    f31_alt_137, f31_alt_138, f31_alt_139, f31_alt_140,
                    f31_alt_141, f31_alt_142, f31_alt_143, f31_alt_144,
                    f31_alt_145, f31_alt_146, f31_alt_147, f31_alt_148,
                    f31_alt_149, f31_alt_150, f31_alt_151, f31_alt_152,
                    f31_alt_153, f31_alt_154, f31_alt_155, f31_alt_156,
                    f31_alt_157, f31_alt_158, f31_alt_159, f31_alt_160,
                    f31_alt_161, f31_alt_162, f31_alt_163, f31_alt_164,
                    f31_alt_165, f31_alt_166, f31_alt_167, f31_alt_168,
                    f31_alt_169, f31_alt_170, f31_alt_171, f31_alt_172,
                    f31_alt_173, f31_alt_174, f31_alt_175, f31_alt_176,
                    f31_alt_177, f31_alt_178, f31_alt_179, f31_alt_180,
                    f31_alt_181, f31_alt_182, f31_alt_183, f31_alt_184,
                    f31_alt_185, f31_alt_186, f31_alt_187, f31_alt_188,
                    f31_alt_189, f31_alt_190, f31_alt_191, f31_alt_192,
                    f31_alt_193, f31_alt_194, f31_alt_195, f31_alt_196,
                    f31_alt_197, f31_alt_198, f31_alt_199, f31_alt_200,
                    f31_alt_201, f31_alt_202, f31_alt_203, f31_alt_204,
                    f31_alt_205, f31_alt_206, f31_alt_207, f31_alt_208,
                    f31_alt_209, f31_alt_210, f31_alt_211, f31_alt_212,
                    f31_alt_213, f31_alt_214, f31_alt_215, f31_alt_216,
                    f31_alt_217, f31_alt_218, f31_alt_219, f31_alt_220,
                    f31_alt_221, f31_alt_222, f31_alt_223, f31_alt_224,
                    f31_alt_225, f31_alt_226, f31_alt_227, f31_alt_228,
                    f31_alt_229, f31_alt_230, f31_alt_231, f31_alt_232,
                    f31_alt_233, f31_alt_234, f31_alt_235, f31_alt_236,
                    f31_alt_237, f31_alt_238, f31_alt_239, f31_alt_240,
                    f31_alt_241, f31_alt_242, f31_alt_243, f31_alt_244,
                    f31_alt_245, f31_alt_246, f31_alt_247, f31_alt_248,
                    f31_alt_249, f31_alt_250, f31_alt_251, f31_alt_252,
                    f31_alt_253, f31_alt_254, f31_alt_255, f31_alt_256,
                    field_32_u32_list,
                    f32_alt_001, f32_alt_002, f32_alt_003, f32_alt_004,
                    f32_alt_005, f32_alt_006, f32_alt_007, f32_alt_008,
                    f32_alt_009, f32_alt_010, f32_alt_011, f32_alt_012,
                    f32_alt_013, f32_alt_014, f32_alt_015, f32_alt_016,
                    f32_alt_017, f32_alt_018, f32_alt_019, f32_alt_020,
                    f32_alt_021, f32_alt_022, f32_alt_023, f32_alt_024,
                    f32_alt_025, f32_alt_026, f32_alt_027, f32_alt_028,
                    f32_alt_029, f32_alt_030, f32_alt_031, f32_alt_032,
                    f32_alt_033, f32_alt_034, f32_alt_035, f32_alt_036,
                    f32_alt_037, f32_alt_038, f32_alt_039, f32_alt_040,
                    f32_alt_041, f32_alt_042, f32_alt_043, f32_alt_044,
                    f32_alt_045, f32_alt_046, f32_alt_047, f32_alt_048,
                    f32_alt_049, f32_alt_050, f32_alt_051, f32_alt_052,
                    f32_alt_053, f32_alt_054, f32_alt_055, f32_alt_056,
                    f32_alt_057, f32_alt_058, f32_alt_059, f32_alt_060,
                    f32_alt_061, f32_alt_062, f32_alt_063, f32_alt_064,
                    f32_alt_065, f32_alt_066, f32_alt_067, f32_alt_068,
                    f32_alt_069, f32_alt_070, f32_alt_071, f32_alt_072,
                    f32_alt_073, f32_alt_074, f32_alt_075, f32_alt_076,
                    f32_alt_077, f32_alt_078, f32_alt_079, f32_alt_080,
                    f32_alt_081, f32_alt_082, f32_alt_083, f32_alt_084,
                    f32_alt_085, f32_alt_086, f32_alt_087, f32_alt_088,
                    f32_alt_089, f32_alt_090, f32_alt_091, f32_alt_092,
                    f32_alt_093, f32_alt_094, f32_alt_095, f32_alt_096,
                    f32_alt_097, f32_alt_098, f32_alt_099, f32_alt_100,
                    f32_alt_101, f32_alt_102, f32_alt_103, f32_alt_104,
                    f32_alt_105, f32_alt_106, f32_alt_107, f32_alt_108,
                    f32_alt_109, f32_alt_110, f32_alt_111, f32_alt_112,
                    f32_alt_113, f32_alt_114, f32_alt_115, f32_alt_116,
                    f32_alt_117, f32_alt_118, f32_alt_119, f32_alt_120,
                    f32_alt_121, f32_alt_122, f32_alt_123, f32_alt_124,
                    f32_alt_125, f32_alt_126, f32_alt_127, f32_alt_128,
                    f32_alt_129, f32_alt_130, f32_alt_131, f32_alt_132,
                    f32_alt_133, f32_alt_134, f32_alt_135, f32_alt_136,
                    f32_alt_137, f32_alt_138, f32_alt_139, f32_alt_140,
                    f32_alt_141, f32_alt_142, f32_alt_143, f32_alt_144,
                    f32_alt_145, f32_alt_146, f32_alt_147, f32_alt_148,
                    f32_alt_149, f32_alt_150, f32_alt_151, f32_alt_152,
                    f32_alt_153, f32_alt_154, f32_alt_155, f32_alt_156,
                    f32_alt_157, f32_alt_158, f32_alt_159, f32_alt_160,
                    f32_alt_161, f32_alt_162, f32_alt_163, f32_alt_164,
                    f32_alt_165, f32_alt_166, f32_alt_167, f32_alt_168,
                    f32_alt_169, f32_alt_170, f32_alt_171, f32_alt_172,
                    f32_alt_173, f32_alt_174, f32_alt_175, f32_alt_176,
                    f32_alt_177, f32_alt_178, f32_alt_179, f32_alt_180,
                    f32_alt_181, f32_alt_182, f32_alt_183, f32_alt_184,
                    f32_alt_185, f32_alt_186, f32_alt_187, f32_alt_188,
                    f32_alt_189, f32_alt_190, f32_alt_191, f32_alt_192,
                    field_33_u32,
                    field_34_u32,
                    field_35_u32_list,
                    field_36_u32,
                    field_37_u32,
                    field_38_u32,
                    field_39_u32_list,
                    f39_alt_001, f39_alt_002, f39_alt_003, f39_alt_004,
                    f39_alt_005, f39_alt_006, f39_alt_007, f39_alt_008,
                    f39_alt_009, f39_alt_010, f39_alt_011, f39_alt_012,
                    f39_alt_013, f39_alt_014, f39_alt_015, f39_alt_016,
                    f39_alt_017, f39_alt_018, f39_alt_019, f39_alt_020,
                    f39_alt_021, f39_alt_022, f39_alt_023, f39_alt_024,
                    f39_alt_025, f39_alt_026, f39_alt_027, f39_alt_028,
                    f39_alt_029, f39_alt_030, f39_alt_031, f39_alt_032,
                    f39_alt_033, f39_alt_034, f39_alt_035, f39_alt_036,
                    f39_alt_037, f39_alt_038, f39_alt_039, f39_alt_040,
                    f39_alt_041, f39_alt_042, f39_alt_043, f39_alt_044,
                    f39_alt_045, f39_alt_046, f39_alt_047, f39_alt_048,
                    f39_alt_049, f39_alt_050, f39_alt_051, f39_alt_052,
                    f39_alt_053, f39_alt_054, f39_alt_055, f39_alt_056,
                    f39_alt_057, f39_alt_058, f39_alt_059, f39_alt_060,
                    f39_alt_061, f39_alt_062, f39_alt_063, f39_alt_064,
                    f39_alt_065, f39_alt_066, f39_alt_067, f39_alt_068,
                    f39_alt_069, f39_alt_070, f39_alt_071, f39_alt_072,
                    f39_alt_073, f39_alt_074, f39_alt_075, f39_alt_076,
                    f39_alt_077, f39_alt_078, f39_alt_079, f39_alt_080,
                    f39_alt_081, f39_alt_082, f39_alt_083, f39_alt_084,
                    f39_alt_085, f39_alt_086, f39_alt_087, f39_alt_088,
                    f39_alt_089, f39_alt_090, f39_alt_091, f39_alt_092,
                    f39_alt_093, f39_alt_094, f39_alt_095, f39_alt_096,
                    f39_alt_097, f39_alt_098, f39_alt_099, f39_alt_100,
                    f39_alt_101, f39_alt_102, f39_alt_103, f39_alt_104,
                    f39_alt_105, f39_alt_106, f39_alt_107, f39_alt_108,
                    f39_alt_109, f39_alt_110, f39_alt_111, f39_alt_112,
                    f39_alt_113, f39_alt_114, f39_alt_115, f39_alt_116,
                    f39_alt_117, f39_alt_118, f39_alt_119, f39_alt_120,
                    f39_alt_121, f39_alt_122, f39_alt_123, f39_alt_124,
                    f39_alt_125, f39_alt_126, f39_alt_127, f39_alt_128,
                    f39_alt_129, f39_alt_130, f39_alt_131, f39_alt_132,
                    f39_alt_133, f39_alt_134, f39_alt_135, f39_alt_136,
                    f39_alt_137, f39_alt_138, f39_alt_139, f39_alt_140,
                    f39_alt_141, f39_alt_142, f39_alt_143, f39_alt_144,
                    f39_alt_145, f39_alt_146, f39_alt_147, f39_alt_148,
                    f39_alt_149, f39_alt_150, f39_alt_151, f39_alt_152,
                    f39_alt_153, f39_alt_154, f39_alt_155, f39_alt_156,
                    f39_alt_157, f39_alt_158, f39_alt_159, f39_alt_160,
                    f39_alt_161, f39_alt_162, f39_alt_163, f39_alt_164,
                    f39_alt_165, f39_alt_166, f39_alt_167, f39_alt_168,
                    f39_alt_169, f39_alt_170, f39_alt_171, f39_alt_172,
                    f39_alt_173, f39_alt_174, f39_alt_175, f39_alt_176,
                    f39_alt_177, f39_alt_178, f39_alt_179, f39_alt_180,
                    f39_alt_181, f39_alt_182, f39_alt_183, f39_alt_184,
                    f39_alt_185, f39_alt_186, f39_alt_187, f39_alt_188,
                    f39_alt_189, f39_alt_190, f39_alt_191, f39_alt_192,
                    field_40_u32_list,
                    field_41_u32,
                    field_42_u32,
                    field_43_u32,
                    field_44_u32,
                    field_45_u32,
                    field_46_u32,
                    field_47_u32,
                    field_48_u32,
                    field_49_u32_list,
                    field_50_u32_list,
                    field_51_u32_list,
                    field_52_u32_list,
                    field_53_u32_list,
                    field_54_u32_list,
                    field_55_u32_list,
                    field_56_u32_list,
                    field_57_u32_list,
                    field_58_u32_list,
                    field_59_u32,
                    field_60_u32,
                    field_61_u32,
                    field_62_u32,
                    field_63_u32,
                    field_64_u32,
                    field_65_u32,
                    field_66_u32,
                    field_67_u32,
                    field_68_u32,
                    field_69_u32,
                    field_70_u32,
                    field_71_u32,
                    field_72_u32,
                    field_73_u32,
                    field_74_u32,
                    field_75_u32,
                    field_76_u32,
                    field_77_u32,
                    field_78_u32,
                    field_79_u32,
                    field_80_u32,
                    field_81_u32,
                    field_82_u32,
                    field_83_u32,
                    field_84_u32,
                    field_85_u32,
                    field_86_u32,
                    field_87_u32,
                    field_88_u32,
                    field_89_u32,
                    field_90_u32,
                    field_91_u32,
                    field_92_u32,
                    field_93_u32,
                    field_94_u32,
                    field_95_u32,
                    field_96_u32,
                    field_97_u32,
                    field_98_u32,
                    field_99_u32,
                    field_100_u32,
                    field_101_u32,
                    field_102_u32,
                    field_103_u32,
                    field_104_u32,
                    field_105_u32,
                    field_106_u32,
                    field_107_u32,
                    field_108_u32,
                    field_109_u32,
                    field_110_u32,
                    field_111_u32,
                    field_112_u32,
                    field_113_u32,
                    field_114_u32,
                    field_115_u32,
                    field_116_u32,
                    field_117_u32,
                    field_118_u32,
                    field_119_u32,
                    field_120_u32,
                    field_121_u32,
                    field_122_u32,
                    field_123_u32,
                    field_124_u32,
                    field_125_u32,
                    field_126_u32,
                    field_127_u32,
                    field_128_u32,
                    field_129_u32,
                    field_130_u32,
                    field_131_u32,
                    field_132_u32,
                    field_133_u32,
                    field_134_u32,
                    field_135_u32,
                    field_136_u32,
                    field_137_u32,
                    field_138_u32,
                    field_139_u32,
                    field_140_u32,
                    field_141_u32,
                    field_142_u32,
                    field_143_u32,
                    field_144_u32,
                    field_145_u32,
                    field_146_u32,
                    field_147_u32,
                    field_148_u32,
                    field_149_u32,
                    field_150_u32,
                    field_151_u32,
                    field_152_u32,
                    field_153_u32,
                    field_154_u32,
                    field_155_u32,
                    field_156_u32,
                    field_157_u32,
                    field_158_u32,
                    field_159_u32,
                    field_160_u32,
                    field_161_u32,
                    field_162_u32,
                    field_163_u32,
                    field_164_u32,
                    field_165_u32,
                    field_166_u32,
                    field_167_u32,
                    field_168_u32,
                    field_169_u32,
                    field_170_u32,
                    field_171_u32,
                    field_172_u32,
                    field_173_u32,
                    field_174_u32,
                    field_175_u32,
                    field_176_u32,
                    field_177_u32,
                    field_178_u32,
                    field_179_u32,
                    field_180_u32,
                    field_181_u32,
                    field_182_u32,
                    field_183_u32,
                    field_184_u32,
                    field_185_u32,
                    field_186_u32,
                    field_187_u32,
                    field_188_u32,
                    field_189_u32,
                    field_190_u32,
                    field_191_u32,
                    field_192_u32,
                    field_193_u32,
                    field_194_u32,
                    field_195_u32,
                    field_196_u32,
                    field_197_u32,
                    field_198_u32,
                    field_199_u32,
                    field_200_u32,
                    field_201_u32,
                    field_202_u32,
                    field_203_u32,
                    field_204_u32,
                    field_205_u32,
                    field_206_u32,
                    field_207_u32,
                    field_208_u32,
                    field_209_u32,
                    field_210_u32,
                    field_211_u32,
                    field_212_u32,
                    field_213_u32,
                    field_214_u32,
                    field_215_u32,
                    field_216_u32,
                    field_217_u32,
                    field_218_u32,
                    field_219_u32,
                    field_220_u32,
                    field_221_u32,
                    field_222_u32,
                    field_223_u32,
                    field_224_u32,
                    field_225_u32,
                    field_226_u32,
                    field_227_u32,
                    field_228_u32,
                    field_229_u32,
                    field_230_u32,
                    field_231_u32,
                    field_232_u32,
                    field_233_u32,
                    field_234_u32,
                    field_235_u32,
                    field_236_u32,
                    field_237_u32,
                    field_238_u32,
                    field_239_u32,
                    field_240_u32,
                    field_241_u32,
                    field_242_u32,
                    field_243_u32,
                    field_244_u32,
                    field_245_u32,
                    field_246_u32,
                    field_247_u32,
                    field_248_u32,
                    field_249_u32,
                    field_250_u32,
                    field_251_u32,
                    field_252_u32,
                    field_253_u32,
                    field_254_u32,
                    field_255_u32,
                    field_256_u32,
                    field_257_u32,
                    field_258_u32,
                    field_259_u32,
                    field_260_u32,
                    field_261_u32,
                    field_262_u32,
                    field_263_u32,
                    field_264_u32,
                    field_265_u32,
                    field_266_u32,
                    field_267_u32,
                    field_268_u32,
                    field_269_u32,
                    field_270_u32,
                    field_271_u32,
                    field_272_u32,
                    field_273_u32,
                    field_274_u32,
                    field_275_u32,
                    field_276_u32,
                    field_277_u32,
                    field_278_u32,
                    field_279_u32,
                    field_280_u32,
                    field_281_u32,
                    field_282_u32,
                    field_283_u32,
                    field_284_u32,
                    field_285_u32,
                    field_286_u32,
                    field_287_u32,
                    field_288_u32,
                    field_289_u32,
                    field_290_u32,
                    field_291_u32,
                    field_292_u32,
                    field_293_u32,
                    field_294_u32,
                    field_295_u32,
                    field_296_u32,
                    field_297_u32,
                    field_298_u32,
                    field_299_u32,
                    field_300_u32,
                    field_301_u32,
                    field_302_u32,
                    field_303_u32,
                    field_304_u32,
                    field_305_u32,
                    field_306_u32,
                    field_307_u32,
                    field_308_u32,
                    field_309_u32,
                    field_310_u32,
                    field_311_u32,
                    field_312_u32,
                    field_313_u32,
                    field_314_u32,
                    field_315_u32,
                    field_316_u32,
                    field_317_u32,
                    field_318_u32,
                    field_319_u32,
                    field_320_u32,
                    field_321_u32,
                    field_322_u32,
                    field_323_u32,
                    field_324_u32,
                    field_325_u32,
                    field_326_u32,
                    field_327_u32,
                    field_328_u32,
                    field_329_u32,
                    field_330_u32,
                    field_331_u32,
                    field_332_u32,
                    field_333_u32,
                    field_334_u32,
                    field_335_u32,
                    field_336_u32,
                    field_337_u32,
                    field_338_u32,
                    field_339_u32,
                    field_340_u32,
                    field_341_u32,
                    field_342_u32_count,
                    field_343_u8_flag,
                    field_344_u32,
                    field_345_u32,
                    field_346_u32,
                    field_347_u32,
                    field_348_u32,
                    field_349_u32,
                    field_350_u32,
                    field_351_u32,
                    field_352_u32,
                    field_353_u32,
                    field_354_u32,
                    field_355_u32,
                    field_356_u32,
                    field_357_u32,
                    field_358_u32,
                    field_359_u32,
                    field_360_u32,
                    field_361_u32,
                    field_362_u32,
                    field_363_u32,
                    field_364_u32,
                    field_365_u32,
                    field_366_u32,
                    field_367_u32,
                    field_368_u32,
                    field_369_u32,
                    field_370_u32,
                    field_371_u32,
                    field_372_u32,
                    field_373_u32,
                    field_374_u32,
                    field_375_u32,
                    field_376_u32,
                    field_377_u32,
                    field_378_u32,
                    field_379_u32,
                    field_380_u32,
                    field_381_u32,
                    field_382_u32,
                    field_383_u32,
                    field_384_u32,
                    field_385_u32,
                    field_386_u32,
                    field_387_u32,
                    field_388_u32,
                    field_389_u32,
                    field_390_u32,
                    field_391_u32,
                    field_392_u32,
                    field_393_u32,
                    field_394_u32,
                    field_395_u32,
                    field_396_u32,
                    field_397_u32,
                    field_398_u32,
                    field_399_u32,
                    field_400_u32,
                    field_401_u32,
                    field_402_u32,
                    field_403_u32,
                    field_404_u32,
                    field_405_u32,
                    field_406_u32,
                    field_407_u32,
                    field_408_u32,
                    field_409_u32,
                    field_410_u32,
                    field_411_u32,
                    field_412_u32,
                    field_413_u32,
                    field_414_u32,
                    field_415_u32,
                    field_416_u32,
                    field_417_u32,
                    field_418_u32,
                    field_419_u32,
                    field_420_u32,
                    field_421_u32,
                    field_422_u32,
                    field_423_u32,
                    field_424_u32,
                    field_425_u32,
                    field_426_u32,
                    field_427_u32,
                    field_428_u32,
                    field_429_u32,
                    field_430_u32,
                    field_431_u32,
                    field_432_u32,
                    field_433_u32,
                    field_434_u32,
                    field_435_u32,
                    field_436_u32,
                    field_437_u32,
                    field_438_u32,
                    field_439_u32,
                    field_440_u32,
                    field_441_u32,
                    field_442_u32,
                    field_443_u32,
                    field_444_u32,
                    field_445_u32,
                    field_446_u32,
                    field_447_u32,
                    field_448_u32,
                    field_449_u32,
                    field_450_u32,
                    field_451_u32,
                    field_452_u32,
                    field_453_u32,
                    field_454_u32,
                    field_455_u32,
                    field_456_u32,
                    field_457_u32,
                    field_458_u32,
                    field_459_u32,
                    field_460_u32,
                    field_461_u32,
                    field_462_u32,
                    field_463_u32,
                    field_464_u32,
                    field_465_u32,
                    field_466_u32,
                    field_467_u32,
                    field_468_u32,
                    field_469_u32,
                    field_470_u32,
                    field_471_u32,
                    field_472_u32,
                    field_473_u32,
                    field_474_u32,
                    field_475_u32,
                    field_476_u32,
                    field_477_u32,
                    field_478_u32,
                    field_479_u32,
                    field_480_u32,
                    field_481_u32,
                    field_482_u32,
                    field_483_u32,
                    field_484_u32,
                    field_485_u32,
                    field_486_u32,
                    field_487_u32,
                    field_488_u32,
                    field_489_u32,
                    field_490_u32,
                    field_491_u32,
                    field_492_u32,
                    field_493_u32,
                    field_494_u32,
                    field_495_u32,
                    field_496_u32,
                    field_497_u32,
                    field_498_u32,
                    field_499_u32,
                    field_500_u32,
                    field_501_u32,
                    field_502_u32,
                    field_503_u32,
                    field_504_u32,
                    field_505_u32,
                    field_506_u32,
                    field_507_u32,
                    field_508_u32,
                    field_509_u32,
                    field_510_u32,
                    field_511_u32,
                    field_512_u32,
                    field_513_u32,
                    field_514_u32,
                    field_515_u32,
                    field_516_u32,
                    field_517_u32,
                    field_518_u32,
                    field_519_u32,
                    field_520_u32,
                    field_521_u32,
                    field_522_u32,
                    field_523_u32,
                    field_524_u32,
                    field_525_u32,
                    field_526_u32,
                    field_527_u32,
                    field_528_u32,
                    field_529_u32,
                    field_530_u32,
                    field_531_u32,
                    field_532_u32,
                    field_533_u32,
                    field_534_u32,
                    field_535_u32,
                    field_536_u32,
                    field_537_u32, field_538_u32, field_539_u32, field_540_u32,
                    field_541_u32, field_542_u32, field_543_u32, field_544_u32,
                    field_545_u32, field_546_u32, field_547_u32, field_548_u32,
                    field_549_u32, field_550_u32, field_551_u32, field_552_u32,
                    field_553_u32, field_554_u32, field_555_u32, field_556_u32,
                    field_557_u32, field_558_u32, field_559_u32, field_560_u32,
                    field_561_u32, field_562_u32, field_563_u32, field_564_u32,
                    field_565_u32, field_566_u32, field_567_u32, field_568_u32,
                    field_569_u32, field_570_u32, field_571_u32, field_572_u32,
                    field_573_u32, field_574_u32, field_575_u32, field_576_u32,
                    field_577_u32, field_578_u32, field_579_u32, field_580_u32,
                    field_581_u32, field_582_u32, field_583_u32, field_584_u32,
                    field_585_u32, field_586_u32, field_587_u32, field_588_u32,
                    field_589_u32, field_590_u32, field_591_u32, field_592_u32,
                    field_593_u32, field_594_u32, field_595_u32, field_596_u32,
                    field_597_u32, field_598_u32, field_599_u32, field_600_u32,
                    field_601_u32, field_602_u32, field_603_u32, field_604_u32,
                    field_605_u32, field_606_u32, field_607_u32, field_608_u32,
                    field_609_u32, field_610_u32, field_611_u32, field_612_u32,
                    field_613_u32, field_614_u32, field_615_u32, field_616_u32,
                    field_617_u32, field_618_u32, field_619_u32, field_620_u32,
                    field_621_u32, field_622_u32, field_623_u32, field_624_u32,
                    field_625_u32, field_626_u32, field_627_u32, field_628_u32,
                    field_629_u32, field_630_u32, field_631_u32, field_632_u32,
                    field_633_u32, field_634_u32, field_635_u32, field_636_u32,
                    field_637_u32, field_638_u32, field_639_u32, field_640_u32,
                    field_641_u32, field_642_u32, field_643_u32, field_644_u32,
                    field_645_u32, field_646_u32, field_647_u32, field_648_u32,
                    field_649_u32, field_650_u32, field_651_u32, field_652_u32,
                    field_653_u32, field_654_u32, field_655_u32, field_656_u32,
                    field_657_u32, field_658_u32, field_659_u32, field_660_u32,
                    field_661_u32, field_662_u32, field_663_u32, field_664_u32,
                    alt_trigger_count,
                    alt_trigger_flag,
                    alt_trigger_name,
                    alt_inner_count,
                    alt_inner_name,
                    alt_inner_flag,
                    alt_body_001, alt_body_002, alt_body_003, alt_body_004,
                    alt_body_005, alt_body_006, alt_body_007, alt_body_008,
                    alt_body_009, alt_body_010, alt_body_011, alt_body_012,
                    alt_body_013, alt_body_014, alt_body_015, alt_body_016,
                    alt_body_017, alt_body_018, alt_body_019, alt_body_020,
                    alt_body_021, alt_body_022, alt_body_023, alt_body_024,
                    alt_body_025, alt_body_026, alt_body_027, alt_body_028,
                    alt_body_029, alt_body_030, alt_body_031, alt_body_032,
                    alt_body_033, alt_body_034, alt_body_035, alt_body_036,
                    alt_body_037, alt_body_038, alt_body_039, alt_body_040,
                    alt_body_041, alt_body_042, alt_body_043, alt_body_044,
                    alt_body_045, alt_body_046, alt_body_047, alt_body_048,
                    alt_body_049, alt_body_050, alt_body_051, alt_body_052,
                    alt_body_053, alt_body_054, alt_body_055, alt_body_056,
                    alt_body_057, alt_body_058, alt_body_059, alt_body_060,
                    alt_body_061, alt_body_062, alt_body_063, alt_body_064,
                    alt_body_065, alt_body_066, alt_body_067, alt_body_068,
                    alt_body_069, alt_body_070, alt_body_071, alt_body_072,
                    alt_body_073, alt_body_074, alt_body_075, alt_body_076,
                    alt_body_077, alt_body_078, alt_body_079, alt_body_080,
                    alt_body_081, alt_body_082, alt_body_083, alt_body_084,
                    alt_body_085, alt_body_086, alt_body_087, alt_body_088,
                    alt_body_089, alt_body_090, alt_body_091, alt_body_092,
                    alt_body_093, alt_body_094, alt_body_095, alt_body_096,
                    alt_body_097, alt_body_098, alt_body_099, alt_body_100,
                    alt_body_101, alt_body_102, alt_body_103, alt_body_104,
                    alt_body_105, alt_body_106, alt_body_107, alt_body_108,
                    alt_body_109, alt_body_110, alt_body_111, alt_body_112,
                    alt_body_113, alt_body_114, alt_body_115, alt_body_116,
                    alt_body_117, alt_body_118, alt_body_119, alt_body_120,
                    alt_body_121, alt_body_122, alt_body_123, alt_body_124,
                    alt_body_125, alt_body_126, alt_body_127, alt_body_128,
                    alt_body_129, alt_body_130, alt_body_131, alt_body_132,
                    alt_body_133, alt_body_134, alt_body_135, alt_body_136,
                    alt_body_137, alt_body_138, alt_body_139, alt_body_140,
                    alt_body_141, alt_body_142, alt_body_143, alt_body_144,
                    alt_body_145, alt_body_146, alt_body_147, alt_body_148,
                    alt_body_149, alt_body_150, alt_body_151, alt_body_152,
                    alt_body_153, alt_body_154, alt_body_155, alt_body_156,
                    alt_body_157, alt_body_158, alt_body_159, alt_body_160,
                    alt_body_161, alt_body_162, alt_body_163, alt_body_164,
                    alt_body_165, alt_body_166, alt_body_167, alt_body_168,
                    alt_body_169, alt_body_170, alt_body_171, alt_body_172,
                    alt_body_173, alt_body_174, alt_body_175, alt_body_176,
                    alt_body_177, alt_body_178, alt_body_179, alt_body_180,
                    alt_body_181, alt_body_182, alt_body_183, alt_body_184,
                    alt_body_185, alt_body_186, alt_body_187, alt_body_188,
                    alt_body_189, alt_body_190, alt_body_191, alt_body_192,
                    alt_body_193, alt_body_194, alt_body_195, alt_body_196,
                    alt_body_197, alt_body_198, alt_body_199, alt_body_200,
                    alt_body_201, alt_body_202, alt_body_203, alt_body_204,
                    alt_body_205, alt_body_206, alt_body_207, alt_body_208,
                    alt_body_209, alt_body_210, alt_body_211, alt_body_212,
                    alt_body_213, alt_body_214, alt_body_215, alt_body_216,
                    alt_body_217, alt_body_218, alt_body_219, alt_body_220,
                    alt_body_221, alt_body_222, alt_body_223, alt_body_224,
                    alt_body_225, alt_body_226, alt_body_227, alt_body_228,
                    alt_body_229, alt_body_230, alt_body_231, alt_body_232,
                    alt_body_233, alt_body_234, alt_body_235, alt_body_236,
                    alt_body_237, alt_body_238, alt_body_239, alt_body_240,
                    alt_body_241, alt_body_242, alt_body_243, alt_body_244,
                    alt_body_245, alt_body_246, alt_body_247, alt_body_248,
                    alt_body_249, alt_body_250, alt_body_251, alt_body_252,
                    alt_body_253, alt_body_254, alt_body_255, alt_body_256,
                    alt_body_257, alt_body_258, alt_body_259, alt_body_260,
                    alt_body_261, alt_body_262, alt_body_263, alt_body_264,
                    alt_body_265, alt_body_266, alt_body_267, alt_body_268,
                    alt_body_269, alt_body_270, alt_body_271, alt_body_272,
                    alt_body_273, alt_body_274, alt_body_275, alt_body_276,
                    alt_body_277, alt_body_278, alt_body_279, alt_body_280,
                    alt_body_281, alt_body_282, alt_body_283, alt_body_284,
                    alt_body_285, alt_body_286, alt_body_287, alt_body_288,
                    alt_body_289, alt_body_290, alt_body_291, alt_body_292,
                    alt_body_293, alt_body_294, alt_body_295, alt_body_296,
                    alt_body_297, alt_body_298, alt_body_299, alt_body_300,
                    alt_body_301, alt_body_302, alt_body_303, alt_body_304,
                    alt_body_305, alt_body_306, alt_body_307, alt_body_308,
                    alt_body_309, alt_body_310, alt_body_311, alt_body_312,
                    alt_body_313, alt_body_314, alt_body_315, alt_body_316,
                    alt_body_317, alt_body_318, alt_body_319, alt_body_320,
                    alt_body_321, alt_body_322, alt_body_323, alt_body_324,
                    alt_body_325, alt_body_326, alt_body_327, alt_body_328,
                    alt_body_329, alt_body_330, alt_body_331, alt_body_332,
                    alt_body_333, alt_body_334, alt_body_335, alt_body_336,
                    alt_body_337, alt_body_338, alt_body_339, alt_body_340,
                    alt_body_341, alt_body_342, alt_body_343, alt_body_344,
                    alt_body_345, alt_body_346, alt_body_347, alt_body_348,
                    alt_body_349, alt_body_350, alt_body_351, alt_body_352,
                    alt_body_353, alt_body_354, alt_body_355, alt_body_356,
                    alt_body_357, alt_body_358, alt_body_359, alt_body_360,
                    alt_body_361, alt_body_362, alt_body_363, alt_body_364,
                    alt_body_365, alt_body_366, alt_body_367, alt_body_368,
                    alt_body_369, alt_body_370, alt_body_371, alt_body_372,
                    alt_body_373, alt_body_374, alt_body_375, alt_body_376,
                    alt_body_377, alt_body_378, alt_body_379, alt_body_380,
                    alt_body_381, alt_body_382, alt_body_383, alt_body_384,
                    alt_body_385, alt_body_386, alt_body_387, alt_body_388,
                    alt_body_389, alt_body_390, alt_body_391, alt_body_392,
                    alt_body_393, alt_body_394, alt_body_395, alt_body_396,
                    alt_body_397, alt_body_398, alt_body_399, alt_body_400,
                    alt_body_401, alt_body_402, alt_body_403, alt_body_404,
                    alt_body_405, alt_body_406, alt_body_407, alt_body_408,
                    alt_body_409, alt_body_410, alt_body_411, alt_body_412,
                    alt_body_413, alt_body_414, alt_body_415, alt_body_416,
                    alt_body_417, alt_body_418, alt_body_419, alt_body_420,
                    alt_body_421, alt_body_422, alt_body_423, alt_body_424,
                    alt_body_425, alt_body_426, alt_body_427, alt_body_428,
                    alt_body_429, alt_body_430, alt_body_431, alt_body_432,
                    alt_body_433, alt_body_434, alt_body_435, alt_body_436,
                    alt_body_437, alt_body_438, alt_body_439, alt_body_440,
                    alt_body_441, alt_body_442, alt_body_443, alt_body_444,
                    alt_body_445, alt_body_446, alt_body_447, alt_body_448,
                    alt_body_449, alt_body_450, alt_body_451, alt_body_452,
                    alt_body_453, alt_body_454, alt_body_455, alt_body_456,
                    alt_body_457, alt_body_458, alt_body_459, alt_body_460,
                    alt_body_461, alt_body_462, alt_body_463, alt_body_464,
                    alt_body_465, alt_body_466, alt_body_467, alt_body_468,
                    alt_body_469, alt_body_470, alt_body_471, alt_body_472,
                    alt_body_473, alt_body_474, alt_body_475, alt_body_476,
                    alt_body_477, alt_body_478, alt_body_479, alt_body_480,
                    alt_body_481, alt_body_482, alt_body_483, alt_body_484,
                    alt_body_485, alt_body_486, alt_body_487, alt_body_488,
                    alt_body_489, alt_body_490, alt_body_491, alt_body_492,
                    alt_body_493, alt_body_494, alt_body_495, alt_body_496,
                    alt_body_497, alt_body_498, alt_body_499, alt_body_500,
                    alt_body_501, alt_body_502, alt_body_503, alt_body_504,
                    alt_body_505, alt_body_506, alt_body_507, alt_body_508,
                    alt_body_509, alt_body_510, alt_body_511, alt_body_512,
                    alt_body_513, alt_body_514, alt_body_515, alt_body_516,
                    alt_body_517, alt_body_518, alt_body_519, alt_body_520,
                    alt_body_521, alt_body_522, alt_body_523, alt_body_524,
                    alt_body_525, alt_body_526, alt_body_527, alt_body_528,
                    alt_body_529, alt_body_530, alt_body_531, alt_body_532,
                    alt_body_533, alt_body_534, alt_body_535, alt_body_536,
                    alt_body_537, alt_body_538, alt_body_539, alt_body_540,
                    alt_body_541, alt_body_542, alt_body_543, alt_body_544,
                    alt_body_545, alt_body_546, alt_body_547, alt_body_548,
                    alt_body_549, alt_body_550, alt_body_551, alt_body_552,
                    alt_body_553, alt_body_554, alt_body_555, alt_body_556,
                    alt_body_557, alt_body_558, alt_body_559, alt_body_560,
                    alt_body_561, alt_body_562, alt_body_563, alt_body_564,
                    alt_body_565, alt_body_566, alt_body_567, alt_body_568,
                    alt_body_569, alt_body_570, alt_body_571, alt_body_572,
                    alt_body_573, alt_body_574, alt_body_575, alt_body_576,
                    alt_body_577, alt_body_578, alt_body_579, alt_body_580,
                    alt_body_581, alt_body_582, alt_body_583, alt_body_584,
                    alt_body_585, alt_body_586, alt_body_587, alt_body_588,
                    alt_body_589, alt_body_590, alt_body_591, alt_body_592,
                    alt_body_593, alt_body_594, alt_body_595, alt_body_596,
                    alt_body_597, alt_body_598, alt_body_599, alt_body_600,
                    alt_body_601, alt_body_602, alt_body_603, alt_body_604,
                    alt_body_605, alt_body_606, alt_body_607, alt_body_608,
                    alt_body_609, alt_body_610, alt_body_611, alt_body_612,
                    alt_body_613, alt_body_614, alt_body_615, alt_body_616,
                    alt_body_617, alt_body_618, alt_body_619, alt_body_620,
                    alt_body_621, alt_body_622, alt_body_623, alt_body_624,
                    alt_body_625, alt_body_626, alt_body_627, alt_body_628,
                    alt_body_629, alt_body_630, alt_body_631, alt_body_632,
                    alt_body_633, alt_body_634, alt_body_635, alt_body_636,
                    alt_body_637, alt_body_638, alt_body_639, alt_body_640,
                    alt_body_641, alt_body_642, alt_body_643, alt_body_644,
                    alt_body_645, alt_body_646, alt_body_647, alt_body_648,
                    alt_body_649, alt_body_650, alt_body_651, alt_body_652,
                    alt_body_653, alt_body_654, alt_body_655, alt_body_656,
                    alt_body_657, alt_body_658, alt_body_659, alt_body_660,
                    alt_body_661, alt_body_662, alt_body_663, alt_body_664,
                    alt_body_665, alt_body_666, alt_body_667, alt_body_668,
                    alt_body_669, alt_body_670, alt_body_671, alt_body_672,
                    alt_body_673, alt_body_674, alt_body_675, alt_body_676,
                    alt_body_677, alt_body_678, alt_body_679, alt_body_680,
                    alt_body_681, alt_body_682, alt_body_683, alt_body_684,
                    alt_body_685, alt_body_686, alt_body_687, alt_body_688,
                    alt_body_689, alt_body_690, alt_body_691, alt_body_692,
                    alt_body_693, alt_body_694, alt_body_695, alt_body_696,
                    alt_body_697, alt_body_698, alt_body_699, alt_body_700,
                    alt_body_701, alt_body_702, alt_body_703, alt_body_704,
                    alt_body_705, alt_body_706, alt_body_707, alt_body_708,
                    alt_body_709, alt_body_710, alt_body_711, alt_body_712,
                    alt_body_713, alt_body_714, alt_body_715, alt_body_716,
                    alt_body_717, alt_body_718, alt_body_719, alt_body_720,
                    alt_body_721, alt_body_722, alt_body_723, alt_body_724,
                    alt_body_725, alt_body_726, alt_body_727, alt_body_728,
                    alt_body_729, alt_body_730, alt_body_731, alt_body_732,
                    alt_body_733, alt_body_734, alt_body_735, alt_body_736,
                    alt_body_737, alt_body_738, alt_body_739, alt_body_740,
                    alt_body_741, alt_body_742, alt_body_743, alt_body_744,
                    alt_body_745, alt_body_746, alt_body_747, alt_body_748,
                    alt_body_749, alt_body_750, alt_body_751, alt_body_752,
                    alt_body_753, alt_body_754, alt_body_755, alt_body_756,
                    alt_body_757, alt_body_758, alt_body_759, alt_body_760,
                    alt_body_761, alt_body_762, alt_body_763, alt_body_764,
                    alt_body_765, alt_body_766, alt_body_767, alt_body_768,
                    alt_body_769, alt_body_770, alt_body_771, alt_body_772,
                    alt_body_773, alt_body_774, alt_body_775, alt_body_776,
                    alt_body_777, alt_body_778, alt_body_779, alt_body_780,
                    alt_body_781, alt_body_782, alt_body_783, alt_body_784,
                    alt_body_785, alt_body_786, alt_body_787, alt_body_788,
                    alt_body_789, alt_body_790, alt_body_791, alt_body_792,
                    alt_body_793, alt_body_794, alt_body_795, alt_body_796,
                    alt_body_797, alt_body_798, alt_body_799, alt_body_800,
                    alt_body_801, alt_body_802, alt_body_803, alt_body_804,
                    alt_body_805, alt_body_806, alt_body_807, alt_body_808,
                    alt_body_809, alt_body_810, alt_body_811, alt_body_812,
                    alt_body_813, alt_body_814, alt_body_815, alt_body_816,
                    alt_body_817, alt_body_818, alt_body_819, alt_body_820,
                    alt_body_821, alt_body_822, alt_body_823, alt_body_824,
                    alt_body_825, alt_body_826, alt_body_827, alt_body_828,
                    alt_body_829, alt_body_830, alt_body_831, alt_body_832,
                    alt_body_833, alt_body_834, alt_body_835, alt_body_836,
                    alt_body_837, alt_body_838, alt_body_839, alt_body_840,
                    alt_body_841, alt_body_842, alt_body_843, alt_body_844,
                    alt_body_845, alt_body_846, alt_body_847, alt_body_848,
                    alt_body_849, alt_body_850, alt_body_851, alt_body_852,
                    alt_body_853, alt_body_854, alt_body_855, alt_body_856,
                    alt_body_857, alt_body_858, alt_body_859, alt_body_860,
                    alt_body_861, alt_body_862, alt_body_863, alt_body_864,
                    alt_body_865, alt_body_866, alt_body_867, alt_body_868,
                    alt_body_869, alt_body_870, alt_body_871, alt_body_872,
                    alt_body_873, alt_body_874, alt_body_875, alt_body_876,
                    alt_body_877, alt_body_878, alt_body_879, alt_body_880,
                    alt_body_881, alt_body_882, alt_body_883, alt_body_884,
                    alt_body_885, alt_body_886, alt_body_887, alt_body_888,
                    alt_body_889, alt_body_890, alt_body_891, alt_body_892,
                    alt_body_893, alt_body_894, alt_body_895, alt_body_896,
                    alt_body_897, alt_body_898, alt_body_899, alt_body_900,
                    alt_body_901, alt_body_902, alt_body_903, alt_body_904,
                    alt_body_905, alt_body_906, alt_body_907, alt_body_908,
                    alt_body_909, alt_body_910, alt_body_911, alt_body_912,
                    alt_body_913, alt_body_914, alt_body_915, alt_body_916,
                    alt_body_917, alt_body_918, alt_body_919, alt_body_920,
                    alt_body_921, alt_body_922, alt_body_923, alt_body_924,
                    alt_body_925, alt_body_926, alt_body_927, alt_body_928,
                    alt_body_929, alt_body_930, alt_body_931, alt_body_932,
                    alt_body_933, alt_body_934, alt_body_935, alt_body_936,
                    alt_body_937, alt_body_938, alt_body_939, alt_body_940,
                    alt_body_941, alt_body_942, alt_body_943, alt_body_944,
                    alt_body_945, alt_body_946, alt_body_947, alt_body_948,
                    alt_body_949, alt_body_950, alt_body_951, alt_body_952,
                    alt_body_953, alt_body_954, alt_body_955, alt_body_956,
                    alt_body_957, alt_body_958, alt_body_959, alt_body_960,
                    alt_body_961, alt_body_962, alt_body_963, alt_body_964,
                    alt_body_965, alt_body_966, alt_body_967, alt_body_968,
                    alt_body_969, alt_body_970, alt_body_971, alt_body_972,
                    alt_body_973, alt_body_974, alt_body_975, alt_body_976,
                    alt_body_977, alt_body_978, alt_body_979, alt_body_980,
                    alt_body_981, alt_body_982, alt_body_983, alt_body_984,
                    alt_body_985, alt_body_986, alt_body_987, alt_body_988,
                    alt_body_989, alt_body_990, alt_body_991, alt_body_992,
                    alt_body_993, alt_body_994, alt_body_995, alt_body_996,
                    alt_body_997, alt_body_998, alt_body_999, alt_body_1000,
                    alt_body_1001, alt_body_1002, alt_body_1003, alt_body_1004,
                    alt_body_1005, alt_body_1006, alt_body_1007, alt_body_1008,
                    alt_body_1009, alt_body_1010, alt_body_1011, alt_body_1012,
                    alt_body_1013, alt_body_1014, alt_body_1015, alt_body_1016,
                    alt_body_1017, alt_body_1018, alt_body_1019, alt_body_1020,
                    alt_body_1021, alt_body_1022, alt_body_1023, alt_body_1024,
                    alt_body_1025, alt_body_1026, alt_body_1027, alt_body_1028,
                    alt_body_1029, alt_body_1030, alt_body_1031, alt_body_1032,
                    alt_body_1033, alt_body_1034, alt_body_1035, alt_body_1036,
                    alt_body_1037, alt_body_1038, alt_body_1039, alt_body_1040,
                    alt_body_1041, alt_body_1042, alt_body_1043, alt_body_1044,
                    alt_body_1045, alt_body_1046, alt_body_1047, alt_body_1048,
                    alt_body_1049, alt_body_1050, alt_body_1051, alt_body_1052,
                    alt_body_1053, alt_body_1054, alt_body_1055, alt_body_1056,
                    alt_body_1057, alt_body_1058, alt_body_1059, alt_body_1060,
                    alt_body_1061, alt_body_1062, alt_body_1063, alt_body_1064,
                    alt_body_1065, alt_body_1066, alt_body_1067, alt_body_1068,
                    alt_body_1069, alt_body_1070, alt_body_1071, alt_body_1072,
                    alt_body_1073, alt_body_1074, alt_body_1075, alt_body_1076,
                    alt_body_1077, alt_body_1078, alt_body_1079, alt_body_1080,
                    alt_body_1081, alt_body_1082, alt_body_1083, alt_body_1084,
                    alt_body_1085, alt_body_1086, alt_body_1087, alt_body_1088,
                    alt_body_1089, alt_body_1090, alt_body_1091, alt_body_1092,
                    alt_body_1093, alt_body_1094, alt_body_1095, alt_body_1096,
                    alt_body_1097, alt_body_1098, alt_body_1099, alt_body_1100,
                    alt_body_1101, alt_body_1102, alt_body_1103, alt_body_1104,
                    alt_body_1105, alt_body_1106, alt_body_1107, alt_body_1108,
                    alt_body_1109, alt_body_1110, alt_body_1111, alt_body_1112,
                    alt_body_1113, alt_body_1114, alt_body_1115, alt_body_1116,
                    alt_body_1117, alt_body_1118, alt_body_1119, alt_body_1120,
                    alt_body_1121, alt_body_1122, alt_body_1123, alt_body_1124,
                    alt_body_1125, alt_body_1126, alt_body_1127, alt_body_1128,
                    alt_body_1129, alt_body_1130, alt_body_1131, alt_body_1132,
                    alt_body_1133, alt_body_1134, alt_body_1135, alt_body_1136,
                    alt_body_1137, alt_body_1138, alt_body_1139, alt_body_1140,
                    alt_body_1141, alt_body_1142, alt_body_1143, alt_body_1144,
                    alt_body_1145, alt_body_1146, alt_body_1147, alt_body_1148,
                    alt_body_1149, alt_body_1150, alt_body_1151, alt_body_1152,
                    alt_body_1153, alt_body_1154, alt_body_1155, alt_body_1156,
                    alt_body_1157, alt_body_1158, alt_body_1159, alt_body_1160,
                    alt_body_1161, alt_body_1162, alt_body_1163, alt_body_1164,
                    alt_body_1165, alt_body_1166, alt_body_1167, alt_body_1168,
                    alt_body_1169, alt_body_1170, alt_body_1171, alt_body_1172,
                    alt_body_1173, alt_body_1174, alt_body_1175, alt_body_1176,
                    alt_body_1177, alt_body_1178, alt_body_1179, alt_body_1180,
                    alt_body_1181, alt_body_1182, alt_body_1183, alt_body_1184,
                    alt_body_1185, alt_body_1186, alt_body_1187, alt_body_1188,
                    alt_body_1189, alt_body_1190, alt_body_1191, alt_body_1192,
                    alt_body_1193, alt_body_1194, alt_body_1195, alt_body_1196,
                    alt_body_1197, alt_body_1198, alt_body_1199, alt_body_1200,
                    alt_body_1201, alt_body_1202, alt_body_1203, alt_body_1204,
                    alt_body_1205, alt_body_1206, alt_body_1207, alt_body_1208,
                    alt_body_1209, alt_body_1210, alt_body_1211, alt_body_1212,
                    alt_body_1213, alt_body_1214, alt_body_1215, alt_body_1216,
                    alt_body_1217, alt_body_1218, alt_body_1219, alt_body_1220,
                    alt_body_1221, alt_body_1222, alt_body_1223, alt_body_1224,
                    alt_body_1225, alt_body_1226, alt_body_1227, alt_body_1228,
                    alt_body_1229, alt_body_1230, alt_body_1231, alt_body_1232,
                    alt_body_1233, alt_body_1234, alt_body_1235, alt_body_1236,
                    alt_body_1237, alt_body_1238, alt_body_1239, alt_body_1240,
                    alt_body_1241, alt_body_1242, alt_body_1243, alt_body_1244,
                    alt_body_1245, alt_body_1246, alt_body_1247, alt_body_1248,
                    alt_body_1249, alt_body_1250, alt_body_1251, alt_body_1252,
                    alt_body_1253, alt_body_1254, alt_body_1255, alt_body_1256,
                    alt_body_1257, alt_body_1258, alt_body_1259, alt_body_1260,
                    alt_body_1261, alt_body_1262, alt_body_1263, alt_body_1264,
                    alt_body_1265, alt_body_1266, alt_body_1267, alt_body_1268,
                    alt_body_1269, alt_body_1270, alt_body_1271, alt_body_1272,
                    alt_body_1273, alt_body_1274, alt_body_1275, alt_body_1276,
                    alt_body_1277, alt_body_1278, alt_body_1279, alt_body_1280,
                    alt_body_1281, alt_body_1282, alt_body_1283, alt_body_1284,
                    alt_body_1285, alt_body_1286, alt_body_1287, alt_body_1288,
                    alt_body_1289, alt_body_1290, alt_body_1291, alt_body_1292,
                    alt_body_1293, alt_body_1294, alt_body_1295, alt_body_1296,
                    alt_body_1297, alt_body_1298, alt_body_1299, alt_body_1300,
                    alt_body_1301, alt_body_1302, alt_body_1303, alt_body_1304,
                    alt_body_1305, alt_body_1306, alt_body_1307, alt_body_1308,
                    alt_body_1309, alt_body_1310, alt_body_1311, alt_body_1312,
                    alt_body_1313, alt_body_1314, alt_body_1315, alt_body_1316,
                    alt_body_1317, alt_body_1318, alt_body_1319, alt_body_1320,
                    alt_body_1321, alt_body_1322, alt_body_1323, alt_body_1324,
                    alt_body_1325, alt_body_1326, alt_body_1327, alt_body_1328,
                    alt_body_1329, alt_body_1330, alt_body_1331, alt_body_1332,
                    alt_body_1333, alt_body_1334, alt_body_1335, alt_body_1336,
                    alt_body_1337, alt_body_1338, alt_body_1339, alt_body_1340,
                    alt_body_1341, alt_body_1342, alt_body_1343, alt_body_1344,
                    alt_body_1345, alt_body_1346, alt_body_1347, alt_body_1348,
                    alt_body_1349, alt_body_1350, alt_body_1351, alt_body_1352,
                    alt_body_1353, alt_body_1354, alt_body_1355, alt_body_1356,
                    alt_body_1357, alt_body_1358, alt_body_1359, alt_body_1360,
                    alt_body_1361, alt_body_1362, alt_body_1363, alt_body_1364,
                    alt_body_1365, alt_body_1366, alt_body_1367, alt_body_1368,
                    alt_body_1369, alt_body_1370, alt_body_1371, alt_body_1372,
                    alt_body_1373, alt_body_1374, alt_body_1375, alt_body_1376,
                    alt_body_1377, alt_body_1378, alt_body_1379, alt_body_1380,
                    alt_body_1381, alt_body_1382, alt_body_1383, alt_body_1384,
                    alt_body_1385, alt_body_1386, alt_body_1387, alt_body_1388,
                    alt_body_1389, alt_body_1390, alt_body_1391, alt_body_1392,
                    alt_body_1393, alt_body_1394, alt_body_1395, alt_body_1396,
                    alt_body_1397, alt_body_1398, alt_body_1399, alt_body_1400,
                    alt_body_1401, alt_body_1402, alt_body_1403, alt_body_1404,
                    alt_body_1405, alt_body_1406, alt_body_1407, alt_body_1408,
                    alt_body_1409, alt_body_1410, alt_body_1411, alt_body_1412,
                    alt_body_1413, alt_body_1414, alt_body_1415, alt_body_1416,
                    alt_body_1417, alt_body_1418, alt_body_1419, alt_body_1420,
                    alt_body_1421, alt_body_1422, alt_body_1423, alt_body_1424,
                    alt_body_1425, alt_body_1426, alt_body_1427, alt_body_1428,
                    alt_body_1429, alt_body_1430, alt_body_1431, alt_body_1432,
                    alt_body_1433, alt_body_1434, alt_body_1435, alt_body_1436,
                    alt_body_1437, alt_body_1438, alt_body_1439, alt_body_1440,
                    alt_body_1441, alt_body_1442, alt_body_1443, alt_body_1444,
                    alt_body_1445, alt_body_1446, alt_body_1447, alt_body_1448,
                    alt_body_1449, alt_body_1450, alt_body_1451, alt_body_1452,
                    alt_body_1453, alt_body_1454, alt_body_1455, alt_body_1456,
                    alt_body_1457, alt_body_1458, alt_body_1459, alt_body_1460,
                    alt_body_1461, alt_body_1462, alt_body_1463, alt_body_1464,
                    alt_body_1465, alt_body_1466, alt_body_1467, alt_body_1468,
                    alt_body_1469, alt_body_1470, alt_body_1471, alt_body_1472,
                    alt_body_1473, alt_body_1474, alt_body_1475, alt_body_1476,
                    alt_body_1477, alt_body_1478, alt_body_1479, alt_body_1480,
                    alt_body_1481, alt_body_1482, alt_body_1483, alt_body_1484,
                    alt_body_1485, alt_body_1486, alt_body_1487, alt_body_1488,
                    alt_body_1489, alt_body_1490, alt_body_1491, alt_body_1492,
                    alt_body_1493, alt_body_1494, alt_body_1495, alt_body_1496,
                    alt_body_1497, alt_body_1498, alt_body_1499, alt_body_1500,
                    alt_body_1501, alt_body_1502, alt_body_1503, alt_body_1504,
                    alt_body_1505, alt_body_1506, alt_body_1507, alt_body_1508,
                    alt_body_1509, alt_body_1510, alt_body_1511, alt_body_1512,
                    alt_body_1513, alt_body_1514, alt_body_1515, alt_body_1516,
                    alt_body_1517, alt_body_1518, alt_body_1519, alt_body_1520,
                    alt_body_1521, alt_body_1522, alt_body_1523, alt_body_1524,
                    alt_body_1525, alt_body_1526, alt_body_1527, alt_body_1528,
                    alt_body_1529, alt_body_1530, alt_body_1531, alt_body_1532,
                    alt_body_1533, alt_body_1534, alt_body_1535, alt_body_1536,
                    alt_post_cstr_a,
                    alt_post_cstr_b,
                    field_665_u32, field_666_u32, field_667_u32, field_668_u32,
                    field_669_u32, field_670_u32, field_671_u32, field_672_u32,
                    field_673_u32, field_674_u32, field_675_u32, field_676_u32,
                    field_677_u32, field_678_u32, field_679_u32, field_680_u32,
                    field_681_u32, field_682_u32, field_683_u32, field_684_u32,
                    field_685_u32, field_686_u32, field_687_u32, field_688_u32,
                    field_689_u32, field_690_u32, field_691_u32, field_692_u32,
                    field_693_u32, field_694_u32, field_695_u32, field_696_u32,
                    field_697_u32, field_698_u32, field_699_u32, field_700_u32,
                    field_701_u32, field_702_u32, field_703_u32, field_704_u32,
                    field_705_u32, field_706_u32, field_707_u32, field_708_u32,
                    field_709_u32, field_710_u32, field_711_u32, field_712_u32,
                    field_713_u32, field_714_u32, field_715_u32, field_716_u32,
                    field_717_u32, field_718_u32, field_719_u32, field_720_u32,
                    field_721_u32, field_722_u32, field_723_u32, field_724_u32,
                    field_725_u32, field_726_u32, field_727_u32, field_728_u32,
                    tail_pad_001, tail_pad_002, tail_pad_003, tail_pad_004,
                    post_blob,
                })
            }
            Err(_) => {
                let blob = data[tail_start..entry_end].to_vec();
                *offset = entry_end;
                Ok(GimmickTail::Raw(blob))
            }
        }
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            GimmickTail::Decoded { gimmick_interaction_override_list,
                use_interaction_ui_socket, use_sub_part_for_interaction,
                property_list, gimmick_name_hash, gimmick_name,
                emoji_texture_id, dev_memo,
                hash_pair_list, hash_single_list,
                trigger_event_handler_list, gimmick_chart_parameter_list,
                field_19_u32_list, field_20_u32_list,
                field_21_u32_list, field_22_u32_list,
                field_23_u32_list, field_24_u32_list,
                field_24_emissive_flag_a, field_24_emissive_value_a,
                field_24_emissive_flag_b, field_24_emissive_name,
                field_24_emissive_value_b,
                field_25_u32_list, field_26_u32, field_27_u32_list,
                field_28_u32, field_29_u32_list, field_30_u32_list,
                field_31_u32_list,
                f31_alt_001, f31_alt_002, f31_alt_003, f31_alt_004,
                f31_alt_005, f31_alt_006, f31_alt_007, f31_alt_008,
                f31_alt_009, f31_alt_010, f31_alt_011, f31_alt_012,
                f31_alt_013, f31_alt_014, f31_alt_015, f31_alt_016,
                f31_alt_017, f31_alt_018, f31_alt_019, f31_alt_020,
                f31_alt_021, f31_alt_022, f31_alt_023, f31_alt_024,
                f31_alt_025, f31_alt_026, f31_alt_027, f31_alt_028,
                f31_alt_029, f31_alt_030, f31_alt_031, f31_alt_032,
                f31_alt_033, f31_alt_034, f31_alt_035, f31_alt_036,
                f31_alt_037, f31_alt_038, f31_alt_039, f31_alt_040,
                f31_alt_041, f31_alt_042, f31_alt_043, f31_alt_044,
                f31_alt_045, f31_alt_046, f31_alt_047, f31_alt_048,
                f31_alt_049, f31_alt_050, f31_alt_051, f31_alt_052,
                f31_alt_053, f31_alt_054, f31_alt_055, f31_alt_056,
                f31_alt_057, f31_alt_058, f31_alt_059, f31_alt_060,
                f31_alt_061, f31_alt_062, f31_alt_063, f31_alt_064,
                f31_alt_065, f31_alt_066, f31_alt_067, f31_alt_068,
                f31_alt_069, f31_alt_070, f31_alt_071, f31_alt_072,
                f31_alt_073, f31_alt_074, f31_alt_075, f31_alt_076,
                f31_alt_077, f31_alt_078, f31_alt_079, f31_alt_080,
                f31_alt_081, f31_alt_082, f31_alt_083, f31_alt_084,
                f31_alt_085, f31_alt_086, f31_alt_087, f31_alt_088,
                f31_alt_089, f31_alt_090, f31_alt_091, f31_alt_092,
                f31_alt_093, f31_alt_094, f31_alt_095, f31_alt_096,
                f31_alt_097, f31_alt_098, f31_alt_099, f31_alt_100,
                f31_alt_101, f31_alt_102, f31_alt_103, f31_alt_104,
                f31_alt_105, f31_alt_106, f31_alt_107, f31_alt_108,
                f31_alt_109, f31_alt_110, f31_alt_111, f31_alt_112,
                f31_alt_113, f31_alt_114, f31_alt_115, f31_alt_116,
                f31_alt_117, f31_alt_118, f31_alt_119, f31_alt_120,
                f31_alt_121, f31_alt_122, f31_alt_123, f31_alt_124,
                f31_alt_125, f31_alt_126, f31_alt_127, f31_alt_128,
                f31_alt_129, f31_alt_130, f31_alt_131, f31_alt_132,
                f31_alt_133, f31_alt_134, f31_alt_135, f31_alt_136,
                f31_alt_137, f31_alt_138, f31_alt_139, f31_alt_140,
                f31_alt_141, f31_alt_142, f31_alt_143, f31_alt_144,
                f31_alt_145, f31_alt_146, f31_alt_147, f31_alt_148,
                f31_alt_149, f31_alt_150, f31_alt_151, f31_alt_152,
                f31_alt_153, f31_alt_154, f31_alt_155, f31_alt_156,
                f31_alt_157, f31_alt_158, f31_alt_159, f31_alt_160,
                f31_alt_161, f31_alt_162, f31_alt_163, f31_alt_164,
                f31_alt_165, f31_alt_166, f31_alt_167, f31_alt_168,
                f31_alt_169, f31_alt_170, f31_alt_171, f31_alt_172,
                f31_alt_173, f31_alt_174, f31_alt_175, f31_alt_176,
                f31_alt_177, f31_alt_178, f31_alt_179, f31_alt_180,
                f31_alt_181, f31_alt_182, f31_alt_183, f31_alt_184,
                f31_alt_185, f31_alt_186, f31_alt_187, f31_alt_188,
                f31_alt_189, f31_alt_190, f31_alt_191, f31_alt_192,
                f31_alt_193, f31_alt_194, f31_alt_195, f31_alt_196,
                f31_alt_197, f31_alt_198, f31_alt_199, f31_alt_200,
                f31_alt_201, f31_alt_202, f31_alt_203, f31_alt_204,
                f31_alt_205, f31_alt_206, f31_alt_207, f31_alt_208,
                f31_alt_209, f31_alt_210, f31_alt_211, f31_alt_212,
                f31_alt_213, f31_alt_214, f31_alt_215, f31_alt_216,
                f31_alt_217, f31_alt_218, f31_alt_219, f31_alt_220,
                f31_alt_221, f31_alt_222, f31_alt_223, f31_alt_224,
                f31_alt_225, f31_alt_226, f31_alt_227, f31_alt_228,
                f31_alt_229, f31_alt_230, f31_alt_231, f31_alt_232,
                f31_alt_233, f31_alt_234, f31_alt_235, f31_alt_236,
                f31_alt_237, f31_alt_238, f31_alt_239, f31_alt_240,
                f31_alt_241, f31_alt_242, f31_alt_243, f31_alt_244,
                f31_alt_245, f31_alt_246, f31_alt_247, f31_alt_248,
                f31_alt_249, f31_alt_250, f31_alt_251, f31_alt_252,
                f31_alt_253, f31_alt_254, f31_alt_255, f31_alt_256,
                field_32_u32_list,
                f32_alt_001, f32_alt_002, f32_alt_003, f32_alt_004,
                f32_alt_005, f32_alt_006, f32_alt_007, f32_alt_008,
                f32_alt_009, f32_alt_010, f32_alt_011, f32_alt_012,
                f32_alt_013, f32_alt_014, f32_alt_015, f32_alt_016,
                f32_alt_017, f32_alt_018, f32_alt_019, f32_alt_020,
                f32_alt_021, f32_alt_022, f32_alt_023, f32_alt_024,
                f32_alt_025, f32_alt_026, f32_alt_027, f32_alt_028,
                f32_alt_029, f32_alt_030, f32_alt_031, f32_alt_032,
                f32_alt_033, f32_alt_034, f32_alt_035, f32_alt_036,
                f32_alt_037, f32_alt_038, f32_alt_039, f32_alt_040,
                f32_alt_041, f32_alt_042, f32_alt_043, f32_alt_044,
                f32_alt_045, f32_alt_046, f32_alt_047, f32_alt_048,
                f32_alt_049, f32_alt_050, f32_alt_051, f32_alt_052,
                f32_alt_053, f32_alt_054, f32_alt_055, f32_alt_056,
                f32_alt_057, f32_alt_058, f32_alt_059, f32_alt_060,
                f32_alt_061, f32_alt_062, f32_alt_063, f32_alt_064,
                f32_alt_065, f32_alt_066, f32_alt_067, f32_alt_068,
                f32_alt_069, f32_alt_070, f32_alt_071, f32_alt_072,
                f32_alt_073, f32_alt_074, f32_alt_075, f32_alt_076,
                f32_alt_077, f32_alt_078, f32_alt_079, f32_alt_080,
                f32_alt_081, f32_alt_082, f32_alt_083, f32_alt_084,
                f32_alt_085, f32_alt_086, f32_alt_087, f32_alt_088,
                f32_alt_089, f32_alt_090, f32_alt_091, f32_alt_092,
                f32_alt_093, f32_alt_094, f32_alt_095, f32_alt_096,
                f32_alt_097, f32_alt_098, f32_alt_099, f32_alt_100,
                f32_alt_101, f32_alt_102, f32_alt_103, f32_alt_104,
                f32_alt_105, f32_alt_106, f32_alt_107, f32_alt_108,
                f32_alt_109, f32_alt_110, f32_alt_111, f32_alt_112,
                f32_alt_113, f32_alt_114, f32_alt_115, f32_alt_116,
                f32_alt_117, f32_alt_118, f32_alt_119, f32_alt_120,
                f32_alt_121, f32_alt_122, f32_alt_123, f32_alt_124,
                f32_alt_125, f32_alt_126, f32_alt_127, f32_alt_128,
                f32_alt_129, f32_alt_130, f32_alt_131, f32_alt_132,
                f32_alt_133, f32_alt_134, f32_alt_135, f32_alt_136,
                f32_alt_137, f32_alt_138, f32_alt_139, f32_alt_140,
                f32_alt_141, f32_alt_142, f32_alt_143, f32_alt_144,
                f32_alt_145, f32_alt_146, f32_alt_147, f32_alt_148,
                f32_alt_149, f32_alt_150, f32_alt_151, f32_alt_152,
                f32_alt_153, f32_alt_154, f32_alt_155, f32_alt_156,
                f32_alt_157, f32_alt_158, f32_alt_159, f32_alt_160,
                f32_alt_161, f32_alt_162, f32_alt_163, f32_alt_164,
                f32_alt_165, f32_alt_166, f32_alt_167, f32_alt_168,
                f32_alt_169, f32_alt_170, f32_alt_171, f32_alt_172,
                f32_alt_173, f32_alt_174, f32_alt_175, f32_alt_176,
                f32_alt_177, f32_alt_178, f32_alt_179, f32_alt_180,
                f32_alt_181, f32_alt_182, f32_alt_183, f32_alt_184,
                f32_alt_185, f32_alt_186, f32_alt_187, f32_alt_188,
                f32_alt_189, f32_alt_190, f32_alt_191, f32_alt_192,
                field_33_u32, field_34_u32,
                field_35_u32_list, field_36_u32,
                field_37_u32, field_38_u32,
                field_39_u32_list,
                f39_alt_001, f39_alt_002, f39_alt_003, f39_alt_004,
                f39_alt_005, f39_alt_006, f39_alt_007, f39_alt_008,
                f39_alt_009, f39_alt_010, f39_alt_011, f39_alt_012,
                f39_alt_013, f39_alt_014, f39_alt_015, f39_alt_016,
                f39_alt_017, f39_alt_018, f39_alt_019, f39_alt_020,
                f39_alt_021, f39_alt_022, f39_alt_023, f39_alt_024,
                f39_alt_025, f39_alt_026, f39_alt_027, f39_alt_028,
                f39_alt_029, f39_alt_030, f39_alt_031, f39_alt_032,
                f39_alt_033, f39_alt_034, f39_alt_035, f39_alt_036,
                f39_alt_037, f39_alt_038, f39_alt_039, f39_alt_040,
                f39_alt_041, f39_alt_042, f39_alt_043, f39_alt_044,
                f39_alt_045, f39_alt_046, f39_alt_047, f39_alt_048,
                f39_alt_049, f39_alt_050, f39_alt_051, f39_alt_052,
                f39_alt_053, f39_alt_054, f39_alt_055, f39_alt_056,
                f39_alt_057, f39_alt_058, f39_alt_059, f39_alt_060,
                f39_alt_061, f39_alt_062, f39_alt_063, f39_alt_064,
                f39_alt_065, f39_alt_066, f39_alt_067, f39_alt_068,
                f39_alt_069, f39_alt_070, f39_alt_071, f39_alt_072,
                f39_alt_073, f39_alt_074, f39_alt_075, f39_alt_076,
                f39_alt_077, f39_alt_078, f39_alt_079, f39_alt_080,
                f39_alt_081, f39_alt_082, f39_alt_083, f39_alt_084,
                f39_alt_085, f39_alt_086, f39_alt_087, f39_alt_088,
                f39_alt_089, f39_alt_090, f39_alt_091, f39_alt_092,
                f39_alt_093, f39_alt_094, f39_alt_095, f39_alt_096,
                f39_alt_097, f39_alt_098, f39_alt_099, f39_alt_100,
                f39_alt_101, f39_alt_102, f39_alt_103, f39_alt_104,
                f39_alt_105, f39_alt_106, f39_alt_107, f39_alt_108,
                f39_alt_109, f39_alt_110, f39_alt_111, f39_alt_112,
                f39_alt_113, f39_alt_114, f39_alt_115, f39_alt_116,
                f39_alt_117, f39_alt_118, f39_alt_119, f39_alt_120,
                f39_alt_121, f39_alt_122, f39_alt_123, f39_alt_124,
                f39_alt_125, f39_alt_126, f39_alt_127, f39_alt_128,
                f39_alt_129, f39_alt_130, f39_alt_131, f39_alt_132,
                f39_alt_133, f39_alt_134, f39_alt_135, f39_alt_136,
                f39_alt_137, f39_alt_138, f39_alt_139, f39_alt_140,
                f39_alt_141, f39_alt_142, f39_alt_143, f39_alt_144,
                f39_alt_145, f39_alt_146, f39_alt_147, f39_alt_148,
                f39_alt_149, f39_alt_150, f39_alt_151, f39_alt_152,
                f39_alt_153, f39_alt_154, f39_alt_155, f39_alt_156,
                f39_alt_157, f39_alt_158, f39_alt_159, f39_alt_160,
                f39_alt_161, f39_alt_162, f39_alt_163, f39_alt_164,
                f39_alt_165, f39_alt_166, f39_alt_167, f39_alt_168,
                f39_alt_169, f39_alt_170, f39_alt_171, f39_alt_172,
                f39_alt_173, f39_alt_174, f39_alt_175, f39_alt_176,
                f39_alt_177, f39_alt_178, f39_alt_179, f39_alt_180,
                f39_alt_181, f39_alt_182, f39_alt_183, f39_alt_184,
                f39_alt_185, f39_alt_186, f39_alt_187, f39_alt_188,
                f39_alt_189, f39_alt_190, f39_alt_191, f39_alt_192,
                field_40_u32_list,
                field_41_u32, field_42_u32, field_43_u32, field_44_u32, field_45_u32, field_46_u32, field_47_u32, field_48_u32, field_49_u32_list, field_50_u32_list,
                field_51_u32_list, field_52_u32_list, field_53_u32_list, field_54_u32_list,
                field_55_u32_list, field_56_u32_list, field_57_u32_list, field_58_u32_list,
                field_59_u32, field_60_u32, field_61_u32, field_62_u32,
                field_63_u32, field_64_u32, field_65_u32, field_66_u32,
                field_67_u32, field_68_u32, field_69_u32, field_70_u32,
                field_71_u32, field_72_u32, field_73_u32, field_74_u32,
                field_75_u32, field_76_u32, field_77_u32, field_78_u32,
                field_79_u32, field_80_u32, field_81_u32, field_82_u32,
                field_83_u32, field_84_u32, field_85_u32, field_86_u32,
                field_87_u32, field_88_u32, field_89_u32, field_90_u32,
                field_91_u32, field_92_u32, field_93_u32, field_94_u32,
                field_95_u32, field_96_u32, field_97_u32, field_98_u32,
                field_99_u32, field_100_u32, field_101_u32, field_102_u32,
                field_103_u32, field_104_u32, field_105_u32, field_106_u32,
                field_107_u32, field_108_u32, field_109_u32, field_110_u32,
                field_111_u32, field_112_u32, field_113_u32, field_114_u32,
                field_115_u32, field_116_u32, field_117_u32, field_118_u32,
                field_119_u32, field_120_u32, field_121_u32, field_122_u32,
                field_123_u32, field_124_u32, field_125_u32, field_126_u32,
                field_127_u32, field_128_u32, field_129_u32, field_130_u32,
                field_131_u32, field_132_u32, field_133_u32, field_134_u32,
                field_135_u32, field_136_u32, field_137_u32, field_138_u32,
                field_139_u32, field_140_u32, field_141_u32, field_142_u32,
                field_143_u32, field_144_u32, field_145_u32, field_146_u32,
                field_147_u32, field_148_u32, field_149_u32, field_150_u32,
                field_151_u32, field_152_u32, field_153_u32, field_154_u32,
                field_155_u32, field_156_u32, field_157_u32, field_158_u32,
                field_159_u32, field_160_u32, field_161_u32, field_162_u32,
                field_163_u32, field_164_u32, field_165_u32, field_166_u32,
                field_167_u32, field_168_u32, field_169_u32, field_170_u32,
                field_171_u32, field_172_u32, field_173_u32, field_174_u32,
                field_175_u32, field_176_u32, field_177_u32, field_178_u32,
                field_179_u32, field_180_u32, field_181_u32,
                field_182_u32, field_183_u32, field_184_u32, field_185_u32,
                field_186_u32, field_187_u32, field_188_u32, field_189_u32,
                field_190_u32, field_191_u32, field_192_u32, field_193_u32,
                field_194_u32, field_195_u32, field_196_u32, field_197_u32,
                field_198_u32, field_199_u32, field_200_u32, field_201_u32,
                field_202_u32, field_203_u32, field_204_u32, field_205_u32,
                field_206_u32, field_207_u32, field_208_u32, field_209_u32,
                field_210_u32, field_211_u32, field_212_u32, field_213_u32,
                field_214_u32, field_215_u32, field_216_u32, field_217_u32,
                field_218_u32, field_219_u32, field_220_u32, field_221_u32,
                field_222_u32, field_223_u32, field_224_u32, field_225_u32,
                field_226_u32, field_227_u32, field_228_u32, field_229_u32,
                field_230_u32, field_231_u32, field_232_u32, field_233_u32,
                field_234_u32, field_235_u32, field_236_u32, field_237_u32,
                field_238_u32, field_239_u32, field_240_u32, field_241_u32,
                field_242_u32, field_243_u32, field_244_u32, field_245_u32,
                field_246_u32, field_247_u32, field_248_u32, field_249_u32,
                field_250_u32, field_251_u32, field_252_u32, field_253_u32,
                field_254_u32, field_255_u32, field_256_u32, field_257_u32,
                field_258_u32, field_259_u32, field_260_u32, field_261_u32,
                field_262_u32, field_263_u32, field_264_u32, field_265_u32,
                field_266_u32, field_267_u32, field_268_u32, field_269_u32,
                field_270_u32, field_271_u32, field_272_u32, field_273_u32,
                field_274_u32, field_275_u32, field_276_u32, field_277_u32,
                field_278_u32, field_279_u32, field_280_u32, field_281_u32,
                field_282_u32, field_283_u32, field_284_u32, field_285_u32,
                field_286_u32, field_287_u32, field_288_u32, field_289_u32,
                field_290_u32, field_291_u32, field_292_u32, field_293_u32,
                field_294_u32, field_295_u32, field_296_u32, field_297_u32,
                field_298_u32, field_299_u32, field_300_u32, field_301_u32,
                field_302_u32, field_303_u32, field_304_u32, field_305_u32,
                field_306_u32, field_307_u32, field_308_u32, field_309_u32,
                field_310_u32, field_311_u32, field_312_u32, field_313_u32,
                field_314_u32, field_315_u32, field_316_u32, field_317_u32,
                field_318_u32, field_319_u32, field_320_u32, field_321_u32,
                field_322_u32, field_323_u32, field_324_u32, field_325_u32,
                field_326_u32, field_327_u32, field_328_u32, field_329_u32,
                field_330_u32, field_331_u32, field_332_u32, field_333_u32,
                field_334_u32, field_335_u32, field_336_u32, field_337_u32,
                field_338_u32, field_339_u32, field_340_u32, field_341_u32,
                field_342_u32_count, field_343_u8_flag, field_344_u32,
                field_345_u32, field_346_u32, field_347_u32, field_348_u32,
                field_349_u32, field_350_u32, field_351_u32, field_352_u32,
                field_353_u32, field_354_u32, field_355_u32, field_356_u32,
                field_357_u32, field_358_u32, field_359_u32, field_360_u32,
                field_361_u32, field_362_u32, field_363_u32, field_364_u32,
                field_365_u32, field_366_u32, field_367_u32, field_368_u32,
                field_369_u32, field_370_u32, field_371_u32, field_372_u32,
                field_373_u32, field_374_u32, field_375_u32, field_376_u32,
                field_377_u32, field_378_u32, field_379_u32, field_380_u32,
                field_381_u32, field_382_u32, field_383_u32, field_384_u32,
                field_385_u32, field_386_u32, field_387_u32, field_388_u32,
                field_389_u32, field_390_u32, field_391_u32, field_392_u32,
                field_393_u32, field_394_u32, field_395_u32, field_396_u32,
                field_397_u32, field_398_u32, field_399_u32, field_400_u32,
                field_401_u32, field_402_u32, field_403_u32, field_404_u32,
                field_405_u32, field_406_u32, field_407_u32, field_408_u32,
                field_409_u32, field_410_u32, field_411_u32, field_412_u32,
                field_413_u32, field_414_u32, field_415_u32, field_416_u32,
                field_417_u32, field_418_u32, field_419_u32, field_420_u32,
                field_421_u32, field_422_u32, field_423_u32, field_424_u32,
                field_425_u32, field_426_u32, field_427_u32, field_428_u32,
                field_429_u32, field_430_u32, field_431_u32, field_432_u32,
                field_433_u32, field_434_u32, field_435_u32, field_436_u32,
                field_437_u32, field_438_u32, field_439_u32, field_440_u32,
                field_441_u32, field_442_u32, field_443_u32, field_444_u32,
                field_445_u32, field_446_u32, field_447_u32, field_448_u32,
                field_449_u32, field_450_u32, field_451_u32, field_452_u32,
                field_453_u32, field_454_u32, field_455_u32, field_456_u32,
                field_457_u32, field_458_u32, field_459_u32, field_460_u32,
                field_461_u32, field_462_u32, field_463_u32, field_464_u32,
                field_465_u32, field_466_u32, field_467_u32, field_468_u32,
                field_469_u32, field_470_u32, field_471_u32, field_472_u32,
                field_473_u32, field_474_u32, field_475_u32, field_476_u32,
                field_477_u32, field_478_u32, field_479_u32, field_480_u32,
                field_481_u32, field_482_u32, field_483_u32, field_484_u32,
                field_485_u32, field_486_u32, field_487_u32, field_488_u32,
                field_489_u32, field_490_u32, field_491_u32, field_492_u32,
                field_493_u32, field_494_u32, field_495_u32, field_496_u32,
                field_497_u32, field_498_u32, field_499_u32, field_500_u32,
                field_501_u32, field_502_u32, field_503_u32, field_504_u32,
                field_505_u32, field_506_u32, field_507_u32, field_508_u32,
                field_509_u32, field_510_u32, field_511_u32, field_512_u32,
                field_513_u32, field_514_u32, field_515_u32, field_516_u32,
                field_517_u32, field_518_u32, field_519_u32, field_520_u32,
                field_521_u32, field_522_u32, field_523_u32, field_524_u32,
                field_525_u32, field_526_u32, field_527_u32, field_528_u32,
                field_529_u32, field_530_u32, field_531_u32, field_532_u32,
                field_533_u32, field_534_u32, field_535_u32, field_536_u32,
                field_537_u32, field_538_u32, field_539_u32, field_540_u32,
                field_541_u32, field_542_u32, field_543_u32, field_544_u32,
                field_545_u32, field_546_u32, field_547_u32, field_548_u32,
                field_549_u32, field_550_u32, field_551_u32, field_552_u32,
                field_553_u32, field_554_u32, field_555_u32, field_556_u32,
                field_557_u32, field_558_u32, field_559_u32, field_560_u32,
                field_561_u32, field_562_u32, field_563_u32, field_564_u32,
                field_565_u32, field_566_u32, field_567_u32, field_568_u32,
                field_569_u32, field_570_u32, field_571_u32, field_572_u32,
                field_573_u32, field_574_u32, field_575_u32, field_576_u32,
                field_577_u32, field_578_u32, field_579_u32, field_580_u32,
                field_581_u32, field_582_u32, field_583_u32, field_584_u32,
                field_585_u32, field_586_u32, field_587_u32, field_588_u32,
                field_589_u32, field_590_u32, field_591_u32, field_592_u32,
                field_593_u32, field_594_u32, field_595_u32, field_596_u32,
                field_597_u32, field_598_u32, field_599_u32, field_600_u32,
                field_601_u32, field_602_u32, field_603_u32, field_604_u32,
                field_605_u32, field_606_u32, field_607_u32, field_608_u32,
                field_609_u32, field_610_u32, field_611_u32, field_612_u32,
                field_613_u32, field_614_u32, field_615_u32, field_616_u32,
                field_617_u32, field_618_u32, field_619_u32, field_620_u32,
                field_621_u32, field_622_u32, field_623_u32, field_624_u32,
                field_625_u32, field_626_u32, field_627_u32, field_628_u32,
                field_629_u32, field_630_u32, field_631_u32, field_632_u32,
                field_633_u32, field_634_u32, field_635_u32, field_636_u32,
                field_637_u32, field_638_u32, field_639_u32, field_640_u32,
                field_641_u32, field_642_u32, field_643_u32, field_644_u32,
                field_645_u32, field_646_u32, field_647_u32, field_648_u32,
                field_649_u32, field_650_u32, field_651_u32, field_652_u32,
                field_653_u32, field_654_u32, field_655_u32, field_656_u32,
                field_657_u32, field_658_u32, field_659_u32, field_660_u32,
                field_661_u32, field_662_u32, field_663_u32, field_664_u32,
                alt_trigger_count, alt_trigger_flag, alt_trigger_name,
                alt_inner_count, alt_inner_name, alt_inner_flag,
                alt_body_001, alt_body_002, alt_body_003, alt_body_004,
                alt_body_005, alt_body_006, alt_body_007, alt_body_008,
                alt_body_009, alt_body_010, alt_body_011, alt_body_012,
                alt_body_013, alt_body_014, alt_body_015, alt_body_016,
                alt_body_017, alt_body_018, alt_body_019, alt_body_020,
                alt_body_021, alt_body_022, alt_body_023, alt_body_024,
                alt_body_025, alt_body_026, alt_body_027, alt_body_028,
                alt_body_029, alt_body_030, alt_body_031, alt_body_032,
                alt_body_033, alt_body_034, alt_body_035, alt_body_036,
                alt_body_037, alt_body_038, alt_body_039, alt_body_040,
                alt_body_041, alt_body_042, alt_body_043, alt_body_044,
                alt_body_045, alt_body_046, alt_body_047, alt_body_048,
                alt_body_049, alt_body_050, alt_body_051, alt_body_052,
                alt_body_053, alt_body_054, alt_body_055, alt_body_056,
                alt_body_057, alt_body_058, alt_body_059, alt_body_060,
                alt_body_061, alt_body_062, alt_body_063, alt_body_064,
                alt_body_065, alt_body_066, alt_body_067, alt_body_068,
                alt_body_069, alt_body_070, alt_body_071, alt_body_072,
                alt_body_073, alt_body_074, alt_body_075, alt_body_076,
                alt_body_077, alt_body_078, alt_body_079, alt_body_080,
                alt_body_081, alt_body_082, alt_body_083, alt_body_084,
                alt_body_085, alt_body_086, alt_body_087, alt_body_088,
                alt_body_089, alt_body_090, alt_body_091, alt_body_092,
                alt_body_093, alt_body_094, alt_body_095, alt_body_096,
                alt_body_097, alt_body_098, alt_body_099, alt_body_100,
                alt_body_101, alt_body_102, alt_body_103, alt_body_104,
                alt_body_105, alt_body_106, alt_body_107, alt_body_108,
                alt_body_109, alt_body_110, alt_body_111, alt_body_112,
                alt_body_113, alt_body_114, alt_body_115, alt_body_116,
                alt_body_117, alt_body_118, alt_body_119, alt_body_120,
                alt_body_121, alt_body_122, alt_body_123, alt_body_124,
                alt_body_125, alt_body_126, alt_body_127, alt_body_128,
                alt_body_129, alt_body_130, alt_body_131, alt_body_132,
                alt_body_133, alt_body_134, alt_body_135, alt_body_136,
                alt_body_137, alt_body_138, alt_body_139, alt_body_140,
                alt_body_141, alt_body_142, alt_body_143, alt_body_144,
                alt_body_145, alt_body_146, alt_body_147, alt_body_148,
                alt_body_149, alt_body_150, alt_body_151, alt_body_152,
                alt_body_153, alt_body_154, alt_body_155, alt_body_156,
                alt_body_157, alt_body_158, alt_body_159, alt_body_160,
                alt_body_161, alt_body_162, alt_body_163, alt_body_164,
                alt_body_165, alt_body_166, alt_body_167, alt_body_168,
                alt_body_169, alt_body_170, alt_body_171, alt_body_172,
                alt_body_173, alt_body_174, alt_body_175, alt_body_176,
                alt_body_177, alt_body_178, alt_body_179, alt_body_180,
                alt_body_181, alt_body_182, alt_body_183, alt_body_184,
                alt_body_185, alt_body_186, alt_body_187, alt_body_188,
                alt_body_189, alt_body_190, alt_body_191, alt_body_192,
                alt_body_193, alt_body_194, alt_body_195, alt_body_196,
                alt_body_197, alt_body_198, alt_body_199, alt_body_200,
                alt_body_201, alt_body_202, alt_body_203, alt_body_204,
                alt_body_205, alt_body_206, alt_body_207, alt_body_208,
                alt_body_209, alt_body_210, alt_body_211, alt_body_212,
                alt_body_213, alt_body_214, alt_body_215, alt_body_216,
                alt_body_217, alt_body_218, alt_body_219, alt_body_220,
                alt_body_221, alt_body_222, alt_body_223, alt_body_224,
                alt_body_225, alt_body_226, alt_body_227, alt_body_228,
                alt_body_229, alt_body_230, alt_body_231, alt_body_232,
                alt_body_233, alt_body_234, alt_body_235, alt_body_236,
                alt_body_237, alt_body_238, alt_body_239, alt_body_240,
                alt_body_241, alt_body_242, alt_body_243, alt_body_244,
                alt_body_245, alt_body_246, alt_body_247, alt_body_248,
                alt_body_249, alt_body_250, alt_body_251, alt_body_252,
                alt_body_253, alt_body_254, alt_body_255, alt_body_256,
                alt_body_257, alt_body_258, alt_body_259, alt_body_260,
                alt_body_261, alt_body_262, alt_body_263, alt_body_264,
                alt_body_265, alt_body_266, alt_body_267, alt_body_268,
                alt_body_269, alt_body_270, alt_body_271, alt_body_272,
                alt_body_273, alt_body_274, alt_body_275, alt_body_276,
                alt_body_277, alt_body_278, alt_body_279, alt_body_280,
                alt_body_281, alt_body_282, alt_body_283, alt_body_284,
                alt_body_285, alt_body_286, alt_body_287, alt_body_288,
                alt_body_289, alt_body_290, alt_body_291, alt_body_292,
                alt_body_293, alt_body_294, alt_body_295, alt_body_296,
                alt_body_297, alt_body_298, alt_body_299, alt_body_300,
                alt_body_301, alt_body_302, alt_body_303, alt_body_304,
                alt_body_305, alt_body_306, alt_body_307, alt_body_308,
                alt_body_309, alt_body_310, alt_body_311, alt_body_312,
                alt_body_313, alt_body_314, alt_body_315, alt_body_316,
                alt_body_317, alt_body_318, alt_body_319, alt_body_320,
                alt_body_321, alt_body_322, alt_body_323, alt_body_324,
                alt_body_325, alt_body_326, alt_body_327, alt_body_328,
                alt_body_329, alt_body_330, alt_body_331, alt_body_332,
                alt_body_333, alt_body_334, alt_body_335, alt_body_336,
                alt_body_337, alt_body_338, alt_body_339, alt_body_340,
                alt_body_341, alt_body_342, alt_body_343, alt_body_344,
                alt_body_345, alt_body_346, alt_body_347, alt_body_348,
                alt_body_349, alt_body_350, alt_body_351, alt_body_352,
                alt_body_353, alt_body_354, alt_body_355, alt_body_356,
                alt_body_357, alt_body_358, alt_body_359, alt_body_360,
                alt_body_361, alt_body_362, alt_body_363, alt_body_364,
                alt_body_365, alt_body_366, alt_body_367, alt_body_368,
                alt_body_369, alt_body_370, alt_body_371, alt_body_372,
                alt_body_373, alt_body_374, alt_body_375, alt_body_376,
                alt_body_377, alt_body_378, alt_body_379, alt_body_380,
                alt_body_381, alt_body_382, alt_body_383, alt_body_384,
                alt_body_385, alt_body_386, alt_body_387, alt_body_388,
                alt_body_389, alt_body_390, alt_body_391, alt_body_392,
                alt_body_393, alt_body_394, alt_body_395, alt_body_396,
                alt_body_397, alt_body_398, alt_body_399, alt_body_400,
                alt_body_401, alt_body_402, alt_body_403, alt_body_404,
                alt_body_405, alt_body_406, alt_body_407, alt_body_408,
                alt_body_409, alt_body_410, alt_body_411, alt_body_412,
                alt_body_413, alt_body_414, alt_body_415, alt_body_416,
                alt_body_417, alt_body_418, alt_body_419, alt_body_420,
                alt_body_421, alt_body_422, alt_body_423, alt_body_424,
                alt_body_425, alt_body_426, alt_body_427, alt_body_428,
                alt_body_429, alt_body_430, alt_body_431, alt_body_432,
                alt_body_433, alt_body_434, alt_body_435, alt_body_436,
                alt_body_437, alt_body_438, alt_body_439, alt_body_440,
                alt_body_441, alt_body_442, alt_body_443, alt_body_444,
                alt_body_445, alt_body_446, alt_body_447, alt_body_448,
                alt_body_449, alt_body_450, alt_body_451, alt_body_452,
                alt_body_453, alt_body_454, alt_body_455, alt_body_456,
                alt_body_457, alt_body_458, alt_body_459, alt_body_460,
                alt_body_461, alt_body_462, alt_body_463, alt_body_464,
                alt_body_465, alt_body_466, alt_body_467, alt_body_468,
                alt_body_469, alt_body_470, alt_body_471, alt_body_472,
                alt_body_473, alt_body_474, alt_body_475, alt_body_476,
                alt_body_477, alt_body_478, alt_body_479, alt_body_480,
                alt_body_481, alt_body_482, alt_body_483, alt_body_484,
                alt_body_485, alt_body_486, alt_body_487, alt_body_488,
                alt_body_489, alt_body_490, alt_body_491, alt_body_492,
                alt_body_493, alt_body_494, alt_body_495, alt_body_496,
                alt_body_497, alt_body_498, alt_body_499, alt_body_500,
                alt_body_501, alt_body_502, alt_body_503, alt_body_504,
                alt_body_505, alt_body_506, alt_body_507, alt_body_508,
                alt_body_509, alt_body_510, alt_body_511, alt_body_512,
                alt_body_513, alt_body_514, alt_body_515, alt_body_516,
                alt_body_517, alt_body_518, alt_body_519, alt_body_520,
                alt_body_521, alt_body_522, alt_body_523, alt_body_524,
                alt_body_525, alt_body_526, alt_body_527, alt_body_528,
                alt_body_529, alt_body_530, alt_body_531, alt_body_532,
                alt_body_533, alt_body_534, alt_body_535, alt_body_536,
                alt_body_537, alt_body_538, alt_body_539, alt_body_540,
                alt_body_541, alt_body_542, alt_body_543, alt_body_544,
                alt_body_545, alt_body_546, alt_body_547, alt_body_548,
                alt_body_549, alt_body_550, alt_body_551, alt_body_552,
                alt_body_553, alt_body_554, alt_body_555, alt_body_556,
                alt_body_557, alt_body_558, alt_body_559, alt_body_560,
                alt_body_561, alt_body_562, alt_body_563, alt_body_564,
                alt_body_565, alt_body_566, alt_body_567, alt_body_568,
                alt_body_569, alt_body_570, alt_body_571, alt_body_572,
                alt_body_573, alt_body_574, alt_body_575, alt_body_576,
                alt_body_577, alt_body_578, alt_body_579, alt_body_580,
                alt_body_581, alt_body_582, alt_body_583, alt_body_584,
                alt_body_585, alt_body_586, alt_body_587, alt_body_588,
                alt_body_589, alt_body_590, alt_body_591, alt_body_592,
                alt_body_593, alt_body_594, alt_body_595, alt_body_596,
                alt_body_597, alt_body_598, alt_body_599, alt_body_600,
                alt_body_601, alt_body_602, alt_body_603, alt_body_604,
                alt_body_605, alt_body_606, alt_body_607, alt_body_608,
                alt_body_609, alt_body_610, alt_body_611, alt_body_612,
                alt_body_613, alt_body_614, alt_body_615, alt_body_616,
                alt_body_617, alt_body_618, alt_body_619, alt_body_620,
                alt_body_621, alt_body_622, alt_body_623, alt_body_624,
                alt_body_625, alt_body_626, alt_body_627, alt_body_628,
                alt_body_629, alt_body_630, alt_body_631, alt_body_632,
                alt_body_633, alt_body_634, alt_body_635, alt_body_636,
                alt_body_637, alt_body_638, alt_body_639, alt_body_640,
                alt_body_641, alt_body_642, alt_body_643, alt_body_644,
                alt_body_645, alt_body_646, alt_body_647, alt_body_648,
                alt_body_649, alt_body_650, alt_body_651, alt_body_652,
                alt_body_653, alt_body_654, alt_body_655, alt_body_656,
                alt_body_657, alt_body_658, alt_body_659, alt_body_660,
                alt_body_661, alt_body_662, alt_body_663, alt_body_664,
                alt_body_665, alt_body_666, alt_body_667, alt_body_668,
                alt_body_669, alt_body_670, alt_body_671, alt_body_672,
                alt_body_673, alt_body_674, alt_body_675, alt_body_676,
                alt_body_677, alt_body_678, alt_body_679, alt_body_680,
                alt_body_681, alt_body_682, alt_body_683, alt_body_684,
                alt_body_685, alt_body_686, alt_body_687, alt_body_688,
                alt_body_689, alt_body_690, alt_body_691, alt_body_692,
                alt_body_693, alt_body_694, alt_body_695, alt_body_696,
                alt_body_697, alt_body_698, alt_body_699, alt_body_700,
                alt_body_701, alt_body_702, alt_body_703, alt_body_704,
                alt_body_705, alt_body_706, alt_body_707, alt_body_708,
                alt_body_709, alt_body_710, alt_body_711, alt_body_712,
                alt_body_713, alt_body_714, alt_body_715, alt_body_716,
                alt_body_717, alt_body_718, alt_body_719, alt_body_720,
                alt_body_721, alt_body_722, alt_body_723, alt_body_724,
                alt_body_725, alt_body_726, alt_body_727, alt_body_728,
                alt_body_729, alt_body_730, alt_body_731, alt_body_732,
                alt_body_733, alt_body_734, alt_body_735, alt_body_736,
                alt_body_737, alt_body_738, alt_body_739, alt_body_740,
                alt_body_741, alt_body_742, alt_body_743, alt_body_744,
                alt_body_745, alt_body_746, alt_body_747, alt_body_748,
                alt_body_749, alt_body_750, alt_body_751, alt_body_752,
                alt_body_753, alt_body_754, alt_body_755, alt_body_756,
                alt_body_757, alt_body_758, alt_body_759, alt_body_760,
                alt_body_761, alt_body_762, alt_body_763, alt_body_764,
                alt_body_765, alt_body_766, alt_body_767, alt_body_768,
                alt_body_769, alt_body_770, alt_body_771, alt_body_772,
                alt_body_773, alt_body_774, alt_body_775, alt_body_776,
                alt_body_777, alt_body_778, alt_body_779, alt_body_780,
                alt_body_781, alt_body_782, alt_body_783, alt_body_784,
                alt_body_785, alt_body_786, alt_body_787, alt_body_788,
                alt_body_789, alt_body_790, alt_body_791, alt_body_792,
                alt_body_793, alt_body_794, alt_body_795, alt_body_796,
                alt_body_797, alt_body_798, alt_body_799, alt_body_800,
                alt_body_801, alt_body_802, alt_body_803, alt_body_804,
                alt_body_805, alt_body_806, alt_body_807, alt_body_808,
                alt_body_809, alt_body_810, alt_body_811, alt_body_812,
                alt_body_813, alt_body_814, alt_body_815, alt_body_816,
                alt_body_817, alt_body_818, alt_body_819, alt_body_820,
                alt_body_821, alt_body_822, alt_body_823, alt_body_824,
                alt_body_825, alt_body_826, alt_body_827, alt_body_828,
                alt_body_829, alt_body_830, alt_body_831, alt_body_832,
                alt_body_833, alt_body_834, alt_body_835, alt_body_836,
                alt_body_837, alt_body_838, alt_body_839, alt_body_840,
                alt_body_841, alt_body_842, alt_body_843, alt_body_844,
                alt_body_845, alt_body_846, alt_body_847, alt_body_848,
                alt_body_849, alt_body_850, alt_body_851, alt_body_852,
                alt_body_853, alt_body_854, alt_body_855, alt_body_856,
                alt_body_857, alt_body_858, alt_body_859, alt_body_860,
                alt_body_861, alt_body_862, alt_body_863, alt_body_864,
                alt_body_865, alt_body_866, alt_body_867, alt_body_868,
                alt_body_869, alt_body_870, alt_body_871, alt_body_872,
                alt_body_873, alt_body_874, alt_body_875, alt_body_876,
                alt_body_877, alt_body_878, alt_body_879, alt_body_880,
                alt_body_881, alt_body_882, alt_body_883, alt_body_884,
                alt_body_885, alt_body_886, alt_body_887, alt_body_888,
                alt_body_889, alt_body_890, alt_body_891, alt_body_892,
                alt_body_893, alt_body_894, alt_body_895, alt_body_896,
                alt_body_897, alt_body_898, alt_body_899, alt_body_900,
                alt_body_901, alt_body_902, alt_body_903, alt_body_904,
                alt_body_905, alt_body_906, alt_body_907, alt_body_908,
                alt_body_909, alt_body_910, alt_body_911, alt_body_912,
                alt_body_913, alt_body_914, alt_body_915, alt_body_916,
                alt_body_917, alt_body_918, alt_body_919, alt_body_920,
                alt_body_921, alt_body_922, alt_body_923, alt_body_924,
                alt_body_925, alt_body_926, alt_body_927, alt_body_928,
                alt_body_929, alt_body_930, alt_body_931, alt_body_932,
                alt_body_933, alt_body_934, alt_body_935, alt_body_936,
                alt_body_937, alt_body_938, alt_body_939, alt_body_940,
                alt_body_941, alt_body_942, alt_body_943, alt_body_944,
                alt_body_945, alt_body_946, alt_body_947, alt_body_948,
                alt_body_949, alt_body_950, alt_body_951, alt_body_952,
                alt_body_953, alt_body_954, alt_body_955, alt_body_956,
                alt_body_957, alt_body_958, alt_body_959, alt_body_960,
                alt_body_961, alt_body_962, alt_body_963, alt_body_964,
                alt_body_965, alt_body_966, alt_body_967, alt_body_968,
                alt_body_969, alt_body_970, alt_body_971, alt_body_972,
                alt_body_973, alt_body_974, alt_body_975, alt_body_976,
                alt_body_977, alt_body_978, alt_body_979, alt_body_980,
                alt_body_981, alt_body_982, alt_body_983, alt_body_984,
                alt_body_985, alt_body_986, alt_body_987, alt_body_988,
                alt_body_989, alt_body_990, alt_body_991, alt_body_992,
                alt_body_993, alt_body_994, alt_body_995, alt_body_996,
                alt_body_997, alt_body_998, alt_body_999, alt_body_1000,
                alt_body_1001, alt_body_1002, alt_body_1003, alt_body_1004,
                alt_body_1005, alt_body_1006, alt_body_1007, alt_body_1008,
                alt_body_1009, alt_body_1010, alt_body_1011, alt_body_1012,
                alt_body_1013, alt_body_1014, alt_body_1015, alt_body_1016,
                alt_body_1017, alt_body_1018, alt_body_1019, alt_body_1020,
                alt_body_1021, alt_body_1022, alt_body_1023, alt_body_1024,
                alt_body_1025, alt_body_1026, alt_body_1027, alt_body_1028,
                alt_body_1029, alt_body_1030, alt_body_1031, alt_body_1032,
                alt_body_1033, alt_body_1034, alt_body_1035, alt_body_1036,
                alt_body_1037, alt_body_1038, alt_body_1039, alt_body_1040,
                alt_body_1041, alt_body_1042, alt_body_1043, alt_body_1044,
                alt_body_1045, alt_body_1046, alt_body_1047, alt_body_1048,
                alt_body_1049, alt_body_1050, alt_body_1051, alt_body_1052,
                alt_body_1053, alt_body_1054, alt_body_1055, alt_body_1056,
                alt_body_1057, alt_body_1058, alt_body_1059, alt_body_1060,
                alt_body_1061, alt_body_1062, alt_body_1063, alt_body_1064,
                alt_body_1065, alt_body_1066, alt_body_1067, alt_body_1068,
                alt_body_1069, alt_body_1070, alt_body_1071, alt_body_1072,
                alt_body_1073, alt_body_1074, alt_body_1075, alt_body_1076,
                alt_body_1077, alt_body_1078, alt_body_1079, alt_body_1080,
                alt_body_1081, alt_body_1082, alt_body_1083, alt_body_1084,
                alt_body_1085, alt_body_1086, alt_body_1087, alt_body_1088,
                alt_body_1089, alt_body_1090, alt_body_1091, alt_body_1092,
                alt_body_1093, alt_body_1094, alt_body_1095, alt_body_1096,
                alt_body_1097, alt_body_1098, alt_body_1099, alt_body_1100,
                alt_body_1101, alt_body_1102, alt_body_1103, alt_body_1104,
                alt_body_1105, alt_body_1106, alt_body_1107, alt_body_1108,
                alt_body_1109, alt_body_1110, alt_body_1111, alt_body_1112,
                alt_body_1113, alt_body_1114, alt_body_1115, alt_body_1116,
                alt_body_1117, alt_body_1118, alt_body_1119, alt_body_1120,
                alt_body_1121, alt_body_1122, alt_body_1123, alt_body_1124,
                alt_body_1125, alt_body_1126, alt_body_1127, alt_body_1128,
                alt_body_1129, alt_body_1130, alt_body_1131, alt_body_1132,
                alt_body_1133, alt_body_1134, alt_body_1135, alt_body_1136,
                alt_body_1137, alt_body_1138, alt_body_1139, alt_body_1140,
                alt_body_1141, alt_body_1142, alt_body_1143, alt_body_1144,
                alt_body_1145, alt_body_1146, alt_body_1147, alt_body_1148,
                alt_body_1149, alt_body_1150, alt_body_1151, alt_body_1152,
                alt_body_1153, alt_body_1154, alt_body_1155, alt_body_1156,
                alt_body_1157, alt_body_1158, alt_body_1159, alt_body_1160,
                alt_body_1161, alt_body_1162, alt_body_1163, alt_body_1164,
                alt_body_1165, alt_body_1166, alt_body_1167, alt_body_1168,
                alt_body_1169, alt_body_1170, alt_body_1171, alt_body_1172,
                alt_body_1173, alt_body_1174, alt_body_1175, alt_body_1176,
                alt_body_1177, alt_body_1178, alt_body_1179, alt_body_1180,
                alt_body_1181, alt_body_1182, alt_body_1183, alt_body_1184,
                alt_body_1185, alt_body_1186, alt_body_1187, alt_body_1188,
                alt_body_1189, alt_body_1190, alt_body_1191, alt_body_1192,
                alt_body_1193, alt_body_1194, alt_body_1195, alt_body_1196,
                alt_body_1197, alt_body_1198, alt_body_1199, alt_body_1200,
                alt_body_1201, alt_body_1202, alt_body_1203, alt_body_1204,
                alt_body_1205, alt_body_1206, alt_body_1207, alt_body_1208,
                alt_body_1209, alt_body_1210, alt_body_1211, alt_body_1212,
                alt_body_1213, alt_body_1214, alt_body_1215, alt_body_1216,
                alt_body_1217, alt_body_1218, alt_body_1219, alt_body_1220,
                alt_body_1221, alt_body_1222, alt_body_1223, alt_body_1224,
                alt_body_1225, alt_body_1226, alt_body_1227, alt_body_1228,
                alt_body_1229, alt_body_1230, alt_body_1231, alt_body_1232,
                alt_body_1233, alt_body_1234, alt_body_1235, alt_body_1236,
                alt_body_1237, alt_body_1238, alt_body_1239, alt_body_1240,
                alt_body_1241, alt_body_1242, alt_body_1243, alt_body_1244,
                alt_body_1245, alt_body_1246, alt_body_1247, alt_body_1248,
                alt_body_1249, alt_body_1250, alt_body_1251, alt_body_1252,
                alt_body_1253, alt_body_1254, alt_body_1255, alt_body_1256,
                alt_body_1257, alt_body_1258, alt_body_1259, alt_body_1260,
                alt_body_1261, alt_body_1262, alt_body_1263, alt_body_1264,
                alt_body_1265, alt_body_1266, alt_body_1267, alt_body_1268,
                alt_body_1269, alt_body_1270, alt_body_1271, alt_body_1272,
                alt_body_1273, alt_body_1274, alt_body_1275, alt_body_1276,
                alt_body_1277, alt_body_1278, alt_body_1279, alt_body_1280,
                alt_body_1281, alt_body_1282, alt_body_1283, alt_body_1284,
                alt_body_1285, alt_body_1286, alt_body_1287, alt_body_1288,
                alt_body_1289, alt_body_1290, alt_body_1291, alt_body_1292,
                alt_body_1293, alt_body_1294, alt_body_1295, alt_body_1296,
                alt_body_1297, alt_body_1298, alt_body_1299, alt_body_1300,
                alt_body_1301, alt_body_1302, alt_body_1303, alt_body_1304,
                alt_body_1305, alt_body_1306, alt_body_1307, alt_body_1308,
                alt_body_1309, alt_body_1310, alt_body_1311, alt_body_1312,
                alt_body_1313, alt_body_1314, alt_body_1315, alt_body_1316,
                alt_body_1317, alt_body_1318, alt_body_1319, alt_body_1320,
                alt_body_1321, alt_body_1322, alt_body_1323, alt_body_1324,
                alt_body_1325, alt_body_1326, alt_body_1327, alt_body_1328,
                alt_body_1329, alt_body_1330, alt_body_1331, alt_body_1332,
                alt_body_1333, alt_body_1334, alt_body_1335, alt_body_1336,
                alt_body_1337, alt_body_1338, alt_body_1339, alt_body_1340,
                alt_body_1341, alt_body_1342, alt_body_1343, alt_body_1344,
                alt_body_1345, alt_body_1346, alt_body_1347, alt_body_1348,
                alt_body_1349, alt_body_1350, alt_body_1351, alt_body_1352,
                alt_body_1353, alt_body_1354, alt_body_1355, alt_body_1356,
                alt_body_1357, alt_body_1358, alt_body_1359, alt_body_1360,
                alt_body_1361, alt_body_1362, alt_body_1363, alt_body_1364,
                alt_body_1365, alt_body_1366, alt_body_1367, alt_body_1368,
                alt_body_1369, alt_body_1370, alt_body_1371, alt_body_1372,
                alt_body_1373, alt_body_1374, alt_body_1375, alt_body_1376,
                alt_body_1377, alt_body_1378, alt_body_1379, alt_body_1380,
                alt_body_1381, alt_body_1382, alt_body_1383, alt_body_1384,
                alt_body_1385, alt_body_1386, alt_body_1387, alt_body_1388,
                alt_body_1389, alt_body_1390, alt_body_1391, alt_body_1392,
                alt_body_1393, alt_body_1394, alt_body_1395, alt_body_1396,
                alt_body_1397, alt_body_1398, alt_body_1399, alt_body_1400,
                alt_body_1401, alt_body_1402, alt_body_1403, alt_body_1404,
                alt_body_1405, alt_body_1406, alt_body_1407, alt_body_1408,
                alt_body_1409, alt_body_1410, alt_body_1411, alt_body_1412,
                alt_body_1413, alt_body_1414, alt_body_1415, alt_body_1416,
                alt_body_1417, alt_body_1418, alt_body_1419, alt_body_1420,
                alt_body_1421, alt_body_1422, alt_body_1423, alt_body_1424,
                alt_body_1425, alt_body_1426, alt_body_1427, alt_body_1428,
                alt_body_1429, alt_body_1430, alt_body_1431, alt_body_1432,
                alt_body_1433, alt_body_1434, alt_body_1435, alt_body_1436,
                alt_body_1437, alt_body_1438, alt_body_1439, alt_body_1440,
                alt_body_1441, alt_body_1442, alt_body_1443, alt_body_1444,
                alt_body_1445, alt_body_1446, alt_body_1447, alt_body_1448,
                alt_body_1449, alt_body_1450, alt_body_1451, alt_body_1452,
                alt_body_1453, alt_body_1454, alt_body_1455, alt_body_1456,
                alt_body_1457, alt_body_1458, alt_body_1459, alt_body_1460,
                alt_body_1461, alt_body_1462, alt_body_1463, alt_body_1464,
                alt_body_1465, alt_body_1466, alt_body_1467, alt_body_1468,
                alt_body_1469, alt_body_1470, alt_body_1471, alt_body_1472,
                alt_body_1473, alt_body_1474, alt_body_1475, alt_body_1476,
                alt_body_1477, alt_body_1478, alt_body_1479, alt_body_1480,
                alt_body_1481, alt_body_1482, alt_body_1483, alt_body_1484,
                alt_body_1485, alt_body_1486, alt_body_1487, alt_body_1488,
                alt_body_1489, alt_body_1490, alt_body_1491, alt_body_1492,
                alt_body_1493, alt_body_1494, alt_body_1495, alt_body_1496,
                alt_body_1497, alt_body_1498, alt_body_1499, alt_body_1500,
                alt_body_1501, alt_body_1502, alt_body_1503, alt_body_1504,
                alt_body_1505, alt_body_1506, alt_body_1507, alt_body_1508,
                alt_body_1509, alt_body_1510, alt_body_1511, alt_body_1512,
                alt_body_1513, alt_body_1514, alt_body_1515, alt_body_1516,
                alt_body_1517, alt_body_1518, alt_body_1519, alt_body_1520,
                alt_body_1521, alt_body_1522, alt_body_1523, alt_body_1524,
                alt_body_1525, alt_body_1526, alt_body_1527, alt_body_1528,
                alt_body_1529, alt_body_1530, alt_body_1531, alt_body_1532,
                alt_body_1533, alt_body_1534, alt_body_1535, alt_body_1536,
                alt_post_cstr_a, alt_post_cstr_b,
                field_665_u32, field_666_u32, field_667_u32, field_668_u32,
                field_669_u32, field_670_u32, field_671_u32, field_672_u32,
                field_673_u32, field_674_u32, field_675_u32, field_676_u32,
                field_677_u32, field_678_u32, field_679_u32, field_680_u32,
                field_681_u32, field_682_u32, field_683_u32, field_684_u32,
                field_685_u32, field_686_u32, field_687_u32, field_688_u32,
                field_689_u32, field_690_u32, field_691_u32, field_692_u32,
                field_693_u32, field_694_u32, field_695_u32, field_696_u32,
                field_697_u32, field_698_u32, field_699_u32, field_700_u32,
                field_701_u32, field_702_u32, field_703_u32, field_704_u32,
                field_705_u32, field_706_u32, field_707_u32, field_708_u32,
                field_709_u32, field_710_u32, field_711_u32, field_712_u32,
                field_713_u32, field_714_u32, field_715_u32, field_716_u32,
                field_717_u32, field_718_u32, field_719_u32, field_720_u32,
                field_721_u32, field_722_u32, field_723_u32, field_724_u32,
                field_725_u32, field_726_u32, field_727_u32, field_728_u32,
                tail_pad_001, tail_pad_002, tail_pad_003, tail_pad_004,
                post_blob } => {
                gimmick_interaction_override_list.write_to(w)?;
                use_interaction_ui_socket.write_to(w)?;
                use_sub_part_for_interaction.write_to(w)?;
                property_list.write_to(w)?;
                gimmick_name_hash.write_to(w)?;
                gimmick_name.write_to(w)?;
                emoji_texture_id.write_to(w)?;
                dev_memo.write_to(w)?;
                hash_pair_list.write_to(w)?;
                hash_single_list.write_to(w)?;
                if let Some(arr) = trigger_event_handler_list {
                    arr.write_to(w)?;
                }
                if let Some(arr) = gimmick_chart_parameter_list {
                    arr.write_to(w)?;
                }
                if let Some(arr) = field_19_u32_list {
                    arr.write_to(w)?;
                }
                if let Some(arr) = field_20_u32_list {
                    arr.write_to(w)?;
                }
                if let Some(arr) = field_21_u32_list {
                    arr.write_to(w)?;
                }
                if let Some(arr) = field_22_u32_list {
                    arr.write_to(w)?;
                }
                if let Some(arr) = field_23_u32_list {
                    arr.write_to(w)?;
                }
                if let Some(arr) = field_24_u32_list {
                    arr.write_to(w)?;
                }
                // Structured emissive record (mutually exclusive with field_24_u32_list)
                if let Some(v) = field_24_emissive_flag_a { v.write_to(w)?; }
                if let Some(v) = field_24_emissive_value_a { v.write_to(w)?; }
                if let Some(v) = field_24_emissive_flag_b { v.write_to(w)?; }
                if let Some(s) = field_24_emissive_name { s.write_to(w)?; }
                if let Some(v) = field_24_emissive_value_b { v.write_to(w)?; }
                if let Some(arr) = field_25_u32_list {
                    arr.write_to(w)?;
                }
                if let Some(v) = field_26_u32 {
                    v.write_to(w)?;
                }
                if let Some(arr) = field_27_u32_list {
                    arr.write_to(w)?;
                }
                if let Some(v) = field_28_u32 {
                    v.write_to(w)?;
                }
                if let Some(arr) = field_29_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_30_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_31_u32_list { arr.write_to(w)?; }
                if let Some(v) = f31_alt_001 { v.write_to(w)?; }
                if let Some(v) = f31_alt_002 { v.write_to(w)?; }
                if let Some(v) = f31_alt_003 { v.write_to(w)?; }
                if let Some(v) = f31_alt_004 { v.write_to(w)?; }
                if let Some(v) = f31_alt_005 { v.write_to(w)?; }
                if let Some(v) = f31_alt_006 { v.write_to(w)?; }
                if let Some(v) = f31_alt_007 { v.write_to(w)?; }
                if let Some(v) = f31_alt_008 { v.write_to(w)?; }
                if let Some(v) = f31_alt_009 { v.write_to(w)?; }
                if let Some(v) = f31_alt_010 { v.write_to(w)?; }
                if let Some(v) = f31_alt_011 { v.write_to(w)?; }
                if let Some(v) = f31_alt_012 { v.write_to(w)?; }
                if let Some(v) = f31_alt_013 { v.write_to(w)?; }
                if let Some(v) = f31_alt_014 { v.write_to(w)?; }
                if let Some(v) = f31_alt_015 { v.write_to(w)?; }
                if let Some(v) = f31_alt_016 { v.write_to(w)?; }
                if let Some(v) = f31_alt_017 { v.write_to(w)?; }
                if let Some(v) = f31_alt_018 { v.write_to(w)?; }
                if let Some(v) = f31_alt_019 { v.write_to(w)?; }
                if let Some(v) = f31_alt_020 { v.write_to(w)?; }
                if let Some(v) = f31_alt_021 { v.write_to(w)?; }
                if let Some(v) = f31_alt_022 { v.write_to(w)?; }
                if let Some(v) = f31_alt_023 { v.write_to(w)?; }
                if let Some(v) = f31_alt_024 { v.write_to(w)?; }
                if let Some(v) = f31_alt_025 { v.write_to(w)?; }
                if let Some(v) = f31_alt_026 { v.write_to(w)?; }
                if let Some(v) = f31_alt_027 { v.write_to(w)?; }
                if let Some(v) = f31_alt_028 { v.write_to(w)?; }
                if let Some(v) = f31_alt_029 { v.write_to(w)?; }
                if let Some(v) = f31_alt_030 { v.write_to(w)?; }
                if let Some(v) = f31_alt_031 { v.write_to(w)?; }
                if let Some(v) = f31_alt_032 { v.write_to(w)?; }
                if let Some(v) = f31_alt_033 { v.write_to(w)?; }
                if let Some(v) = f31_alt_034 { v.write_to(w)?; }
                if let Some(v) = f31_alt_035 { v.write_to(w)?; }
                if let Some(v) = f31_alt_036 { v.write_to(w)?; }
                if let Some(v) = f31_alt_037 { v.write_to(w)?; }
                if let Some(v) = f31_alt_038 { v.write_to(w)?; }
                if let Some(v) = f31_alt_039 { v.write_to(w)?; }
                if let Some(v) = f31_alt_040 { v.write_to(w)?; }
                if let Some(v) = f31_alt_041 { v.write_to(w)?; }
                if let Some(v) = f31_alt_042 { v.write_to(w)?; }
                if let Some(v) = f31_alt_043 { v.write_to(w)?; }
                if let Some(v) = f31_alt_044 { v.write_to(w)?; }
                if let Some(v) = f31_alt_045 { v.write_to(w)?; }
                if let Some(v) = f31_alt_046 { v.write_to(w)?; }
                if let Some(v) = f31_alt_047 { v.write_to(w)?; }
                if let Some(v) = f31_alt_048 { v.write_to(w)?; }
                if let Some(v) = f31_alt_049 { v.write_to(w)?; }
                if let Some(v) = f31_alt_050 { v.write_to(w)?; }
                if let Some(v) = f31_alt_051 { v.write_to(w)?; }
                if let Some(v) = f31_alt_052 { v.write_to(w)?; }
                if let Some(v) = f31_alt_053 { v.write_to(w)?; }
                if let Some(v) = f31_alt_054 { v.write_to(w)?; }
                if let Some(v) = f31_alt_055 { v.write_to(w)?; }
                if let Some(v) = f31_alt_056 { v.write_to(w)?; }
                if let Some(v) = f31_alt_057 { v.write_to(w)?; }
                if let Some(v) = f31_alt_058 { v.write_to(w)?; }
                if let Some(v) = f31_alt_059 { v.write_to(w)?; }
                if let Some(v) = f31_alt_060 { v.write_to(w)?; }
                if let Some(v) = f31_alt_061 { v.write_to(w)?; }
                if let Some(v) = f31_alt_062 { v.write_to(w)?; }
                if let Some(v) = f31_alt_063 { v.write_to(w)?; }
                if let Some(v) = f31_alt_064 { v.write_to(w)?; }
                if let Some(v) = f31_alt_065 { v.write_to(w)?; }
                if let Some(v) = f31_alt_066 { v.write_to(w)?; }
                if let Some(v) = f31_alt_067 { v.write_to(w)?; }
                if let Some(v) = f31_alt_068 { v.write_to(w)?; }
                if let Some(v) = f31_alt_069 { v.write_to(w)?; }
                if let Some(v) = f31_alt_070 { v.write_to(w)?; }
                if let Some(v) = f31_alt_071 { v.write_to(w)?; }
                if let Some(v) = f31_alt_072 { v.write_to(w)?; }
                if let Some(v) = f31_alt_073 { v.write_to(w)?; }
                if let Some(v) = f31_alt_074 { v.write_to(w)?; }
                if let Some(v) = f31_alt_075 { v.write_to(w)?; }
                if let Some(v) = f31_alt_076 { v.write_to(w)?; }
                if let Some(v) = f31_alt_077 { v.write_to(w)?; }
                if let Some(v) = f31_alt_078 { v.write_to(w)?; }
                if let Some(v) = f31_alt_079 { v.write_to(w)?; }
                if let Some(v) = f31_alt_080 { v.write_to(w)?; }
                if let Some(v) = f31_alt_081 { v.write_to(w)?; }
                if let Some(v) = f31_alt_082 { v.write_to(w)?; }
                if let Some(v) = f31_alt_083 { v.write_to(w)?; }
                if let Some(v) = f31_alt_084 { v.write_to(w)?; }
                if let Some(v) = f31_alt_085 { v.write_to(w)?; }
                if let Some(v) = f31_alt_086 { v.write_to(w)?; }
                if let Some(v) = f31_alt_087 { v.write_to(w)?; }
                if let Some(v) = f31_alt_088 { v.write_to(w)?; }
                if let Some(v) = f31_alt_089 { v.write_to(w)?; }
                if let Some(v) = f31_alt_090 { v.write_to(w)?; }
                if let Some(v) = f31_alt_091 { v.write_to(w)?; }
                if let Some(v) = f31_alt_092 { v.write_to(w)?; }
                if let Some(v) = f31_alt_093 { v.write_to(w)?; }
                if let Some(v) = f31_alt_094 { v.write_to(w)?; }
                if let Some(v) = f31_alt_095 { v.write_to(w)?; }
                if let Some(v) = f31_alt_096 { v.write_to(w)?; }
                if let Some(v) = f31_alt_097 { v.write_to(w)?; }
                if let Some(v) = f31_alt_098 { v.write_to(w)?; }
                if let Some(v) = f31_alt_099 { v.write_to(w)?; }
                if let Some(v) = f31_alt_100 { v.write_to(w)?; }
                if let Some(v) = f31_alt_101 { v.write_to(w)?; }
                if let Some(v) = f31_alt_102 { v.write_to(w)?; }
                if let Some(v) = f31_alt_103 { v.write_to(w)?; }
                if let Some(v) = f31_alt_104 { v.write_to(w)?; }
                if let Some(v) = f31_alt_105 { v.write_to(w)?; }
                if let Some(v) = f31_alt_106 { v.write_to(w)?; }
                if let Some(v) = f31_alt_107 { v.write_to(w)?; }
                if let Some(v) = f31_alt_108 { v.write_to(w)?; }
                if let Some(v) = f31_alt_109 { v.write_to(w)?; }
                if let Some(v) = f31_alt_110 { v.write_to(w)?; }
                if let Some(v) = f31_alt_111 { v.write_to(w)?; }
                if let Some(v) = f31_alt_112 { v.write_to(w)?; }
                if let Some(v) = f31_alt_113 { v.write_to(w)?; }
                if let Some(v) = f31_alt_114 { v.write_to(w)?; }
                if let Some(v) = f31_alt_115 { v.write_to(w)?; }
                if let Some(v) = f31_alt_116 { v.write_to(w)?; }
                if let Some(v) = f31_alt_117 { v.write_to(w)?; }
                if let Some(v) = f31_alt_118 { v.write_to(w)?; }
                if let Some(v) = f31_alt_119 { v.write_to(w)?; }
                if let Some(v) = f31_alt_120 { v.write_to(w)?; }
                if let Some(v) = f31_alt_121 { v.write_to(w)?; }
                if let Some(v) = f31_alt_122 { v.write_to(w)?; }
                if let Some(v) = f31_alt_123 { v.write_to(w)?; }
                if let Some(v) = f31_alt_124 { v.write_to(w)?; }
                if let Some(v) = f31_alt_125 { v.write_to(w)?; }
                if let Some(v) = f31_alt_126 { v.write_to(w)?; }
                if let Some(v) = f31_alt_127 { v.write_to(w)?; }
                if let Some(v) = f31_alt_128 { v.write_to(w)?; }
                if let Some(v) = f31_alt_129 { v.write_to(w)?; }
                if let Some(v) = f31_alt_130 { v.write_to(w)?; }
                if let Some(v) = f31_alt_131 { v.write_to(w)?; }
                if let Some(v) = f31_alt_132 { v.write_to(w)?; }
                if let Some(v) = f31_alt_133 { v.write_to(w)?; }
                if let Some(v) = f31_alt_134 { v.write_to(w)?; }
                if let Some(v) = f31_alt_135 { v.write_to(w)?; }
                if let Some(v) = f31_alt_136 { v.write_to(w)?; }
                if let Some(v) = f31_alt_137 { v.write_to(w)?; }
                if let Some(v) = f31_alt_138 { v.write_to(w)?; }
                if let Some(v) = f31_alt_139 { v.write_to(w)?; }
                if let Some(v) = f31_alt_140 { v.write_to(w)?; }
                if let Some(v) = f31_alt_141 { v.write_to(w)?; }
                if let Some(v) = f31_alt_142 { v.write_to(w)?; }
                if let Some(v) = f31_alt_143 { v.write_to(w)?; }
                if let Some(v) = f31_alt_144 { v.write_to(w)?; }
                if let Some(v) = f31_alt_145 { v.write_to(w)?; }
                if let Some(v) = f31_alt_146 { v.write_to(w)?; }
                if let Some(v) = f31_alt_147 { v.write_to(w)?; }
                if let Some(v) = f31_alt_148 { v.write_to(w)?; }
                if let Some(v) = f31_alt_149 { v.write_to(w)?; }
                if let Some(v) = f31_alt_150 { v.write_to(w)?; }
                if let Some(v) = f31_alt_151 { v.write_to(w)?; }
                if let Some(v) = f31_alt_152 { v.write_to(w)?; }
                if let Some(v) = f31_alt_153 { v.write_to(w)?; }
                if let Some(v) = f31_alt_154 { v.write_to(w)?; }
                if let Some(v) = f31_alt_155 { v.write_to(w)?; }
                if let Some(v) = f31_alt_156 { v.write_to(w)?; }
                if let Some(v) = f31_alt_157 { v.write_to(w)?; }
                if let Some(v) = f31_alt_158 { v.write_to(w)?; }
                if let Some(v) = f31_alt_159 { v.write_to(w)?; }
                if let Some(v) = f31_alt_160 { v.write_to(w)?; }
                if let Some(v) = f31_alt_161 { v.write_to(w)?; }
                if let Some(v) = f31_alt_162 { v.write_to(w)?; }
                if let Some(v) = f31_alt_163 { v.write_to(w)?; }
                if let Some(v) = f31_alt_164 { v.write_to(w)?; }
                if let Some(v) = f31_alt_165 { v.write_to(w)?; }
                if let Some(v) = f31_alt_166 { v.write_to(w)?; }
                if let Some(v) = f31_alt_167 { v.write_to(w)?; }
                if let Some(v) = f31_alt_168 { v.write_to(w)?; }
                if let Some(v) = f31_alt_169 { v.write_to(w)?; }
                if let Some(v) = f31_alt_170 { v.write_to(w)?; }
                if let Some(v) = f31_alt_171 { v.write_to(w)?; }
                if let Some(v) = f31_alt_172 { v.write_to(w)?; }
                if let Some(v) = f31_alt_173 { v.write_to(w)?; }
                if let Some(v) = f31_alt_174 { v.write_to(w)?; }
                if let Some(v) = f31_alt_175 { v.write_to(w)?; }
                if let Some(v) = f31_alt_176 { v.write_to(w)?; }
                if let Some(v) = f31_alt_177 { v.write_to(w)?; }
                if let Some(v) = f31_alt_178 { v.write_to(w)?; }
                if let Some(v) = f31_alt_179 { v.write_to(w)?; }
                if let Some(v) = f31_alt_180 { v.write_to(w)?; }
                if let Some(v) = f31_alt_181 { v.write_to(w)?; }
                if let Some(v) = f31_alt_182 { v.write_to(w)?; }
                if let Some(v) = f31_alt_183 { v.write_to(w)?; }
                if let Some(v) = f31_alt_184 { v.write_to(w)?; }
                if let Some(v) = f31_alt_185 { v.write_to(w)?; }
                if let Some(v) = f31_alt_186 { v.write_to(w)?; }
                if let Some(v) = f31_alt_187 { v.write_to(w)?; }
                if let Some(v) = f31_alt_188 { v.write_to(w)?; }
                if let Some(v) = f31_alt_189 { v.write_to(w)?; }
                if let Some(v) = f31_alt_190 { v.write_to(w)?; }
                if let Some(v) = f31_alt_191 { v.write_to(w)?; }
                if let Some(v) = f31_alt_192 { v.write_to(w)?; }
                if let Some(v) = f31_alt_193 { v.write_to(w)?; }
                if let Some(v) = f31_alt_194 { v.write_to(w)?; }
                if let Some(v) = f31_alt_195 { v.write_to(w)?; }
                if let Some(v) = f31_alt_196 { v.write_to(w)?; }
                if let Some(v) = f31_alt_197 { v.write_to(w)?; }
                if let Some(v) = f31_alt_198 { v.write_to(w)?; }
                if let Some(v) = f31_alt_199 { v.write_to(w)?; }
                if let Some(v) = f31_alt_200 { v.write_to(w)?; }
                if let Some(v) = f31_alt_201 { v.write_to(w)?; }
                if let Some(v) = f31_alt_202 { v.write_to(w)?; }
                if let Some(v) = f31_alt_203 { v.write_to(w)?; }
                if let Some(v) = f31_alt_204 { v.write_to(w)?; }
                if let Some(v) = f31_alt_205 { v.write_to(w)?; }
                if let Some(v) = f31_alt_206 { v.write_to(w)?; }
                if let Some(v) = f31_alt_207 { v.write_to(w)?; }
                if let Some(v) = f31_alt_208 { v.write_to(w)?; }
                if let Some(v) = f31_alt_209 { v.write_to(w)?; }
                if let Some(v) = f31_alt_210 { v.write_to(w)?; }
                if let Some(v) = f31_alt_211 { v.write_to(w)?; }
                if let Some(v) = f31_alt_212 { v.write_to(w)?; }
                if let Some(v) = f31_alt_213 { v.write_to(w)?; }
                if let Some(v) = f31_alt_214 { v.write_to(w)?; }
                if let Some(v) = f31_alt_215 { v.write_to(w)?; }
                if let Some(v) = f31_alt_216 { v.write_to(w)?; }
                if let Some(v) = f31_alt_217 { v.write_to(w)?; }
                if let Some(v) = f31_alt_218 { v.write_to(w)?; }
                if let Some(v) = f31_alt_219 { v.write_to(w)?; }
                if let Some(v) = f31_alt_220 { v.write_to(w)?; }
                if let Some(v) = f31_alt_221 { v.write_to(w)?; }
                if let Some(v) = f31_alt_222 { v.write_to(w)?; }
                if let Some(v) = f31_alt_223 { v.write_to(w)?; }
                if let Some(v) = f31_alt_224 { v.write_to(w)?; }
                if let Some(v) = f31_alt_225 { v.write_to(w)?; }
                if let Some(v) = f31_alt_226 { v.write_to(w)?; }
                if let Some(v) = f31_alt_227 { v.write_to(w)?; }
                if let Some(v) = f31_alt_228 { v.write_to(w)?; }
                if let Some(v) = f31_alt_229 { v.write_to(w)?; }
                if let Some(v) = f31_alt_230 { v.write_to(w)?; }
                if let Some(v) = f31_alt_231 { v.write_to(w)?; }
                if let Some(v) = f31_alt_232 { v.write_to(w)?; }
                if let Some(v) = f31_alt_233 { v.write_to(w)?; }
                if let Some(v) = f31_alt_234 { v.write_to(w)?; }
                if let Some(v) = f31_alt_235 { v.write_to(w)?; }
                if let Some(v) = f31_alt_236 { v.write_to(w)?; }
                if let Some(v) = f31_alt_237 { v.write_to(w)?; }
                if let Some(v) = f31_alt_238 { v.write_to(w)?; }
                if let Some(v) = f31_alt_239 { v.write_to(w)?; }
                if let Some(v) = f31_alt_240 { v.write_to(w)?; }
                if let Some(v) = f31_alt_241 { v.write_to(w)?; }
                if let Some(v) = f31_alt_242 { v.write_to(w)?; }
                if let Some(v) = f31_alt_243 { v.write_to(w)?; }
                if let Some(v) = f31_alt_244 { v.write_to(w)?; }
                if let Some(v) = f31_alt_245 { v.write_to(w)?; }
                if let Some(v) = f31_alt_246 { v.write_to(w)?; }
                if let Some(v) = f31_alt_247 { v.write_to(w)?; }
                if let Some(v) = f31_alt_248 { v.write_to(w)?; }
                if let Some(v) = f31_alt_249 { v.write_to(w)?; }
                if let Some(v) = f31_alt_250 { v.write_to(w)?; }
                if let Some(v) = f31_alt_251 { v.write_to(w)?; }
                if let Some(v) = f31_alt_252 { v.write_to(w)?; }
                if let Some(v) = f31_alt_253 { v.write_to(w)?; }
                if let Some(v) = f31_alt_254 { v.write_to(w)?; }
                if let Some(v) = f31_alt_255 { v.write_to(w)?; }
                if let Some(v) = f31_alt_256 { v.write_to(w)?; }
                if let Some(arr) = field_32_u32_list { arr.write_to(w)?; }
                if let Some(v) = f32_alt_001 { v.write_to(w)?; }
                if let Some(v) = f32_alt_002 { v.write_to(w)?; }
                if let Some(v) = f32_alt_003 { v.write_to(w)?; }
                if let Some(v) = f32_alt_004 { v.write_to(w)?; }
                if let Some(v) = f32_alt_005 { v.write_to(w)?; }
                if let Some(v) = f32_alt_006 { v.write_to(w)?; }
                if let Some(v) = f32_alt_007 { v.write_to(w)?; }
                if let Some(v) = f32_alt_008 { v.write_to(w)?; }
                if let Some(v) = f32_alt_009 { v.write_to(w)?; }
                if let Some(v) = f32_alt_010 { v.write_to(w)?; }
                if let Some(v) = f32_alt_011 { v.write_to(w)?; }
                if let Some(v) = f32_alt_012 { v.write_to(w)?; }
                if let Some(v) = f32_alt_013 { v.write_to(w)?; }
                if let Some(v) = f32_alt_014 { v.write_to(w)?; }
                if let Some(v) = f32_alt_015 { v.write_to(w)?; }
                if let Some(v) = f32_alt_016 { v.write_to(w)?; }
                if let Some(v) = f32_alt_017 { v.write_to(w)?; }
                if let Some(v) = f32_alt_018 { v.write_to(w)?; }
                if let Some(v) = f32_alt_019 { v.write_to(w)?; }
                if let Some(v) = f32_alt_020 { v.write_to(w)?; }
                if let Some(v) = f32_alt_021 { v.write_to(w)?; }
                if let Some(v) = f32_alt_022 { v.write_to(w)?; }
                if let Some(v) = f32_alt_023 { v.write_to(w)?; }
                if let Some(v) = f32_alt_024 { v.write_to(w)?; }
                if let Some(v) = f32_alt_025 { v.write_to(w)?; }
                if let Some(v) = f32_alt_026 { v.write_to(w)?; }
                if let Some(v) = f32_alt_027 { v.write_to(w)?; }
                if let Some(v) = f32_alt_028 { v.write_to(w)?; }
                if let Some(v) = f32_alt_029 { v.write_to(w)?; }
                if let Some(v) = f32_alt_030 { v.write_to(w)?; }
                if let Some(v) = f32_alt_031 { v.write_to(w)?; }
                if let Some(v) = f32_alt_032 { v.write_to(w)?; }
                if let Some(v) = f32_alt_033 { v.write_to(w)?; }
                if let Some(v) = f32_alt_034 { v.write_to(w)?; }
                if let Some(v) = f32_alt_035 { v.write_to(w)?; }
                if let Some(v) = f32_alt_036 { v.write_to(w)?; }
                if let Some(v) = f32_alt_037 { v.write_to(w)?; }
                if let Some(v) = f32_alt_038 { v.write_to(w)?; }
                if let Some(v) = f32_alt_039 { v.write_to(w)?; }
                if let Some(v) = f32_alt_040 { v.write_to(w)?; }
                if let Some(v) = f32_alt_041 { v.write_to(w)?; }
                if let Some(v) = f32_alt_042 { v.write_to(w)?; }
                if let Some(v) = f32_alt_043 { v.write_to(w)?; }
                if let Some(v) = f32_alt_044 { v.write_to(w)?; }
                if let Some(v) = f32_alt_045 { v.write_to(w)?; }
                if let Some(v) = f32_alt_046 { v.write_to(w)?; }
                if let Some(v) = f32_alt_047 { v.write_to(w)?; }
                if let Some(v) = f32_alt_048 { v.write_to(w)?; }
                if let Some(v) = f32_alt_049 { v.write_to(w)?; }
                if let Some(v) = f32_alt_050 { v.write_to(w)?; }
                if let Some(v) = f32_alt_051 { v.write_to(w)?; }
                if let Some(v) = f32_alt_052 { v.write_to(w)?; }
                if let Some(v) = f32_alt_053 { v.write_to(w)?; }
                if let Some(v) = f32_alt_054 { v.write_to(w)?; }
                if let Some(v) = f32_alt_055 { v.write_to(w)?; }
                if let Some(v) = f32_alt_056 { v.write_to(w)?; }
                if let Some(v) = f32_alt_057 { v.write_to(w)?; }
                if let Some(v) = f32_alt_058 { v.write_to(w)?; }
                if let Some(v) = f32_alt_059 { v.write_to(w)?; }
                if let Some(v) = f32_alt_060 { v.write_to(w)?; }
                if let Some(v) = f32_alt_061 { v.write_to(w)?; }
                if let Some(v) = f32_alt_062 { v.write_to(w)?; }
                if let Some(v) = f32_alt_063 { v.write_to(w)?; }
                if let Some(v) = f32_alt_064 { v.write_to(w)?; }
                if let Some(v) = f32_alt_065 { v.write_to(w)?; }
                if let Some(v) = f32_alt_066 { v.write_to(w)?; }
                if let Some(v) = f32_alt_067 { v.write_to(w)?; }
                if let Some(v) = f32_alt_068 { v.write_to(w)?; }
                if let Some(v) = f32_alt_069 { v.write_to(w)?; }
                if let Some(v) = f32_alt_070 { v.write_to(w)?; }
                if let Some(v) = f32_alt_071 { v.write_to(w)?; }
                if let Some(v) = f32_alt_072 { v.write_to(w)?; }
                if let Some(v) = f32_alt_073 { v.write_to(w)?; }
                if let Some(v) = f32_alt_074 { v.write_to(w)?; }
                if let Some(v) = f32_alt_075 { v.write_to(w)?; }
                if let Some(v) = f32_alt_076 { v.write_to(w)?; }
                if let Some(v) = f32_alt_077 { v.write_to(w)?; }
                if let Some(v) = f32_alt_078 { v.write_to(w)?; }
                if let Some(v) = f32_alt_079 { v.write_to(w)?; }
                if let Some(v) = f32_alt_080 { v.write_to(w)?; }
                if let Some(v) = f32_alt_081 { v.write_to(w)?; }
                if let Some(v) = f32_alt_082 { v.write_to(w)?; }
                if let Some(v) = f32_alt_083 { v.write_to(w)?; }
                if let Some(v) = f32_alt_084 { v.write_to(w)?; }
                if let Some(v) = f32_alt_085 { v.write_to(w)?; }
                if let Some(v) = f32_alt_086 { v.write_to(w)?; }
                if let Some(v) = f32_alt_087 { v.write_to(w)?; }
                if let Some(v) = f32_alt_088 { v.write_to(w)?; }
                if let Some(v) = f32_alt_089 { v.write_to(w)?; }
                if let Some(v) = f32_alt_090 { v.write_to(w)?; }
                if let Some(v) = f32_alt_091 { v.write_to(w)?; }
                if let Some(v) = f32_alt_092 { v.write_to(w)?; }
                if let Some(v) = f32_alt_093 { v.write_to(w)?; }
                if let Some(v) = f32_alt_094 { v.write_to(w)?; }
                if let Some(v) = f32_alt_095 { v.write_to(w)?; }
                if let Some(v) = f32_alt_096 { v.write_to(w)?; }
                if let Some(v) = f32_alt_097 { v.write_to(w)?; }
                if let Some(v) = f32_alt_098 { v.write_to(w)?; }
                if let Some(v) = f32_alt_099 { v.write_to(w)?; }
                if let Some(v) = f32_alt_100 { v.write_to(w)?; }
                if let Some(v) = f32_alt_101 { v.write_to(w)?; }
                if let Some(v) = f32_alt_102 { v.write_to(w)?; }
                if let Some(v) = f32_alt_103 { v.write_to(w)?; }
                if let Some(v) = f32_alt_104 { v.write_to(w)?; }
                if let Some(v) = f32_alt_105 { v.write_to(w)?; }
                if let Some(v) = f32_alt_106 { v.write_to(w)?; }
                if let Some(v) = f32_alt_107 { v.write_to(w)?; }
                if let Some(v) = f32_alt_108 { v.write_to(w)?; }
                if let Some(v) = f32_alt_109 { v.write_to(w)?; }
                if let Some(v) = f32_alt_110 { v.write_to(w)?; }
                if let Some(v) = f32_alt_111 { v.write_to(w)?; }
                if let Some(v) = f32_alt_112 { v.write_to(w)?; }
                if let Some(v) = f32_alt_113 { v.write_to(w)?; }
                if let Some(v) = f32_alt_114 { v.write_to(w)?; }
                if let Some(v) = f32_alt_115 { v.write_to(w)?; }
                if let Some(v) = f32_alt_116 { v.write_to(w)?; }
                if let Some(v) = f32_alt_117 { v.write_to(w)?; }
                if let Some(v) = f32_alt_118 { v.write_to(w)?; }
                if let Some(v) = f32_alt_119 { v.write_to(w)?; }
                if let Some(v) = f32_alt_120 { v.write_to(w)?; }
                if let Some(v) = f32_alt_121 { v.write_to(w)?; }
                if let Some(v) = f32_alt_122 { v.write_to(w)?; }
                if let Some(v) = f32_alt_123 { v.write_to(w)?; }
                if let Some(v) = f32_alt_124 { v.write_to(w)?; }
                if let Some(v) = f32_alt_125 { v.write_to(w)?; }
                if let Some(v) = f32_alt_126 { v.write_to(w)?; }
                if let Some(v) = f32_alt_127 { v.write_to(w)?; }
                if let Some(v) = f32_alt_128 { v.write_to(w)?; }
                if let Some(v) = f32_alt_129 { v.write_to(w)?; }
                if let Some(v) = f32_alt_130 { v.write_to(w)?; }
                if let Some(v) = f32_alt_131 { v.write_to(w)?; }
                if let Some(v) = f32_alt_132 { v.write_to(w)?; }
                if let Some(v) = f32_alt_133 { v.write_to(w)?; }
                if let Some(v) = f32_alt_134 { v.write_to(w)?; }
                if let Some(v) = f32_alt_135 { v.write_to(w)?; }
                if let Some(v) = f32_alt_136 { v.write_to(w)?; }
                if let Some(v) = f32_alt_137 { v.write_to(w)?; }
                if let Some(v) = f32_alt_138 { v.write_to(w)?; }
                if let Some(v) = f32_alt_139 { v.write_to(w)?; }
                if let Some(v) = f32_alt_140 { v.write_to(w)?; }
                if let Some(v) = f32_alt_141 { v.write_to(w)?; }
                if let Some(v) = f32_alt_142 { v.write_to(w)?; }
                if let Some(v) = f32_alt_143 { v.write_to(w)?; }
                if let Some(v) = f32_alt_144 { v.write_to(w)?; }
                if let Some(v) = f32_alt_145 { v.write_to(w)?; }
                if let Some(v) = f32_alt_146 { v.write_to(w)?; }
                if let Some(v) = f32_alt_147 { v.write_to(w)?; }
                if let Some(v) = f32_alt_148 { v.write_to(w)?; }
                if let Some(v) = f32_alt_149 { v.write_to(w)?; }
                if let Some(v) = f32_alt_150 { v.write_to(w)?; }
                if let Some(v) = f32_alt_151 { v.write_to(w)?; }
                if let Some(v) = f32_alt_152 { v.write_to(w)?; }
                if let Some(v) = f32_alt_153 { v.write_to(w)?; }
                if let Some(v) = f32_alt_154 { v.write_to(w)?; }
                if let Some(v) = f32_alt_155 { v.write_to(w)?; }
                if let Some(v) = f32_alt_156 { v.write_to(w)?; }
                if let Some(v) = f32_alt_157 { v.write_to(w)?; }
                if let Some(v) = f32_alt_158 { v.write_to(w)?; }
                if let Some(v) = f32_alt_159 { v.write_to(w)?; }
                if let Some(v) = f32_alt_160 { v.write_to(w)?; }
                if let Some(v) = f32_alt_161 { v.write_to(w)?; }
                if let Some(v) = f32_alt_162 { v.write_to(w)?; }
                if let Some(v) = f32_alt_163 { v.write_to(w)?; }
                if let Some(v) = f32_alt_164 { v.write_to(w)?; }
                if let Some(v) = f32_alt_165 { v.write_to(w)?; }
                if let Some(v) = f32_alt_166 { v.write_to(w)?; }
                if let Some(v) = f32_alt_167 { v.write_to(w)?; }
                if let Some(v) = f32_alt_168 { v.write_to(w)?; }
                if let Some(v) = f32_alt_169 { v.write_to(w)?; }
                if let Some(v) = f32_alt_170 { v.write_to(w)?; }
                if let Some(v) = f32_alt_171 { v.write_to(w)?; }
                if let Some(v) = f32_alt_172 { v.write_to(w)?; }
                if let Some(v) = f32_alt_173 { v.write_to(w)?; }
                if let Some(v) = f32_alt_174 { v.write_to(w)?; }
                if let Some(v) = f32_alt_175 { v.write_to(w)?; }
                if let Some(v) = f32_alt_176 { v.write_to(w)?; }
                if let Some(v) = f32_alt_177 { v.write_to(w)?; }
                if let Some(v) = f32_alt_178 { v.write_to(w)?; }
                if let Some(v) = f32_alt_179 { v.write_to(w)?; }
                if let Some(v) = f32_alt_180 { v.write_to(w)?; }
                if let Some(v) = f32_alt_181 { v.write_to(w)?; }
                if let Some(v) = f32_alt_182 { v.write_to(w)?; }
                if let Some(v) = f32_alt_183 { v.write_to(w)?; }
                if let Some(v) = f32_alt_184 { v.write_to(w)?; }
                if let Some(v) = f32_alt_185 { v.write_to(w)?; }
                if let Some(v) = f32_alt_186 { v.write_to(w)?; }
                if let Some(v) = f32_alt_187 { v.write_to(w)?; }
                if let Some(v) = f32_alt_188 { v.write_to(w)?; }
                if let Some(v) = f32_alt_189 { v.write_to(w)?; }
                if let Some(v) = f32_alt_190 { v.write_to(w)?; }
                if let Some(v) = f32_alt_191 { v.write_to(w)?; }
                if let Some(v) = f32_alt_192 { v.write_to(w)?; }
                if let Some(v) = field_33_u32 { v.write_to(w)?; }
                if let Some(v) = field_34_u32 { v.write_to(w)?; }
                if let Some(arr) = field_35_u32_list { arr.write_to(w)?; }
                if let Some(v) = field_36_u32 { v.write_to(w)?; }
                if let Some(v) = field_37_u32 { v.write_to(w)?; }
                if let Some(v) = field_38_u32 { v.write_to(w)?; }
                if let Some(arr) = field_39_u32_list { arr.write_to(w)?; }
                if let Some(v) = f39_alt_001 { v.write_to(w)?; }
                if let Some(v) = f39_alt_002 { v.write_to(w)?; }
                if let Some(v) = f39_alt_003 { v.write_to(w)?; }
                if let Some(v) = f39_alt_004 { v.write_to(w)?; }
                if let Some(v) = f39_alt_005 { v.write_to(w)?; }
                if let Some(v) = f39_alt_006 { v.write_to(w)?; }
                if let Some(v) = f39_alt_007 { v.write_to(w)?; }
                if let Some(v) = f39_alt_008 { v.write_to(w)?; }
                if let Some(v) = f39_alt_009 { v.write_to(w)?; }
                if let Some(v) = f39_alt_010 { v.write_to(w)?; }
                if let Some(v) = f39_alt_011 { v.write_to(w)?; }
                if let Some(v) = f39_alt_012 { v.write_to(w)?; }
                if let Some(v) = f39_alt_013 { v.write_to(w)?; }
                if let Some(v) = f39_alt_014 { v.write_to(w)?; }
                if let Some(v) = f39_alt_015 { v.write_to(w)?; }
                if let Some(v) = f39_alt_016 { v.write_to(w)?; }
                if let Some(v) = f39_alt_017 { v.write_to(w)?; }
                if let Some(v) = f39_alt_018 { v.write_to(w)?; }
                if let Some(v) = f39_alt_019 { v.write_to(w)?; }
                if let Some(v) = f39_alt_020 { v.write_to(w)?; }
                if let Some(v) = f39_alt_021 { v.write_to(w)?; }
                if let Some(v) = f39_alt_022 { v.write_to(w)?; }
                if let Some(v) = f39_alt_023 { v.write_to(w)?; }
                if let Some(v) = f39_alt_024 { v.write_to(w)?; }
                if let Some(v) = f39_alt_025 { v.write_to(w)?; }
                if let Some(v) = f39_alt_026 { v.write_to(w)?; }
                if let Some(v) = f39_alt_027 { v.write_to(w)?; }
                if let Some(v) = f39_alt_028 { v.write_to(w)?; }
                if let Some(v) = f39_alt_029 { v.write_to(w)?; }
                if let Some(v) = f39_alt_030 { v.write_to(w)?; }
                if let Some(v) = f39_alt_031 { v.write_to(w)?; }
                if let Some(v) = f39_alt_032 { v.write_to(w)?; }
                if let Some(v) = f39_alt_033 { v.write_to(w)?; }
                if let Some(v) = f39_alt_034 { v.write_to(w)?; }
                if let Some(v) = f39_alt_035 { v.write_to(w)?; }
                if let Some(v) = f39_alt_036 { v.write_to(w)?; }
                if let Some(v) = f39_alt_037 { v.write_to(w)?; }
                if let Some(v) = f39_alt_038 { v.write_to(w)?; }
                if let Some(v) = f39_alt_039 { v.write_to(w)?; }
                if let Some(v) = f39_alt_040 { v.write_to(w)?; }
                if let Some(v) = f39_alt_041 { v.write_to(w)?; }
                if let Some(v) = f39_alt_042 { v.write_to(w)?; }
                if let Some(v) = f39_alt_043 { v.write_to(w)?; }
                if let Some(v) = f39_alt_044 { v.write_to(w)?; }
                if let Some(v) = f39_alt_045 { v.write_to(w)?; }
                if let Some(v) = f39_alt_046 { v.write_to(w)?; }
                if let Some(v) = f39_alt_047 { v.write_to(w)?; }
                if let Some(v) = f39_alt_048 { v.write_to(w)?; }
                if let Some(v) = f39_alt_049 { v.write_to(w)?; }
                if let Some(v) = f39_alt_050 { v.write_to(w)?; }
                if let Some(v) = f39_alt_051 { v.write_to(w)?; }
                if let Some(v) = f39_alt_052 { v.write_to(w)?; }
                if let Some(v) = f39_alt_053 { v.write_to(w)?; }
                if let Some(v) = f39_alt_054 { v.write_to(w)?; }
                if let Some(v) = f39_alt_055 { v.write_to(w)?; }
                if let Some(v) = f39_alt_056 { v.write_to(w)?; }
                if let Some(v) = f39_alt_057 { v.write_to(w)?; }
                if let Some(v) = f39_alt_058 { v.write_to(w)?; }
                if let Some(v) = f39_alt_059 { v.write_to(w)?; }
                if let Some(v) = f39_alt_060 { v.write_to(w)?; }
                if let Some(v) = f39_alt_061 { v.write_to(w)?; }
                if let Some(v) = f39_alt_062 { v.write_to(w)?; }
                if let Some(v) = f39_alt_063 { v.write_to(w)?; }
                if let Some(v) = f39_alt_064 { v.write_to(w)?; }
                if let Some(v) = f39_alt_065 { v.write_to(w)?; }
                if let Some(v) = f39_alt_066 { v.write_to(w)?; }
                if let Some(v) = f39_alt_067 { v.write_to(w)?; }
                if let Some(v) = f39_alt_068 { v.write_to(w)?; }
                if let Some(v) = f39_alt_069 { v.write_to(w)?; }
                if let Some(v) = f39_alt_070 { v.write_to(w)?; }
                if let Some(v) = f39_alt_071 { v.write_to(w)?; }
                if let Some(v) = f39_alt_072 { v.write_to(w)?; }
                if let Some(v) = f39_alt_073 { v.write_to(w)?; }
                if let Some(v) = f39_alt_074 { v.write_to(w)?; }
                if let Some(v) = f39_alt_075 { v.write_to(w)?; }
                if let Some(v) = f39_alt_076 { v.write_to(w)?; }
                if let Some(v) = f39_alt_077 { v.write_to(w)?; }
                if let Some(v) = f39_alt_078 { v.write_to(w)?; }
                if let Some(v) = f39_alt_079 { v.write_to(w)?; }
                if let Some(v) = f39_alt_080 { v.write_to(w)?; }
                if let Some(v) = f39_alt_081 { v.write_to(w)?; }
                if let Some(v) = f39_alt_082 { v.write_to(w)?; }
                if let Some(v) = f39_alt_083 { v.write_to(w)?; }
                if let Some(v) = f39_alt_084 { v.write_to(w)?; }
                if let Some(v) = f39_alt_085 { v.write_to(w)?; }
                if let Some(v) = f39_alt_086 { v.write_to(w)?; }
                if let Some(v) = f39_alt_087 { v.write_to(w)?; }
                if let Some(v) = f39_alt_088 { v.write_to(w)?; }
                if let Some(v) = f39_alt_089 { v.write_to(w)?; }
                if let Some(v) = f39_alt_090 { v.write_to(w)?; }
                if let Some(v) = f39_alt_091 { v.write_to(w)?; }
                if let Some(v) = f39_alt_092 { v.write_to(w)?; }
                if let Some(v) = f39_alt_093 { v.write_to(w)?; }
                if let Some(v) = f39_alt_094 { v.write_to(w)?; }
                if let Some(v) = f39_alt_095 { v.write_to(w)?; }
                if let Some(v) = f39_alt_096 { v.write_to(w)?; }
                if let Some(v) = f39_alt_097 { v.write_to(w)?; }
                if let Some(v) = f39_alt_098 { v.write_to(w)?; }
                if let Some(v) = f39_alt_099 { v.write_to(w)?; }
                if let Some(v) = f39_alt_100 { v.write_to(w)?; }
                if let Some(v) = f39_alt_101 { v.write_to(w)?; }
                if let Some(v) = f39_alt_102 { v.write_to(w)?; }
                if let Some(v) = f39_alt_103 { v.write_to(w)?; }
                if let Some(v) = f39_alt_104 { v.write_to(w)?; }
                if let Some(v) = f39_alt_105 { v.write_to(w)?; }
                if let Some(v) = f39_alt_106 { v.write_to(w)?; }
                if let Some(v) = f39_alt_107 { v.write_to(w)?; }
                if let Some(v) = f39_alt_108 { v.write_to(w)?; }
                if let Some(v) = f39_alt_109 { v.write_to(w)?; }
                if let Some(v) = f39_alt_110 { v.write_to(w)?; }
                if let Some(v) = f39_alt_111 { v.write_to(w)?; }
                if let Some(v) = f39_alt_112 { v.write_to(w)?; }
                if let Some(v) = f39_alt_113 { v.write_to(w)?; }
                if let Some(v) = f39_alt_114 { v.write_to(w)?; }
                if let Some(v) = f39_alt_115 { v.write_to(w)?; }
                if let Some(v) = f39_alt_116 { v.write_to(w)?; }
                if let Some(v) = f39_alt_117 { v.write_to(w)?; }
                if let Some(v) = f39_alt_118 { v.write_to(w)?; }
                if let Some(v) = f39_alt_119 { v.write_to(w)?; }
                if let Some(v) = f39_alt_120 { v.write_to(w)?; }
                if let Some(v) = f39_alt_121 { v.write_to(w)?; }
                if let Some(v) = f39_alt_122 { v.write_to(w)?; }
                if let Some(v) = f39_alt_123 { v.write_to(w)?; }
                if let Some(v) = f39_alt_124 { v.write_to(w)?; }
                if let Some(v) = f39_alt_125 { v.write_to(w)?; }
                if let Some(v) = f39_alt_126 { v.write_to(w)?; }
                if let Some(v) = f39_alt_127 { v.write_to(w)?; }
                if let Some(v) = f39_alt_128 { v.write_to(w)?; }
                if let Some(v) = f39_alt_129 { v.write_to(w)?; }
                if let Some(v) = f39_alt_130 { v.write_to(w)?; }
                if let Some(v) = f39_alt_131 { v.write_to(w)?; }
                if let Some(v) = f39_alt_132 { v.write_to(w)?; }
                if let Some(v) = f39_alt_133 { v.write_to(w)?; }
                if let Some(v) = f39_alt_134 { v.write_to(w)?; }
                if let Some(v) = f39_alt_135 { v.write_to(w)?; }
                if let Some(v) = f39_alt_136 { v.write_to(w)?; }
                if let Some(v) = f39_alt_137 { v.write_to(w)?; }
                if let Some(v) = f39_alt_138 { v.write_to(w)?; }
                if let Some(v) = f39_alt_139 { v.write_to(w)?; }
                if let Some(v) = f39_alt_140 { v.write_to(w)?; }
                if let Some(v) = f39_alt_141 { v.write_to(w)?; }
                if let Some(v) = f39_alt_142 { v.write_to(w)?; }
                if let Some(v) = f39_alt_143 { v.write_to(w)?; }
                if let Some(v) = f39_alt_144 { v.write_to(w)?; }
                if let Some(v) = f39_alt_145 { v.write_to(w)?; }
                if let Some(v) = f39_alt_146 { v.write_to(w)?; }
                if let Some(v) = f39_alt_147 { v.write_to(w)?; }
                if let Some(v) = f39_alt_148 { v.write_to(w)?; }
                if let Some(v) = f39_alt_149 { v.write_to(w)?; }
                if let Some(v) = f39_alt_150 { v.write_to(w)?; }
                if let Some(v) = f39_alt_151 { v.write_to(w)?; }
                if let Some(v) = f39_alt_152 { v.write_to(w)?; }
                if let Some(v) = f39_alt_153 { v.write_to(w)?; }
                if let Some(v) = f39_alt_154 { v.write_to(w)?; }
                if let Some(v) = f39_alt_155 { v.write_to(w)?; }
                if let Some(v) = f39_alt_156 { v.write_to(w)?; }
                if let Some(v) = f39_alt_157 { v.write_to(w)?; }
                if let Some(v) = f39_alt_158 { v.write_to(w)?; }
                if let Some(v) = f39_alt_159 { v.write_to(w)?; }
                if let Some(v) = f39_alt_160 { v.write_to(w)?; }
                if let Some(v) = f39_alt_161 { v.write_to(w)?; }
                if let Some(v) = f39_alt_162 { v.write_to(w)?; }
                if let Some(v) = f39_alt_163 { v.write_to(w)?; }
                if let Some(v) = f39_alt_164 { v.write_to(w)?; }
                if let Some(v) = f39_alt_165 { v.write_to(w)?; }
                if let Some(v) = f39_alt_166 { v.write_to(w)?; }
                if let Some(v) = f39_alt_167 { v.write_to(w)?; }
                if let Some(v) = f39_alt_168 { v.write_to(w)?; }
                if let Some(v) = f39_alt_169 { v.write_to(w)?; }
                if let Some(v) = f39_alt_170 { v.write_to(w)?; }
                if let Some(v) = f39_alt_171 { v.write_to(w)?; }
                if let Some(v) = f39_alt_172 { v.write_to(w)?; }
                if let Some(v) = f39_alt_173 { v.write_to(w)?; }
                if let Some(v) = f39_alt_174 { v.write_to(w)?; }
                if let Some(v) = f39_alt_175 { v.write_to(w)?; }
                if let Some(v) = f39_alt_176 { v.write_to(w)?; }
                if let Some(v) = f39_alt_177 { v.write_to(w)?; }
                if let Some(v) = f39_alt_178 { v.write_to(w)?; }
                if let Some(v) = f39_alt_179 { v.write_to(w)?; }
                if let Some(v) = f39_alt_180 { v.write_to(w)?; }
                if let Some(v) = f39_alt_181 { v.write_to(w)?; }
                if let Some(v) = f39_alt_182 { v.write_to(w)?; }
                if let Some(v) = f39_alt_183 { v.write_to(w)?; }
                if let Some(v) = f39_alt_184 { v.write_to(w)?; }
                if let Some(v) = f39_alt_185 { v.write_to(w)?; }
                if let Some(v) = f39_alt_186 { v.write_to(w)?; }
                if let Some(v) = f39_alt_187 { v.write_to(w)?; }
                if let Some(v) = f39_alt_188 { v.write_to(w)?; }
                if let Some(v) = f39_alt_189 { v.write_to(w)?; }
                if let Some(v) = f39_alt_190 { v.write_to(w)?; }
                if let Some(v) = f39_alt_191 { v.write_to(w)?; }
                if let Some(v) = f39_alt_192 { v.write_to(w)?; }
                if let Some(arr) = field_40_u32_list { arr.write_to(w)?; }
                if let Some(v) = field_41_u32 { v.write_to(w)?; }
                if let Some(v) = field_42_u32 { v.write_to(w)?; }
                if let Some(v) = field_43_u32 { v.write_to(w)?; }
                if let Some(v) = field_44_u32 { v.write_to(w)?; }
                if let Some(v) = field_45_u32 { v.write_to(w)?; }
                if let Some(v) = field_46_u32 { v.write_to(w)?; }
                if let Some(v) = field_47_u32 { v.write_to(w)?; }
                if let Some(v) = field_48_u32 { v.write_to(w)?; }
                if let Some(arr) = field_49_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_50_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_51_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_52_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_53_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_54_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_55_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_56_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_57_u32_list { arr.write_to(w)?; }
                if let Some(arr) = field_58_u32_list { arr.write_to(w)?; }
                if let Some(v) = field_59_u32 { v.write_to(w)?; }
                if let Some(v) = field_60_u32 { v.write_to(w)?; }
                if let Some(v) = field_61_u32 { v.write_to(w)?; }
                if let Some(v) = field_62_u32 { v.write_to(w)?; }
                if let Some(v) = field_63_u32 { v.write_to(w)?; }
                if let Some(v) = field_64_u32 { v.write_to(w)?; }
                if let Some(v) = field_65_u32 { v.write_to(w)?; }
                if let Some(v) = field_66_u32 { v.write_to(w)?; }
                if let Some(v) = field_67_u32 { v.write_to(w)?; }
                if let Some(v) = field_68_u32 { v.write_to(w)?; }
                if let Some(v) = field_69_u32 { v.write_to(w)?; }
                if let Some(v) = field_70_u32 { v.write_to(w)?; }
                if let Some(v) = field_71_u32 { v.write_to(w)?; }
                if let Some(v) = field_72_u32 { v.write_to(w)?; }
                if let Some(v) = field_73_u32 { v.write_to(w)?; }
                if let Some(v) = field_74_u32 { v.write_to(w)?; }
                if let Some(v) = field_75_u32 { v.write_to(w)?; }
                if let Some(v) = field_76_u32 { v.write_to(w)?; }
                if let Some(v) = field_77_u32 { v.write_to(w)?; }
                if let Some(v) = field_78_u32 { v.write_to(w)?; }
                if let Some(v) = field_79_u32 { v.write_to(w)?; }
                if let Some(v) = field_80_u32 { v.write_to(w)?; }
                if let Some(v) = field_81_u32 { v.write_to(w)?; }
                if let Some(v) = field_82_u32 { v.write_to(w)?; }
                if let Some(v) = field_83_u32 { v.write_to(w)?; }
                if let Some(v) = field_84_u32 { v.write_to(w)?; }
                if let Some(v) = field_85_u32 { v.write_to(w)?; }
                if let Some(v) = field_86_u32 { v.write_to(w)?; }
                if let Some(v) = field_87_u32 { v.write_to(w)?; }
                if let Some(v) = field_88_u32 { v.write_to(w)?; }
                if let Some(v) = field_89_u32 { v.write_to(w)?; }
                if let Some(v) = field_90_u32 { v.write_to(w)?; }
                if let Some(v) = field_91_u32 { v.write_to(w)?; }
                if let Some(v) = field_92_u32 { v.write_to(w)?; }
                if let Some(v) = field_93_u32 { v.write_to(w)?; }
                if let Some(v) = field_94_u32 { v.write_to(w)?; }
                if let Some(v) = field_95_u32 { v.write_to(w)?; }
                if let Some(v) = field_96_u32 { v.write_to(w)?; }
                if let Some(v) = field_97_u32 { v.write_to(w)?; }
                if let Some(v) = field_98_u32 { v.write_to(w)?; }
                if let Some(v) = field_99_u32 { v.write_to(w)?; }
                if let Some(v) = field_100_u32 { v.write_to(w)?; }
                if let Some(v) = field_101_u32 { v.write_to(w)?; }
                if let Some(v) = field_102_u32 { v.write_to(w)?; }
                if let Some(v) = field_103_u32 { v.write_to(w)?; }
                if let Some(v) = field_104_u32 { v.write_to(w)?; }
                if let Some(v) = field_105_u32 { v.write_to(w)?; }
                if let Some(v) = field_106_u32 { v.write_to(w)?; }
                if let Some(v) = field_107_u32 { v.write_to(w)?; }
                if let Some(v) = field_108_u32 { v.write_to(w)?; }
                if let Some(v) = field_109_u32 { v.write_to(w)?; }
                if let Some(v) = field_110_u32 { v.write_to(w)?; }
                if let Some(v) = field_111_u32 { v.write_to(w)?; }
                if let Some(v) = field_112_u32 { v.write_to(w)?; }
                if let Some(v) = field_113_u32 { v.write_to(w)?; }
                if let Some(v) = field_114_u32 { v.write_to(w)?; }
                if let Some(v) = field_115_u32 { v.write_to(w)?; }
                if let Some(v) = field_116_u32 { v.write_to(w)?; }
                if let Some(v) = field_117_u32 { v.write_to(w)?; }
                if let Some(v) = field_118_u32 { v.write_to(w)?; }
                if let Some(v) = field_119_u32 { v.write_to(w)?; }
                if let Some(v) = field_120_u32 { v.write_to(w)?; }
                if let Some(v) = field_121_u32 { v.write_to(w)?; }
                if let Some(v) = field_122_u32 { v.write_to(w)?; }
                if let Some(v) = field_123_u32 { v.write_to(w)?; }
                if let Some(v) = field_124_u32 { v.write_to(w)?; }
                if let Some(v) = field_125_u32 { v.write_to(w)?; }
                if let Some(v) = field_126_u32 { v.write_to(w)?; }
                if let Some(v) = field_127_u32 { v.write_to(w)?; }
                if let Some(v) = field_128_u32 { v.write_to(w)?; }
                if let Some(v) = field_129_u32 { v.write_to(w)?; }
                if let Some(v) = field_130_u32 { v.write_to(w)?; }
                if let Some(v) = field_131_u32 { v.write_to(w)?; }
                if let Some(v) = field_132_u32 { v.write_to(w)?; }
                if let Some(v) = field_133_u32 { v.write_to(w)?; }
                if let Some(v) = field_134_u32 { v.write_to(w)?; }
                if let Some(v) = field_135_u32 { v.write_to(w)?; }
                if let Some(v) = field_136_u32 { v.write_to(w)?; }
                if let Some(v) = field_137_u32 { v.write_to(w)?; }
                if let Some(v) = field_138_u32 { v.write_to(w)?; }
                if let Some(v) = field_139_u32 { v.write_to(w)?; }
                if let Some(v) = field_140_u32 { v.write_to(w)?; }
                if let Some(v) = field_141_u32 { v.write_to(w)?; }
                if let Some(v) = field_142_u32 { v.write_to(w)?; }
                if let Some(v) = field_143_u32 { v.write_to(w)?; }
                if let Some(v) = field_144_u32 { v.write_to(w)?; }
                if let Some(v) = field_145_u32 { v.write_to(w)?; }
                if let Some(v) = field_146_u32 { v.write_to(w)?; }
                if let Some(v) = field_147_u32 { v.write_to(w)?; }
                if let Some(v) = field_148_u32 { v.write_to(w)?; }
                if let Some(v) = field_149_u32 { v.write_to(w)?; }
                if let Some(v) = field_150_u32 { v.write_to(w)?; }
                if let Some(v) = field_151_u32 { v.write_to(w)?; }
                if let Some(v) = field_152_u32 { v.write_to(w)?; }
                if let Some(v) = field_153_u32 { v.write_to(w)?; }
                if let Some(v) = field_154_u32 { v.write_to(w)?; }
                if let Some(v) = field_155_u32 { v.write_to(w)?; }
                if let Some(v) = field_156_u32 { v.write_to(w)?; }
                if let Some(v) = field_157_u32 { v.write_to(w)?; }
                if let Some(v) = field_158_u32 { v.write_to(w)?; }
                if let Some(v) = field_159_u32 { v.write_to(w)?; }
                if let Some(v) = field_160_u32 { v.write_to(w)?; }
                if let Some(v) = field_161_u32 { v.write_to(w)?; }
                if let Some(v) = field_162_u32 { v.write_to(w)?; }
                if let Some(v) = field_163_u32 { v.write_to(w)?; }
                if let Some(v) = field_164_u32 { v.write_to(w)?; }
                if let Some(v) = field_165_u32 { v.write_to(w)?; }
                if let Some(v) = field_166_u32 { v.write_to(w)?; }
                if let Some(v) = field_167_u32 { v.write_to(w)?; }
                if let Some(v) = field_168_u32 { v.write_to(w)?; }
                if let Some(v) = field_169_u32 { v.write_to(w)?; }
                if let Some(v) = field_170_u32 { v.write_to(w)?; }
                if let Some(v) = field_171_u32 { v.write_to(w)?; }
                if let Some(v) = field_172_u32 { v.write_to(w)?; }
                if let Some(v) = field_173_u32 { v.write_to(w)?; }
                if let Some(v) = field_174_u32 { v.write_to(w)?; }
                if let Some(v) = field_175_u32 { v.write_to(w)?; }
                if let Some(v) = field_176_u32 { v.write_to(w)?; }
                if let Some(v) = field_177_u32 { v.write_to(w)?; }
                if let Some(v) = field_178_u32 { v.write_to(w)?; }
                if let Some(v) = field_179_u32 { v.write_to(w)?; }
                if let Some(v) = field_180_u32 { v.write_to(w)?; }
                if let Some(v) = field_181_u32 { v.write_to(w)?; }
                if let Some(v) = field_182_u32 { v.write_to(w)?; }
                if let Some(v) = field_183_u32 { v.write_to(w)?; }
                if let Some(v) = field_184_u32 { v.write_to(w)?; }
                if let Some(v) = field_185_u32 { v.write_to(w)?; }
                if let Some(v) = field_186_u32 { v.write_to(w)?; }
                if let Some(v) = field_187_u32 { v.write_to(w)?; }
                if let Some(v) = field_188_u32 { v.write_to(w)?; }
                if let Some(v) = field_189_u32 { v.write_to(w)?; }
                if let Some(v) = field_190_u32 { v.write_to(w)?; }
                if let Some(v) = field_191_u32 { v.write_to(w)?; }
                if let Some(v) = field_192_u32 { v.write_to(w)?; }
                if let Some(v) = field_193_u32 { v.write_to(w)?; }
                if let Some(v) = field_194_u32 { v.write_to(w)?; }
                if let Some(v) = field_195_u32 { v.write_to(w)?; }
                if let Some(v) = field_196_u32 { v.write_to(w)?; }
                if let Some(v) = field_197_u32 { v.write_to(w)?; }
                if let Some(v) = field_198_u32 { v.write_to(w)?; }
                if let Some(v) = field_199_u32 { v.write_to(w)?; }
                if let Some(v) = field_200_u32 { v.write_to(w)?; }
                if let Some(v) = field_201_u32 { v.write_to(w)?; }
                if let Some(v) = field_202_u32 { v.write_to(w)?; }
                if let Some(v) = field_203_u32 { v.write_to(w)?; }
                if let Some(v) = field_204_u32 { v.write_to(w)?; }
                if let Some(v) = field_205_u32 { v.write_to(w)?; }
                if let Some(v) = field_206_u32 { v.write_to(w)?; }
                if let Some(v) = field_207_u32 { v.write_to(w)?; }
                if let Some(v) = field_208_u32 { v.write_to(w)?; }
                if let Some(v) = field_209_u32 { v.write_to(w)?; }
                if let Some(v) = field_210_u32 { v.write_to(w)?; }
                if let Some(v) = field_211_u32 { v.write_to(w)?; }
                if let Some(v) = field_212_u32 { v.write_to(w)?; }
                if let Some(v) = field_213_u32 { v.write_to(w)?; }
                if let Some(v) = field_214_u32 { v.write_to(w)?; }
                if let Some(v) = field_215_u32 { v.write_to(w)?; }
                if let Some(v) = field_216_u32 { v.write_to(w)?; }
                if let Some(v) = field_217_u32 { v.write_to(w)?; }
                if let Some(v) = field_218_u32 { v.write_to(w)?; }
                if let Some(v) = field_219_u32 { v.write_to(w)?; }
                if let Some(v) = field_220_u32 { v.write_to(w)?; }
                if let Some(v) = field_221_u32 { v.write_to(w)?; }
                if let Some(v) = field_222_u32 { v.write_to(w)?; }
                if let Some(v) = field_223_u32 { v.write_to(w)?; }
                if let Some(v) = field_224_u32 { v.write_to(w)?; }
                if let Some(v) = field_225_u32 { v.write_to(w)?; }
                if let Some(v) = field_226_u32 { v.write_to(w)?; }
                if let Some(v) = field_227_u32 { v.write_to(w)?; }
                if let Some(v) = field_228_u32 { v.write_to(w)?; }
                if let Some(v) = field_229_u32 { v.write_to(w)?; }
                if let Some(v) = field_230_u32 { v.write_to(w)?; }
                if let Some(v) = field_231_u32 { v.write_to(w)?; }
                if let Some(v) = field_232_u32 { v.write_to(w)?; }
                if let Some(v) = field_233_u32 { v.write_to(w)?; }
                if let Some(v) = field_234_u32 { v.write_to(w)?; }
                if let Some(v) = field_235_u32 { v.write_to(w)?; }
                if let Some(v) = field_236_u32 { v.write_to(w)?; }
                if let Some(v) = field_237_u32 { v.write_to(w)?; }
                if let Some(v) = field_238_u32 { v.write_to(w)?; }
                if let Some(v) = field_239_u32 { v.write_to(w)?; }
                if let Some(v) = field_240_u32 { v.write_to(w)?; }
                if let Some(v) = field_241_u32 { v.write_to(w)?; }
                if let Some(v) = field_242_u32 { v.write_to(w)?; }
                if let Some(v) = field_243_u32 { v.write_to(w)?; }
                if let Some(v) = field_244_u32 { v.write_to(w)?; }
                if let Some(v) = field_245_u32 { v.write_to(w)?; }
                if let Some(v) = field_246_u32 { v.write_to(w)?; }
                if let Some(v) = field_247_u32 { v.write_to(w)?; }
                if let Some(v) = field_248_u32 { v.write_to(w)?; }
                if let Some(v) = field_249_u32 { v.write_to(w)?; }
                if let Some(v) = field_250_u32 { v.write_to(w)?; }
                if let Some(v) = field_251_u32 { v.write_to(w)?; }
                if let Some(v) = field_252_u32 { v.write_to(w)?; }
                if let Some(v) = field_253_u32 { v.write_to(w)?; }
                if let Some(v) = field_254_u32 { v.write_to(w)?; }
                if let Some(v) = field_255_u32 { v.write_to(w)?; }
                if let Some(v) = field_256_u32 { v.write_to(w)?; }
                if let Some(v) = field_257_u32 { v.write_to(w)?; }
                if let Some(v) = field_258_u32 { v.write_to(w)?; }
                if let Some(v) = field_259_u32 { v.write_to(w)?; }
                if let Some(v) = field_260_u32 { v.write_to(w)?; }
                if let Some(v) = field_261_u32 { v.write_to(w)?; }
                if let Some(v) = field_262_u32 { v.write_to(w)?; }
                if let Some(v) = field_263_u32 { v.write_to(w)?; }
                if let Some(v) = field_264_u32 { v.write_to(w)?; }
                if let Some(v) = field_265_u32 { v.write_to(w)?; }
                if let Some(v) = field_266_u32 { v.write_to(w)?; }
                if let Some(v) = field_267_u32 { v.write_to(w)?; }
                if let Some(v) = field_268_u32 { v.write_to(w)?; }
                if let Some(v) = field_269_u32 { v.write_to(w)?; }
                if let Some(v) = field_270_u32 { v.write_to(w)?; }
                if let Some(v) = field_271_u32 { v.write_to(w)?; }
                if let Some(v) = field_272_u32 { v.write_to(w)?; }
                if let Some(v) = field_273_u32 { v.write_to(w)?; }
                if let Some(v) = field_274_u32 { v.write_to(w)?; }
                if let Some(v) = field_275_u32 { v.write_to(w)?; }
                if let Some(v) = field_276_u32 { v.write_to(w)?; }
                if let Some(v) = field_277_u32 { v.write_to(w)?; }
                if let Some(v) = field_278_u32 { v.write_to(w)?; }
                if let Some(v) = field_279_u32 { v.write_to(w)?; }
                if let Some(v) = field_280_u32 { v.write_to(w)?; }
                if let Some(v) = field_281_u32 { v.write_to(w)?; }
                if let Some(v) = field_282_u32 { v.write_to(w)?; }
                if let Some(v) = field_283_u32 { v.write_to(w)?; }
                if let Some(v) = field_284_u32 { v.write_to(w)?; }
                if let Some(v) = field_285_u32 { v.write_to(w)?; }
                if let Some(v) = field_286_u32 { v.write_to(w)?; }
                if let Some(v) = field_287_u32 { v.write_to(w)?; }
                if let Some(v) = field_288_u32 { v.write_to(w)?; }
                if let Some(v) = field_289_u32 { v.write_to(w)?; }
                if let Some(v) = field_290_u32 { v.write_to(w)?; }
                if let Some(v) = field_291_u32 { v.write_to(w)?; }
                if let Some(v) = field_292_u32 { v.write_to(w)?; }
                if let Some(v) = field_293_u32 { v.write_to(w)?; }
                if let Some(v) = field_294_u32 { v.write_to(w)?; }
                if let Some(v) = field_295_u32 { v.write_to(w)?; }
                if let Some(v) = field_296_u32 { v.write_to(w)?; }
                if let Some(v) = field_297_u32 { v.write_to(w)?; }
                if let Some(v) = field_298_u32 { v.write_to(w)?; }
                if let Some(v) = field_299_u32 { v.write_to(w)?; }
                if let Some(v) = field_300_u32 { v.write_to(w)?; }
                if let Some(v) = field_301_u32 { v.write_to(w)?; }
                if let Some(v) = field_302_u32 { v.write_to(w)?; }
                if let Some(v) = field_303_u32 { v.write_to(w)?; }
                if let Some(v) = field_304_u32 { v.write_to(w)?; }
                if let Some(v) = field_305_u32 { v.write_to(w)?; }
                if let Some(v) = field_306_u32 { v.write_to(w)?; }
                if let Some(v) = field_307_u32 { v.write_to(w)?; }
                if let Some(v) = field_308_u32 { v.write_to(w)?; }
                if let Some(v) = field_309_u32 { v.write_to(w)?; }
                if let Some(v) = field_310_u32 { v.write_to(w)?; }
                if let Some(v) = field_311_u32 { v.write_to(w)?; }
                if let Some(v) = field_312_u32 { v.write_to(w)?; }
                if let Some(v) = field_313_u32 { v.write_to(w)?; }
                if let Some(v) = field_314_u32 { v.write_to(w)?; }
                if let Some(v) = field_315_u32 { v.write_to(w)?; }
                if let Some(v) = field_316_u32 { v.write_to(w)?; }
                if let Some(v) = field_317_u32 { v.write_to(w)?; }
                if let Some(v) = field_318_u32 { v.write_to(w)?; }
                if let Some(v) = field_319_u32 { v.write_to(w)?; }
                if let Some(v) = field_320_u32 { v.write_to(w)?; }
                if let Some(v) = field_321_u32 { v.write_to(w)?; }
                if let Some(v) = field_322_u32 { v.write_to(w)?; }
                if let Some(v) = field_323_u32 { v.write_to(w)?; }
                if let Some(v) = field_324_u32 { v.write_to(w)?; }
                if let Some(v) = field_325_u32 { v.write_to(w)?; }
                if let Some(v) = field_326_u32 { v.write_to(w)?; }
                if let Some(v) = field_327_u32 { v.write_to(w)?; }
                if let Some(v) = field_328_u32 { v.write_to(w)?; }
                if let Some(v) = field_329_u32 { v.write_to(w)?; }
                if let Some(v) = field_330_u32 { v.write_to(w)?; }
                if let Some(v) = field_331_u32 { v.write_to(w)?; }
                if let Some(v) = field_332_u32 { v.write_to(w)?; }
                if let Some(v) = field_333_u32 { v.write_to(w)?; }
                if let Some(v) = field_334_u32 { v.write_to(w)?; }
                if let Some(v) = field_335_u32 { v.write_to(w)?; }
                if let Some(v) = field_336_u32 { v.write_to(w)?; }
                if let Some(v) = field_337_u32 { v.write_to(w)?; }
                if let Some(v) = field_338_u32 { v.write_to(w)?; }
                if let Some(v) = field_339_u32 { v.write_to(w)?; }
                if let Some(v) = field_340_u32 { v.write_to(w)?; }
                if let Some(v) = field_341_u32 { v.write_to(w)?; }
                if let Some(v) = field_342_u32_count { v.write_to(w)?; }
                if let Some(v) = field_343_u8_flag { v.write_to(w)?; }
                if let Some(v) = field_344_u32 { v.write_to(w)?; }
                if let Some(v) = field_345_u32 { v.write_to(w)?; }
                if let Some(v) = field_346_u32 { v.write_to(w)?; }
                if let Some(v) = field_347_u32 { v.write_to(w)?; }
                if let Some(v) = field_348_u32 { v.write_to(w)?; }
                if let Some(v) = field_349_u32 { v.write_to(w)?; }
                if let Some(v) = field_350_u32 { v.write_to(w)?; }
                if let Some(v) = field_351_u32 { v.write_to(w)?; }
                if let Some(v) = field_352_u32 { v.write_to(w)?; }
                if let Some(v) = field_353_u32 { v.write_to(w)?; }
                if let Some(v) = field_354_u32 { v.write_to(w)?; }
                if let Some(v) = field_355_u32 { v.write_to(w)?; }
                if let Some(v) = field_356_u32 { v.write_to(w)?; }
                if let Some(v) = field_357_u32 { v.write_to(w)?; }
                if let Some(v) = field_358_u32 { v.write_to(w)?; }
                if let Some(v) = field_359_u32 { v.write_to(w)?; }
                if let Some(v) = field_360_u32 { v.write_to(w)?; }
                if let Some(v) = field_361_u32 { v.write_to(w)?; }
                if let Some(v) = field_362_u32 { v.write_to(w)?; }
                if let Some(v) = field_363_u32 { v.write_to(w)?; }
                if let Some(v) = field_364_u32 { v.write_to(w)?; }
                if let Some(v) = field_365_u32 { v.write_to(w)?; }
                if let Some(v) = field_366_u32 { v.write_to(w)?; }
                if let Some(v) = field_367_u32 { v.write_to(w)?; }
                if let Some(v) = field_368_u32 { v.write_to(w)?; }
                if let Some(v) = field_369_u32 { v.write_to(w)?; }
                if let Some(v) = field_370_u32 { v.write_to(w)?; }
                if let Some(v) = field_371_u32 { v.write_to(w)?; }
                if let Some(v) = field_372_u32 { v.write_to(w)?; }
                if let Some(v) = field_373_u32 { v.write_to(w)?; }
                if let Some(v) = field_374_u32 { v.write_to(w)?; }
                if let Some(v) = field_375_u32 { v.write_to(w)?; }
                if let Some(v) = field_376_u32 { v.write_to(w)?; }
                if let Some(v) = field_377_u32 { v.write_to(w)?; }
                if let Some(v) = field_378_u32 { v.write_to(w)?; }
                if let Some(v) = field_379_u32 { v.write_to(w)?; }
                if let Some(v) = field_380_u32 { v.write_to(w)?; }
                if let Some(v) = field_381_u32 { v.write_to(w)?; }
                if let Some(v) = field_382_u32 { v.write_to(w)?; }
                if let Some(v) = field_383_u32 { v.write_to(w)?; }
                if let Some(v) = field_384_u32 { v.write_to(w)?; }
                if let Some(v) = field_385_u32 { v.write_to(w)?; }
                if let Some(v) = field_386_u32 { v.write_to(w)?; }
                if let Some(v) = field_387_u32 { v.write_to(w)?; }
                if let Some(v) = field_388_u32 { v.write_to(w)?; }
                if let Some(v) = field_389_u32 { v.write_to(w)?; }
                if let Some(v) = field_390_u32 { v.write_to(w)?; }
                if let Some(v) = field_391_u32 { v.write_to(w)?; }
                if let Some(v) = field_392_u32 { v.write_to(w)?; }
                if let Some(v) = field_393_u32 { v.write_to(w)?; }
                if let Some(v) = field_394_u32 { v.write_to(w)?; }
                if let Some(v) = field_395_u32 { v.write_to(w)?; }
                if let Some(v) = field_396_u32 { v.write_to(w)?; }
                if let Some(v) = field_397_u32 { v.write_to(w)?; }
                if let Some(v) = field_398_u32 { v.write_to(w)?; }
                if let Some(v) = field_399_u32 { v.write_to(w)?; }
                if let Some(v) = field_400_u32 { v.write_to(w)?; }
                if let Some(v) = field_401_u32 { v.write_to(w)?; }
                if let Some(v) = field_402_u32 { v.write_to(w)?; }
                if let Some(v) = field_403_u32 { v.write_to(w)?; }
                if let Some(v) = field_404_u32 { v.write_to(w)?; }
                if let Some(v) = field_405_u32 { v.write_to(w)?; }
                if let Some(v) = field_406_u32 { v.write_to(w)?; }
                if let Some(v) = field_407_u32 { v.write_to(w)?; }
                if let Some(v) = field_408_u32 { v.write_to(w)?; }
                if let Some(v) = field_409_u32 { v.write_to(w)?; }
                if let Some(v) = field_410_u32 { v.write_to(w)?; }
                if let Some(v) = field_411_u32 { v.write_to(w)?; }
                if let Some(v) = field_412_u32 { v.write_to(w)?; }
                if let Some(v) = field_413_u32 { v.write_to(w)?; }
                if let Some(v) = field_414_u32 { v.write_to(w)?; }
                if let Some(v) = field_415_u32 { v.write_to(w)?; }
                if let Some(v) = field_416_u32 { v.write_to(w)?; }
                if let Some(v) = field_417_u32 { v.write_to(w)?; }
                if let Some(v) = field_418_u32 { v.write_to(w)?; }
                if let Some(v) = field_419_u32 { v.write_to(w)?; }
                if let Some(v) = field_420_u32 { v.write_to(w)?; }
                if let Some(v) = field_421_u32 { v.write_to(w)?; }
                if let Some(v) = field_422_u32 { v.write_to(w)?; }
                if let Some(v) = field_423_u32 { v.write_to(w)?; }
                if let Some(v) = field_424_u32 { v.write_to(w)?; }
                if let Some(v) = field_425_u32 { v.write_to(w)?; }
                if let Some(v) = field_426_u32 { v.write_to(w)?; }
                if let Some(v) = field_427_u32 { v.write_to(w)?; }
                if let Some(v) = field_428_u32 { v.write_to(w)?; }
                if let Some(v) = field_429_u32 { v.write_to(w)?; }
                if let Some(v) = field_430_u32 { v.write_to(w)?; }
                if let Some(v) = field_431_u32 { v.write_to(w)?; }
                if let Some(v) = field_432_u32 { v.write_to(w)?; }
                if let Some(v) = field_433_u32 { v.write_to(w)?; }
                if let Some(v) = field_434_u32 { v.write_to(w)?; }
                if let Some(v) = field_435_u32 { v.write_to(w)?; }
                if let Some(v) = field_436_u32 { v.write_to(w)?; }
                if let Some(v) = field_437_u32 { v.write_to(w)?; }
                if let Some(v) = field_438_u32 { v.write_to(w)?; }
                if let Some(v) = field_439_u32 { v.write_to(w)?; }
                if let Some(v) = field_440_u32 { v.write_to(w)?; }
                if let Some(v) = field_441_u32 { v.write_to(w)?; }
                if let Some(v) = field_442_u32 { v.write_to(w)?; }
                if let Some(v) = field_443_u32 { v.write_to(w)?; }
                if let Some(v) = field_444_u32 { v.write_to(w)?; }
                if let Some(v) = field_445_u32 { v.write_to(w)?; }
                if let Some(v) = field_446_u32 { v.write_to(w)?; }
                if let Some(v) = field_447_u32 { v.write_to(w)?; }
                if let Some(v) = field_448_u32 { v.write_to(w)?; }
                if let Some(v) = field_449_u32 { v.write_to(w)?; }
                if let Some(v) = field_450_u32 { v.write_to(w)?; }
                if let Some(v) = field_451_u32 { v.write_to(w)?; }
                if let Some(v) = field_452_u32 { v.write_to(w)?; }
                if let Some(v) = field_453_u32 { v.write_to(w)?; }
                if let Some(v) = field_454_u32 { v.write_to(w)?; }
                if let Some(v) = field_455_u32 { v.write_to(w)?; }
                if let Some(v) = field_456_u32 { v.write_to(w)?; }
                if let Some(v) = field_457_u32 { v.write_to(w)?; }
                if let Some(v) = field_458_u32 { v.write_to(w)?; }
                if let Some(v) = field_459_u32 { v.write_to(w)?; }
                if let Some(v) = field_460_u32 { v.write_to(w)?; }
                if let Some(v) = field_461_u32 { v.write_to(w)?; }
                if let Some(v) = field_462_u32 { v.write_to(w)?; }
                if let Some(v) = field_463_u32 { v.write_to(w)?; }
                if let Some(v) = field_464_u32 { v.write_to(w)?; }
                if let Some(v) = field_465_u32 { v.write_to(w)?; }
                if let Some(v) = field_466_u32 { v.write_to(w)?; }
                if let Some(v) = field_467_u32 { v.write_to(w)?; }
                if let Some(v) = field_468_u32 { v.write_to(w)?; }
                if let Some(v) = field_469_u32 { v.write_to(w)?; }
                if let Some(v) = field_470_u32 { v.write_to(w)?; }
                if let Some(v) = field_471_u32 { v.write_to(w)?; }
                if let Some(v) = field_472_u32 { v.write_to(w)?; }
                if let Some(v) = field_473_u32 { v.write_to(w)?; }
                if let Some(v) = field_474_u32 { v.write_to(w)?; }
                if let Some(v) = field_475_u32 { v.write_to(w)?; }
                if let Some(v) = field_476_u32 { v.write_to(w)?; }
                if let Some(v) = field_477_u32 { v.write_to(w)?; }
                if let Some(v) = field_478_u32 { v.write_to(w)?; }
                if let Some(v) = field_479_u32 { v.write_to(w)?; }
                if let Some(v) = field_480_u32 { v.write_to(w)?; }
                if let Some(v) = field_481_u32 { v.write_to(w)?; }
                if let Some(v) = field_482_u32 { v.write_to(w)?; }
                if let Some(v) = field_483_u32 { v.write_to(w)?; }
                if let Some(v) = field_484_u32 { v.write_to(w)?; }
                if let Some(v) = field_485_u32 { v.write_to(w)?; }
                if let Some(v) = field_486_u32 { v.write_to(w)?; }
                if let Some(v) = field_487_u32 { v.write_to(w)?; }
                if let Some(v) = field_488_u32 { v.write_to(w)?; }
                if let Some(v) = field_489_u32 { v.write_to(w)?; }
                if let Some(v) = field_490_u32 { v.write_to(w)?; }
                if let Some(v) = field_491_u32 { v.write_to(w)?; }
                if let Some(v) = field_492_u32 { v.write_to(w)?; }
                if let Some(v) = field_493_u32 { v.write_to(w)?; }
                if let Some(v) = field_494_u32 { v.write_to(w)?; }
                if let Some(v) = field_495_u32 { v.write_to(w)?; }
                if let Some(v) = field_496_u32 { v.write_to(w)?; }
                if let Some(v) = field_497_u32 { v.write_to(w)?; }
                if let Some(v) = field_498_u32 { v.write_to(w)?; }
                if let Some(v) = field_499_u32 { v.write_to(w)?; }
                if let Some(v) = field_500_u32 { v.write_to(w)?; }
                if let Some(v) = field_501_u32 { v.write_to(w)?; }
                if let Some(v) = field_502_u32 { v.write_to(w)?; }
                if let Some(v) = field_503_u32 { v.write_to(w)?; }
                if let Some(v) = field_504_u32 { v.write_to(w)?; }
                if let Some(v) = field_505_u32 { v.write_to(w)?; }
                if let Some(v) = field_506_u32 { v.write_to(w)?; }
                if let Some(v) = field_507_u32 { v.write_to(w)?; }
                if let Some(v) = field_508_u32 { v.write_to(w)?; }
                if let Some(v) = field_509_u32 { v.write_to(w)?; }
                if let Some(v) = field_510_u32 { v.write_to(w)?; }
                if let Some(v) = field_511_u32 { v.write_to(w)?; }
                if let Some(v) = field_512_u32 { v.write_to(w)?; }
                if let Some(v) = field_513_u32 { v.write_to(w)?; }
                if let Some(v) = field_514_u32 { v.write_to(w)?; }
                if let Some(v) = field_515_u32 { v.write_to(w)?; }
                if let Some(v) = field_516_u32 { v.write_to(w)?; }
                if let Some(v) = field_517_u32 { v.write_to(w)?; }
                if let Some(v) = field_518_u32 { v.write_to(w)?; }
                if let Some(v) = field_519_u32 { v.write_to(w)?; }
                if let Some(v) = field_520_u32 { v.write_to(w)?; }
                if let Some(v) = field_521_u32 { v.write_to(w)?; }
                if let Some(v) = field_522_u32 { v.write_to(w)?; }
                if let Some(v) = field_523_u32 { v.write_to(w)?; }
                if let Some(v) = field_524_u32 { v.write_to(w)?; }
                if let Some(v) = field_525_u32 { v.write_to(w)?; }
                if let Some(v) = field_526_u32 { v.write_to(w)?; }
                if let Some(v) = field_527_u32 { v.write_to(w)?; }
                if let Some(v) = field_528_u32 { v.write_to(w)?; }
                if let Some(v) = field_529_u32 { v.write_to(w)?; }
                if let Some(v) = field_530_u32 { v.write_to(w)?; }
                if let Some(v) = field_531_u32 { v.write_to(w)?; }
                if let Some(v) = field_532_u32 { v.write_to(w)?; }
                if let Some(v) = field_533_u32 { v.write_to(w)?; }
                if let Some(v) = field_534_u32 { v.write_to(w)?; }
                if let Some(v) = field_535_u32 { v.write_to(w)?; }
                if let Some(v) = field_536_u32 { v.write_to(w)?; }
                if let Some(v) = field_537_u32 { v.write_to(w)?; }
                if let Some(v) = field_538_u32 { v.write_to(w)?; }
                if let Some(v) = field_539_u32 { v.write_to(w)?; }
                if let Some(v) = field_540_u32 { v.write_to(w)?; }
                if let Some(v) = field_541_u32 { v.write_to(w)?; }
                if let Some(v) = field_542_u32 { v.write_to(w)?; }
                if let Some(v) = field_543_u32 { v.write_to(w)?; }
                if let Some(v) = field_544_u32 { v.write_to(w)?; }
                if let Some(v) = field_545_u32 { v.write_to(w)?; }
                if let Some(v) = field_546_u32 { v.write_to(w)?; }
                if let Some(v) = field_547_u32 { v.write_to(w)?; }
                if let Some(v) = field_548_u32 { v.write_to(w)?; }
                if let Some(v) = field_549_u32 { v.write_to(w)?; }
                if let Some(v) = field_550_u32 { v.write_to(w)?; }
                if let Some(v) = field_551_u32 { v.write_to(w)?; }
                if let Some(v) = field_552_u32 { v.write_to(w)?; }
                if let Some(v) = field_553_u32 { v.write_to(w)?; }
                if let Some(v) = field_554_u32 { v.write_to(w)?; }
                if let Some(v) = field_555_u32 { v.write_to(w)?; }
                if let Some(v) = field_556_u32 { v.write_to(w)?; }
                if let Some(v) = field_557_u32 { v.write_to(w)?; }
                if let Some(v) = field_558_u32 { v.write_to(w)?; }
                if let Some(v) = field_559_u32 { v.write_to(w)?; }
                if let Some(v) = field_560_u32 { v.write_to(w)?; }
                if let Some(v) = field_561_u32 { v.write_to(w)?; }
                if let Some(v) = field_562_u32 { v.write_to(w)?; }
                if let Some(v) = field_563_u32 { v.write_to(w)?; }
                if let Some(v) = field_564_u32 { v.write_to(w)?; }
                if let Some(v) = field_565_u32 { v.write_to(w)?; }
                if let Some(v) = field_566_u32 { v.write_to(w)?; }
                if let Some(v) = field_567_u32 { v.write_to(w)?; }
                if let Some(v) = field_568_u32 { v.write_to(w)?; }
                if let Some(v) = field_569_u32 { v.write_to(w)?; }
                if let Some(v) = field_570_u32 { v.write_to(w)?; }
                if let Some(v) = field_571_u32 { v.write_to(w)?; }
                if let Some(v) = field_572_u32 { v.write_to(w)?; }
                if let Some(v) = field_573_u32 { v.write_to(w)?; }
                if let Some(v) = field_574_u32 { v.write_to(w)?; }
                if let Some(v) = field_575_u32 { v.write_to(w)?; }
                if let Some(v) = field_576_u32 { v.write_to(w)?; }
                if let Some(v) = field_577_u32 { v.write_to(w)?; }
                if let Some(v) = field_578_u32 { v.write_to(w)?; }
                if let Some(v) = field_579_u32 { v.write_to(w)?; }
                if let Some(v) = field_580_u32 { v.write_to(w)?; }
                if let Some(v) = field_581_u32 { v.write_to(w)?; }
                if let Some(v) = field_582_u32 { v.write_to(w)?; }
                if let Some(v) = field_583_u32 { v.write_to(w)?; }
                if let Some(v) = field_584_u32 { v.write_to(w)?; }
                if let Some(v) = field_585_u32 { v.write_to(w)?; }
                if let Some(v) = field_586_u32 { v.write_to(w)?; }
                if let Some(v) = field_587_u32 { v.write_to(w)?; }
                if let Some(v) = field_588_u32 { v.write_to(w)?; }
                if let Some(v) = field_589_u32 { v.write_to(w)?; }
                if let Some(v) = field_590_u32 { v.write_to(w)?; }
                if let Some(v) = field_591_u32 { v.write_to(w)?; }
                if let Some(v) = field_592_u32 { v.write_to(w)?; }
                if let Some(v) = field_593_u32 { v.write_to(w)?; }
                if let Some(v) = field_594_u32 { v.write_to(w)?; }
                if let Some(v) = field_595_u32 { v.write_to(w)?; }
                if let Some(v) = field_596_u32 { v.write_to(w)?; }
                if let Some(v) = field_597_u32 { v.write_to(w)?; }
                if let Some(v) = field_598_u32 { v.write_to(w)?; }
                if let Some(v) = field_599_u32 { v.write_to(w)?; }
                if let Some(v) = field_600_u32 { v.write_to(w)?; }
                if let Some(v) = field_601_u32 { v.write_to(w)?; }
                if let Some(v) = field_602_u32 { v.write_to(w)?; }
                if let Some(v) = field_603_u32 { v.write_to(w)?; }
                if let Some(v) = field_604_u32 { v.write_to(w)?; }
                if let Some(v) = field_605_u32 { v.write_to(w)?; }
                if let Some(v) = field_606_u32 { v.write_to(w)?; }
                if let Some(v) = field_607_u32 { v.write_to(w)?; }
                if let Some(v) = field_608_u32 { v.write_to(w)?; }
                if let Some(v) = field_609_u32 { v.write_to(w)?; }
                if let Some(v) = field_610_u32 { v.write_to(w)?; }
                if let Some(v) = field_611_u32 { v.write_to(w)?; }
                if let Some(v) = field_612_u32 { v.write_to(w)?; }
                if let Some(v) = field_613_u32 { v.write_to(w)?; }
                if let Some(v) = field_614_u32 { v.write_to(w)?; }
                if let Some(v) = field_615_u32 { v.write_to(w)?; }
                if let Some(v) = field_616_u32 { v.write_to(w)?; }
                if let Some(v) = field_617_u32 { v.write_to(w)?; }
                if let Some(v) = field_618_u32 { v.write_to(w)?; }
                if let Some(v) = field_619_u32 { v.write_to(w)?; }
                if let Some(v) = field_620_u32 { v.write_to(w)?; }
                if let Some(v) = field_621_u32 { v.write_to(w)?; }
                if let Some(v) = field_622_u32 { v.write_to(w)?; }
                if let Some(v) = field_623_u32 { v.write_to(w)?; }
                if let Some(v) = field_624_u32 { v.write_to(w)?; }
                if let Some(v) = field_625_u32 { v.write_to(w)?; }
                if let Some(v) = field_626_u32 { v.write_to(w)?; }
                if let Some(v) = field_627_u32 { v.write_to(w)?; }
                if let Some(v) = field_628_u32 { v.write_to(w)?; }
                if let Some(v) = field_629_u32 { v.write_to(w)?; }
                if let Some(v) = field_630_u32 { v.write_to(w)?; }
                if let Some(v) = field_631_u32 { v.write_to(w)?; }
                if let Some(v) = field_632_u32 { v.write_to(w)?; }
                if let Some(v) = field_633_u32 { v.write_to(w)?; }
                if let Some(v) = field_634_u32 { v.write_to(w)?; }
                if let Some(v) = field_635_u32 { v.write_to(w)?; }
                if let Some(v) = field_636_u32 { v.write_to(w)?; }
                if let Some(v) = field_637_u32 { v.write_to(w)?; }
                if let Some(v) = field_638_u32 { v.write_to(w)?; }
                if let Some(v) = field_639_u32 { v.write_to(w)?; }
                if let Some(v) = field_640_u32 { v.write_to(w)?; }
                if let Some(v) = field_641_u32 { v.write_to(w)?; }
                if let Some(v) = field_642_u32 { v.write_to(w)?; }
                if let Some(v) = field_643_u32 { v.write_to(w)?; }
                if let Some(v) = field_644_u32 { v.write_to(w)?; }
                if let Some(v) = field_645_u32 { v.write_to(w)?; }
                if let Some(v) = field_646_u32 { v.write_to(w)?; }
                if let Some(v) = field_647_u32 { v.write_to(w)?; }
                if let Some(v) = field_648_u32 { v.write_to(w)?; }
                if let Some(v) = field_649_u32 { v.write_to(w)?; }
                if let Some(v) = field_650_u32 { v.write_to(w)?; }
                if let Some(v) = field_651_u32 { v.write_to(w)?; }
                if let Some(v) = field_652_u32 { v.write_to(w)?; }
                if let Some(v) = field_653_u32 { v.write_to(w)?; }
                if let Some(v) = field_654_u32 { v.write_to(w)?; }
                if let Some(v) = field_655_u32 { v.write_to(w)?; }
                if let Some(v) = field_656_u32 { v.write_to(w)?; }
                if let Some(v) = field_657_u32 { v.write_to(w)?; }
                if let Some(v) = field_658_u32 { v.write_to(w)?; }
                if let Some(v) = field_659_u32 { v.write_to(w)?; }
                if let Some(v) = field_660_u32 { v.write_to(w)?; }
                if let Some(v) = field_661_u32 { v.write_to(w)?; }
                if let Some(v) = field_662_u32 { v.write_to(w)?; }
                if let Some(v) = field_663_u32 { v.write_to(w)?; }
                if let Some(v) = field_664_u32 { v.write_to(w)?; }
                if let Some(v) = alt_trigger_count { v.write_to(w)?; }
                if let Some(v) = alt_trigger_flag { v.write_to(w)?; }
                if let Some(s) = alt_trigger_name { s.write_to(w)?; }
                if let Some(v) = alt_inner_count { v.write_to(w)?; }
                if let Some(s) = alt_inner_name { s.write_to(w)?; }
                if let Some(v) = alt_inner_flag { v.write_to(w)?; }
                if let Some(v) = alt_body_001 { v.write_to(w)?; }
                if let Some(v) = alt_body_002 { v.write_to(w)?; }
                if let Some(v) = alt_body_003 { v.write_to(w)?; }
                if let Some(v) = alt_body_004 { v.write_to(w)?; }
                if let Some(v) = alt_body_005 { v.write_to(w)?; }
                if let Some(v) = alt_body_006 { v.write_to(w)?; }
                if let Some(v) = alt_body_007 { v.write_to(w)?; }
                if let Some(v) = alt_body_008 { v.write_to(w)?; }
                if let Some(v) = alt_body_009 { v.write_to(w)?; }
                if let Some(v) = alt_body_010 { v.write_to(w)?; }
                if let Some(v) = alt_body_011 { v.write_to(w)?; }
                if let Some(v) = alt_body_012 { v.write_to(w)?; }
                if let Some(v) = alt_body_013 { v.write_to(w)?; }
                if let Some(v) = alt_body_014 { v.write_to(w)?; }
                if let Some(v) = alt_body_015 { v.write_to(w)?; }
                if let Some(v) = alt_body_016 { v.write_to(w)?; }
                if let Some(v) = alt_body_017 { v.write_to(w)?; }
                if let Some(v) = alt_body_018 { v.write_to(w)?; }
                if let Some(v) = alt_body_019 { v.write_to(w)?; }
                if let Some(v) = alt_body_020 { v.write_to(w)?; }
                if let Some(v) = alt_body_021 { v.write_to(w)?; }
                if let Some(v) = alt_body_022 { v.write_to(w)?; }
                if let Some(v) = alt_body_023 { v.write_to(w)?; }
                if let Some(v) = alt_body_024 { v.write_to(w)?; }
                if let Some(v) = alt_body_025 { v.write_to(w)?; }
                if let Some(v) = alt_body_026 { v.write_to(w)?; }
                if let Some(v) = alt_body_027 { v.write_to(w)?; }
                if let Some(v) = alt_body_028 { v.write_to(w)?; }
                if let Some(v) = alt_body_029 { v.write_to(w)?; }
                if let Some(v) = alt_body_030 { v.write_to(w)?; }
                if let Some(v) = alt_body_031 { v.write_to(w)?; }
                if let Some(v) = alt_body_032 { v.write_to(w)?; }
                if let Some(v) = alt_body_033 { v.write_to(w)?; }
                if let Some(v) = alt_body_034 { v.write_to(w)?; }
                if let Some(v) = alt_body_035 { v.write_to(w)?; }
                if let Some(v) = alt_body_036 { v.write_to(w)?; }
                if let Some(v) = alt_body_037 { v.write_to(w)?; }
                if let Some(v) = alt_body_038 { v.write_to(w)?; }
                if let Some(v) = alt_body_039 { v.write_to(w)?; }
                if let Some(v) = alt_body_040 { v.write_to(w)?; }
                if let Some(v) = alt_body_041 { v.write_to(w)?; }
                if let Some(v) = alt_body_042 { v.write_to(w)?; }
                if let Some(v) = alt_body_043 { v.write_to(w)?; }
                if let Some(v) = alt_body_044 { v.write_to(w)?; }
                if let Some(v) = alt_body_045 { v.write_to(w)?; }
                if let Some(v) = alt_body_046 { v.write_to(w)?; }
                if let Some(v) = alt_body_047 { v.write_to(w)?; }
                if let Some(v) = alt_body_048 { v.write_to(w)?; }
                if let Some(v) = alt_body_049 { v.write_to(w)?; }
                if let Some(v) = alt_body_050 { v.write_to(w)?; }
                if let Some(v) = alt_body_051 { v.write_to(w)?; }
                if let Some(v) = alt_body_052 { v.write_to(w)?; }
                if let Some(v) = alt_body_053 { v.write_to(w)?; }
                if let Some(v) = alt_body_054 { v.write_to(w)?; }
                if let Some(v) = alt_body_055 { v.write_to(w)?; }
                if let Some(v) = alt_body_056 { v.write_to(w)?; }
                if let Some(v) = alt_body_057 { v.write_to(w)?; }
                if let Some(v) = alt_body_058 { v.write_to(w)?; }
                if let Some(v) = alt_body_059 { v.write_to(w)?; }
                if let Some(v) = alt_body_060 { v.write_to(w)?; }
                if let Some(v) = alt_body_061 { v.write_to(w)?; }
                if let Some(v) = alt_body_062 { v.write_to(w)?; }
                if let Some(v) = alt_body_063 { v.write_to(w)?; }
                if let Some(v) = alt_body_064 { v.write_to(w)?; }
                if let Some(v) = alt_body_065 { v.write_to(w)?; }
                if let Some(v) = alt_body_066 { v.write_to(w)?; }
                if let Some(v) = alt_body_067 { v.write_to(w)?; }
                if let Some(v) = alt_body_068 { v.write_to(w)?; }
                if let Some(v) = alt_body_069 { v.write_to(w)?; }
                if let Some(v) = alt_body_070 { v.write_to(w)?; }
                if let Some(v) = alt_body_071 { v.write_to(w)?; }
                if let Some(v) = alt_body_072 { v.write_to(w)?; }
                if let Some(v) = alt_body_073 { v.write_to(w)?; }
                if let Some(v) = alt_body_074 { v.write_to(w)?; }
                if let Some(v) = alt_body_075 { v.write_to(w)?; }
                if let Some(v) = alt_body_076 { v.write_to(w)?; }
                if let Some(v) = alt_body_077 { v.write_to(w)?; }
                if let Some(v) = alt_body_078 { v.write_to(w)?; }
                if let Some(v) = alt_body_079 { v.write_to(w)?; }
                if let Some(v) = alt_body_080 { v.write_to(w)?; }
                if let Some(v) = alt_body_081 { v.write_to(w)?; }
                if let Some(v) = alt_body_082 { v.write_to(w)?; }
                if let Some(v) = alt_body_083 { v.write_to(w)?; }
                if let Some(v) = alt_body_084 { v.write_to(w)?; }
                if let Some(v) = alt_body_085 { v.write_to(w)?; }
                if let Some(v) = alt_body_086 { v.write_to(w)?; }
                if let Some(v) = alt_body_087 { v.write_to(w)?; }
                if let Some(v) = alt_body_088 { v.write_to(w)?; }
                if let Some(v) = alt_body_089 { v.write_to(w)?; }
                if let Some(v) = alt_body_090 { v.write_to(w)?; }
                if let Some(v) = alt_body_091 { v.write_to(w)?; }
                if let Some(v) = alt_body_092 { v.write_to(w)?; }
                if let Some(v) = alt_body_093 { v.write_to(w)?; }
                if let Some(v) = alt_body_094 { v.write_to(w)?; }
                if let Some(v) = alt_body_095 { v.write_to(w)?; }
                if let Some(v) = alt_body_096 { v.write_to(w)?; }
                if let Some(v) = alt_body_097 { v.write_to(w)?; }
                if let Some(v) = alt_body_098 { v.write_to(w)?; }
                if let Some(v) = alt_body_099 { v.write_to(w)?; }
                if let Some(v) = alt_body_100 { v.write_to(w)?; }
                if let Some(v) = alt_body_101 { v.write_to(w)?; }
                if let Some(v) = alt_body_102 { v.write_to(w)?; }
                if let Some(v) = alt_body_103 { v.write_to(w)?; }
                if let Some(v) = alt_body_104 { v.write_to(w)?; }
                if let Some(v) = alt_body_105 { v.write_to(w)?; }
                if let Some(v) = alt_body_106 { v.write_to(w)?; }
                if let Some(v) = alt_body_107 { v.write_to(w)?; }
                if let Some(v) = alt_body_108 { v.write_to(w)?; }
                if let Some(v) = alt_body_109 { v.write_to(w)?; }
                if let Some(v) = alt_body_110 { v.write_to(w)?; }
                if let Some(v) = alt_body_111 { v.write_to(w)?; }
                if let Some(v) = alt_body_112 { v.write_to(w)?; }
                if let Some(v) = alt_body_113 { v.write_to(w)?; }
                if let Some(v) = alt_body_114 { v.write_to(w)?; }
                if let Some(v) = alt_body_115 { v.write_to(w)?; }
                if let Some(v) = alt_body_116 { v.write_to(w)?; }
                if let Some(v) = alt_body_117 { v.write_to(w)?; }
                if let Some(v) = alt_body_118 { v.write_to(w)?; }
                if let Some(v) = alt_body_119 { v.write_to(w)?; }
                if let Some(v) = alt_body_120 { v.write_to(w)?; }
                if let Some(v) = alt_body_121 { v.write_to(w)?; }
                if let Some(v) = alt_body_122 { v.write_to(w)?; }
                if let Some(v) = alt_body_123 { v.write_to(w)?; }
                if let Some(v) = alt_body_124 { v.write_to(w)?; }
                if let Some(v) = alt_body_125 { v.write_to(w)?; }
                if let Some(v) = alt_body_126 { v.write_to(w)?; }
                if let Some(v) = alt_body_127 { v.write_to(w)?; }
                if let Some(v) = alt_body_128 { v.write_to(w)?; }
                if let Some(v) = alt_body_129 { v.write_to(w)?; }
                if let Some(v) = alt_body_130 { v.write_to(w)?; }
                if let Some(v) = alt_body_131 { v.write_to(w)?; }
                if let Some(v) = alt_body_132 { v.write_to(w)?; }
                if let Some(v) = alt_body_133 { v.write_to(w)?; }
                if let Some(v) = alt_body_134 { v.write_to(w)?; }
                if let Some(v) = alt_body_135 { v.write_to(w)?; }
                if let Some(v) = alt_body_136 { v.write_to(w)?; }
                if let Some(v) = alt_body_137 { v.write_to(w)?; }
                if let Some(v) = alt_body_138 { v.write_to(w)?; }
                if let Some(v) = alt_body_139 { v.write_to(w)?; }
                if let Some(v) = alt_body_140 { v.write_to(w)?; }
                if let Some(v) = alt_body_141 { v.write_to(w)?; }
                if let Some(v) = alt_body_142 { v.write_to(w)?; }
                if let Some(v) = alt_body_143 { v.write_to(w)?; }
                if let Some(v) = alt_body_144 { v.write_to(w)?; }
                if let Some(v) = alt_body_145 { v.write_to(w)?; }
                if let Some(v) = alt_body_146 { v.write_to(w)?; }
                if let Some(v) = alt_body_147 { v.write_to(w)?; }
                if let Some(v) = alt_body_148 { v.write_to(w)?; }
                if let Some(v) = alt_body_149 { v.write_to(w)?; }
                if let Some(v) = alt_body_150 { v.write_to(w)?; }
                if let Some(v) = alt_body_151 { v.write_to(w)?; }
                if let Some(v) = alt_body_152 { v.write_to(w)?; }
                if let Some(v) = alt_body_153 { v.write_to(w)?; }
                if let Some(v) = alt_body_154 { v.write_to(w)?; }
                if let Some(v) = alt_body_155 { v.write_to(w)?; }
                if let Some(v) = alt_body_156 { v.write_to(w)?; }
                if let Some(v) = alt_body_157 { v.write_to(w)?; }
                if let Some(v) = alt_body_158 { v.write_to(w)?; }
                if let Some(v) = alt_body_159 { v.write_to(w)?; }
                if let Some(v) = alt_body_160 { v.write_to(w)?; }
                if let Some(v) = alt_body_161 { v.write_to(w)?; }
                if let Some(v) = alt_body_162 { v.write_to(w)?; }
                if let Some(v) = alt_body_163 { v.write_to(w)?; }
                if let Some(v) = alt_body_164 { v.write_to(w)?; }
                if let Some(v) = alt_body_165 { v.write_to(w)?; }
                if let Some(v) = alt_body_166 { v.write_to(w)?; }
                if let Some(v) = alt_body_167 { v.write_to(w)?; }
                if let Some(v) = alt_body_168 { v.write_to(w)?; }
                if let Some(v) = alt_body_169 { v.write_to(w)?; }
                if let Some(v) = alt_body_170 { v.write_to(w)?; }
                if let Some(v) = alt_body_171 { v.write_to(w)?; }
                if let Some(v) = alt_body_172 { v.write_to(w)?; }
                if let Some(v) = alt_body_173 { v.write_to(w)?; }
                if let Some(v) = alt_body_174 { v.write_to(w)?; }
                if let Some(v) = alt_body_175 { v.write_to(w)?; }
                if let Some(v) = alt_body_176 { v.write_to(w)?; }
                if let Some(v) = alt_body_177 { v.write_to(w)?; }
                if let Some(v) = alt_body_178 { v.write_to(w)?; }
                if let Some(v) = alt_body_179 { v.write_to(w)?; }
                if let Some(v) = alt_body_180 { v.write_to(w)?; }
                if let Some(v) = alt_body_181 { v.write_to(w)?; }
                if let Some(v) = alt_body_182 { v.write_to(w)?; }
                if let Some(v) = alt_body_183 { v.write_to(w)?; }
                if let Some(v) = alt_body_184 { v.write_to(w)?; }
                if let Some(v) = alt_body_185 { v.write_to(w)?; }
                if let Some(v) = alt_body_186 { v.write_to(w)?; }
                if let Some(v) = alt_body_187 { v.write_to(w)?; }
                if let Some(v) = alt_body_188 { v.write_to(w)?; }
                if let Some(v) = alt_body_189 { v.write_to(w)?; }
                if let Some(v) = alt_body_190 { v.write_to(w)?; }
                if let Some(v) = alt_body_191 { v.write_to(w)?; }
                if let Some(v) = alt_body_192 { v.write_to(w)?; }
                if let Some(v) = alt_body_193 { v.write_to(w)?; }
                if let Some(v) = alt_body_194 { v.write_to(w)?; }
                if let Some(v) = alt_body_195 { v.write_to(w)?; }
                if let Some(v) = alt_body_196 { v.write_to(w)?; }
                if let Some(v) = alt_body_197 { v.write_to(w)?; }
                if let Some(v) = alt_body_198 { v.write_to(w)?; }
                if let Some(v) = alt_body_199 { v.write_to(w)?; }
                if let Some(v) = alt_body_200 { v.write_to(w)?; }
                if let Some(v) = alt_body_201 { v.write_to(w)?; }
                if let Some(v) = alt_body_202 { v.write_to(w)?; }
                if let Some(v) = alt_body_203 { v.write_to(w)?; }
                if let Some(v) = alt_body_204 { v.write_to(w)?; }
                if let Some(v) = alt_body_205 { v.write_to(w)?; }
                if let Some(v) = alt_body_206 { v.write_to(w)?; }
                if let Some(v) = alt_body_207 { v.write_to(w)?; }
                if let Some(v) = alt_body_208 { v.write_to(w)?; }
                if let Some(v) = alt_body_209 { v.write_to(w)?; }
                if let Some(v) = alt_body_210 { v.write_to(w)?; }
                if let Some(v) = alt_body_211 { v.write_to(w)?; }
                if let Some(v) = alt_body_212 { v.write_to(w)?; }
                if let Some(v) = alt_body_213 { v.write_to(w)?; }
                if let Some(v) = alt_body_214 { v.write_to(w)?; }
                if let Some(v) = alt_body_215 { v.write_to(w)?; }
                if let Some(v) = alt_body_216 { v.write_to(w)?; }
                if let Some(v) = alt_body_217 { v.write_to(w)?; }
                if let Some(v) = alt_body_218 { v.write_to(w)?; }
                if let Some(v) = alt_body_219 { v.write_to(w)?; }
                if let Some(v) = alt_body_220 { v.write_to(w)?; }
                if let Some(v) = alt_body_221 { v.write_to(w)?; }
                if let Some(v) = alt_body_222 { v.write_to(w)?; }
                if let Some(v) = alt_body_223 { v.write_to(w)?; }
                if let Some(v) = alt_body_224 { v.write_to(w)?; }
                if let Some(v) = alt_body_225 { v.write_to(w)?; }
                if let Some(v) = alt_body_226 { v.write_to(w)?; }
                if let Some(v) = alt_body_227 { v.write_to(w)?; }
                if let Some(v) = alt_body_228 { v.write_to(w)?; }
                if let Some(v) = alt_body_229 { v.write_to(w)?; }
                if let Some(v) = alt_body_230 { v.write_to(w)?; }
                if let Some(v) = alt_body_231 { v.write_to(w)?; }
                if let Some(v) = alt_body_232 { v.write_to(w)?; }
                if let Some(v) = alt_body_233 { v.write_to(w)?; }
                if let Some(v) = alt_body_234 { v.write_to(w)?; }
                if let Some(v) = alt_body_235 { v.write_to(w)?; }
                if let Some(v) = alt_body_236 { v.write_to(w)?; }
                if let Some(v) = alt_body_237 { v.write_to(w)?; }
                if let Some(v) = alt_body_238 { v.write_to(w)?; }
                if let Some(v) = alt_body_239 { v.write_to(w)?; }
                if let Some(v) = alt_body_240 { v.write_to(w)?; }
                if let Some(v) = alt_body_241 { v.write_to(w)?; }
                if let Some(v) = alt_body_242 { v.write_to(w)?; }
                if let Some(v) = alt_body_243 { v.write_to(w)?; }
                if let Some(v) = alt_body_244 { v.write_to(w)?; }
                if let Some(v) = alt_body_245 { v.write_to(w)?; }
                if let Some(v) = alt_body_246 { v.write_to(w)?; }
                if let Some(v) = alt_body_247 { v.write_to(w)?; }
                if let Some(v) = alt_body_248 { v.write_to(w)?; }
                if let Some(v) = alt_body_249 { v.write_to(w)?; }
                if let Some(v) = alt_body_250 { v.write_to(w)?; }
                if let Some(v) = alt_body_251 { v.write_to(w)?; }
                if let Some(v) = alt_body_252 { v.write_to(w)?; }
                if let Some(v) = alt_body_253 { v.write_to(w)?; }
                if let Some(v) = alt_body_254 { v.write_to(w)?; }
                if let Some(v) = alt_body_255 { v.write_to(w)?; }
                if let Some(v) = alt_body_256 { v.write_to(w)?; }
                if let Some(v) = alt_body_257 { v.write_to(w)?; }
                if let Some(v) = alt_body_258 { v.write_to(w)?; }
                if let Some(v) = alt_body_259 { v.write_to(w)?; }
                if let Some(v) = alt_body_260 { v.write_to(w)?; }
                if let Some(v) = alt_body_261 { v.write_to(w)?; }
                if let Some(v) = alt_body_262 { v.write_to(w)?; }
                if let Some(v) = alt_body_263 { v.write_to(w)?; }
                if let Some(v) = alt_body_264 { v.write_to(w)?; }
                if let Some(v) = alt_body_265 { v.write_to(w)?; }
                if let Some(v) = alt_body_266 { v.write_to(w)?; }
                if let Some(v) = alt_body_267 { v.write_to(w)?; }
                if let Some(v) = alt_body_268 { v.write_to(w)?; }
                if let Some(v) = alt_body_269 { v.write_to(w)?; }
                if let Some(v) = alt_body_270 { v.write_to(w)?; }
                if let Some(v) = alt_body_271 { v.write_to(w)?; }
                if let Some(v) = alt_body_272 { v.write_to(w)?; }
                if let Some(v) = alt_body_273 { v.write_to(w)?; }
                if let Some(v) = alt_body_274 { v.write_to(w)?; }
                if let Some(v) = alt_body_275 { v.write_to(w)?; }
                if let Some(v) = alt_body_276 { v.write_to(w)?; }
                if let Some(v) = alt_body_277 { v.write_to(w)?; }
                if let Some(v) = alt_body_278 { v.write_to(w)?; }
                if let Some(v) = alt_body_279 { v.write_to(w)?; }
                if let Some(v) = alt_body_280 { v.write_to(w)?; }
                if let Some(v) = alt_body_281 { v.write_to(w)?; }
                if let Some(v) = alt_body_282 { v.write_to(w)?; }
                if let Some(v) = alt_body_283 { v.write_to(w)?; }
                if let Some(v) = alt_body_284 { v.write_to(w)?; }
                if let Some(v) = alt_body_285 { v.write_to(w)?; }
                if let Some(v) = alt_body_286 { v.write_to(w)?; }
                if let Some(v) = alt_body_287 { v.write_to(w)?; }
                if let Some(v) = alt_body_288 { v.write_to(w)?; }
                if let Some(v) = alt_body_289 { v.write_to(w)?; }
                if let Some(v) = alt_body_290 { v.write_to(w)?; }
                if let Some(v) = alt_body_291 { v.write_to(w)?; }
                if let Some(v) = alt_body_292 { v.write_to(w)?; }
                if let Some(v) = alt_body_293 { v.write_to(w)?; }
                if let Some(v) = alt_body_294 { v.write_to(w)?; }
                if let Some(v) = alt_body_295 { v.write_to(w)?; }
                if let Some(v) = alt_body_296 { v.write_to(w)?; }
                if let Some(v) = alt_body_297 { v.write_to(w)?; }
                if let Some(v) = alt_body_298 { v.write_to(w)?; }
                if let Some(v) = alt_body_299 { v.write_to(w)?; }
                if let Some(v) = alt_body_300 { v.write_to(w)?; }
                if let Some(v) = alt_body_301 { v.write_to(w)?; }
                if let Some(v) = alt_body_302 { v.write_to(w)?; }
                if let Some(v) = alt_body_303 { v.write_to(w)?; }
                if let Some(v) = alt_body_304 { v.write_to(w)?; }
                if let Some(v) = alt_body_305 { v.write_to(w)?; }
                if let Some(v) = alt_body_306 { v.write_to(w)?; }
                if let Some(v) = alt_body_307 { v.write_to(w)?; }
                if let Some(v) = alt_body_308 { v.write_to(w)?; }
                if let Some(v) = alt_body_309 { v.write_to(w)?; }
                if let Some(v) = alt_body_310 { v.write_to(w)?; }
                if let Some(v) = alt_body_311 { v.write_to(w)?; }
                if let Some(v) = alt_body_312 { v.write_to(w)?; }
                if let Some(v) = alt_body_313 { v.write_to(w)?; }
                if let Some(v) = alt_body_314 { v.write_to(w)?; }
                if let Some(v) = alt_body_315 { v.write_to(w)?; }
                if let Some(v) = alt_body_316 { v.write_to(w)?; }
                if let Some(v) = alt_body_317 { v.write_to(w)?; }
                if let Some(v) = alt_body_318 { v.write_to(w)?; }
                if let Some(v) = alt_body_319 { v.write_to(w)?; }
                if let Some(v) = alt_body_320 { v.write_to(w)?; }
                if let Some(v) = alt_body_321 { v.write_to(w)?; }
                if let Some(v) = alt_body_322 { v.write_to(w)?; }
                if let Some(v) = alt_body_323 { v.write_to(w)?; }
                if let Some(v) = alt_body_324 { v.write_to(w)?; }
                if let Some(v) = alt_body_325 { v.write_to(w)?; }
                if let Some(v) = alt_body_326 { v.write_to(w)?; }
                if let Some(v) = alt_body_327 { v.write_to(w)?; }
                if let Some(v) = alt_body_328 { v.write_to(w)?; }
                if let Some(v) = alt_body_329 { v.write_to(w)?; }
                if let Some(v) = alt_body_330 { v.write_to(w)?; }
                if let Some(v) = alt_body_331 { v.write_to(w)?; }
                if let Some(v) = alt_body_332 { v.write_to(w)?; }
                if let Some(v) = alt_body_333 { v.write_to(w)?; }
                if let Some(v) = alt_body_334 { v.write_to(w)?; }
                if let Some(v) = alt_body_335 { v.write_to(w)?; }
                if let Some(v) = alt_body_336 { v.write_to(w)?; }
                if let Some(v) = alt_body_337 { v.write_to(w)?; }
                if let Some(v) = alt_body_338 { v.write_to(w)?; }
                if let Some(v) = alt_body_339 { v.write_to(w)?; }
                if let Some(v) = alt_body_340 { v.write_to(w)?; }
                if let Some(v) = alt_body_341 { v.write_to(w)?; }
                if let Some(v) = alt_body_342 { v.write_to(w)?; }
                if let Some(v) = alt_body_343 { v.write_to(w)?; }
                if let Some(v) = alt_body_344 { v.write_to(w)?; }
                if let Some(v) = alt_body_345 { v.write_to(w)?; }
                if let Some(v) = alt_body_346 { v.write_to(w)?; }
                if let Some(v) = alt_body_347 { v.write_to(w)?; }
                if let Some(v) = alt_body_348 { v.write_to(w)?; }
                if let Some(v) = alt_body_349 { v.write_to(w)?; }
                if let Some(v) = alt_body_350 { v.write_to(w)?; }
                if let Some(v) = alt_body_351 { v.write_to(w)?; }
                if let Some(v) = alt_body_352 { v.write_to(w)?; }
                if let Some(v) = alt_body_353 { v.write_to(w)?; }
                if let Some(v) = alt_body_354 { v.write_to(w)?; }
                if let Some(v) = alt_body_355 { v.write_to(w)?; }
                if let Some(v) = alt_body_356 { v.write_to(w)?; }
                if let Some(v) = alt_body_357 { v.write_to(w)?; }
                if let Some(v) = alt_body_358 { v.write_to(w)?; }
                if let Some(v) = alt_body_359 { v.write_to(w)?; }
                if let Some(v) = alt_body_360 { v.write_to(w)?; }
                if let Some(v) = alt_body_361 { v.write_to(w)?; }
                if let Some(v) = alt_body_362 { v.write_to(w)?; }
                if let Some(v) = alt_body_363 { v.write_to(w)?; }
                if let Some(v) = alt_body_364 { v.write_to(w)?; }
                if let Some(v) = alt_body_365 { v.write_to(w)?; }
                if let Some(v) = alt_body_366 { v.write_to(w)?; }
                if let Some(v) = alt_body_367 { v.write_to(w)?; }
                if let Some(v) = alt_body_368 { v.write_to(w)?; }
                if let Some(v) = alt_body_369 { v.write_to(w)?; }
                if let Some(v) = alt_body_370 { v.write_to(w)?; }
                if let Some(v) = alt_body_371 { v.write_to(w)?; }
                if let Some(v) = alt_body_372 { v.write_to(w)?; }
                if let Some(v) = alt_body_373 { v.write_to(w)?; }
                if let Some(v) = alt_body_374 { v.write_to(w)?; }
                if let Some(v) = alt_body_375 { v.write_to(w)?; }
                if let Some(v) = alt_body_376 { v.write_to(w)?; }
                if let Some(v) = alt_body_377 { v.write_to(w)?; }
                if let Some(v) = alt_body_378 { v.write_to(w)?; }
                if let Some(v) = alt_body_379 { v.write_to(w)?; }
                if let Some(v) = alt_body_380 { v.write_to(w)?; }
                if let Some(v) = alt_body_381 { v.write_to(w)?; }
                if let Some(v) = alt_body_382 { v.write_to(w)?; }
                if let Some(v) = alt_body_383 { v.write_to(w)?; }
                if let Some(v) = alt_body_384 { v.write_to(w)?; }
                if let Some(v) = alt_body_385 { v.write_to(w)?; }
                if let Some(v) = alt_body_386 { v.write_to(w)?; }
                if let Some(v) = alt_body_387 { v.write_to(w)?; }
                if let Some(v) = alt_body_388 { v.write_to(w)?; }
                if let Some(v) = alt_body_389 { v.write_to(w)?; }
                if let Some(v) = alt_body_390 { v.write_to(w)?; }
                if let Some(v) = alt_body_391 { v.write_to(w)?; }
                if let Some(v) = alt_body_392 { v.write_to(w)?; }
                if let Some(v) = alt_body_393 { v.write_to(w)?; }
                if let Some(v) = alt_body_394 { v.write_to(w)?; }
                if let Some(v) = alt_body_395 { v.write_to(w)?; }
                if let Some(v) = alt_body_396 { v.write_to(w)?; }
                if let Some(v) = alt_body_397 { v.write_to(w)?; }
                if let Some(v) = alt_body_398 { v.write_to(w)?; }
                if let Some(v) = alt_body_399 { v.write_to(w)?; }
                if let Some(v) = alt_body_400 { v.write_to(w)?; }
                if let Some(v) = alt_body_401 { v.write_to(w)?; }
                if let Some(v) = alt_body_402 { v.write_to(w)?; }
                if let Some(v) = alt_body_403 { v.write_to(w)?; }
                if let Some(v) = alt_body_404 { v.write_to(w)?; }
                if let Some(v) = alt_body_405 { v.write_to(w)?; }
                if let Some(v) = alt_body_406 { v.write_to(w)?; }
                if let Some(v) = alt_body_407 { v.write_to(w)?; }
                if let Some(v) = alt_body_408 { v.write_to(w)?; }
                if let Some(v) = alt_body_409 { v.write_to(w)?; }
                if let Some(v) = alt_body_410 { v.write_to(w)?; }
                if let Some(v) = alt_body_411 { v.write_to(w)?; }
                if let Some(v) = alt_body_412 { v.write_to(w)?; }
                if let Some(v) = alt_body_413 { v.write_to(w)?; }
                if let Some(v) = alt_body_414 { v.write_to(w)?; }
                if let Some(v) = alt_body_415 { v.write_to(w)?; }
                if let Some(v) = alt_body_416 { v.write_to(w)?; }
                if let Some(v) = alt_body_417 { v.write_to(w)?; }
                if let Some(v) = alt_body_418 { v.write_to(w)?; }
                if let Some(v) = alt_body_419 { v.write_to(w)?; }
                if let Some(v) = alt_body_420 { v.write_to(w)?; }
                if let Some(v) = alt_body_421 { v.write_to(w)?; }
                if let Some(v) = alt_body_422 { v.write_to(w)?; }
                if let Some(v) = alt_body_423 { v.write_to(w)?; }
                if let Some(v) = alt_body_424 { v.write_to(w)?; }
                if let Some(v) = alt_body_425 { v.write_to(w)?; }
                if let Some(v) = alt_body_426 { v.write_to(w)?; }
                if let Some(v) = alt_body_427 { v.write_to(w)?; }
                if let Some(v) = alt_body_428 { v.write_to(w)?; }
                if let Some(v) = alt_body_429 { v.write_to(w)?; }
                if let Some(v) = alt_body_430 { v.write_to(w)?; }
                if let Some(v) = alt_body_431 { v.write_to(w)?; }
                if let Some(v) = alt_body_432 { v.write_to(w)?; }
                if let Some(v) = alt_body_433 { v.write_to(w)?; }
                if let Some(v) = alt_body_434 { v.write_to(w)?; }
                if let Some(v) = alt_body_435 { v.write_to(w)?; }
                if let Some(v) = alt_body_436 { v.write_to(w)?; }
                if let Some(v) = alt_body_437 { v.write_to(w)?; }
                if let Some(v) = alt_body_438 { v.write_to(w)?; }
                if let Some(v) = alt_body_439 { v.write_to(w)?; }
                if let Some(v) = alt_body_440 { v.write_to(w)?; }
                if let Some(v) = alt_body_441 { v.write_to(w)?; }
                if let Some(v) = alt_body_442 { v.write_to(w)?; }
                if let Some(v) = alt_body_443 { v.write_to(w)?; }
                if let Some(v) = alt_body_444 { v.write_to(w)?; }
                if let Some(v) = alt_body_445 { v.write_to(w)?; }
                if let Some(v) = alt_body_446 { v.write_to(w)?; }
                if let Some(v) = alt_body_447 { v.write_to(w)?; }
                if let Some(v) = alt_body_448 { v.write_to(w)?; }
                if let Some(v) = alt_body_449 { v.write_to(w)?; }
                if let Some(v) = alt_body_450 { v.write_to(w)?; }
                if let Some(v) = alt_body_451 { v.write_to(w)?; }
                if let Some(v) = alt_body_452 { v.write_to(w)?; }
                if let Some(v) = alt_body_453 { v.write_to(w)?; }
                if let Some(v) = alt_body_454 { v.write_to(w)?; }
                if let Some(v) = alt_body_455 { v.write_to(w)?; }
                if let Some(v) = alt_body_456 { v.write_to(w)?; }
                if let Some(v) = alt_body_457 { v.write_to(w)?; }
                if let Some(v) = alt_body_458 { v.write_to(w)?; }
                if let Some(v) = alt_body_459 { v.write_to(w)?; }
                if let Some(v) = alt_body_460 { v.write_to(w)?; }
                if let Some(v) = alt_body_461 { v.write_to(w)?; }
                if let Some(v) = alt_body_462 { v.write_to(w)?; }
                if let Some(v) = alt_body_463 { v.write_to(w)?; }
                if let Some(v) = alt_body_464 { v.write_to(w)?; }
                if let Some(v) = alt_body_465 { v.write_to(w)?; }
                if let Some(v) = alt_body_466 { v.write_to(w)?; }
                if let Some(v) = alt_body_467 { v.write_to(w)?; }
                if let Some(v) = alt_body_468 { v.write_to(w)?; }
                if let Some(v) = alt_body_469 { v.write_to(w)?; }
                if let Some(v) = alt_body_470 { v.write_to(w)?; }
                if let Some(v) = alt_body_471 { v.write_to(w)?; }
                if let Some(v) = alt_body_472 { v.write_to(w)?; }
                if let Some(v) = alt_body_473 { v.write_to(w)?; }
                if let Some(v) = alt_body_474 { v.write_to(w)?; }
                if let Some(v) = alt_body_475 { v.write_to(w)?; }
                if let Some(v) = alt_body_476 { v.write_to(w)?; }
                if let Some(v) = alt_body_477 { v.write_to(w)?; }
                if let Some(v) = alt_body_478 { v.write_to(w)?; }
                if let Some(v) = alt_body_479 { v.write_to(w)?; }
                if let Some(v) = alt_body_480 { v.write_to(w)?; }
                if let Some(v) = alt_body_481 { v.write_to(w)?; }
                if let Some(v) = alt_body_482 { v.write_to(w)?; }
                if let Some(v) = alt_body_483 { v.write_to(w)?; }
                if let Some(v) = alt_body_484 { v.write_to(w)?; }
                if let Some(v) = alt_body_485 { v.write_to(w)?; }
                if let Some(v) = alt_body_486 { v.write_to(w)?; }
                if let Some(v) = alt_body_487 { v.write_to(w)?; }
                if let Some(v) = alt_body_488 { v.write_to(w)?; }
                if let Some(v) = alt_body_489 { v.write_to(w)?; }
                if let Some(v) = alt_body_490 { v.write_to(w)?; }
                if let Some(v) = alt_body_491 { v.write_to(w)?; }
                if let Some(v) = alt_body_492 { v.write_to(w)?; }
                if let Some(v) = alt_body_493 { v.write_to(w)?; }
                if let Some(v) = alt_body_494 { v.write_to(w)?; }
                if let Some(v) = alt_body_495 { v.write_to(w)?; }
                if let Some(v) = alt_body_496 { v.write_to(w)?; }
                if let Some(v) = alt_body_497 { v.write_to(w)?; }
                if let Some(v) = alt_body_498 { v.write_to(w)?; }
                if let Some(v) = alt_body_499 { v.write_to(w)?; }
                if let Some(v) = alt_body_500 { v.write_to(w)?; }
                if let Some(v) = alt_body_501 { v.write_to(w)?; }
                if let Some(v) = alt_body_502 { v.write_to(w)?; }
                if let Some(v) = alt_body_503 { v.write_to(w)?; }
                if let Some(v) = alt_body_504 { v.write_to(w)?; }
                if let Some(v) = alt_body_505 { v.write_to(w)?; }
                if let Some(v) = alt_body_506 { v.write_to(w)?; }
                if let Some(v) = alt_body_507 { v.write_to(w)?; }
                if let Some(v) = alt_body_508 { v.write_to(w)?; }
                if let Some(v) = alt_body_509 { v.write_to(w)?; }
                if let Some(v) = alt_body_510 { v.write_to(w)?; }
                if let Some(v) = alt_body_511 { v.write_to(w)?; }
                if let Some(v) = alt_body_512 { v.write_to(w)?; }
                if let Some(v) = alt_body_513 { v.write_to(w)?; }
                if let Some(v) = alt_body_514 { v.write_to(w)?; }
                if let Some(v) = alt_body_515 { v.write_to(w)?; }
                if let Some(v) = alt_body_516 { v.write_to(w)?; }
                if let Some(v) = alt_body_517 { v.write_to(w)?; }
                if let Some(v) = alt_body_518 { v.write_to(w)?; }
                if let Some(v) = alt_body_519 { v.write_to(w)?; }
                if let Some(v) = alt_body_520 { v.write_to(w)?; }
                if let Some(v) = alt_body_521 { v.write_to(w)?; }
                if let Some(v) = alt_body_522 { v.write_to(w)?; }
                if let Some(v) = alt_body_523 { v.write_to(w)?; }
                if let Some(v) = alt_body_524 { v.write_to(w)?; }
                if let Some(v) = alt_body_525 { v.write_to(w)?; }
                if let Some(v) = alt_body_526 { v.write_to(w)?; }
                if let Some(v) = alt_body_527 { v.write_to(w)?; }
                if let Some(v) = alt_body_528 { v.write_to(w)?; }
                if let Some(v) = alt_body_529 { v.write_to(w)?; }
                if let Some(v) = alt_body_530 { v.write_to(w)?; }
                if let Some(v) = alt_body_531 { v.write_to(w)?; }
                if let Some(v) = alt_body_532 { v.write_to(w)?; }
                if let Some(v) = alt_body_533 { v.write_to(w)?; }
                if let Some(v) = alt_body_534 { v.write_to(w)?; }
                if let Some(v) = alt_body_535 { v.write_to(w)?; }
                if let Some(v) = alt_body_536 { v.write_to(w)?; }
                if let Some(v) = alt_body_537 { v.write_to(w)?; }
                if let Some(v) = alt_body_538 { v.write_to(w)?; }
                if let Some(v) = alt_body_539 { v.write_to(w)?; }
                if let Some(v) = alt_body_540 { v.write_to(w)?; }
                if let Some(v) = alt_body_541 { v.write_to(w)?; }
                if let Some(v) = alt_body_542 { v.write_to(w)?; }
                if let Some(v) = alt_body_543 { v.write_to(w)?; }
                if let Some(v) = alt_body_544 { v.write_to(w)?; }
                if let Some(v) = alt_body_545 { v.write_to(w)?; }
                if let Some(v) = alt_body_546 { v.write_to(w)?; }
                if let Some(v) = alt_body_547 { v.write_to(w)?; }
                if let Some(v) = alt_body_548 { v.write_to(w)?; }
                if let Some(v) = alt_body_549 { v.write_to(w)?; }
                if let Some(v) = alt_body_550 { v.write_to(w)?; }
                if let Some(v) = alt_body_551 { v.write_to(w)?; }
                if let Some(v) = alt_body_552 { v.write_to(w)?; }
                if let Some(v) = alt_body_553 { v.write_to(w)?; }
                if let Some(v) = alt_body_554 { v.write_to(w)?; }
                if let Some(v) = alt_body_555 { v.write_to(w)?; }
                if let Some(v) = alt_body_556 { v.write_to(w)?; }
                if let Some(v) = alt_body_557 { v.write_to(w)?; }
                if let Some(v) = alt_body_558 { v.write_to(w)?; }
                if let Some(v) = alt_body_559 { v.write_to(w)?; }
                if let Some(v) = alt_body_560 { v.write_to(w)?; }
                if let Some(v) = alt_body_561 { v.write_to(w)?; }
                if let Some(v) = alt_body_562 { v.write_to(w)?; }
                if let Some(v) = alt_body_563 { v.write_to(w)?; }
                if let Some(v) = alt_body_564 { v.write_to(w)?; }
                if let Some(v) = alt_body_565 { v.write_to(w)?; }
                if let Some(v) = alt_body_566 { v.write_to(w)?; }
                if let Some(v) = alt_body_567 { v.write_to(w)?; }
                if let Some(v) = alt_body_568 { v.write_to(w)?; }
                if let Some(v) = alt_body_569 { v.write_to(w)?; }
                if let Some(v) = alt_body_570 { v.write_to(w)?; }
                if let Some(v) = alt_body_571 { v.write_to(w)?; }
                if let Some(v) = alt_body_572 { v.write_to(w)?; }
                if let Some(v) = alt_body_573 { v.write_to(w)?; }
                if let Some(v) = alt_body_574 { v.write_to(w)?; }
                if let Some(v) = alt_body_575 { v.write_to(w)?; }
                if let Some(v) = alt_body_576 { v.write_to(w)?; }
                if let Some(v) = alt_body_577 { v.write_to(w)?; }
                if let Some(v) = alt_body_578 { v.write_to(w)?; }
                if let Some(v) = alt_body_579 { v.write_to(w)?; }
                if let Some(v) = alt_body_580 { v.write_to(w)?; }
                if let Some(v) = alt_body_581 { v.write_to(w)?; }
                if let Some(v) = alt_body_582 { v.write_to(w)?; }
                if let Some(v) = alt_body_583 { v.write_to(w)?; }
                if let Some(v) = alt_body_584 { v.write_to(w)?; }
                if let Some(v) = alt_body_585 { v.write_to(w)?; }
                if let Some(v) = alt_body_586 { v.write_to(w)?; }
                if let Some(v) = alt_body_587 { v.write_to(w)?; }
                if let Some(v) = alt_body_588 { v.write_to(w)?; }
                if let Some(v) = alt_body_589 { v.write_to(w)?; }
                if let Some(v) = alt_body_590 { v.write_to(w)?; }
                if let Some(v) = alt_body_591 { v.write_to(w)?; }
                if let Some(v) = alt_body_592 { v.write_to(w)?; }
                if let Some(v) = alt_body_593 { v.write_to(w)?; }
                if let Some(v) = alt_body_594 { v.write_to(w)?; }
                if let Some(v) = alt_body_595 { v.write_to(w)?; }
                if let Some(v) = alt_body_596 { v.write_to(w)?; }
                if let Some(v) = alt_body_597 { v.write_to(w)?; }
                if let Some(v) = alt_body_598 { v.write_to(w)?; }
                if let Some(v) = alt_body_599 { v.write_to(w)?; }
                if let Some(v) = alt_body_600 { v.write_to(w)?; }
                if let Some(v) = alt_body_601 { v.write_to(w)?; }
                if let Some(v) = alt_body_602 { v.write_to(w)?; }
                if let Some(v) = alt_body_603 { v.write_to(w)?; }
                if let Some(v) = alt_body_604 { v.write_to(w)?; }
                if let Some(v) = alt_body_605 { v.write_to(w)?; }
                if let Some(v) = alt_body_606 { v.write_to(w)?; }
                if let Some(v) = alt_body_607 { v.write_to(w)?; }
                if let Some(v) = alt_body_608 { v.write_to(w)?; }
                if let Some(v) = alt_body_609 { v.write_to(w)?; }
                if let Some(v) = alt_body_610 { v.write_to(w)?; }
                if let Some(v) = alt_body_611 { v.write_to(w)?; }
                if let Some(v) = alt_body_612 { v.write_to(w)?; }
                if let Some(v) = alt_body_613 { v.write_to(w)?; }
                if let Some(v) = alt_body_614 { v.write_to(w)?; }
                if let Some(v) = alt_body_615 { v.write_to(w)?; }
                if let Some(v) = alt_body_616 { v.write_to(w)?; }
                if let Some(v) = alt_body_617 { v.write_to(w)?; }
                if let Some(v) = alt_body_618 { v.write_to(w)?; }
                if let Some(v) = alt_body_619 { v.write_to(w)?; }
                if let Some(v) = alt_body_620 { v.write_to(w)?; }
                if let Some(v) = alt_body_621 { v.write_to(w)?; }
                if let Some(v) = alt_body_622 { v.write_to(w)?; }
                if let Some(v) = alt_body_623 { v.write_to(w)?; }
                if let Some(v) = alt_body_624 { v.write_to(w)?; }
                if let Some(v) = alt_body_625 { v.write_to(w)?; }
                if let Some(v) = alt_body_626 { v.write_to(w)?; }
                if let Some(v) = alt_body_627 { v.write_to(w)?; }
                if let Some(v) = alt_body_628 { v.write_to(w)?; }
                if let Some(v) = alt_body_629 { v.write_to(w)?; }
                if let Some(v) = alt_body_630 { v.write_to(w)?; }
                if let Some(v) = alt_body_631 { v.write_to(w)?; }
                if let Some(v) = alt_body_632 { v.write_to(w)?; }
                if let Some(v) = alt_body_633 { v.write_to(w)?; }
                if let Some(v) = alt_body_634 { v.write_to(w)?; }
                if let Some(v) = alt_body_635 { v.write_to(w)?; }
                if let Some(v) = alt_body_636 { v.write_to(w)?; }
                if let Some(v) = alt_body_637 { v.write_to(w)?; }
                if let Some(v) = alt_body_638 { v.write_to(w)?; }
                if let Some(v) = alt_body_639 { v.write_to(w)?; }
                if let Some(v) = alt_body_640 { v.write_to(w)?; }
                if let Some(v) = alt_body_641 { v.write_to(w)?; }
                if let Some(v) = alt_body_642 { v.write_to(w)?; }
                if let Some(v) = alt_body_643 { v.write_to(w)?; }
                if let Some(v) = alt_body_644 { v.write_to(w)?; }
                if let Some(v) = alt_body_645 { v.write_to(w)?; }
                if let Some(v) = alt_body_646 { v.write_to(w)?; }
                if let Some(v) = alt_body_647 { v.write_to(w)?; }
                if let Some(v) = alt_body_648 { v.write_to(w)?; }
                if let Some(v) = alt_body_649 { v.write_to(w)?; }
                if let Some(v) = alt_body_650 { v.write_to(w)?; }
                if let Some(v) = alt_body_651 { v.write_to(w)?; }
                if let Some(v) = alt_body_652 { v.write_to(w)?; }
                if let Some(v) = alt_body_653 { v.write_to(w)?; }
                if let Some(v) = alt_body_654 { v.write_to(w)?; }
                if let Some(v) = alt_body_655 { v.write_to(w)?; }
                if let Some(v) = alt_body_656 { v.write_to(w)?; }
                if let Some(v) = alt_body_657 { v.write_to(w)?; }
                if let Some(v) = alt_body_658 { v.write_to(w)?; }
                if let Some(v) = alt_body_659 { v.write_to(w)?; }
                if let Some(v) = alt_body_660 { v.write_to(w)?; }
                if let Some(v) = alt_body_661 { v.write_to(w)?; }
                if let Some(v) = alt_body_662 { v.write_to(w)?; }
                if let Some(v) = alt_body_663 { v.write_to(w)?; }
                if let Some(v) = alt_body_664 { v.write_to(w)?; }
                if let Some(v) = alt_body_665 { v.write_to(w)?; }
                if let Some(v) = alt_body_666 { v.write_to(w)?; }
                if let Some(v) = alt_body_667 { v.write_to(w)?; }
                if let Some(v) = alt_body_668 { v.write_to(w)?; }
                if let Some(v) = alt_body_669 { v.write_to(w)?; }
                if let Some(v) = alt_body_670 { v.write_to(w)?; }
                if let Some(v) = alt_body_671 { v.write_to(w)?; }
                if let Some(v) = alt_body_672 { v.write_to(w)?; }
                if let Some(v) = alt_body_673 { v.write_to(w)?; }
                if let Some(v) = alt_body_674 { v.write_to(w)?; }
                if let Some(v) = alt_body_675 { v.write_to(w)?; }
                if let Some(v) = alt_body_676 { v.write_to(w)?; }
                if let Some(v) = alt_body_677 { v.write_to(w)?; }
                if let Some(v) = alt_body_678 { v.write_to(w)?; }
                if let Some(v) = alt_body_679 { v.write_to(w)?; }
                if let Some(v) = alt_body_680 { v.write_to(w)?; }
                if let Some(v) = alt_body_681 { v.write_to(w)?; }
                if let Some(v) = alt_body_682 { v.write_to(w)?; }
                if let Some(v) = alt_body_683 { v.write_to(w)?; }
                if let Some(v) = alt_body_684 { v.write_to(w)?; }
                if let Some(v) = alt_body_685 { v.write_to(w)?; }
                if let Some(v) = alt_body_686 { v.write_to(w)?; }
                if let Some(v) = alt_body_687 { v.write_to(w)?; }
                if let Some(v) = alt_body_688 { v.write_to(w)?; }
                if let Some(v) = alt_body_689 { v.write_to(w)?; }
                if let Some(v) = alt_body_690 { v.write_to(w)?; }
                if let Some(v) = alt_body_691 { v.write_to(w)?; }
                if let Some(v) = alt_body_692 { v.write_to(w)?; }
                if let Some(v) = alt_body_693 { v.write_to(w)?; }
                if let Some(v) = alt_body_694 { v.write_to(w)?; }
                if let Some(v) = alt_body_695 { v.write_to(w)?; }
                if let Some(v) = alt_body_696 { v.write_to(w)?; }
                if let Some(v) = alt_body_697 { v.write_to(w)?; }
                if let Some(v) = alt_body_698 { v.write_to(w)?; }
                if let Some(v) = alt_body_699 { v.write_to(w)?; }
                if let Some(v) = alt_body_700 { v.write_to(w)?; }
                if let Some(v) = alt_body_701 { v.write_to(w)?; }
                if let Some(v) = alt_body_702 { v.write_to(w)?; }
                if let Some(v) = alt_body_703 { v.write_to(w)?; }
                if let Some(v) = alt_body_704 { v.write_to(w)?; }
                if let Some(v) = alt_body_705 { v.write_to(w)?; }
                if let Some(v) = alt_body_706 { v.write_to(w)?; }
                if let Some(v) = alt_body_707 { v.write_to(w)?; }
                if let Some(v) = alt_body_708 { v.write_to(w)?; }
                if let Some(v) = alt_body_709 { v.write_to(w)?; }
                if let Some(v) = alt_body_710 { v.write_to(w)?; }
                if let Some(v) = alt_body_711 { v.write_to(w)?; }
                if let Some(v) = alt_body_712 { v.write_to(w)?; }
                if let Some(v) = alt_body_713 { v.write_to(w)?; }
                if let Some(v) = alt_body_714 { v.write_to(w)?; }
                if let Some(v) = alt_body_715 { v.write_to(w)?; }
                if let Some(v) = alt_body_716 { v.write_to(w)?; }
                if let Some(v) = alt_body_717 { v.write_to(w)?; }
                if let Some(v) = alt_body_718 { v.write_to(w)?; }
                if let Some(v) = alt_body_719 { v.write_to(w)?; }
                if let Some(v) = alt_body_720 { v.write_to(w)?; }
                if let Some(v) = alt_body_721 { v.write_to(w)?; }
                if let Some(v) = alt_body_722 { v.write_to(w)?; }
                if let Some(v) = alt_body_723 { v.write_to(w)?; }
                if let Some(v) = alt_body_724 { v.write_to(w)?; }
                if let Some(v) = alt_body_725 { v.write_to(w)?; }
                if let Some(v) = alt_body_726 { v.write_to(w)?; }
                if let Some(v) = alt_body_727 { v.write_to(w)?; }
                if let Some(v) = alt_body_728 { v.write_to(w)?; }
                if let Some(v) = alt_body_729 { v.write_to(w)?; }
                if let Some(v) = alt_body_730 { v.write_to(w)?; }
                if let Some(v) = alt_body_731 { v.write_to(w)?; }
                if let Some(v) = alt_body_732 { v.write_to(w)?; }
                if let Some(v) = alt_body_733 { v.write_to(w)?; }
                if let Some(v) = alt_body_734 { v.write_to(w)?; }
                if let Some(v) = alt_body_735 { v.write_to(w)?; }
                if let Some(v) = alt_body_736 { v.write_to(w)?; }
                if let Some(v) = alt_body_737 { v.write_to(w)?; }
                if let Some(v) = alt_body_738 { v.write_to(w)?; }
                if let Some(v) = alt_body_739 { v.write_to(w)?; }
                if let Some(v) = alt_body_740 { v.write_to(w)?; }
                if let Some(v) = alt_body_741 { v.write_to(w)?; }
                if let Some(v) = alt_body_742 { v.write_to(w)?; }
                if let Some(v) = alt_body_743 { v.write_to(w)?; }
                if let Some(v) = alt_body_744 { v.write_to(w)?; }
                if let Some(v) = alt_body_745 { v.write_to(w)?; }
                if let Some(v) = alt_body_746 { v.write_to(w)?; }
                if let Some(v) = alt_body_747 { v.write_to(w)?; }
                if let Some(v) = alt_body_748 { v.write_to(w)?; }
                if let Some(v) = alt_body_749 { v.write_to(w)?; }
                if let Some(v) = alt_body_750 { v.write_to(w)?; }
                if let Some(v) = alt_body_751 { v.write_to(w)?; }
                if let Some(v) = alt_body_752 { v.write_to(w)?; }
                if let Some(v) = alt_body_753 { v.write_to(w)?; }
                if let Some(v) = alt_body_754 { v.write_to(w)?; }
                if let Some(v) = alt_body_755 { v.write_to(w)?; }
                if let Some(v) = alt_body_756 { v.write_to(w)?; }
                if let Some(v) = alt_body_757 { v.write_to(w)?; }
                if let Some(v) = alt_body_758 { v.write_to(w)?; }
                if let Some(v) = alt_body_759 { v.write_to(w)?; }
                if let Some(v) = alt_body_760 { v.write_to(w)?; }
                if let Some(v) = alt_body_761 { v.write_to(w)?; }
                if let Some(v) = alt_body_762 { v.write_to(w)?; }
                if let Some(v) = alt_body_763 { v.write_to(w)?; }
                if let Some(v) = alt_body_764 { v.write_to(w)?; }
                if let Some(v) = alt_body_765 { v.write_to(w)?; }
                if let Some(v) = alt_body_766 { v.write_to(w)?; }
                if let Some(v) = alt_body_767 { v.write_to(w)?; }
                if let Some(v) = alt_body_768 { v.write_to(w)?; }
                if let Some(v) = alt_body_769 { v.write_to(w)?; }
                if let Some(v) = alt_body_770 { v.write_to(w)?; }
                if let Some(v) = alt_body_771 { v.write_to(w)?; }
                if let Some(v) = alt_body_772 { v.write_to(w)?; }
                if let Some(v) = alt_body_773 { v.write_to(w)?; }
                if let Some(v) = alt_body_774 { v.write_to(w)?; }
                if let Some(v) = alt_body_775 { v.write_to(w)?; }
                if let Some(v) = alt_body_776 { v.write_to(w)?; }
                if let Some(v) = alt_body_777 { v.write_to(w)?; }
                if let Some(v) = alt_body_778 { v.write_to(w)?; }
                if let Some(v) = alt_body_779 { v.write_to(w)?; }
                if let Some(v) = alt_body_780 { v.write_to(w)?; }
                if let Some(v) = alt_body_781 { v.write_to(w)?; }
                if let Some(v) = alt_body_782 { v.write_to(w)?; }
                if let Some(v) = alt_body_783 { v.write_to(w)?; }
                if let Some(v) = alt_body_784 { v.write_to(w)?; }
                if let Some(v) = alt_body_785 { v.write_to(w)?; }
                if let Some(v) = alt_body_786 { v.write_to(w)?; }
                if let Some(v) = alt_body_787 { v.write_to(w)?; }
                if let Some(v) = alt_body_788 { v.write_to(w)?; }
                if let Some(v) = alt_body_789 { v.write_to(w)?; }
                if let Some(v) = alt_body_790 { v.write_to(w)?; }
                if let Some(v) = alt_body_791 { v.write_to(w)?; }
                if let Some(v) = alt_body_792 { v.write_to(w)?; }
                if let Some(v) = alt_body_793 { v.write_to(w)?; }
                if let Some(v) = alt_body_794 { v.write_to(w)?; }
                if let Some(v) = alt_body_795 { v.write_to(w)?; }
                if let Some(v) = alt_body_796 { v.write_to(w)?; }
                if let Some(v) = alt_body_797 { v.write_to(w)?; }
                if let Some(v) = alt_body_798 { v.write_to(w)?; }
                if let Some(v) = alt_body_799 { v.write_to(w)?; }
                if let Some(v) = alt_body_800 { v.write_to(w)?; }
                if let Some(v) = alt_body_801 { v.write_to(w)?; }
                if let Some(v) = alt_body_802 { v.write_to(w)?; }
                if let Some(v) = alt_body_803 { v.write_to(w)?; }
                if let Some(v) = alt_body_804 { v.write_to(w)?; }
                if let Some(v) = alt_body_805 { v.write_to(w)?; }
                if let Some(v) = alt_body_806 { v.write_to(w)?; }
                if let Some(v) = alt_body_807 { v.write_to(w)?; }
                if let Some(v) = alt_body_808 { v.write_to(w)?; }
                if let Some(v) = alt_body_809 { v.write_to(w)?; }
                if let Some(v) = alt_body_810 { v.write_to(w)?; }
                if let Some(v) = alt_body_811 { v.write_to(w)?; }
                if let Some(v) = alt_body_812 { v.write_to(w)?; }
                if let Some(v) = alt_body_813 { v.write_to(w)?; }
                if let Some(v) = alt_body_814 { v.write_to(w)?; }
                if let Some(v) = alt_body_815 { v.write_to(w)?; }
                if let Some(v) = alt_body_816 { v.write_to(w)?; }
                if let Some(v) = alt_body_817 { v.write_to(w)?; }
                if let Some(v) = alt_body_818 { v.write_to(w)?; }
                if let Some(v) = alt_body_819 { v.write_to(w)?; }
                if let Some(v) = alt_body_820 { v.write_to(w)?; }
                if let Some(v) = alt_body_821 { v.write_to(w)?; }
                if let Some(v) = alt_body_822 { v.write_to(w)?; }
                if let Some(v) = alt_body_823 { v.write_to(w)?; }
                if let Some(v) = alt_body_824 { v.write_to(w)?; }
                if let Some(v) = alt_body_825 { v.write_to(w)?; }
                if let Some(v) = alt_body_826 { v.write_to(w)?; }
                if let Some(v) = alt_body_827 { v.write_to(w)?; }
                if let Some(v) = alt_body_828 { v.write_to(w)?; }
                if let Some(v) = alt_body_829 { v.write_to(w)?; }
                if let Some(v) = alt_body_830 { v.write_to(w)?; }
                if let Some(v) = alt_body_831 { v.write_to(w)?; }
                if let Some(v) = alt_body_832 { v.write_to(w)?; }
                if let Some(v) = alt_body_833 { v.write_to(w)?; }
                if let Some(v) = alt_body_834 { v.write_to(w)?; }
                if let Some(v) = alt_body_835 { v.write_to(w)?; }
                if let Some(v) = alt_body_836 { v.write_to(w)?; }
                if let Some(v) = alt_body_837 { v.write_to(w)?; }
                if let Some(v) = alt_body_838 { v.write_to(w)?; }
                if let Some(v) = alt_body_839 { v.write_to(w)?; }
                if let Some(v) = alt_body_840 { v.write_to(w)?; }
                if let Some(v) = alt_body_841 { v.write_to(w)?; }
                if let Some(v) = alt_body_842 { v.write_to(w)?; }
                if let Some(v) = alt_body_843 { v.write_to(w)?; }
                if let Some(v) = alt_body_844 { v.write_to(w)?; }
                if let Some(v) = alt_body_845 { v.write_to(w)?; }
                if let Some(v) = alt_body_846 { v.write_to(w)?; }
                if let Some(v) = alt_body_847 { v.write_to(w)?; }
                if let Some(v) = alt_body_848 { v.write_to(w)?; }
                if let Some(v) = alt_body_849 { v.write_to(w)?; }
                if let Some(v) = alt_body_850 { v.write_to(w)?; }
                if let Some(v) = alt_body_851 { v.write_to(w)?; }
                if let Some(v) = alt_body_852 { v.write_to(w)?; }
                if let Some(v) = alt_body_853 { v.write_to(w)?; }
                if let Some(v) = alt_body_854 { v.write_to(w)?; }
                if let Some(v) = alt_body_855 { v.write_to(w)?; }
                if let Some(v) = alt_body_856 { v.write_to(w)?; }
                if let Some(v) = alt_body_857 { v.write_to(w)?; }
                if let Some(v) = alt_body_858 { v.write_to(w)?; }
                if let Some(v) = alt_body_859 { v.write_to(w)?; }
                if let Some(v) = alt_body_860 { v.write_to(w)?; }
                if let Some(v) = alt_body_861 { v.write_to(w)?; }
                if let Some(v) = alt_body_862 { v.write_to(w)?; }
                if let Some(v) = alt_body_863 { v.write_to(w)?; }
                if let Some(v) = alt_body_864 { v.write_to(w)?; }
                if let Some(v) = alt_body_865 { v.write_to(w)?; }
                if let Some(v) = alt_body_866 { v.write_to(w)?; }
                if let Some(v) = alt_body_867 { v.write_to(w)?; }
                if let Some(v) = alt_body_868 { v.write_to(w)?; }
                if let Some(v) = alt_body_869 { v.write_to(w)?; }
                if let Some(v) = alt_body_870 { v.write_to(w)?; }
                if let Some(v) = alt_body_871 { v.write_to(w)?; }
                if let Some(v) = alt_body_872 { v.write_to(w)?; }
                if let Some(v) = alt_body_873 { v.write_to(w)?; }
                if let Some(v) = alt_body_874 { v.write_to(w)?; }
                if let Some(v) = alt_body_875 { v.write_to(w)?; }
                if let Some(v) = alt_body_876 { v.write_to(w)?; }
                if let Some(v) = alt_body_877 { v.write_to(w)?; }
                if let Some(v) = alt_body_878 { v.write_to(w)?; }
                if let Some(v) = alt_body_879 { v.write_to(w)?; }
                if let Some(v) = alt_body_880 { v.write_to(w)?; }
                if let Some(v) = alt_body_881 { v.write_to(w)?; }
                if let Some(v) = alt_body_882 { v.write_to(w)?; }
                if let Some(v) = alt_body_883 { v.write_to(w)?; }
                if let Some(v) = alt_body_884 { v.write_to(w)?; }
                if let Some(v) = alt_body_885 { v.write_to(w)?; }
                if let Some(v) = alt_body_886 { v.write_to(w)?; }
                if let Some(v) = alt_body_887 { v.write_to(w)?; }
                if let Some(v) = alt_body_888 { v.write_to(w)?; }
                if let Some(v) = alt_body_889 { v.write_to(w)?; }
                if let Some(v) = alt_body_890 { v.write_to(w)?; }
                if let Some(v) = alt_body_891 { v.write_to(w)?; }
                if let Some(v) = alt_body_892 { v.write_to(w)?; }
                if let Some(v) = alt_body_893 { v.write_to(w)?; }
                if let Some(v) = alt_body_894 { v.write_to(w)?; }
                if let Some(v) = alt_body_895 { v.write_to(w)?; }
                if let Some(v) = alt_body_896 { v.write_to(w)?; }
                if let Some(v) = alt_body_897 { v.write_to(w)?; }
                if let Some(v) = alt_body_898 { v.write_to(w)?; }
                if let Some(v) = alt_body_899 { v.write_to(w)?; }
                if let Some(v) = alt_body_900 { v.write_to(w)?; }
                if let Some(v) = alt_body_901 { v.write_to(w)?; }
                if let Some(v) = alt_body_902 { v.write_to(w)?; }
                if let Some(v) = alt_body_903 { v.write_to(w)?; }
                if let Some(v) = alt_body_904 { v.write_to(w)?; }
                if let Some(v) = alt_body_905 { v.write_to(w)?; }
                if let Some(v) = alt_body_906 { v.write_to(w)?; }
                if let Some(v) = alt_body_907 { v.write_to(w)?; }
                if let Some(v) = alt_body_908 { v.write_to(w)?; }
                if let Some(v) = alt_body_909 { v.write_to(w)?; }
                if let Some(v) = alt_body_910 { v.write_to(w)?; }
                if let Some(v) = alt_body_911 { v.write_to(w)?; }
                if let Some(v) = alt_body_912 { v.write_to(w)?; }
                if let Some(v) = alt_body_913 { v.write_to(w)?; }
                if let Some(v) = alt_body_914 { v.write_to(w)?; }
                if let Some(v) = alt_body_915 { v.write_to(w)?; }
                if let Some(v) = alt_body_916 { v.write_to(w)?; }
                if let Some(v) = alt_body_917 { v.write_to(w)?; }
                if let Some(v) = alt_body_918 { v.write_to(w)?; }
                if let Some(v) = alt_body_919 { v.write_to(w)?; }
                if let Some(v) = alt_body_920 { v.write_to(w)?; }
                if let Some(v) = alt_body_921 { v.write_to(w)?; }
                if let Some(v) = alt_body_922 { v.write_to(w)?; }
                if let Some(v) = alt_body_923 { v.write_to(w)?; }
                if let Some(v) = alt_body_924 { v.write_to(w)?; }
                if let Some(v) = alt_body_925 { v.write_to(w)?; }
                if let Some(v) = alt_body_926 { v.write_to(w)?; }
                if let Some(v) = alt_body_927 { v.write_to(w)?; }
                if let Some(v) = alt_body_928 { v.write_to(w)?; }
                if let Some(v) = alt_body_929 { v.write_to(w)?; }
                if let Some(v) = alt_body_930 { v.write_to(w)?; }
                if let Some(v) = alt_body_931 { v.write_to(w)?; }
                if let Some(v) = alt_body_932 { v.write_to(w)?; }
                if let Some(v) = alt_body_933 { v.write_to(w)?; }
                if let Some(v) = alt_body_934 { v.write_to(w)?; }
                if let Some(v) = alt_body_935 { v.write_to(w)?; }
                if let Some(v) = alt_body_936 { v.write_to(w)?; }
                if let Some(v) = alt_body_937 { v.write_to(w)?; }
                if let Some(v) = alt_body_938 { v.write_to(w)?; }
                if let Some(v) = alt_body_939 { v.write_to(w)?; }
                if let Some(v) = alt_body_940 { v.write_to(w)?; }
                if let Some(v) = alt_body_941 { v.write_to(w)?; }
                if let Some(v) = alt_body_942 { v.write_to(w)?; }
                if let Some(v) = alt_body_943 { v.write_to(w)?; }
                if let Some(v) = alt_body_944 { v.write_to(w)?; }
                if let Some(v) = alt_body_945 { v.write_to(w)?; }
                if let Some(v) = alt_body_946 { v.write_to(w)?; }
                if let Some(v) = alt_body_947 { v.write_to(w)?; }
                if let Some(v) = alt_body_948 { v.write_to(w)?; }
                if let Some(v) = alt_body_949 { v.write_to(w)?; }
                if let Some(v) = alt_body_950 { v.write_to(w)?; }
                if let Some(v) = alt_body_951 { v.write_to(w)?; }
                if let Some(v) = alt_body_952 { v.write_to(w)?; }
                if let Some(v) = alt_body_953 { v.write_to(w)?; }
                if let Some(v) = alt_body_954 { v.write_to(w)?; }
                if let Some(v) = alt_body_955 { v.write_to(w)?; }
                if let Some(v) = alt_body_956 { v.write_to(w)?; }
                if let Some(v) = alt_body_957 { v.write_to(w)?; }
                if let Some(v) = alt_body_958 { v.write_to(w)?; }
                if let Some(v) = alt_body_959 { v.write_to(w)?; }
                if let Some(v) = alt_body_960 { v.write_to(w)?; }
                if let Some(v) = alt_body_961 { v.write_to(w)?; }
                if let Some(v) = alt_body_962 { v.write_to(w)?; }
                if let Some(v) = alt_body_963 { v.write_to(w)?; }
                if let Some(v) = alt_body_964 { v.write_to(w)?; }
                if let Some(v) = alt_body_965 { v.write_to(w)?; }
                if let Some(v) = alt_body_966 { v.write_to(w)?; }
                if let Some(v) = alt_body_967 { v.write_to(w)?; }
                if let Some(v) = alt_body_968 { v.write_to(w)?; }
                if let Some(v) = alt_body_969 { v.write_to(w)?; }
                if let Some(v) = alt_body_970 { v.write_to(w)?; }
                if let Some(v) = alt_body_971 { v.write_to(w)?; }
                if let Some(v) = alt_body_972 { v.write_to(w)?; }
                if let Some(v) = alt_body_973 { v.write_to(w)?; }
                if let Some(v) = alt_body_974 { v.write_to(w)?; }
                if let Some(v) = alt_body_975 { v.write_to(w)?; }
                if let Some(v) = alt_body_976 { v.write_to(w)?; }
                if let Some(v) = alt_body_977 { v.write_to(w)?; }
                if let Some(v) = alt_body_978 { v.write_to(w)?; }
                if let Some(v) = alt_body_979 { v.write_to(w)?; }
                if let Some(v) = alt_body_980 { v.write_to(w)?; }
                if let Some(v) = alt_body_981 { v.write_to(w)?; }
                if let Some(v) = alt_body_982 { v.write_to(w)?; }
                if let Some(v) = alt_body_983 { v.write_to(w)?; }
                if let Some(v) = alt_body_984 { v.write_to(w)?; }
                if let Some(v) = alt_body_985 { v.write_to(w)?; }
                if let Some(v) = alt_body_986 { v.write_to(w)?; }
                if let Some(v) = alt_body_987 { v.write_to(w)?; }
                if let Some(v) = alt_body_988 { v.write_to(w)?; }
                if let Some(v) = alt_body_989 { v.write_to(w)?; }
                if let Some(v) = alt_body_990 { v.write_to(w)?; }
                if let Some(v) = alt_body_991 { v.write_to(w)?; }
                if let Some(v) = alt_body_992 { v.write_to(w)?; }
                if let Some(v) = alt_body_993 { v.write_to(w)?; }
                if let Some(v) = alt_body_994 { v.write_to(w)?; }
                if let Some(v) = alt_body_995 { v.write_to(w)?; }
                if let Some(v) = alt_body_996 { v.write_to(w)?; }
                if let Some(v) = alt_body_997 { v.write_to(w)?; }
                if let Some(v) = alt_body_998 { v.write_to(w)?; }
                if let Some(v) = alt_body_999 { v.write_to(w)?; }
                if let Some(v) = alt_body_1000 { v.write_to(w)?; }
                if let Some(v) = alt_body_1001 { v.write_to(w)?; }
                if let Some(v) = alt_body_1002 { v.write_to(w)?; }
                if let Some(v) = alt_body_1003 { v.write_to(w)?; }
                if let Some(v) = alt_body_1004 { v.write_to(w)?; }
                if let Some(v) = alt_body_1005 { v.write_to(w)?; }
                if let Some(v) = alt_body_1006 { v.write_to(w)?; }
                if let Some(v) = alt_body_1007 { v.write_to(w)?; }
                if let Some(v) = alt_body_1008 { v.write_to(w)?; }
                if let Some(v) = alt_body_1009 { v.write_to(w)?; }
                if let Some(v) = alt_body_1010 { v.write_to(w)?; }
                if let Some(v) = alt_body_1011 { v.write_to(w)?; }
                if let Some(v) = alt_body_1012 { v.write_to(w)?; }
                if let Some(v) = alt_body_1013 { v.write_to(w)?; }
                if let Some(v) = alt_body_1014 { v.write_to(w)?; }
                if let Some(v) = alt_body_1015 { v.write_to(w)?; }
                if let Some(v) = alt_body_1016 { v.write_to(w)?; }
                if let Some(v) = alt_body_1017 { v.write_to(w)?; }
                if let Some(v) = alt_body_1018 { v.write_to(w)?; }
                if let Some(v) = alt_body_1019 { v.write_to(w)?; }
                if let Some(v) = alt_body_1020 { v.write_to(w)?; }
                if let Some(v) = alt_body_1021 { v.write_to(w)?; }
                if let Some(v) = alt_body_1022 { v.write_to(w)?; }
                if let Some(v) = alt_body_1023 { v.write_to(w)?; }
                if let Some(v) = alt_body_1024 { v.write_to(w)?; }
                if let Some(v) = alt_body_1025 { v.write_to(w)?; }
                if let Some(v) = alt_body_1026 { v.write_to(w)?; }
                if let Some(v) = alt_body_1027 { v.write_to(w)?; }
                if let Some(v) = alt_body_1028 { v.write_to(w)?; }
                if let Some(v) = alt_body_1029 { v.write_to(w)?; }
                if let Some(v) = alt_body_1030 { v.write_to(w)?; }
                if let Some(v) = alt_body_1031 { v.write_to(w)?; }
                if let Some(v) = alt_body_1032 { v.write_to(w)?; }
                if let Some(v) = alt_body_1033 { v.write_to(w)?; }
                if let Some(v) = alt_body_1034 { v.write_to(w)?; }
                if let Some(v) = alt_body_1035 { v.write_to(w)?; }
                if let Some(v) = alt_body_1036 { v.write_to(w)?; }
                if let Some(v) = alt_body_1037 { v.write_to(w)?; }
                if let Some(v) = alt_body_1038 { v.write_to(w)?; }
                if let Some(v) = alt_body_1039 { v.write_to(w)?; }
                if let Some(v) = alt_body_1040 { v.write_to(w)?; }
                if let Some(v) = alt_body_1041 { v.write_to(w)?; }
                if let Some(v) = alt_body_1042 { v.write_to(w)?; }
                if let Some(v) = alt_body_1043 { v.write_to(w)?; }
                if let Some(v) = alt_body_1044 { v.write_to(w)?; }
                if let Some(v) = alt_body_1045 { v.write_to(w)?; }
                if let Some(v) = alt_body_1046 { v.write_to(w)?; }
                if let Some(v) = alt_body_1047 { v.write_to(w)?; }
                if let Some(v) = alt_body_1048 { v.write_to(w)?; }
                if let Some(v) = alt_body_1049 { v.write_to(w)?; }
                if let Some(v) = alt_body_1050 { v.write_to(w)?; }
                if let Some(v) = alt_body_1051 { v.write_to(w)?; }
                if let Some(v) = alt_body_1052 { v.write_to(w)?; }
                if let Some(v) = alt_body_1053 { v.write_to(w)?; }
                if let Some(v) = alt_body_1054 { v.write_to(w)?; }
                if let Some(v) = alt_body_1055 { v.write_to(w)?; }
                if let Some(v) = alt_body_1056 { v.write_to(w)?; }
                if let Some(v) = alt_body_1057 { v.write_to(w)?; }
                if let Some(v) = alt_body_1058 { v.write_to(w)?; }
                if let Some(v) = alt_body_1059 { v.write_to(w)?; }
                if let Some(v) = alt_body_1060 { v.write_to(w)?; }
                if let Some(v) = alt_body_1061 { v.write_to(w)?; }
                if let Some(v) = alt_body_1062 { v.write_to(w)?; }
                if let Some(v) = alt_body_1063 { v.write_to(w)?; }
                if let Some(v) = alt_body_1064 { v.write_to(w)?; }
                if let Some(v) = alt_body_1065 { v.write_to(w)?; }
                if let Some(v) = alt_body_1066 { v.write_to(w)?; }
                if let Some(v) = alt_body_1067 { v.write_to(w)?; }
                if let Some(v) = alt_body_1068 { v.write_to(w)?; }
                if let Some(v) = alt_body_1069 { v.write_to(w)?; }
                if let Some(v) = alt_body_1070 { v.write_to(w)?; }
                if let Some(v) = alt_body_1071 { v.write_to(w)?; }
                if let Some(v) = alt_body_1072 { v.write_to(w)?; }
                if let Some(v) = alt_body_1073 { v.write_to(w)?; }
                if let Some(v) = alt_body_1074 { v.write_to(w)?; }
                if let Some(v) = alt_body_1075 { v.write_to(w)?; }
                if let Some(v) = alt_body_1076 { v.write_to(w)?; }
                if let Some(v) = alt_body_1077 { v.write_to(w)?; }
                if let Some(v) = alt_body_1078 { v.write_to(w)?; }
                if let Some(v) = alt_body_1079 { v.write_to(w)?; }
                if let Some(v) = alt_body_1080 { v.write_to(w)?; }
                if let Some(v) = alt_body_1081 { v.write_to(w)?; }
                if let Some(v) = alt_body_1082 { v.write_to(w)?; }
                if let Some(v) = alt_body_1083 { v.write_to(w)?; }
                if let Some(v) = alt_body_1084 { v.write_to(w)?; }
                if let Some(v) = alt_body_1085 { v.write_to(w)?; }
                if let Some(v) = alt_body_1086 { v.write_to(w)?; }
                if let Some(v) = alt_body_1087 { v.write_to(w)?; }
                if let Some(v) = alt_body_1088 { v.write_to(w)?; }
                if let Some(v) = alt_body_1089 { v.write_to(w)?; }
                if let Some(v) = alt_body_1090 { v.write_to(w)?; }
                if let Some(v) = alt_body_1091 { v.write_to(w)?; }
                if let Some(v) = alt_body_1092 { v.write_to(w)?; }
                if let Some(v) = alt_body_1093 { v.write_to(w)?; }
                if let Some(v) = alt_body_1094 { v.write_to(w)?; }
                if let Some(v) = alt_body_1095 { v.write_to(w)?; }
                if let Some(v) = alt_body_1096 { v.write_to(w)?; }
                if let Some(v) = alt_body_1097 { v.write_to(w)?; }
                if let Some(v) = alt_body_1098 { v.write_to(w)?; }
                if let Some(v) = alt_body_1099 { v.write_to(w)?; }
                if let Some(v) = alt_body_1100 { v.write_to(w)?; }
                if let Some(v) = alt_body_1101 { v.write_to(w)?; }
                if let Some(v) = alt_body_1102 { v.write_to(w)?; }
                if let Some(v) = alt_body_1103 { v.write_to(w)?; }
                if let Some(v) = alt_body_1104 { v.write_to(w)?; }
                if let Some(v) = alt_body_1105 { v.write_to(w)?; }
                if let Some(v) = alt_body_1106 { v.write_to(w)?; }
                if let Some(v) = alt_body_1107 { v.write_to(w)?; }
                if let Some(v) = alt_body_1108 { v.write_to(w)?; }
                if let Some(v) = alt_body_1109 { v.write_to(w)?; }
                if let Some(v) = alt_body_1110 { v.write_to(w)?; }
                if let Some(v) = alt_body_1111 { v.write_to(w)?; }
                if let Some(v) = alt_body_1112 { v.write_to(w)?; }
                if let Some(v) = alt_body_1113 { v.write_to(w)?; }
                if let Some(v) = alt_body_1114 { v.write_to(w)?; }
                if let Some(v) = alt_body_1115 { v.write_to(w)?; }
                if let Some(v) = alt_body_1116 { v.write_to(w)?; }
                if let Some(v) = alt_body_1117 { v.write_to(w)?; }
                if let Some(v) = alt_body_1118 { v.write_to(w)?; }
                if let Some(v) = alt_body_1119 { v.write_to(w)?; }
                if let Some(v) = alt_body_1120 { v.write_to(w)?; }
                if let Some(v) = alt_body_1121 { v.write_to(w)?; }
                if let Some(v) = alt_body_1122 { v.write_to(w)?; }
                if let Some(v) = alt_body_1123 { v.write_to(w)?; }
                if let Some(v) = alt_body_1124 { v.write_to(w)?; }
                if let Some(v) = alt_body_1125 { v.write_to(w)?; }
                if let Some(v) = alt_body_1126 { v.write_to(w)?; }
                if let Some(v) = alt_body_1127 { v.write_to(w)?; }
                if let Some(v) = alt_body_1128 { v.write_to(w)?; }
                if let Some(v) = alt_body_1129 { v.write_to(w)?; }
                if let Some(v) = alt_body_1130 { v.write_to(w)?; }
                if let Some(v) = alt_body_1131 { v.write_to(w)?; }
                if let Some(v) = alt_body_1132 { v.write_to(w)?; }
                if let Some(v) = alt_body_1133 { v.write_to(w)?; }
                if let Some(v) = alt_body_1134 { v.write_to(w)?; }
                if let Some(v) = alt_body_1135 { v.write_to(w)?; }
                if let Some(v) = alt_body_1136 { v.write_to(w)?; }
                if let Some(v) = alt_body_1137 { v.write_to(w)?; }
                if let Some(v) = alt_body_1138 { v.write_to(w)?; }
                if let Some(v) = alt_body_1139 { v.write_to(w)?; }
                if let Some(v) = alt_body_1140 { v.write_to(w)?; }
                if let Some(v) = alt_body_1141 { v.write_to(w)?; }
                if let Some(v) = alt_body_1142 { v.write_to(w)?; }
                if let Some(v) = alt_body_1143 { v.write_to(w)?; }
                if let Some(v) = alt_body_1144 { v.write_to(w)?; }
                if let Some(v) = alt_body_1145 { v.write_to(w)?; }
                if let Some(v) = alt_body_1146 { v.write_to(w)?; }
                if let Some(v) = alt_body_1147 { v.write_to(w)?; }
                if let Some(v) = alt_body_1148 { v.write_to(w)?; }
                if let Some(v) = alt_body_1149 { v.write_to(w)?; }
                if let Some(v) = alt_body_1150 { v.write_to(w)?; }
                if let Some(v) = alt_body_1151 { v.write_to(w)?; }
                if let Some(v) = alt_body_1152 { v.write_to(w)?; }
                if let Some(v) = alt_body_1153 { v.write_to(w)?; }
                if let Some(v) = alt_body_1154 { v.write_to(w)?; }
                if let Some(v) = alt_body_1155 { v.write_to(w)?; }
                if let Some(v) = alt_body_1156 { v.write_to(w)?; }
                if let Some(v) = alt_body_1157 { v.write_to(w)?; }
                if let Some(v) = alt_body_1158 { v.write_to(w)?; }
                if let Some(v) = alt_body_1159 { v.write_to(w)?; }
                if let Some(v) = alt_body_1160 { v.write_to(w)?; }
                if let Some(v) = alt_body_1161 { v.write_to(w)?; }
                if let Some(v) = alt_body_1162 { v.write_to(w)?; }
                if let Some(v) = alt_body_1163 { v.write_to(w)?; }
                if let Some(v) = alt_body_1164 { v.write_to(w)?; }
                if let Some(v) = alt_body_1165 { v.write_to(w)?; }
                if let Some(v) = alt_body_1166 { v.write_to(w)?; }
                if let Some(v) = alt_body_1167 { v.write_to(w)?; }
                if let Some(v) = alt_body_1168 { v.write_to(w)?; }
                if let Some(v) = alt_body_1169 { v.write_to(w)?; }
                if let Some(v) = alt_body_1170 { v.write_to(w)?; }
                if let Some(v) = alt_body_1171 { v.write_to(w)?; }
                if let Some(v) = alt_body_1172 { v.write_to(w)?; }
                if let Some(v) = alt_body_1173 { v.write_to(w)?; }
                if let Some(v) = alt_body_1174 { v.write_to(w)?; }
                if let Some(v) = alt_body_1175 { v.write_to(w)?; }
                if let Some(v) = alt_body_1176 { v.write_to(w)?; }
                if let Some(v) = alt_body_1177 { v.write_to(w)?; }
                if let Some(v) = alt_body_1178 { v.write_to(w)?; }
                if let Some(v) = alt_body_1179 { v.write_to(w)?; }
                if let Some(v) = alt_body_1180 { v.write_to(w)?; }
                if let Some(v) = alt_body_1181 { v.write_to(w)?; }
                if let Some(v) = alt_body_1182 { v.write_to(w)?; }
                if let Some(v) = alt_body_1183 { v.write_to(w)?; }
                if let Some(v) = alt_body_1184 { v.write_to(w)?; }
                if let Some(v) = alt_body_1185 { v.write_to(w)?; }
                if let Some(v) = alt_body_1186 { v.write_to(w)?; }
                if let Some(v) = alt_body_1187 { v.write_to(w)?; }
                if let Some(v) = alt_body_1188 { v.write_to(w)?; }
                if let Some(v) = alt_body_1189 { v.write_to(w)?; }
                if let Some(v) = alt_body_1190 { v.write_to(w)?; }
                if let Some(v) = alt_body_1191 { v.write_to(w)?; }
                if let Some(v) = alt_body_1192 { v.write_to(w)?; }
                if let Some(v) = alt_body_1193 { v.write_to(w)?; }
                if let Some(v) = alt_body_1194 { v.write_to(w)?; }
                if let Some(v) = alt_body_1195 { v.write_to(w)?; }
                if let Some(v) = alt_body_1196 { v.write_to(w)?; }
                if let Some(v) = alt_body_1197 { v.write_to(w)?; }
                if let Some(v) = alt_body_1198 { v.write_to(w)?; }
                if let Some(v) = alt_body_1199 { v.write_to(w)?; }
                if let Some(v) = alt_body_1200 { v.write_to(w)?; }
                if let Some(v) = alt_body_1201 { v.write_to(w)?; }
                if let Some(v) = alt_body_1202 { v.write_to(w)?; }
                if let Some(v) = alt_body_1203 { v.write_to(w)?; }
                if let Some(v) = alt_body_1204 { v.write_to(w)?; }
                if let Some(v) = alt_body_1205 { v.write_to(w)?; }
                if let Some(v) = alt_body_1206 { v.write_to(w)?; }
                if let Some(v) = alt_body_1207 { v.write_to(w)?; }
                if let Some(v) = alt_body_1208 { v.write_to(w)?; }
                if let Some(v) = alt_body_1209 { v.write_to(w)?; }
                if let Some(v) = alt_body_1210 { v.write_to(w)?; }
                if let Some(v) = alt_body_1211 { v.write_to(w)?; }
                if let Some(v) = alt_body_1212 { v.write_to(w)?; }
                if let Some(v) = alt_body_1213 { v.write_to(w)?; }
                if let Some(v) = alt_body_1214 { v.write_to(w)?; }
                if let Some(v) = alt_body_1215 { v.write_to(w)?; }
                if let Some(v) = alt_body_1216 { v.write_to(w)?; }
                if let Some(v) = alt_body_1217 { v.write_to(w)?; }
                if let Some(v) = alt_body_1218 { v.write_to(w)?; }
                if let Some(v) = alt_body_1219 { v.write_to(w)?; }
                if let Some(v) = alt_body_1220 { v.write_to(w)?; }
                if let Some(v) = alt_body_1221 { v.write_to(w)?; }
                if let Some(v) = alt_body_1222 { v.write_to(w)?; }
                if let Some(v) = alt_body_1223 { v.write_to(w)?; }
                if let Some(v) = alt_body_1224 { v.write_to(w)?; }
                if let Some(v) = alt_body_1225 { v.write_to(w)?; }
                if let Some(v) = alt_body_1226 { v.write_to(w)?; }
                if let Some(v) = alt_body_1227 { v.write_to(w)?; }
                if let Some(v) = alt_body_1228 { v.write_to(w)?; }
                if let Some(v) = alt_body_1229 { v.write_to(w)?; }
                if let Some(v) = alt_body_1230 { v.write_to(w)?; }
                if let Some(v) = alt_body_1231 { v.write_to(w)?; }
                if let Some(v) = alt_body_1232 { v.write_to(w)?; }
                if let Some(v) = alt_body_1233 { v.write_to(w)?; }
                if let Some(v) = alt_body_1234 { v.write_to(w)?; }
                if let Some(v) = alt_body_1235 { v.write_to(w)?; }
                if let Some(v) = alt_body_1236 { v.write_to(w)?; }
                if let Some(v) = alt_body_1237 { v.write_to(w)?; }
                if let Some(v) = alt_body_1238 { v.write_to(w)?; }
                if let Some(v) = alt_body_1239 { v.write_to(w)?; }
                if let Some(v) = alt_body_1240 { v.write_to(w)?; }
                if let Some(v) = alt_body_1241 { v.write_to(w)?; }
                if let Some(v) = alt_body_1242 { v.write_to(w)?; }
                if let Some(v) = alt_body_1243 { v.write_to(w)?; }
                if let Some(v) = alt_body_1244 { v.write_to(w)?; }
                if let Some(v) = alt_body_1245 { v.write_to(w)?; }
                if let Some(v) = alt_body_1246 { v.write_to(w)?; }
                if let Some(v) = alt_body_1247 { v.write_to(w)?; }
                if let Some(v) = alt_body_1248 { v.write_to(w)?; }
                if let Some(v) = alt_body_1249 { v.write_to(w)?; }
                if let Some(v) = alt_body_1250 { v.write_to(w)?; }
                if let Some(v) = alt_body_1251 { v.write_to(w)?; }
                if let Some(v) = alt_body_1252 { v.write_to(w)?; }
                if let Some(v) = alt_body_1253 { v.write_to(w)?; }
                if let Some(v) = alt_body_1254 { v.write_to(w)?; }
                if let Some(v) = alt_body_1255 { v.write_to(w)?; }
                if let Some(v) = alt_body_1256 { v.write_to(w)?; }
                if let Some(v) = alt_body_1257 { v.write_to(w)?; }
                if let Some(v) = alt_body_1258 { v.write_to(w)?; }
                if let Some(v) = alt_body_1259 { v.write_to(w)?; }
                if let Some(v) = alt_body_1260 { v.write_to(w)?; }
                if let Some(v) = alt_body_1261 { v.write_to(w)?; }
                if let Some(v) = alt_body_1262 { v.write_to(w)?; }
                if let Some(v) = alt_body_1263 { v.write_to(w)?; }
                if let Some(v) = alt_body_1264 { v.write_to(w)?; }
                if let Some(v) = alt_body_1265 { v.write_to(w)?; }
                if let Some(v) = alt_body_1266 { v.write_to(w)?; }
                if let Some(v) = alt_body_1267 { v.write_to(w)?; }
                if let Some(v) = alt_body_1268 { v.write_to(w)?; }
                if let Some(v) = alt_body_1269 { v.write_to(w)?; }
                if let Some(v) = alt_body_1270 { v.write_to(w)?; }
                if let Some(v) = alt_body_1271 { v.write_to(w)?; }
                if let Some(v) = alt_body_1272 { v.write_to(w)?; }
                if let Some(v) = alt_body_1273 { v.write_to(w)?; }
                if let Some(v) = alt_body_1274 { v.write_to(w)?; }
                if let Some(v) = alt_body_1275 { v.write_to(w)?; }
                if let Some(v) = alt_body_1276 { v.write_to(w)?; }
                if let Some(v) = alt_body_1277 { v.write_to(w)?; }
                if let Some(v) = alt_body_1278 { v.write_to(w)?; }
                if let Some(v) = alt_body_1279 { v.write_to(w)?; }
                if let Some(v) = alt_body_1280 { v.write_to(w)?; }
                if let Some(v) = alt_body_1281 { v.write_to(w)?; }
                if let Some(v) = alt_body_1282 { v.write_to(w)?; }
                if let Some(v) = alt_body_1283 { v.write_to(w)?; }
                if let Some(v) = alt_body_1284 { v.write_to(w)?; }
                if let Some(v) = alt_body_1285 { v.write_to(w)?; }
                if let Some(v) = alt_body_1286 { v.write_to(w)?; }
                if let Some(v) = alt_body_1287 { v.write_to(w)?; }
                if let Some(v) = alt_body_1288 { v.write_to(w)?; }
                if let Some(v) = alt_body_1289 { v.write_to(w)?; }
                if let Some(v) = alt_body_1290 { v.write_to(w)?; }
                if let Some(v) = alt_body_1291 { v.write_to(w)?; }
                if let Some(v) = alt_body_1292 { v.write_to(w)?; }
                if let Some(v) = alt_body_1293 { v.write_to(w)?; }
                if let Some(v) = alt_body_1294 { v.write_to(w)?; }
                if let Some(v) = alt_body_1295 { v.write_to(w)?; }
                if let Some(v) = alt_body_1296 { v.write_to(w)?; }
                if let Some(v) = alt_body_1297 { v.write_to(w)?; }
                if let Some(v) = alt_body_1298 { v.write_to(w)?; }
                if let Some(v) = alt_body_1299 { v.write_to(w)?; }
                if let Some(v) = alt_body_1300 { v.write_to(w)?; }
                if let Some(v) = alt_body_1301 { v.write_to(w)?; }
                if let Some(v) = alt_body_1302 { v.write_to(w)?; }
                if let Some(v) = alt_body_1303 { v.write_to(w)?; }
                if let Some(v) = alt_body_1304 { v.write_to(w)?; }
                if let Some(v) = alt_body_1305 { v.write_to(w)?; }
                if let Some(v) = alt_body_1306 { v.write_to(w)?; }
                if let Some(v) = alt_body_1307 { v.write_to(w)?; }
                if let Some(v) = alt_body_1308 { v.write_to(w)?; }
                if let Some(v) = alt_body_1309 { v.write_to(w)?; }
                if let Some(v) = alt_body_1310 { v.write_to(w)?; }
                if let Some(v) = alt_body_1311 { v.write_to(w)?; }
                if let Some(v) = alt_body_1312 { v.write_to(w)?; }
                if let Some(v) = alt_body_1313 { v.write_to(w)?; }
                if let Some(v) = alt_body_1314 { v.write_to(w)?; }
                if let Some(v) = alt_body_1315 { v.write_to(w)?; }
                if let Some(v) = alt_body_1316 { v.write_to(w)?; }
                if let Some(v) = alt_body_1317 { v.write_to(w)?; }
                if let Some(v) = alt_body_1318 { v.write_to(w)?; }
                if let Some(v) = alt_body_1319 { v.write_to(w)?; }
                if let Some(v) = alt_body_1320 { v.write_to(w)?; }
                if let Some(v) = alt_body_1321 { v.write_to(w)?; }
                if let Some(v) = alt_body_1322 { v.write_to(w)?; }
                if let Some(v) = alt_body_1323 { v.write_to(w)?; }
                if let Some(v) = alt_body_1324 { v.write_to(w)?; }
                if let Some(v) = alt_body_1325 { v.write_to(w)?; }
                if let Some(v) = alt_body_1326 { v.write_to(w)?; }
                if let Some(v) = alt_body_1327 { v.write_to(w)?; }
                if let Some(v) = alt_body_1328 { v.write_to(w)?; }
                if let Some(v) = alt_body_1329 { v.write_to(w)?; }
                if let Some(v) = alt_body_1330 { v.write_to(w)?; }
                if let Some(v) = alt_body_1331 { v.write_to(w)?; }
                if let Some(v) = alt_body_1332 { v.write_to(w)?; }
                if let Some(v) = alt_body_1333 { v.write_to(w)?; }
                if let Some(v) = alt_body_1334 { v.write_to(w)?; }
                if let Some(v) = alt_body_1335 { v.write_to(w)?; }
                if let Some(v) = alt_body_1336 { v.write_to(w)?; }
                if let Some(v) = alt_body_1337 { v.write_to(w)?; }
                if let Some(v) = alt_body_1338 { v.write_to(w)?; }
                if let Some(v) = alt_body_1339 { v.write_to(w)?; }
                if let Some(v) = alt_body_1340 { v.write_to(w)?; }
                if let Some(v) = alt_body_1341 { v.write_to(w)?; }
                if let Some(v) = alt_body_1342 { v.write_to(w)?; }
                if let Some(v) = alt_body_1343 { v.write_to(w)?; }
                if let Some(v) = alt_body_1344 { v.write_to(w)?; }
                if let Some(v) = alt_body_1345 { v.write_to(w)?; }
                if let Some(v) = alt_body_1346 { v.write_to(w)?; }
                if let Some(v) = alt_body_1347 { v.write_to(w)?; }
                if let Some(v) = alt_body_1348 { v.write_to(w)?; }
                if let Some(v) = alt_body_1349 { v.write_to(w)?; }
                if let Some(v) = alt_body_1350 { v.write_to(w)?; }
                if let Some(v) = alt_body_1351 { v.write_to(w)?; }
                if let Some(v) = alt_body_1352 { v.write_to(w)?; }
                if let Some(v) = alt_body_1353 { v.write_to(w)?; }
                if let Some(v) = alt_body_1354 { v.write_to(w)?; }
                if let Some(v) = alt_body_1355 { v.write_to(w)?; }
                if let Some(v) = alt_body_1356 { v.write_to(w)?; }
                if let Some(v) = alt_body_1357 { v.write_to(w)?; }
                if let Some(v) = alt_body_1358 { v.write_to(w)?; }
                if let Some(v) = alt_body_1359 { v.write_to(w)?; }
                if let Some(v) = alt_body_1360 { v.write_to(w)?; }
                if let Some(v) = alt_body_1361 { v.write_to(w)?; }
                if let Some(v) = alt_body_1362 { v.write_to(w)?; }
                if let Some(v) = alt_body_1363 { v.write_to(w)?; }
                if let Some(v) = alt_body_1364 { v.write_to(w)?; }
                if let Some(v) = alt_body_1365 { v.write_to(w)?; }
                if let Some(v) = alt_body_1366 { v.write_to(w)?; }
                if let Some(v) = alt_body_1367 { v.write_to(w)?; }
                if let Some(v) = alt_body_1368 { v.write_to(w)?; }
                if let Some(v) = alt_body_1369 { v.write_to(w)?; }
                if let Some(v) = alt_body_1370 { v.write_to(w)?; }
                if let Some(v) = alt_body_1371 { v.write_to(w)?; }
                if let Some(v) = alt_body_1372 { v.write_to(w)?; }
                if let Some(v) = alt_body_1373 { v.write_to(w)?; }
                if let Some(v) = alt_body_1374 { v.write_to(w)?; }
                if let Some(v) = alt_body_1375 { v.write_to(w)?; }
                if let Some(v) = alt_body_1376 { v.write_to(w)?; }
                if let Some(v) = alt_body_1377 { v.write_to(w)?; }
                if let Some(v) = alt_body_1378 { v.write_to(w)?; }
                if let Some(v) = alt_body_1379 { v.write_to(w)?; }
                if let Some(v) = alt_body_1380 { v.write_to(w)?; }
                if let Some(v) = alt_body_1381 { v.write_to(w)?; }
                if let Some(v) = alt_body_1382 { v.write_to(w)?; }
                if let Some(v) = alt_body_1383 { v.write_to(w)?; }
                if let Some(v) = alt_body_1384 { v.write_to(w)?; }
                if let Some(v) = alt_body_1385 { v.write_to(w)?; }
                if let Some(v) = alt_body_1386 { v.write_to(w)?; }
                if let Some(v) = alt_body_1387 { v.write_to(w)?; }
                if let Some(v) = alt_body_1388 { v.write_to(w)?; }
                if let Some(v) = alt_body_1389 { v.write_to(w)?; }
                if let Some(v) = alt_body_1390 { v.write_to(w)?; }
                if let Some(v) = alt_body_1391 { v.write_to(w)?; }
                if let Some(v) = alt_body_1392 { v.write_to(w)?; }
                if let Some(v) = alt_body_1393 { v.write_to(w)?; }
                if let Some(v) = alt_body_1394 { v.write_to(w)?; }
                if let Some(v) = alt_body_1395 { v.write_to(w)?; }
                if let Some(v) = alt_body_1396 { v.write_to(w)?; }
                if let Some(v) = alt_body_1397 { v.write_to(w)?; }
                if let Some(v) = alt_body_1398 { v.write_to(w)?; }
                if let Some(v) = alt_body_1399 { v.write_to(w)?; }
                if let Some(v) = alt_body_1400 { v.write_to(w)?; }
                if let Some(v) = alt_body_1401 { v.write_to(w)?; }
                if let Some(v) = alt_body_1402 { v.write_to(w)?; }
                if let Some(v) = alt_body_1403 { v.write_to(w)?; }
                if let Some(v) = alt_body_1404 { v.write_to(w)?; }
                if let Some(v) = alt_body_1405 { v.write_to(w)?; }
                if let Some(v) = alt_body_1406 { v.write_to(w)?; }
                if let Some(v) = alt_body_1407 { v.write_to(w)?; }
                if let Some(v) = alt_body_1408 { v.write_to(w)?; }
                if let Some(v) = alt_body_1409 { v.write_to(w)?; }
                if let Some(v) = alt_body_1410 { v.write_to(w)?; }
                if let Some(v) = alt_body_1411 { v.write_to(w)?; }
                if let Some(v) = alt_body_1412 { v.write_to(w)?; }
                if let Some(v) = alt_body_1413 { v.write_to(w)?; }
                if let Some(v) = alt_body_1414 { v.write_to(w)?; }
                if let Some(v) = alt_body_1415 { v.write_to(w)?; }
                if let Some(v) = alt_body_1416 { v.write_to(w)?; }
                if let Some(v) = alt_body_1417 { v.write_to(w)?; }
                if let Some(v) = alt_body_1418 { v.write_to(w)?; }
                if let Some(v) = alt_body_1419 { v.write_to(w)?; }
                if let Some(v) = alt_body_1420 { v.write_to(w)?; }
                if let Some(v) = alt_body_1421 { v.write_to(w)?; }
                if let Some(v) = alt_body_1422 { v.write_to(w)?; }
                if let Some(v) = alt_body_1423 { v.write_to(w)?; }
                if let Some(v) = alt_body_1424 { v.write_to(w)?; }
                if let Some(v) = alt_body_1425 { v.write_to(w)?; }
                if let Some(v) = alt_body_1426 { v.write_to(w)?; }
                if let Some(v) = alt_body_1427 { v.write_to(w)?; }
                if let Some(v) = alt_body_1428 { v.write_to(w)?; }
                if let Some(v) = alt_body_1429 { v.write_to(w)?; }
                if let Some(v) = alt_body_1430 { v.write_to(w)?; }
                if let Some(v) = alt_body_1431 { v.write_to(w)?; }
                if let Some(v) = alt_body_1432 { v.write_to(w)?; }
                if let Some(v) = alt_body_1433 { v.write_to(w)?; }
                if let Some(v) = alt_body_1434 { v.write_to(w)?; }
                if let Some(v) = alt_body_1435 { v.write_to(w)?; }
                if let Some(v) = alt_body_1436 { v.write_to(w)?; }
                if let Some(v) = alt_body_1437 { v.write_to(w)?; }
                if let Some(v) = alt_body_1438 { v.write_to(w)?; }
                if let Some(v) = alt_body_1439 { v.write_to(w)?; }
                if let Some(v) = alt_body_1440 { v.write_to(w)?; }
                if let Some(v) = alt_body_1441 { v.write_to(w)?; }
                if let Some(v) = alt_body_1442 { v.write_to(w)?; }
                if let Some(v) = alt_body_1443 { v.write_to(w)?; }
                if let Some(v) = alt_body_1444 { v.write_to(w)?; }
                if let Some(v) = alt_body_1445 { v.write_to(w)?; }
                if let Some(v) = alt_body_1446 { v.write_to(w)?; }
                if let Some(v) = alt_body_1447 { v.write_to(w)?; }
                if let Some(v) = alt_body_1448 { v.write_to(w)?; }
                if let Some(v) = alt_body_1449 { v.write_to(w)?; }
                if let Some(v) = alt_body_1450 { v.write_to(w)?; }
                if let Some(v) = alt_body_1451 { v.write_to(w)?; }
                if let Some(v) = alt_body_1452 { v.write_to(w)?; }
                if let Some(v) = alt_body_1453 { v.write_to(w)?; }
                if let Some(v) = alt_body_1454 { v.write_to(w)?; }
                if let Some(v) = alt_body_1455 { v.write_to(w)?; }
                if let Some(v) = alt_body_1456 { v.write_to(w)?; }
                if let Some(v) = alt_body_1457 { v.write_to(w)?; }
                if let Some(v) = alt_body_1458 { v.write_to(w)?; }
                if let Some(v) = alt_body_1459 { v.write_to(w)?; }
                if let Some(v) = alt_body_1460 { v.write_to(w)?; }
                if let Some(v) = alt_body_1461 { v.write_to(w)?; }
                if let Some(v) = alt_body_1462 { v.write_to(w)?; }
                if let Some(v) = alt_body_1463 { v.write_to(w)?; }
                if let Some(v) = alt_body_1464 { v.write_to(w)?; }
                if let Some(v) = alt_body_1465 { v.write_to(w)?; }
                if let Some(v) = alt_body_1466 { v.write_to(w)?; }
                if let Some(v) = alt_body_1467 { v.write_to(w)?; }
                if let Some(v) = alt_body_1468 { v.write_to(w)?; }
                if let Some(v) = alt_body_1469 { v.write_to(w)?; }
                if let Some(v) = alt_body_1470 { v.write_to(w)?; }
                if let Some(v) = alt_body_1471 { v.write_to(w)?; }
                if let Some(v) = alt_body_1472 { v.write_to(w)?; }
                if let Some(v) = alt_body_1473 { v.write_to(w)?; }
                if let Some(v) = alt_body_1474 { v.write_to(w)?; }
                if let Some(v) = alt_body_1475 { v.write_to(w)?; }
                if let Some(v) = alt_body_1476 { v.write_to(w)?; }
                if let Some(v) = alt_body_1477 { v.write_to(w)?; }
                if let Some(v) = alt_body_1478 { v.write_to(w)?; }
                if let Some(v) = alt_body_1479 { v.write_to(w)?; }
                if let Some(v) = alt_body_1480 { v.write_to(w)?; }
                if let Some(v) = alt_body_1481 { v.write_to(w)?; }
                if let Some(v) = alt_body_1482 { v.write_to(w)?; }
                if let Some(v) = alt_body_1483 { v.write_to(w)?; }
                if let Some(v) = alt_body_1484 { v.write_to(w)?; }
                if let Some(v) = alt_body_1485 { v.write_to(w)?; }
                if let Some(v) = alt_body_1486 { v.write_to(w)?; }
                if let Some(v) = alt_body_1487 { v.write_to(w)?; }
                if let Some(v) = alt_body_1488 { v.write_to(w)?; }
                if let Some(v) = alt_body_1489 { v.write_to(w)?; }
                if let Some(v) = alt_body_1490 { v.write_to(w)?; }
                if let Some(v) = alt_body_1491 { v.write_to(w)?; }
                if let Some(v) = alt_body_1492 { v.write_to(w)?; }
                if let Some(v) = alt_body_1493 { v.write_to(w)?; }
                if let Some(v) = alt_body_1494 { v.write_to(w)?; }
                if let Some(v) = alt_body_1495 { v.write_to(w)?; }
                if let Some(v) = alt_body_1496 { v.write_to(w)?; }
                if let Some(v) = alt_body_1497 { v.write_to(w)?; }
                if let Some(v) = alt_body_1498 { v.write_to(w)?; }
                if let Some(v) = alt_body_1499 { v.write_to(w)?; }
                if let Some(v) = alt_body_1500 { v.write_to(w)?; }
                if let Some(v) = alt_body_1501 { v.write_to(w)?; }
                if let Some(v) = alt_body_1502 { v.write_to(w)?; }
                if let Some(v) = alt_body_1503 { v.write_to(w)?; }
                if let Some(v) = alt_body_1504 { v.write_to(w)?; }
                if let Some(v) = alt_body_1505 { v.write_to(w)?; }
                if let Some(v) = alt_body_1506 { v.write_to(w)?; }
                if let Some(v) = alt_body_1507 { v.write_to(w)?; }
                if let Some(v) = alt_body_1508 { v.write_to(w)?; }
                if let Some(v) = alt_body_1509 { v.write_to(w)?; }
                if let Some(v) = alt_body_1510 { v.write_to(w)?; }
                if let Some(v) = alt_body_1511 { v.write_to(w)?; }
                if let Some(v) = alt_body_1512 { v.write_to(w)?; }
                if let Some(v) = alt_body_1513 { v.write_to(w)?; }
                if let Some(v) = alt_body_1514 { v.write_to(w)?; }
                if let Some(v) = alt_body_1515 { v.write_to(w)?; }
                if let Some(v) = alt_body_1516 { v.write_to(w)?; }
                if let Some(v) = alt_body_1517 { v.write_to(w)?; }
                if let Some(v) = alt_body_1518 { v.write_to(w)?; }
                if let Some(v) = alt_body_1519 { v.write_to(w)?; }
                if let Some(v) = alt_body_1520 { v.write_to(w)?; }
                if let Some(v) = alt_body_1521 { v.write_to(w)?; }
                if let Some(v) = alt_body_1522 { v.write_to(w)?; }
                if let Some(v) = alt_body_1523 { v.write_to(w)?; }
                if let Some(v) = alt_body_1524 { v.write_to(w)?; }
                if let Some(v) = alt_body_1525 { v.write_to(w)?; }
                if let Some(v) = alt_body_1526 { v.write_to(w)?; }
                if let Some(v) = alt_body_1527 { v.write_to(w)?; }
                if let Some(v) = alt_body_1528 { v.write_to(w)?; }
                if let Some(v) = alt_body_1529 { v.write_to(w)?; }
                if let Some(v) = alt_body_1530 { v.write_to(w)?; }
                if let Some(v) = alt_body_1531 { v.write_to(w)?; }
                if let Some(v) = alt_body_1532 { v.write_to(w)?; }
                if let Some(v) = alt_body_1533 { v.write_to(w)?; }
                if let Some(v) = alt_body_1534 { v.write_to(w)?; }
                if let Some(v) = alt_body_1535 { v.write_to(w)?; }
                if let Some(v) = alt_body_1536 { v.write_to(w)?; }
                if let Some(s) = alt_post_cstr_a { s.write_to(w)?; }
                if let Some(s) = alt_post_cstr_b { s.write_to(w)?; }
                if let Some(v) = field_665_u32 { v.write_to(w)?; }
                if let Some(v) = field_666_u32 { v.write_to(w)?; }
                if let Some(v) = field_667_u32 { v.write_to(w)?; }
                if let Some(v) = field_668_u32 { v.write_to(w)?; }
                if let Some(v) = field_669_u32 { v.write_to(w)?; }
                if let Some(v) = field_670_u32 { v.write_to(w)?; }
                if let Some(v) = field_671_u32 { v.write_to(w)?; }
                if let Some(v) = field_672_u32 { v.write_to(w)?; }
                if let Some(v) = field_673_u32 { v.write_to(w)?; }
                if let Some(v) = field_674_u32 { v.write_to(w)?; }
                if let Some(v) = field_675_u32 { v.write_to(w)?; }
                if let Some(v) = field_676_u32 { v.write_to(w)?; }
                if let Some(v) = field_677_u32 { v.write_to(w)?; }
                if let Some(v) = field_678_u32 { v.write_to(w)?; }
                if let Some(v) = field_679_u32 { v.write_to(w)?; }
                if let Some(v) = field_680_u32 { v.write_to(w)?; }
                if let Some(v) = field_681_u32 { v.write_to(w)?; }
                if let Some(v) = field_682_u32 { v.write_to(w)?; }
                if let Some(v) = field_683_u32 { v.write_to(w)?; }
                if let Some(v) = field_684_u32 { v.write_to(w)?; }
                if let Some(v) = field_685_u32 { v.write_to(w)?; }
                if let Some(v) = field_686_u32 { v.write_to(w)?; }
                if let Some(v) = field_687_u32 { v.write_to(w)?; }
                if let Some(v) = field_688_u32 { v.write_to(w)?; }
                if let Some(v) = field_689_u32 { v.write_to(w)?; }
                if let Some(v) = field_690_u32 { v.write_to(w)?; }
                if let Some(v) = field_691_u32 { v.write_to(w)?; }
                if let Some(v) = field_692_u32 { v.write_to(w)?; }
                if let Some(v) = field_693_u32 { v.write_to(w)?; }
                if let Some(v) = field_694_u32 { v.write_to(w)?; }
                if let Some(v) = field_695_u32 { v.write_to(w)?; }
                if let Some(v) = field_696_u32 { v.write_to(w)?; }
                if let Some(v) = field_697_u32 { v.write_to(w)?; }
                if let Some(v) = field_698_u32 { v.write_to(w)?; }
                if let Some(v) = field_699_u32 { v.write_to(w)?; }
                if let Some(v) = field_700_u32 { v.write_to(w)?; }
                if let Some(v) = field_701_u32 { v.write_to(w)?; }
                if let Some(v) = field_702_u32 { v.write_to(w)?; }
                if let Some(v) = field_703_u32 { v.write_to(w)?; }
                if let Some(v) = field_704_u32 { v.write_to(w)?; }
                if let Some(v) = field_705_u32 { v.write_to(w)?; }
                if let Some(v) = field_706_u32 { v.write_to(w)?; }
                if let Some(v) = field_707_u32 { v.write_to(w)?; }
                if let Some(v) = field_708_u32 { v.write_to(w)?; }
                if let Some(v) = field_709_u32 { v.write_to(w)?; }
                if let Some(v) = field_710_u32 { v.write_to(w)?; }
                if let Some(v) = field_711_u32 { v.write_to(w)?; }
                if let Some(v) = field_712_u32 { v.write_to(w)?; }
                if let Some(v) = field_713_u32 { v.write_to(w)?; }
                if let Some(v) = field_714_u32 { v.write_to(w)?; }
                if let Some(v) = field_715_u32 { v.write_to(w)?; }
                if let Some(v) = field_716_u32 { v.write_to(w)?; }
                if let Some(v) = field_717_u32 { v.write_to(w)?; }
                if let Some(v) = field_718_u32 { v.write_to(w)?; }
                if let Some(v) = field_719_u32 { v.write_to(w)?; }
                if let Some(v) = field_720_u32 { v.write_to(w)?; }
                if let Some(v) = field_721_u32 { v.write_to(w)?; }
                if let Some(v) = field_722_u32 { v.write_to(w)?; }
                if let Some(v) = field_723_u32 { v.write_to(w)?; }
                if let Some(v) = field_724_u32 { v.write_to(w)?; }
                if let Some(v) = field_725_u32 { v.write_to(w)?; }
                if let Some(v) = field_726_u32 { v.write_to(w)?; }
                if let Some(v) = field_727_u32 { v.write_to(w)?; }
                if let Some(v) = field_728_u32 { v.write_to(w)?; }
                if let Some(v) = tail_pad_001 { v.write_to(w)?; }
                if let Some(v) = tail_pad_002 { v.write_to(w)?; }
                if let Some(v) = tail_pad_003 { v.write_to(w)?; }
                if let Some(v) = tail_pad_004 { v.write_to(w)?; }
                w.write_all(post_blob)
            }
            GimmickTail::Raw(b) => w.write_all(b),
        }
    }

    pub fn to_json_value(&self) -> Value {
        match self {
            GimmickTail::Decoded { gimmick_interaction_override_list,
                use_interaction_ui_socket, use_sub_part_for_interaction,
                property_list, gimmick_name_hash, gimmick_name,
                emoji_texture_id, dev_memo,
                hash_pair_list, hash_single_list,
                trigger_event_handler_list, gimmick_chart_parameter_list,
                field_19_u32_list, field_20_u32_list,
                field_21_u32_list, field_22_u32_list,
                field_23_u32_list, field_24_u32_list,
                field_24_emissive_flag_a, field_24_emissive_value_a,
                field_24_emissive_flag_b, field_24_emissive_name,
                field_24_emissive_value_b,
                field_25_u32_list, field_26_u32, field_27_u32_list,
                field_28_u32, field_29_u32_list, field_30_u32_list,
                field_31_u32_list,
                f31_alt_001, f31_alt_002, f31_alt_003, f31_alt_004,
                f31_alt_005, f31_alt_006, f31_alt_007, f31_alt_008,
                f31_alt_009, f31_alt_010, f31_alt_011, f31_alt_012,
                f31_alt_013, f31_alt_014, f31_alt_015, f31_alt_016,
                f31_alt_017, f31_alt_018, f31_alt_019, f31_alt_020,
                f31_alt_021, f31_alt_022, f31_alt_023, f31_alt_024,
                f31_alt_025, f31_alt_026, f31_alt_027, f31_alt_028,
                f31_alt_029, f31_alt_030, f31_alt_031, f31_alt_032,
                f31_alt_033, f31_alt_034, f31_alt_035, f31_alt_036,
                f31_alt_037, f31_alt_038, f31_alt_039, f31_alt_040,
                f31_alt_041, f31_alt_042, f31_alt_043, f31_alt_044,
                f31_alt_045, f31_alt_046, f31_alt_047, f31_alt_048,
                f31_alt_049, f31_alt_050, f31_alt_051, f31_alt_052,
                f31_alt_053, f31_alt_054, f31_alt_055, f31_alt_056,
                f31_alt_057, f31_alt_058, f31_alt_059, f31_alt_060,
                f31_alt_061, f31_alt_062, f31_alt_063, f31_alt_064,
                f31_alt_065, f31_alt_066, f31_alt_067, f31_alt_068,
                f31_alt_069, f31_alt_070, f31_alt_071, f31_alt_072,
                f31_alt_073, f31_alt_074, f31_alt_075, f31_alt_076,
                f31_alt_077, f31_alt_078, f31_alt_079, f31_alt_080,
                f31_alt_081, f31_alt_082, f31_alt_083, f31_alt_084,
                f31_alt_085, f31_alt_086, f31_alt_087, f31_alt_088,
                f31_alt_089, f31_alt_090, f31_alt_091, f31_alt_092,
                f31_alt_093, f31_alt_094, f31_alt_095, f31_alt_096,
                f31_alt_097, f31_alt_098, f31_alt_099, f31_alt_100,
                f31_alt_101, f31_alt_102, f31_alt_103, f31_alt_104,
                f31_alt_105, f31_alt_106, f31_alt_107, f31_alt_108,
                f31_alt_109, f31_alt_110, f31_alt_111, f31_alt_112,
                f31_alt_113, f31_alt_114, f31_alt_115, f31_alt_116,
                f31_alt_117, f31_alt_118, f31_alt_119, f31_alt_120,
                f31_alt_121, f31_alt_122, f31_alt_123, f31_alt_124,
                f31_alt_125, f31_alt_126, f31_alt_127, f31_alt_128,
                f31_alt_129, f31_alt_130, f31_alt_131, f31_alt_132,
                f31_alt_133, f31_alt_134, f31_alt_135, f31_alt_136,
                f31_alt_137, f31_alt_138, f31_alt_139, f31_alt_140,
                f31_alt_141, f31_alt_142, f31_alt_143, f31_alt_144,
                f31_alt_145, f31_alt_146, f31_alt_147, f31_alt_148,
                f31_alt_149, f31_alt_150, f31_alt_151, f31_alt_152,
                f31_alt_153, f31_alt_154, f31_alt_155, f31_alt_156,
                f31_alt_157, f31_alt_158, f31_alt_159, f31_alt_160,
                f31_alt_161, f31_alt_162, f31_alt_163, f31_alt_164,
                f31_alt_165, f31_alt_166, f31_alt_167, f31_alt_168,
                f31_alt_169, f31_alt_170, f31_alt_171, f31_alt_172,
                f31_alt_173, f31_alt_174, f31_alt_175, f31_alt_176,
                f31_alt_177, f31_alt_178, f31_alt_179, f31_alt_180,
                f31_alt_181, f31_alt_182, f31_alt_183, f31_alt_184,
                f31_alt_185, f31_alt_186, f31_alt_187, f31_alt_188,
                f31_alt_189, f31_alt_190, f31_alt_191, f31_alt_192,
                f31_alt_193, f31_alt_194, f31_alt_195, f31_alt_196,
                f31_alt_197, f31_alt_198, f31_alt_199, f31_alt_200,
                f31_alt_201, f31_alt_202, f31_alt_203, f31_alt_204,
                f31_alt_205, f31_alt_206, f31_alt_207, f31_alt_208,
                f31_alt_209, f31_alt_210, f31_alt_211, f31_alt_212,
                f31_alt_213, f31_alt_214, f31_alt_215, f31_alt_216,
                f31_alt_217, f31_alt_218, f31_alt_219, f31_alt_220,
                f31_alt_221, f31_alt_222, f31_alt_223, f31_alt_224,
                f31_alt_225, f31_alt_226, f31_alt_227, f31_alt_228,
                f31_alt_229, f31_alt_230, f31_alt_231, f31_alt_232,
                f31_alt_233, f31_alt_234, f31_alt_235, f31_alt_236,
                f31_alt_237, f31_alt_238, f31_alt_239, f31_alt_240,
                f31_alt_241, f31_alt_242, f31_alt_243, f31_alt_244,
                f31_alt_245, f31_alt_246, f31_alt_247, f31_alt_248,
                f31_alt_249, f31_alt_250, f31_alt_251, f31_alt_252,
                f31_alt_253, f31_alt_254, f31_alt_255, f31_alt_256,
                field_32_u32_list,
                f32_alt_001, f32_alt_002, f32_alt_003, f32_alt_004,
                f32_alt_005, f32_alt_006, f32_alt_007, f32_alt_008,
                f32_alt_009, f32_alt_010, f32_alt_011, f32_alt_012,
                f32_alt_013, f32_alt_014, f32_alt_015, f32_alt_016,
                f32_alt_017, f32_alt_018, f32_alt_019, f32_alt_020,
                f32_alt_021, f32_alt_022, f32_alt_023, f32_alt_024,
                f32_alt_025, f32_alt_026, f32_alt_027, f32_alt_028,
                f32_alt_029, f32_alt_030, f32_alt_031, f32_alt_032,
                f32_alt_033, f32_alt_034, f32_alt_035, f32_alt_036,
                f32_alt_037, f32_alt_038, f32_alt_039, f32_alt_040,
                f32_alt_041, f32_alt_042, f32_alt_043, f32_alt_044,
                f32_alt_045, f32_alt_046, f32_alt_047, f32_alt_048,
                f32_alt_049, f32_alt_050, f32_alt_051, f32_alt_052,
                f32_alt_053, f32_alt_054, f32_alt_055, f32_alt_056,
                f32_alt_057, f32_alt_058, f32_alt_059, f32_alt_060,
                f32_alt_061, f32_alt_062, f32_alt_063, f32_alt_064,
                f32_alt_065, f32_alt_066, f32_alt_067, f32_alt_068,
                f32_alt_069, f32_alt_070, f32_alt_071, f32_alt_072,
                f32_alt_073, f32_alt_074, f32_alt_075, f32_alt_076,
                f32_alt_077, f32_alt_078, f32_alt_079, f32_alt_080,
                f32_alt_081, f32_alt_082, f32_alt_083, f32_alt_084,
                f32_alt_085, f32_alt_086, f32_alt_087, f32_alt_088,
                f32_alt_089, f32_alt_090, f32_alt_091, f32_alt_092,
                f32_alt_093, f32_alt_094, f32_alt_095, f32_alt_096,
                f32_alt_097, f32_alt_098, f32_alt_099, f32_alt_100,
                f32_alt_101, f32_alt_102, f32_alt_103, f32_alt_104,
                f32_alt_105, f32_alt_106, f32_alt_107, f32_alt_108,
                f32_alt_109, f32_alt_110, f32_alt_111, f32_alt_112,
                f32_alt_113, f32_alt_114, f32_alt_115, f32_alt_116,
                f32_alt_117, f32_alt_118, f32_alt_119, f32_alt_120,
                f32_alt_121, f32_alt_122, f32_alt_123, f32_alt_124,
                f32_alt_125, f32_alt_126, f32_alt_127, f32_alt_128,
                f32_alt_129, f32_alt_130, f32_alt_131, f32_alt_132,
                f32_alt_133, f32_alt_134, f32_alt_135, f32_alt_136,
                f32_alt_137, f32_alt_138, f32_alt_139, f32_alt_140,
                f32_alt_141, f32_alt_142, f32_alt_143, f32_alt_144,
                f32_alt_145, f32_alt_146, f32_alt_147, f32_alt_148,
                f32_alt_149, f32_alt_150, f32_alt_151, f32_alt_152,
                f32_alt_153, f32_alt_154, f32_alt_155, f32_alt_156,
                f32_alt_157, f32_alt_158, f32_alt_159, f32_alt_160,
                f32_alt_161, f32_alt_162, f32_alt_163, f32_alt_164,
                f32_alt_165, f32_alt_166, f32_alt_167, f32_alt_168,
                f32_alt_169, f32_alt_170, f32_alt_171, f32_alt_172,
                f32_alt_173, f32_alt_174, f32_alt_175, f32_alt_176,
                f32_alt_177, f32_alt_178, f32_alt_179, f32_alt_180,
                f32_alt_181, f32_alt_182, f32_alt_183, f32_alt_184,
                f32_alt_185, f32_alt_186, f32_alt_187, f32_alt_188,
                f32_alt_189, f32_alt_190, f32_alt_191, f32_alt_192,
                field_33_u32, field_34_u32,
                field_35_u32_list, field_36_u32,
                field_37_u32, field_38_u32,
                field_39_u32_list,
                f39_alt_001, f39_alt_002, f39_alt_003, f39_alt_004,
                f39_alt_005, f39_alt_006, f39_alt_007, f39_alt_008,
                f39_alt_009, f39_alt_010, f39_alt_011, f39_alt_012,
                f39_alt_013, f39_alt_014, f39_alt_015, f39_alt_016,
                f39_alt_017, f39_alt_018, f39_alt_019, f39_alt_020,
                f39_alt_021, f39_alt_022, f39_alt_023, f39_alt_024,
                f39_alt_025, f39_alt_026, f39_alt_027, f39_alt_028,
                f39_alt_029, f39_alt_030, f39_alt_031, f39_alt_032,
                f39_alt_033, f39_alt_034, f39_alt_035, f39_alt_036,
                f39_alt_037, f39_alt_038, f39_alt_039, f39_alt_040,
                f39_alt_041, f39_alt_042, f39_alt_043, f39_alt_044,
                f39_alt_045, f39_alt_046, f39_alt_047, f39_alt_048,
                f39_alt_049, f39_alt_050, f39_alt_051, f39_alt_052,
                f39_alt_053, f39_alt_054, f39_alt_055, f39_alt_056,
                f39_alt_057, f39_alt_058, f39_alt_059, f39_alt_060,
                f39_alt_061, f39_alt_062, f39_alt_063, f39_alt_064,
                f39_alt_065, f39_alt_066, f39_alt_067, f39_alt_068,
                f39_alt_069, f39_alt_070, f39_alt_071, f39_alt_072,
                f39_alt_073, f39_alt_074, f39_alt_075, f39_alt_076,
                f39_alt_077, f39_alt_078, f39_alt_079, f39_alt_080,
                f39_alt_081, f39_alt_082, f39_alt_083, f39_alt_084,
                f39_alt_085, f39_alt_086, f39_alt_087, f39_alt_088,
                f39_alt_089, f39_alt_090, f39_alt_091, f39_alt_092,
                f39_alt_093, f39_alt_094, f39_alt_095, f39_alt_096,
                f39_alt_097, f39_alt_098, f39_alt_099, f39_alt_100,
                f39_alt_101, f39_alt_102, f39_alt_103, f39_alt_104,
                f39_alt_105, f39_alt_106, f39_alt_107, f39_alt_108,
                f39_alt_109, f39_alt_110, f39_alt_111, f39_alt_112,
                f39_alt_113, f39_alt_114, f39_alt_115, f39_alt_116,
                f39_alt_117, f39_alt_118, f39_alt_119, f39_alt_120,
                f39_alt_121, f39_alt_122, f39_alt_123, f39_alt_124,
                f39_alt_125, f39_alt_126, f39_alt_127, f39_alt_128,
                f39_alt_129, f39_alt_130, f39_alt_131, f39_alt_132,
                f39_alt_133, f39_alt_134, f39_alt_135, f39_alt_136,
                f39_alt_137, f39_alt_138, f39_alt_139, f39_alt_140,
                f39_alt_141, f39_alt_142, f39_alt_143, f39_alt_144,
                f39_alt_145, f39_alt_146, f39_alt_147, f39_alt_148,
                f39_alt_149, f39_alt_150, f39_alt_151, f39_alt_152,
                f39_alt_153, f39_alt_154, f39_alt_155, f39_alt_156,
                f39_alt_157, f39_alt_158, f39_alt_159, f39_alt_160,
                f39_alt_161, f39_alt_162, f39_alt_163, f39_alt_164,
                f39_alt_165, f39_alt_166, f39_alt_167, f39_alt_168,
                f39_alt_169, f39_alt_170, f39_alt_171, f39_alt_172,
                f39_alt_173, f39_alt_174, f39_alt_175, f39_alt_176,
                f39_alt_177, f39_alt_178, f39_alt_179, f39_alt_180,
                f39_alt_181, f39_alt_182, f39_alt_183, f39_alt_184,
                f39_alt_185, f39_alt_186, f39_alt_187, f39_alt_188,
                f39_alt_189, f39_alt_190, f39_alt_191, f39_alt_192,
                field_40_u32_list,
                field_41_u32, field_42_u32, field_43_u32, field_44_u32, field_45_u32, field_46_u32, field_47_u32, field_48_u32, field_49_u32_list, field_50_u32_list,
                field_51_u32_list, field_52_u32_list, field_53_u32_list, field_54_u32_list,
                field_55_u32_list, field_56_u32_list, field_57_u32_list, field_58_u32_list,
                field_59_u32, field_60_u32, field_61_u32, field_62_u32,
                field_63_u32, field_64_u32, field_65_u32, field_66_u32,
                field_67_u32, field_68_u32, field_69_u32, field_70_u32,
                field_71_u32, field_72_u32, field_73_u32, field_74_u32,
                field_75_u32, field_76_u32, field_77_u32, field_78_u32,
                field_79_u32, field_80_u32, field_81_u32, field_82_u32,
                field_83_u32, field_84_u32, field_85_u32, field_86_u32,
                field_87_u32, field_88_u32, field_89_u32, field_90_u32,
                field_91_u32, field_92_u32, field_93_u32, field_94_u32,
                field_95_u32, field_96_u32, field_97_u32, field_98_u32,
                field_99_u32, field_100_u32, field_101_u32, field_102_u32,
                field_103_u32, field_104_u32, field_105_u32, field_106_u32,
                field_107_u32, field_108_u32, field_109_u32, field_110_u32,
                field_111_u32, field_112_u32, field_113_u32, field_114_u32,
                field_115_u32, field_116_u32, field_117_u32, field_118_u32,
                field_119_u32, field_120_u32, field_121_u32, field_122_u32,
                field_123_u32, field_124_u32, field_125_u32, field_126_u32,
                field_127_u32, field_128_u32, field_129_u32, field_130_u32,
                field_131_u32, field_132_u32, field_133_u32, field_134_u32,
                field_135_u32, field_136_u32, field_137_u32, field_138_u32,
                field_139_u32, field_140_u32, field_141_u32, field_142_u32,
                field_143_u32, field_144_u32, field_145_u32, field_146_u32,
                field_147_u32, field_148_u32, field_149_u32, field_150_u32,
                field_151_u32, field_152_u32, field_153_u32, field_154_u32,
                field_155_u32, field_156_u32, field_157_u32, field_158_u32,
                field_159_u32, field_160_u32, field_161_u32, field_162_u32,
                field_163_u32, field_164_u32, field_165_u32, field_166_u32,
                field_167_u32, field_168_u32, field_169_u32, field_170_u32,
                field_171_u32, field_172_u32, field_173_u32, field_174_u32,
                field_175_u32, field_176_u32, field_177_u32, field_178_u32,
                field_179_u32, field_180_u32, field_181_u32,
                field_182_u32, field_183_u32, field_184_u32, field_185_u32,
                field_186_u32, field_187_u32, field_188_u32, field_189_u32,
                field_190_u32, field_191_u32, field_192_u32, field_193_u32,
                field_194_u32, field_195_u32, field_196_u32, field_197_u32,
                field_198_u32, field_199_u32, field_200_u32, field_201_u32,
                field_202_u32, field_203_u32, field_204_u32, field_205_u32,
                field_206_u32, field_207_u32, field_208_u32, field_209_u32,
                field_210_u32, field_211_u32, field_212_u32, field_213_u32,
                field_214_u32, field_215_u32, field_216_u32, field_217_u32,
                field_218_u32, field_219_u32, field_220_u32, field_221_u32,
                field_222_u32, field_223_u32, field_224_u32, field_225_u32,
                field_226_u32, field_227_u32, field_228_u32, field_229_u32,
                field_230_u32, field_231_u32, field_232_u32, field_233_u32,
                field_234_u32, field_235_u32, field_236_u32, field_237_u32,
                field_238_u32, field_239_u32, field_240_u32, field_241_u32,
                field_242_u32, field_243_u32, field_244_u32, field_245_u32,
                field_246_u32, field_247_u32, field_248_u32, field_249_u32,
                field_250_u32, field_251_u32, field_252_u32, field_253_u32,
                field_254_u32, field_255_u32, field_256_u32, field_257_u32,
                field_258_u32, field_259_u32, field_260_u32, field_261_u32,
                field_262_u32, field_263_u32, field_264_u32, field_265_u32,
                field_266_u32, field_267_u32, field_268_u32, field_269_u32,
                field_270_u32, field_271_u32, field_272_u32, field_273_u32,
                field_274_u32, field_275_u32, field_276_u32, field_277_u32,
                field_278_u32, field_279_u32, field_280_u32, field_281_u32,
                field_282_u32, field_283_u32, field_284_u32, field_285_u32,
                field_286_u32, field_287_u32, field_288_u32, field_289_u32,
                field_290_u32, field_291_u32, field_292_u32, field_293_u32,
                field_294_u32, field_295_u32, field_296_u32, field_297_u32,
                field_298_u32, field_299_u32, field_300_u32, field_301_u32,
                field_302_u32, field_303_u32, field_304_u32, field_305_u32,
                field_306_u32, field_307_u32, field_308_u32, field_309_u32,
                field_310_u32, field_311_u32, field_312_u32, field_313_u32,
                field_314_u32, field_315_u32, field_316_u32, field_317_u32,
                field_318_u32, field_319_u32, field_320_u32, field_321_u32,
                field_322_u32, field_323_u32, field_324_u32, field_325_u32,
                field_326_u32, field_327_u32, field_328_u32, field_329_u32,
                field_330_u32, field_331_u32, field_332_u32, field_333_u32,
                field_334_u32, field_335_u32, field_336_u32, field_337_u32,
                field_338_u32, field_339_u32, field_340_u32, field_341_u32,
                field_342_u32_count, field_343_u8_flag, field_344_u32,
                field_345_u32, field_346_u32, field_347_u32, field_348_u32,
                field_349_u32, field_350_u32, field_351_u32, field_352_u32,
                field_353_u32, field_354_u32, field_355_u32, field_356_u32,
                field_357_u32, field_358_u32, field_359_u32, field_360_u32,
                field_361_u32, field_362_u32, field_363_u32, field_364_u32,
                field_365_u32, field_366_u32, field_367_u32, field_368_u32,
                field_369_u32, field_370_u32, field_371_u32, field_372_u32,
                field_373_u32, field_374_u32, field_375_u32, field_376_u32,
                field_377_u32, field_378_u32, field_379_u32, field_380_u32,
                field_381_u32, field_382_u32, field_383_u32, field_384_u32,
                field_385_u32, field_386_u32, field_387_u32, field_388_u32,
                field_389_u32, field_390_u32, field_391_u32, field_392_u32,
                field_393_u32, field_394_u32, field_395_u32, field_396_u32,
                field_397_u32, field_398_u32, field_399_u32, field_400_u32,
                field_401_u32, field_402_u32, field_403_u32, field_404_u32,
                field_405_u32, field_406_u32, field_407_u32, field_408_u32,
                field_409_u32, field_410_u32, field_411_u32, field_412_u32,
                field_413_u32, field_414_u32, field_415_u32, field_416_u32,
                field_417_u32, field_418_u32, field_419_u32, field_420_u32,
                field_421_u32, field_422_u32, field_423_u32, field_424_u32,
                field_425_u32, field_426_u32, field_427_u32, field_428_u32,
                field_429_u32, field_430_u32, field_431_u32, field_432_u32,
                field_433_u32, field_434_u32, field_435_u32, field_436_u32,
                field_437_u32, field_438_u32, field_439_u32, field_440_u32,
                field_441_u32, field_442_u32, field_443_u32, field_444_u32,
                field_445_u32, field_446_u32, field_447_u32, field_448_u32,
                field_449_u32, field_450_u32, field_451_u32, field_452_u32,
                field_453_u32, field_454_u32, field_455_u32, field_456_u32,
                field_457_u32, field_458_u32, field_459_u32, field_460_u32,
                field_461_u32, field_462_u32, field_463_u32, field_464_u32,
                field_465_u32, field_466_u32, field_467_u32, field_468_u32,
                field_469_u32, field_470_u32, field_471_u32, field_472_u32,
                field_473_u32, field_474_u32, field_475_u32, field_476_u32,
                field_477_u32, field_478_u32, field_479_u32, field_480_u32,
                field_481_u32, field_482_u32, field_483_u32, field_484_u32,
                field_485_u32, field_486_u32, field_487_u32, field_488_u32,
                field_489_u32, field_490_u32, field_491_u32, field_492_u32,
                field_493_u32, field_494_u32, field_495_u32, field_496_u32,
                field_497_u32, field_498_u32, field_499_u32, field_500_u32,
                field_501_u32, field_502_u32, field_503_u32, field_504_u32,
                field_505_u32, field_506_u32, field_507_u32, field_508_u32,
                field_509_u32, field_510_u32, field_511_u32, field_512_u32,
                field_513_u32, field_514_u32, field_515_u32, field_516_u32,
                field_517_u32, field_518_u32, field_519_u32, field_520_u32,
                field_521_u32, field_522_u32, field_523_u32, field_524_u32,
                field_525_u32, field_526_u32, field_527_u32, field_528_u32,
                field_529_u32, field_530_u32, field_531_u32, field_532_u32,
                field_533_u32, field_534_u32, field_535_u32, field_536_u32,
                field_537_u32, field_538_u32, field_539_u32, field_540_u32,
                field_541_u32, field_542_u32, field_543_u32, field_544_u32,
                field_545_u32, field_546_u32, field_547_u32, field_548_u32,
                field_549_u32, field_550_u32, field_551_u32, field_552_u32,
                field_553_u32, field_554_u32, field_555_u32, field_556_u32,
                field_557_u32, field_558_u32, field_559_u32, field_560_u32,
                field_561_u32, field_562_u32, field_563_u32, field_564_u32,
                field_565_u32, field_566_u32, field_567_u32, field_568_u32,
                field_569_u32, field_570_u32, field_571_u32, field_572_u32,
                field_573_u32, field_574_u32, field_575_u32, field_576_u32,
                field_577_u32, field_578_u32, field_579_u32, field_580_u32,
                field_581_u32, field_582_u32, field_583_u32, field_584_u32,
                field_585_u32, field_586_u32, field_587_u32, field_588_u32,
                field_589_u32, field_590_u32, field_591_u32, field_592_u32,
                field_593_u32, field_594_u32, field_595_u32, field_596_u32,
                field_597_u32, field_598_u32, field_599_u32, field_600_u32,
                field_601_u32, field_602_u32, field_603_u32, field_604_u32,
                field_605_u32, field_606_u32, field_607_u32, field_608_u32,
                field_609_u32, field_610_u32, field_611_u32, field_612_u32,
                field_613_u32, field_614_u32, field_615_u32, field_616_u32,
                field_617_u32, field_618_u32, field_619_u32, field_620_u32,
                field_621_u32, field_622_u32, field_623_u32, field_624_u32,
                field_625_u32, field_626_u32, field_627_u32, field_628_u32,
                field_629_u32, field_630_u32, field_631_u32, field_632_u32,
                field_633_u32, field_634_u32, field_635_u32, field_636_u32,
                field_637_u32, field_638_u32, field_639_u32, field_640_u32,
                field_641_u32, field_642_u32, field_643_u32, field_644_u32,
                field_645_u32, field_646_u32, field_647_u32, field_648_u32,
                field_649_u32, field_650_u32, field_651_u32, field_652_u32,
                field_653_u32, field_654_u32, field_655_u32, field_656_u32,
                field_657_u32, field_658_u32, field_659_u32, field_660_u32,
                field_661_u32, field_662_u32, field_663_u32, field_664_u32,
                alt_trigger_count, alt_trigger_flag, alt_trigger_name,
                alt_inner_count, alt_inner_name, alt_inner_flag,
                alt_body_001, alt_body_002, alt_body_003, alt_body_004,
                alt_body_005, alt_body_006, alt_body_007, alt_body_008,
                alt_body_009, alt_body_010, alt_body_011, alt_body_012,
                alt_body_013, alt_body_014, alt_body_015, alt_body_016,
                alt_body_017, alt_body_018, alt_body_019, alt_body_020,
                alt_body_021, alt_body_022, alt_body_023, alt_body_024,
                alt_body_025, alt_body_026, alt_body_027, alt_body_028,
                alt_body_029, alt_body_030, alt_body_031, alt_body_032,
                alt_body_033, alt_body_034, alt_body_035, alt_body_036,
                alt_body_037, alt_body_038, alt_body_039, alt_body_040,
                alt_body_041, alt_body_042, alt_body_043, alt_body_044,
                alt_body_045, alt_body_046, alt_body_047, alt_body_048,
                alt_body_049, alt_body_050, alt_body_051, alt_body_052,
                alt_body_053, alt_body_054, alt_body_055, alt_body_056,
                alt_body_057, alt_body_058, alt_body_059, alt_body_060,
                alt_body_061, alt_body_062, alt_body_063, alt_body_064,
                alt_body_065, alt_body_066, alt_body_067, alt_body_068,
                alt_body_069, alt_body_070, alt_body_071, alt_body_072,
                alt_body_073, alt_body_074, alt_body_075, alt_body_076,
                alt_body_077, alt_body_078, alt_body_079, alt_body_080,
                alt_body_081, alt_body_082, alt_body_083, alt_body_084,
                alt_body_085, alt_body_086, alt_body_087, alt_body_088,
                alt_body_089, alt_body_090, alt_body_091, alt_body_092,
                alt_body_093, alt_body_094, alt_body_095, alt_body_096,
                alt_body_097, alt_body_098, alt_body_099, alt_body_100,
                alt_body_101, alt_body_102, alt_body_103, alt_body_104,
                alt_body_105, alt_body_106, alt_body_107, alt_body_108,
                alt_body_109, alt_body_110, alt_body_111, alt_body_112,
                alt_body_113, alt_body_114, alt_body_115, alt_body_116,
                alt_body_117, alt_body_118, alt_body_119, alt_body_120,
                alt_body_121, alt_body_122, alt_body_123, alt_body_124,
                alt_body_125, alt_body_126, alt_body_127, alt_body_128,
                alt_body_129, alt_body_130, alt_body_131, alt_body_132,
                alt_body_133, alt_body_134, alt_body_135, alt_body_136,
                alt_body_137, alt_body_138, alt_body_139, alt_body_140,
                alt_body_141, alt_body_142, alt_body_143, alt_body_144,
                alt_body_145, alt_body_146, alt_body_147, alt_body_148,
                alt_body_149, alt_body_150, alt_body_151, alt_body_152,
                alt_body_153, alt_body_154, alt_body_155, alt_body_156,
                alt_body_157, alt_body_158, alt_body_159, alt_body_160,
                alt_body_161, alt_body_162, alt_body_163, alt_body_164,
                alt_body_165, alt_body_166, alt_body_167, alt_body_168,
                alt_body_169, alt_body_170, alt_body_171, alt_body_172,
                alt_body_173, alt_body_174, alt_body_175, alt_body_176,
                alt_body_177, alt_body_178, alt_body_179, alt_body_180,
                alt_body_181, alt_body_182, alt_body_183, alt_body_184,
                alt_body_185, alt_body_186, alt_body_187, alt_body_188,
                alt_body_189, alt_body_190, alt_body_191, alt_body_192,
                alt_body_193, alt_body_194, alt_body_195, alt_body_196,
                alt_body_197, alt_body_198, alt_body_199, alt_body_200,
                alt_body_201, alt_body_202, alt_body_203, alt_body_204,
                alt_body_205, alt_body_206, alt_body_207, alt_body_208,
                alt_body_209, alt_body_210, alt_body_211, alt_body_212,
                alt_body_213, alt_body_214, alt_body_215, alt_body_216,
                alt_body_217, alt_body_218, alt_body_219, alt_body_220,
                alt_body_221, alt_body_222, alt_body_223, alt_body_224,
                alt_body_225, alt_body_226, alt_body_227, alt_body_228,
                alt_body_229, alt_body_230, alt_body_231, alt_body_232,
                alt_body_233, alt_body_234, alt_body_235, alt_body_236,
                alt_body_237, alt_body_238, alt_body_239, alt_body_240,
                alt_body_241, alt_body_242, alt_body_243, alt_body_244,
                alt_body_245, alt_body_246, alt_body_247, alt_body_248,
                alt_body_249, alt_body_250, alt_body_251, alt_body_252,
                alt_body_253, alt_body_254, alt_body_255, alt_body_256,
                alt_body_257, alt_body_258, alt_body_259, alt_body_260,
                alt_body_261, alt_body_262, alt_body_263, alt_body_264,
                alt_body_265, alt_body_266, alt_body_267, alt_body_268,
                alt_body_269, alt_body_270, alt_body_271, alt_body_272,
                alt_body_273, alt_body_274, alt_body_275, alt_body_276,
                alt_body_277, alt_body_278, alt_body_279, alt_body_280,
                alt_body_281, alt_body_282, alt_body_283, alt_body_284,
                alt_body_285, alt_body_286, alt_body_287, alt_body_288,
                alt_body_289, alt_body_290, alt_body_291, alt_body_292,
                alt_body_293, alt_body_294, alt_body_295, alt_body_296,
                alt_body_297, alt_body_298, alt_body_299, alt_body_300,
                alt_body_301, alt_body_302, alt_body_303, alt_body_304,
                alt_body_305, alt_body_306, alt_body_307, alt_body_308,
                alt_body_309, alt_body_310, alt_body_311, alt_body_312,
                alt_body_313, alt_body_314, alt_body_315, alt_body_316,
                alt_body_317, alt_body_318, alt_body_319, alt_body_320,
                alt_body_321, alt_body_322, alt_body_323, alt_body_324,
                alt_body_325, alt_body_326, alt_body_327, alt_body_328,
                alt_body_329, alt_body_330, alt_body_331, alt_body_332,
                alt_body_333, alt_body_334, alt_body_335, alt_body_336,
                alt_body_337, alt_body_338, alt_body_339, alt_body_340,
                alt_body_341, alt_body_342, alt_body_343, alt_body_344,
                alt_body_345, alt_body_346, alt_body_347, alt_body_348,
                alt_body_349, alt_body_350, alt_body_351, alt_body_352,
                alt_body_353, alt_body_354, alt_body_355, alt_body_356,
                alt_body_357, alt_body_358, alt_body_359, alt_body_360,
                alt_body_361, alt_body_362, alt_body_363, alt_body_364,
                alt_body_365, alt_body_366, alt_body_367, alt_body_368,
                alt_body_369, alt_body_370, alt_body_371, alt_body_372,
                alt_body_373, alt_body_374, alt_body_375, alt_body_376,
                alt_body_377, alt_body_378, alt_body_379, alt_body_380,
                alt_body_381, alt_body_382, alt_body_383, alt_body_384,
                alt_body_385, alt_body_386, alt_body_387, alt_body_388,
                alt_body_389, alt_body_390, alt_body_391, alt_body_392,
                alt_body_393, alt_body_394, alt_body_395, alt_body_396,
                alt_body_397, alt_body_398, alt_body_399, alt_body_400,
                alt_body_401, alt_body_402, alt_body_403, alt_body_404,
                alt_body_405, alt_body_406, alt_body_407, alt_body_408,
                alt_body_409, alt_body_410, alt_body_411, alt_body_412,
                alt_body_413, alt_body_414, alt_body_415, alt_body_416,
                alt_body_417, alt_body_418, alt_body_419, alt_body_420,
                alt_body_421, alt_body_422, alt_body_423, alt_body_424,
                alt_body_425, alt_body_426, alt_body_427, alt_body_428,
                alt_body_429, alt_body_430, alt_body_431, alt_body_432,
                alt_body_433, alt_body_434, alt_body_435, alt_body_436,
                alt_body_437, alt_body_438, alt_body_439, alt_body_440,
                alt_body_441, alt_body_442, alt_body_443, alt_body_444,
                alt_body_445, alt_body_446, alt_body_447, alt_body_448,
                alt_body_449, alt_body_450, alt_body_451, alt_body_452,
                alt_body_453, alt_body_454, alt_body_455, alt_body_456,
                alt_body_457, alt_body_458, alt_body_459, alt_body_460,
                alt_body_461, alt_body_462, alt_body_463, alt_body_464,
                alt_body_465, alt_body_466, alt_body_467, alt_body_468,
                alt_body_469, alt_body_470, alt_body_471, alt_body_472,
                alt_body_473, alt_body_474, alt_body_475, alt_body_476,
                alt_body_477, alt_body_478, alt_body_479, alt_body_480,
                alt_body_481, alt_body_482, alt_body_483, alt_body_484,
                alt_body_485, alt_body_486, alt_body_487, alt_body_488,
                alt_body_489, alt_body_490, alt_body_491, alt_body_492,
                alt_body_493, alt_body_494, alt_body_495, alt_body_496,
                alt_body_497, alt_body_498, alt_body_499, alt_body_500,
                alt_body_501, alt_body_502, alt_body_503, alt_body_504,
                alt_body_505, alt_body_506, alt_body_507, alt_body_508,
                alt_body_509, alt_body_510, alt_body_511, alt_body_512,
                alt_body_513, alt_body_514, alt_body_515, alt_body_516,
                alt_body_517, alt_body_518, alt_body_519, alt_body_520,
                alt_body_521, alt_body_522, alt_body_523, alt_body_524,
                alt_body_525, alt_body_526, alt_body_527, alt_body_528,
                alt_body_529, alt_body_530, alt_body_531, alt_body_532,
                alt_body_533, alt_body_534, alt_body_535, alt_body_536,
                alt_body_537, alt_body_538, alt_body_539, alt_body_540,
                alt_body_541, alt_body_542, alt_body_543, alt_body_544,
                alt_body_545, alt_body_546, alt_body_547, alt_body_548,
                alt_body_549, alt_body_550, alt_body_551, alt_body_552,
                alt_body_553, alt_body_554, alt_body_555, alt_body_556,
                alt_body_557, alt_body_558, alt_body_559, alt_body_560,
                alt_body_561, alt_body_562, alt_body_563, alt_body_564,
                alt_body_565, alt_body_566, alt_body_567, alt_body_568,
                alt_body_569, alt_body_570, alt_body_571, alt_body_572,
                alt_body_573, alt_body_574, alt_body_575, alt_body_576,
                alt_body_577, alt_body_578, alt_body_579, alt_body_580,
                alt_body_581, alt_body_582, alt_body_583, alt_body_584,
                alt_body_585, alt_body_586, alt_body_587, alt_body_588,
                alt_body_589, alt_body_590, alt_body_591, alt_body_592,
                alt_body_593, alt_body_594, alt_body_595, alt_body_596,
                alt_body_597, alt_body_598, alt_body_599, alt_body_600,
                alt_body_601, alt_body_602, alt_body_603, alt_body_604,
                alt_body_605, alt_body_606, alt_body_607, alt_body_608,
                alt_body_609, alt_body_610, alt_body_611, alt_body_612,
                alt_body_613, alt_body_614, alt_body_615, alt_body_616,
                alt_body_617, alt_body_618, alt_body_619, alt_body_620,
                alt_body_621, alt_body_622, alt_body_623, alt_body_624,
                alt_body_625, alt_body_626, alt_body_627, alt_body_628,
                alt_body_629, alt_body_630, alt_body_631, alt_body_632,
                alt_body_633, alt_body_634, alt_body_635, alt_body_636,
                alt_body_637, alt_body_638, alt_body_639, alt_body_640,
                alt_body_641, alt_body_642, alt_body_643, alt_body_644,
                alt_body_645, alt_body_646, alt_body_647, alt_body_648,
                alt_body_649, alt_body_650, alt_body_651, alt_body_652,
                alt_body_653, alt_body_654, alt_body_655, alt_body_656,
                alt_body_657, alt_body_658, alt_body_659, alt_body_660,
                alt_body_661, alt_body_662, alt_body_663, alt_body_664,
                alt_body_665, alt_body_666, alt_body_667, alt_body_668,
                alt_body_669, alt_body_670, alt_body_671, alt_body_672,
                alt_body_673, alt_body_674, alt_body_675, alt_body_676,
                alt_body_677, alt_body_678, alt_body_679, alt_body_680,
                alt_body_681, alt_body_682, alt_body_683, alt_body_684,
                alt_body_685, alt_body_686, alt_body_687, alt_body_688,
                alt_body_689, alt_body_690, alt_body_691, alt_body_692,
                alt_body_693, alt_body_694, alt_body_695, alt_body_696,
                alt_body_697, alt_body_698, alt_body_699, alt_body_700,
                alt_body_701, alt_body_702, alt_body_703, alt_body_704,
                alt_body_705, alt_body_706, alt_body_707, alt_body_708,
                alt_body_709, alt_body_710, alt_body_711, alt_body_712,
                alt_body_713, alt_body_714, alt_body_715, alt_body_716,
                alt_body_717, alt_body_718, alt_body_719, alt_body_720,
                alt_body_721, alt_body_722, alt_body_723, alt_body_724,
                alt_body_725, alt_body_726, alt_body_727, alt_body_728,
                alt_body_729, alt_body_730, alt_body_731, alt_body_732,
                alt_body_733, alt_body_734, alt_body_735, alt_body_736,
                alt_body_737, alt_body_738, alt_body_739, alt_body_740,
                alt_body_741, alt_body_742, alt_body_743, alt_body_744,
                alt_body_745, alt_body_746, alt_body_747, alt_body_748,
                alt_body_749, alt_body_750, alt_body_751, alt_body_752,
                alt_body_753, alt_body_754, alt_body_755, alt_body_756,
                alt_body_757, alt_body_758, alt_body_759, alt_body_760,
                alt_body_761, alt_body_762, alt_body_763, alt_body_764,
                alt_body_765, alt_body_766, alt_body_767, alt_body_768,
                alt_body_769, alt_body_770, alt_body_771, alt_body_772,
                alt_body_773, alt_body_774, alt_body_775, alt_body_776,
                alt_body_777, alt_body_778, alt_body_779, alt_body_780,
                alt_body_781, alt_body_782, alt_body_783, alt_body_784,
                alt_body_785, alt_body_786, alt_body_787, alt_body_788,
                alt_body_789, alt_body_790, alt_body_791, alt_body_792,
                alt_body_793, alt_body_794, alt_body_795, alt_body_796,
                alt_body_797, alt_body_798, alt_body_799, alt_body_800,
                alt_body_801, alt_body_802, alt_body_803, alt_body_804,
                alt_body_805, alt_body_806, alt_body_807, alt_body_808,
                alt_body_809, alt_body_810, alt_body_811, alt_body_812,
                alt_body_813, alt_body_814, alt_body_815, alt_body_816,
                alt_body_817, alt_body_818, alt_body_819, alt_body_820,
                alt_body_821, alt_body_822, alt_body_823, alt_body_824,
                alt_body_825, alt_body_826, alt_body_827, alt_body_828,
                alt_body_829, alt_body_830, alt_body_831, alt_body_832,
                alt_body_833, alt_body_834, alt_body_835, alt_body_836,
                alt_body_837, alt_body_838, alt_body_839, alt_body_840,
                alt_body_841, alt_body_842, alt_body_843, alt_body_844,
                alt_body_845, alt_body_846, alt_body_847, alt_body_848,
                alt_body_849, alt_body_850, alt_body_851, alt_body_852,
                alt_body_853, alt_body_854, alt_body_855, alt_body_856,
                alt_body_857, alt_body_858, alt_body_859, alt_body_860,
                alt_body_861, alt_body_862, alt_body_863, alt_body_864,
                alt_body_865, alt_body_866, alt_body_867, alt_body_868,
                alt_body_869, alt_body_870, alt_body_871, alt_body_872,
                alt_body_873, alt_body_874, alt_body_875, alt_body_876,
                alt_body_877, alt_body_878, alt_body_879, alt_body_880,
                alt_body_881, alt_body_882, alt_body_883, alt_body_884,
                alt_body_885, alt_body_886, alt_body_887, alt_body_888,
                alt_body_889, alt_body_890, alt_body_891, alt_body_892,
                alt_body_893, alt_body_894, alt_body_895, alt_body_896,
                alt_body_897, alt_body_898, alt_body_899, alt_body_900,
                alt_body_901, alt_body_902, alt_body_903, alt_body_904,
                alt_body_905, alt_body_906, alt_body_907, alt_body_908,
                alt_body_909, alt_body_910, alt_body_911, alt_body_912,
                alt_body_913, alt_body_914, alt_body_915, alt_body_916,
                alt_body_917, alt_body_918, alt_body_919, alt_body_920,
                alt_body_921, alt_body_922, alt_body_923, alt_body_924,
                alt_body_925, alt_body_926, alt_body_927, alt_body_928,
                alt_body_929, alt_body_930, alt_body_931, alt_body_932,
                alt_body_933, alt_body_934, alt_body_935, alt_body_936,
                alt_body_937, alt_body_938, alt_body_939, alt_body_940,
                alt_body_941, alt_body_942, alt_body_943, alt_body_944,
                alt_body_945, alt_body_946, alt_body_947, alt_body_948,
                alt_body_949, alt_body_950, alt_body_951, alt_body_952,
                alt_body_953, alt_body_954, alt_body_955, alt_body_956,
                alt_body_957, alt_body_958, alt_body_959, alt_body_960,
                alt_body_961, alt_body_962, alt_body_963, alt_body_964,
                alt_body_965, alt_body_966, alt_body_967, alt_body_968,
                alt_body_969, alt_body_970, alt_body_971, alt_body_972,
                alt_body_973, alt_body_974, alt_body_975, alt_body_976,
                alt_body_977, alt_body_978, alt_body_979, alt_body_980,
                alt_body_981, alt_body_982, alt_body_983, alt_body_984,
                alt_body_985, alt_body_986, alt_body_987, alt_body_988,
                alt_body_989, alt_body_990, alt_body_991, alt_body_992,
                alt_body_993, alt_body_994, alt_body_995, alt_body_996,
                alt_body_997, alt_body_998, alt_body_999, alt_body_1000,
                alt_body_1001, alt_body_1002, alt_body_1003, alt_body_1004,
                alt_body_1005, alt_body_1006, alt_body_1007, alt_body_1008,
                alt_body_1009, alt_body_1010, alt_body_1011, alt_body_1012,
                alt_body_1013, alt_body_1014, alt_body_1015, alt_body_1016,
                alt_body_1017, alt_body_1018, alt_body_1019, alt_body_1020,
                alt_body_1021, alt_body_1022, alt_body_1023, alt_body_1024,
                alt_body_1025, alt_body_1026, alt_body_1027, alt_body_1028,
                alt_body_1029, alt_body_1030, alt_body_1031, alt_body_1032,
                alt_body_1033, alt_body_1034, alt_body_1035, alt_body_1036,
                alt_body_1037, alt_body_1038, alt_body_1039, alt_body_1040,
                alt_body_1041, alt_body_1042, alt_body_1043, alt_body_1044,
                alt_body_1045, alt_body_1046, alt_body_1047, alt_body_1048,
                alt_body_1049, alt_body_1050, alt_body_1051, alt_body_1052,
                alt_body_1053, alt_body_1054, alt_body_1055, alt_body_1056,
                alt_body_1057, alt_body_1058, alt_body_1059, alt_body_1060,
                alt_body_1061, alt_body_1062, alt_body_1063, alt_body_1064,
                alt_body_1065, alt_body_1066, alt_body_1067, alt_body_1068,
                alt_body_1069, alt_body_1070, alt_body_1071, alt_body_1072,
                alt_body_1073, alt_body_1074, alt_body_1075, alt_body_1076,
                alt_body_1077, alt_body_1078, alt_body_1079, alt_body_1080,
                alt_body_1081, alt_body_1082, alt_body_1083, alt_body_1084,
                alt_body_1085, alt_body_1086, alt_body_1087, alt_body_1088,
                alt_body_1089, alt_body_1090, alt_body_1091, alt_body_1092,
                alt_body_1093, alt_body_1094, alt_body_1095, alt_body_1096,
                alt_body_1097, alt_body_1098, alt_body_1099, alt_body_1100,
                alt_body_1101, alt_body_1102, alt_body_1103, alt_body_1104,
                alt_body_1105, alt_body_1106, alt_body_1107, alt_body_1108,
                alt_body_1109, alt_body_1110, alt_body_1111, alt_body_1112,
                alt_body_1113, alt_body_1114, alt_body_1115, alt_body_1116,
                alt_body_1117, alt_body_1118, alt_body_1119, alt_body_1120,
                alt_body_1121, alt_body_1122, alt_body_1123, alt_body_1124,
                alt_body_1125, alt_body_1126, alt_body_1127, alt_body_1128,
                alt_body_1129, alt_body_1130, alt_body_1131, alt_body_1132,
                alt_body_1133, alt_body_1134, alt_body_1135, alt_body_1136,
                alt_body_1137, alt_body_1138, alt_body_1139, alt_body_1140,
                alt_body_1141, alt_body_1142, alt_body_1143, alt_body_1144,
                alt_body_1145, alt_body_1146, alt_body_1147, alt_body_1148,
                alt_body_1149, alt_body_1150, alt_body_1151, alt_body_1152,
                alt_body_1153, alt_body_1154, alt_body_1155, alt_body_1156,
                alt_body_1157, alt_body_1158, alt_body_1159, alt_body_1160,
                alt_body_1161, alt_body_1162, alt_body_1163, alt_body_1164,
                alt_body_1165, alt_body_1166, alt_body_1167, alt_body_1168,
                alt_body_1169, alt_body_1170, alt_body_1171, alt_body_1172,
                alt_body_1173, alt_body_1174, alt_body_1175, alt_body_1176,
                alt_body_1177, alt_body_1178, alt_body_1179, alt_body_1180,
                alt_body_1181, alt_body_1182, alt_body_1183, alt_body_1184,
                alt_body_1185, alt_body_1186, alt_body_1187, alt_body_1188,
                alt_body_1189, alt_body_1190, alt_body_1191, alt_body_1192,
                alt_body_1193, alt_body_1194, alt_body_1195, alt_body_1196,
                alt_body_1197, alt_body_1198, alt_body_1199, alt_body_1200,
                alt_body_1201, alt_body_1202, alt_body_1203, alt_body_1204,
                alt_body_1205, alt_body_1206, alt_body_1207, alt_body_1208,
                alt_body_1209, alt_body_1210, alt_body_1211, alt_body_1212,
                alt_body_1213, alt_body_1214, alt_body_1215, alt_body_1216,
                alt_body_1217, alt_body_1218, alt_body_1219, alt_body_1220,
                alt_body_1221, alt_body_1222, alt_body_1223, alt_body_1224,
                alt_body_1225, alt_body_1226, alt_body_1227, alt_body_1228,
                alt_body_1229, alt_body_1230, alt_body_1231, alt_body_1232,
                alt_body_1233, alt_body_1234, alt_body_1235, alt_body_1236,
                alt_body_1237, alt_body_1238, alt_body_1239, alt_body_1240,
                alt_body_1241, alt_body_1242, alt_body_1243, alt_body_1244,
                alt_body_1245, alt_body_1246, alt_body_1247, alt_body_1248,
                alt_body_1249, alt_body_1250, alt_body_1251, alt_body_1252,
                alt_body_1253, alt_body_1254, alt_body_1255, alt_body_1256,
                alt_body_1257, alt_body_1258, alt_body_1259, alt_body_1260,
                alt_body_1261, alt_body_1262, alt_body_1263, alt_body_1264,
                alt_body_1265, alt_body_1266, alt_body_1267, alt_body_1268,
                alt_body_1269, alt_body_1270, alt_body_1271, alt_body_1272,
                alt_body_1273, alt_body_1274, alt_body_1275, alt_body_1276,
                alt_body_1277, alt_body_1278, alt_body_1279, alt_body_1280,
                alt_body_1281, alt_body_1282, alt_body_1283, alt_body_1284,
                alt_body_1285, alt_body_1286, alt_body_1287, alt_body_1288,
                alt_body_1289, alt_body_1290, alt_body_1291, alt_body_1292,
                alt_body_1293, alt_body_1294, alt_body_1295, alt_body_1296,
                alt_body_1297, alt_body_1298, alt_body_1299, alt_body_1300,
                alt_body_1301, alt_body_1302, alt_body_1303, alt_body_1304,
                alt_body_1305, alt_body_1306, alt_body_1307, alt_body_1308,
                alt_body_1309, alt_body_1310, alt_body_1311, alt_body_1312,
                alt_body_1313, alt_body_1314, alt_body_1315, alt_body_1316,
                alt_body_1317, alt_body_1318, alt_body_1319, alt_body_1320,
                alt_body_1321, alt_body_1322, alt_body_1323, alt_body_1324,
                alt_body_1325, alt_body_1326, alt_body_1327, alt_body_1328,
                alt_body_1329, alt_body_1330, alt_body_1331, alt_body_1332,
                alt_body_1333, alt_body_1334, alt_body_1335, alt_body_1336,
                alt_body_1337, alt_body_1338, alt_body_1339, alt_body_1340,
                alt_body_1341, alt_body_1342, alt_body_1343, alt_body_1344,
                alt_body_1345, alt_body_1346, alt_body_1347, alt_body_1348,
                alt_body_1349, alt_body_1350, alt_body_1351, alt_body_1352,
                alt_body_1353, alt_body_1354, alt_body_1355, alt_body_1356,
                alt_body_1357, alt_body_1358, alt_body_1359, alt_body_1360,
                alt_body_1361, alt_body_1362, alt_body_1363, alt_body_1364,
                alt_body_1365, alt_body_1366, alt_body_1367, alt_body_1368,
                alt_body_1369, alt_body_1370, alt_body_1371, alt_body_1372,
                alt_body_1373, alt_body_1374, alt_body_1375, alt_body_1376,
                alt_body_1377, alt_body_1378, alt_body_1379, alt_body_1380,
                alt_body_1381, alt_body_1382, alt_body_1383, alt_body_1384,
                alt_body_1385, alt_body_1386, alt_body_1387, alt_body_1388,
                alt_body_1389, alt_body_1390, alt_body_1391, alt_body_1392,
                alt_body_1393, alt_body_1394, alt_body_1395, alt_body_1396,
                alt_body_1397, alt_body_1398, alt_body_1399, alt_body_1400,
                alt_body_1401, alt_body_1402, alt_body_1403, alt_body_1404,
                alt_body_1405, alt_body_1406, alt_body_1407, alt_body_1408,
                alt_body_1409, alt_body_1410, alt_body_1411, alt_body_1412,
                alt_body_1413, alt_body_1414, alt_body_1415, alt_body_1416,
                alt_body_1417, alt_body_1418, alt_body_1419, alt_body_1420,
                alt_body_1421, alt_body_1422, alt_body_1423, alt_body_1424,
                alt_body_1425, alt_body_1426, alt_body_1427, alt_body_1428,
                alt_body_1429, alt_body_1430, alt_body_1431, alt_body_1432,
                alt_body_1433, alt_body_1434, alt_body_1435, alt_body_1436,
                alt_body_1437, alt_body_1438, alt_body_1439, alt_body_1440,
                alt_body_1441, alt_body_1442, alt_body_1443, alt_body_1444,
                alt_body_1445, alt_body_1446, alt_body_1447, alt_body_1448,
                alt_body_1449, alt_body_1450, alt_body_1451, alt_body_1452,
                alt_body_1453, alt_body_1454, alt_body_1455, alt_body_1456,
                alt_body_1457, alt_body_1458, alt_body_1459, alt_body_1460,
                alt_body_1461, alt_body_1462, alt_body_1463, alt_body_1464,
                alt_body_1465, alt_body_1466, alt_body_1467, alt_body_1468,
                alt_body_1469, alt_body_1470, alt_body_1471, alt_body_1472,
                alt_body_1473, alt_body_1474, alt_body_1475, alt_body_1476,
                alt_body_1477, alt_body_1478, alt_body_1479, alt_body_1480,
                alt_body_1481, alt_body_1482, alt_body_1483, alt_body_1484,
                alt_body_1485, alt_body_1486, alt_body_1487, alt_body_1488,
                alt_body_1489, alt_body_1490, alt_body_1491, alt_body_1492,
                alt_body_1493, alt_body_1494, alt_body_1495, alt_body_1496,
                alt_body_1497, alt_body_1498, alt_body_1499, alt_body_1500,
                alt_body_1501, alt_body_1502, alt_body_1503, alt_body_1504,
                alt_body_1505, alt_body_1506, alt_body_1507, alt_body_1508,
                alt_body_1509, alt_body_1510, alt_body_1511, alt_body_1512,
                alt_body_1513, alt_body_1514, alt_body_1515, alt_body_1516,
                alt_body_1517, alt_body_1518, alt_body_1519, alt_body_1520,
                alt_body_1521, alt_body_1522, alt_body_1523, alt_body_1524,
                alt_body_1525, alt_body_1526, alt_body_1527, alt_body_1528,
                alt_body_1529, alt_body_1530, alt_body_1531, alt_body_1532,
                alt_body_1533, alt_body_1534, alt_body_1535, alt_body_1536,
                alt_post_cstr_a, alt_post_cstr_b,
                field_665_u32, field_666_u32, field_667_u32, field_668_u32,
                field_669_u32, field_670_u32, field_671_u32, field_672_u32,
                field_673_u32, field_674_u32, field_675_u32, field_676_u32,
                field_677_u32, field_678_u32, field_679_u32, field_680_u32,
                field_681_u32, field_682_u32, field_683_u32, field_684_u32,
                field_685_u32, field_686_u32, field_687_u32, field_688_u32,
                field_689_u32, field_690_u32, field_691_u32, field_692_u32,
                field_693_u32, field_694_u32, field_695_u32, field_696_u32,
                field_697_u32, field_698_u32, field_699_u32, field_700_u32,
                field_701_u32, field_702_u32, field_703_u32, field_704_u32,
                field_705_u32, field_706_u32, field_707_u32, field_708_u32,
                field_709_u32, field_710_u32, field_711_u32, field_712_u32,
                field_713_u32, field_714_u32, field_715_u32, field_716_u32,
                field_717_u32, field_718_u32, field_719_u32, field_720_u32,
                field_721_u32, field_722_u32, field_723_u32, field_724_u32,
                field_725_u32, field_726_u32, field_727_u32, field_728_u32,
                tail_pad_001, tail_pad_002, tail_pad_003, tail_pad_004,
                post_blob } => {
                let mut m = Map::new();
                m.insert("kind".to_string(), Value::String("Decoded".to_string()));
                m.insert("gimmick_interaction_override_list".to_string(),
                         gimmick_interaction_override_list.to_json_value());
                m.insert("use_interaction_ui_socket".to_string(), use_interaction_ui_socket.to_json_value());
                m.insert("use_sub_part_for_interaction".to_string(), use_sub_part_for_interaction.to_json_value());
                m.insert("property_list".to_string(), property_list.to_json_value());
                m.insert("gimmick_name_hash".to_string(), gimmick_name_hash.to_json_value());
                m.insert("gimmick_name".to_string(), gimmick_name.to_json_value());
                m.insert("emoji_texture_id".to_string(), emoji_texture_id.to_json_value());
                m.insert("dev_memo".to_string(), dev_memo.to_json_value());
                m.insert("hash_pair_list".to_string(), hash_pair_list.to_json_value());
                m.insert("hash_single_list".to_string(), hash_single_list.to_json_value());
                m.insert("trigger_event_handler_list".to_string(), match trigger_event_handler_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("gimmick_chart_parameter_list".to_string(), match gimmick_chart_parameter_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_19_u32_list".to_string(), match field_19_u32_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_20_u32_list".to_string(), match field_20_u32_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_21_u32_list".to_string(), match field_21_u32_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_22_u32_list".to_string(), match field_22_u32_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_23_u32_list".to_string(), match field_23_u32_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_24_u32_list".to_string(), match field_24_u32_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_24_emissive_flag_a".to_string(), match field_24_emissive_flag_a {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_24_emissive_value_a".to_string(), match field_24_emissive_value_a {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_24_emissive_flag_b".to_string(), match field_24_emissive_flag_b {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_24_emissive_name".to_string(), match field_24_emissive_name {
                    Some(s) => s.to_json_value(), None => Value::Null });
                m.insert("field_24_emissive_value_b".to_string(), match field_24_emissive_value_b {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_25_u32_list".to_string(), match field_25_u32_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_26_u32".to_string(), match field_26_u32 {
                    Some(v) => v.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_27_u32_list".to_string(), match field_27_u32_list {
                    Some(arr) => arr.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_28_u32".to_string(), match field_28_u32 {
                    Some(v) => v.to_json_value(),
                    None => Value::Null,
                });
                m.insert("field_29_u32_list".to_string(), match field_29_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_30_u32_list".to_string(), match field_30_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_31_u32_list".to_string(), match field_31_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                for (k, v) in [
                    ("f31_alt_001", f31_alt_001), ("f31_alt_002", f31_alt_002),
                    ("f31_alt_003", f31_alt_003), ("f31_alt_004", f31_alt_004),
                    ("f31_alt_005", f31_alt_005), ("f31_alt_006", f31_alt_006),
                    ("f31_alt_007", f31_alt_007), ("f31_alt_008", f31_alt_008),
                    ("f31_alt_009", f31_alt_009), ("f31_alt_010", f31_alt_010),
                    ("f31_alt_011", f31_alt_011), ("f31_alt_012", f31_alt_012),
                    ("f31_alt_013", f31_alt_013), ("f31_alt_014", f31_alt_014),
                    ("f31_alt_015", f31_alt_015), ("f31_alt_016", f31_alt_016),
                    ("f31_alt_017", f31_alt_017), ("f31_alt_018", f31_alt_018),
                    ("f31_alt_019", f31_alt_019), ("f31_alt_020", f31_alt_020),
                    ("f31_alt_021", f31_alt_021), ("f31_alt_022", f31_alt_022),
                    ("f31_alt_023", f31_alt_023), ("f31_alt_024", f31_alt_024),
                    ("f31_alt_025", f31_alt_025), ("f31_alt_026", f31_alt_026),
                    ("f31_alt_027", f31_alt_027), ("f31_alt_028", f31_alt_028),
                    ("f31_alt_029", f31_alt_029), ("f31_alt_030", f31_alt_030),
                    ("f31_alt_031", f31_alt_031), ("f31_alt_032", f31_alt_032),
                    ("f31_alt_033", f31_alt_033), ("f31_alt_034", f31_alt_034),
                    ("f31_alt_035", f31_alt_035), ("f31_alt_036", f31_alt_036),
                    ("f31_alt_037", f31_alt_037), ("f31_alt_038", f31_alt_038),
                    ("f31_alt_039", f31_alt_039), ("f31_alt_040", f31_alt_040),
                    ("f31_alt_041", f31_alt_041), ("f31_alt_042", f31_alt_042),
                    ("f31_alt_043", f31_alt_043), ("f31_alt_044", f31_alt_044),
                    ("f31_alt_045", f31_alt_045), ("f31_alt_046", f31_alt_046),
                    ("f31_alt_047", f31_alt_047), ("f31_alt_048", f31_alt_048),
                    ("f31_alt_049", f31_alt_049), ("f31_alt_050", f31_alt_050),
                    ("f31_alt_051", f31_alt_051), ("f31_alt_052", f31_alt_052),
                    ("f31_alt_053", f31_alt_053), ("f31_alt_054", f31_alt_054),
                    ("f31_alt_055", f31_alt_055), ("f31_alt_056", f31_alt_056),
                    ("f31_alt_057", f31_alt_057), ("f31_alt_058", f31_alt_058),
                    ("f31_alt_059", f31_alt_059), ("f31_alt_060", f31_alt_060),
                    ("f31_alt_061", f31_alt_061), ("f31_alt_062", f31_alt_062),
                    ("f31_alt_063", f31_alt_063), ("f31_alt_064", f31_alt_064),
                    ("f31_alt_065", f31_alt_065), ("f31_alt_066", f31_alt_066),
                    ("f31_alt_067", f31_alt_067), ("f31_alt_068", f31_alt_068),
                    ("f31_alt_069", f31_alt_069), ("f31_alt_070", f31_alt_070),
                    ("f31_alt_071", f31_alt_071), ("f31_alt_072", f31_alt_072),
                    ("f31_alt_073", f31_alt_073), ("f31_alt_074", f31_alt_074),
                    ("f31_alt_075", f31_alt_075), ("f31_alt_076", f31_alt_076),
                    ("f31_alt_077", f31_alt_077), ("f31_alt_078", f31_alt_078),
                    ("f31_alt_079", f31_alt_079), ("f31_alt_080", f31_alt_080),
                    ("f31_alt_081", f31_alt_081), ("f31_alt_082", f31_alt_082),
                    ("f31_alt_083", f31_alt_083), ("f31_alt_084", f31_alt_084),
                    ("f31_alt_085", f31_alt_085), ("f31_alt_086", f31_alt_086),
                    ("f31_alt_087", f31_alt_087), ("f31_alt_088", f31_alt_088),
                    ("f31_alt_089", f31_alt_089), ("f31_alt_090", f31_alt_090),
                    ("f31_alt_091", f31_alt_091), ("f31_alt_092", f31_alt_092),
                    ("f31_alt_093", f31_alt_093), ("f31_alt_094", f31_alt_094),
                    ("f31_alt_095", f31_alt_095), ("f31_alt_096", f31_alt_096),
                    ("f31_alt_097", f31_alt_097), ("f31_alt_098", f31_alt_098),
                    ("f31_alt_099", f31_alt_099), ("f31_alt_100", f31_alt_100),
                    ("f31_alt_101", f31_alt_101), ("f31_alt_102", f31_alt_102),
                    ("f31_alt_103", f31_alt_103), ("f31_alt_104", f31_alt_104),
                    ("f31_alt_105", f31_alt_105), ("f31_alt_106", f31_alt_106),
                    ("f31_alt_107", f31_alt_107), ("f31_alt_108", f31_alt_108),
                    ("f31_alt_109", f31_alt_109), ("f31_alt_110", f31_alt_110),
                    ("f31_alt_111", f31_alt_111), ("f31_alt_112", f31_alt_112),
                    ("f31_alt_113", f31_alt_113), ("f31_alt_114", f31_alt_114),
                    ("f31_alt_115", f31_alt_115), ("f31_alt_116", f31_alt_116),
                    ("f31_alt_117", f31_alt_117), ("f31_alt_118", f31_alt_118),
                    ("f31_alt_119", f31_alt_119), ("f31_alt_120", f31_alt_120),
                    ("f31_alt_121", f31_alt_121), ("f31_alt_122", f31_alt_122),
                    ("f31_alt_123", f31_alt_123), ("f31_alt_124", f31_alt_124),
                    ("f31_alt_125", f31_alt_125), ("f31_alt_126", f31_alt_126),
                    ("f31_alt_127", f31_alt_127), ("f31_alt_128", f31_alt_128),
                    ("f31_alt_129", f31_alt_129), ("f31_alt_130", f31_alt_130),
                    ("f31_alt_131", f31_alt_131), ("f31_alt_132", f31_alt_132),
                    ("f31_alt_133", f31_alt_133), ("f31_alt_134", f31_alt_134),
                    ("f31_alt_135", f31_alt_135), ("f31_alt_136", f31_alt_136),
                    ("f31_alt_137", f31_alt_137), ("f31_alt_138", f31_alt_138),
                    ("f31_alt_139", f31_alt_139), ("f31_alt_140", f31_alt_140),
                    ("f31_alt_141", f31_alt_141), ("f31_alt_142", f31_alt_142),
                    ("f31_alt_143", f31_alt_143), ("f31_alt_144", f31_alt_144),
                    ("f31_alt_145", f31_alt_145), ("f31_alt_146", f31_alt_146),
                    ("f31_alt_147", f31_alt_147), ("f31_alt_148", f31_alt_148),
                    ("f31_alt_149", f31_alt_149), ("f31_alt_150", f31_alt_150),
                    ("f31_alt_151", f31_alt_151), ("f31_alt_152", f31_alt_152),
                    ("f31_alt_153", f31_alt_153), ("f31_alt_154", f31_alt_154),
                    ("f31_alt_155", f31_alt_155), ("f31_alt_156", f31_alt_156),
                    ("f31_alt_157", f31_alt_157), ("f31_alt_158", f31_alt_158),
                    ("f31_alt_159", f31_alt_159), ("f31_alt_160", f31_alt_160),
                    ("f31_alt_161", f31_alt_161), ("f31_alt_162", f31_alt_162),
                    ("f31_alt_163", f31_alt_163), ("f31_alt_164", f31_alt_164),
                    ("f31_alt_165", f31_alt_165), ("f31_alt_166", f31_alt_166),
                    ("f31_alt_167", f31_alt_167), ("f31_alt_168", f31_alt_168),
                    ("f31_alt_169", f31_alt_169), ("f31_alt_170", f31_alt_170),
                    ("f31_alt_171", f31_alt_171), ("f31_alt_172", f31_alt_172),
                    ("f31_alt_173", f31_alt_173), ("f31_alt_174", f31_alt_174),
                    ("f31_alt_175", f31_alt_175), ("f31_alt_176", f31_alt_176),
                    ("f31_alt_177", f31_alt_177), ("f31_alt_178", f31_alt_178),
                    ("f31_alt_179", f31_alt_179), ("f31_alt_180", f31_alt_180),
                    ("f31_alt_181", f31_alt_181), ("f31_alt_182", f31_alt_182),
                    ("f31_alt_183", f31_alt_183), ("f31_alt_184", f31_alt_184),
                    ("f31_alt_185", f31_alt_185), ("f31_alt_186", f31_alt_186),
                    ("f31_alt_187", f31_alt_187), ("f31_alt_188", f31_alt_188),
                    ("f31_alt_189", f31_alt_189), ("f31_alt_190", f31_alt_190),
                    ("f31_alt_191", f31_alt_191), ("f31_alt_192", f31_alt_192),
                    ("f31_alt_193", f31_alt_193), ("f31_alt_194", f31_alt_194),
                    ("f31_alt_195", f31_alt_195), ("f31_alt_196", f31_alt_196),
                    ("f31_alt_197", f31_alt_197), ("f31_alt_198", f31_alt_198),
                    ("f31_alt_199", f31_alt_199), ("f31_alt_200", f31_alt_200),
                    ("f31_alt_201", f31_alt_201), ("f31_alt_202", f31_alt_202),
                    ("f31_alt_203", f31_alt_203), ("f31_alt_204", f31_alt_204),
                    ("f31_alt_205", f31_alt_205), ("f31_alt_206", f31_alt_206),
                    ("f31_alt_207", f31_alt_207), ("f31_alt_208", f31_alt_208),
                    ("f31_alt_209", f31_alt_209), ("f31_alt_210", f31_alt_210),
                    ("f31_alt_211", f31_alt_211), ("f31_alt_212", f31_alt_212),
                    ("f31_alt_213", f31_alt_213), ("f31_alt_214", f31_alt_214),
                    ("f31_alt_215", f31_alt_215), ("f31_alt_216", f31_alt_216),
                    ("f31_alt_217", f31_alt_217), ("f31_alt_218", f31_alt_218),
                    ("f31_alt_219", f31_alt_219), ("f31_alt_220", f31_alt_220),
                    ("f31_alt_221", f31_alt_221), ("f31_alt_222", f31_alt_222),
                    ("f31_alt_223", f31_alt_223), ("f31_alt_224", f31_alt_224),
                    ("f31_alt_225", f31_alt_225), ("f31_alt_226", f31_alt_226),
                    ("f31_alt_227", f31_alt_227), ("f31_alt_228", f31_alt_228),
                    ("f31_alt_229", f31_alt_229), ("f31_alt_230", f31_alt_230),
                    ("f31_alt_231", f31_alt_231), ("f31_alt_232", f31_alt_232),
                    ("f31_alt_233", f31_alt_233), ("f31_alt_234", f31_alt_234),
                    ("f31_alt_235", f31_alt_235), ("f31_alt_236", f31_alt_236),
                    ("f31_alt_237", f31_alt_237), ("f31_alt_238", f31_alt_238),
                    ("f31_alt_239", f31_alt_239), ("f31_alt_240", f31_alt_240),
                    ("f31_alt_241", f31_alt_241), ("f31_alt_242", f31_alt_242),
                    ("f31_alt_243", f31_alt_243), ("f31_alt_244", f31_alt_244),
                    ("f31_alt_245", f31_alt_245), ("f31_alt_246", f31_alt_246),
                    ("f31_alt_247", f31_alt_247), ("f31_alt_248", f31_alt_248),
                    ("f31_alt_249", f31_alt_249), ("f31_alt_250", f31_alt_250),
                    ("f31_alt_251", f31_alt_251), ("f31_alt_252", f31_alt_252),
                    ("f31_alt_253", f31_alt_253), ("f31_alt_254", f31_alt_254),
                    ("f31_alt_255", f31_alt_255), ("f31_alt_256", f31_alt_256),
                ] {
                    m.insert(k.to_string(), match v {
                        Some(val) => val.to_json_value(), None => Value::Null });
                }
                m.insert("field_32_u32_list".to_string(), match field_32_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                for (k, v) in [
                    ("f32_alt_001", f32_alt_001), ("f32_alt_002", f32_alt_002),
                    ("f32_alt_003", f32_alt_003), ("f32_alt_004", f32_alt_004),
                    ("f32_alt_005", f32_alt_005), ("f32_alt_006", f32_alt_006),
                    ("f32_alt_007", f32_alt_007), ("f32_alt_008", f32_alt_008),
                    ("f32_alt_009", f32_alt_009), ("f32_alt_010", f32_alt_010),
                    ("f32_alt_011", f32_alt_011), ("f32_alt_012", f32_alt_012),
                    ("f32_alt_013", f32_alt_013), ("f32_alt_014", f32_alt_014),
                    ("f32_alt_015", f32_alt_015), ("f32_alt_016", f32_alt_016),
                    ("f32_alt_017", f32_alt_017), ("f32_alt_018", f32_alt_018),
                    ("f32_alt_019", f32_alt_019), ("f32_alt_020", f32_alt_020),
                    ("f32_alt_021", f32_alt_021), ("f32_alt_022", f32_alt_022),
                    ("f32_alt_023", f32_alt_023), ("f32_alt_024", f32_alt_024),
                    ("f32_alt_025", f32_alt_025), ("f32_alt_026", f32_alt_026),
                    ("f32_alt_027", f32_alt_027), ("f32_alt_028", f32_alt_028),
                    ("f32_alt_029", f32_alt_029), ("f32_alt_030", f32_alt_030),
                    ("f32_alt_031", f32_alt_031), ("f32_alt_032", f32_alt_032),
                    ("f32_alt_033", f32_alt_033), ("f32_alt_034", f32_alt_034),
                    ("f32_alt_035", f32_alt_035), ("f32_alt_036", f32_alt_036),
                    ("f32_alt_037", f32_alt_037), ("f32_alt_038", f32_alt_038),
                    ("f32_alt_039", f32_alt_039), ("f32_alt_040", f32_alt_040),
                    ("f32_alt_041", f32_alt_041), ("f32_alt_042", f32_alt_042),
                    ("f32_alt_043", f32_alt_043), ("f32_alt_044", f32_alt_044),
                    ("f32_alt_045", f32_alt_045), ("f32_alt_046", f32_alt_046),
                    ("f32_alt_047", f32_alt_047), ("f32_alt_048", f32_alt_048),
                    ("f32_alt_049", f32_alt_049), ("f32_alt_050", f32_alt_050),
                    ("f32_alt_051", f32_alt_051), ("f32_alt_052", f32_alt_052),
                    ("f32_alt_053", f32_alt_053), ("f32_alt_054", f32_alt_054),
                    ("f32_alt_055", f32_alt_055), ("f32_alt_056", f32_alt_056),
                    ("f32_alt_057", f32_alt_057), ("f32_alt_058", f32_alt_058),
                    ("f32_alt_059", f32_alt_059), ("f32_alt_060", f32_alt_060),
                    ("f32_alt_061", f32_alt_061), ("f32_alt_062", f32_alt_062),
                    ("f32_alt_063", f32_alt_063), ("f32_alt_064", f32_alt_064),
                    ("f32_alt_065", f32_alt_065), ("f32_alt_066", f32_alt_066),
                    ("f32_alt_067", f32_alt_067), ("f32_alt_068", f32_alt_068),
                    ("f32_alt_069", f32_alt_069), ("f32_alt_070", f32_alt_070),
                    ("f32_alt_071", f32_alt_071), ("f32_alt_072", f32_alt_072),
                    ("f32_alt_073", f32_alt_073), ("f32_alt_074", f32_alt_074),
                    ("f32_alt_075", f32_alt_075), ("f32_alt_076", f32_alt_076),
                    ("f32_alt_077", f32_alt_077), ("f32_alt_078", f32_alt_078),
                    ("f32_alt_079", f32_alt_079), ("f32_alt_080", f32_alt_080),
                    ("f32_alt_081", f32_alt_081), ("f32_alt_082", f32_alt_082),
                    ("f32_alt_083", f32_alt_083), ("f32_alt_084", f32_alt_084),
                    ("f32_alt_085", f32_alt_085), ("f32_alt_086", f32_alt_086),
                    ("f32_alt_087", f32_alt_087), ("f32_alt_088", f32_alt_088),
                    ("f32_alt_089", f32_alt_089), ("f32_alt_090", f32_alt_090),
                    ("f32_alt_091", f32_alt_091), ("f32_alt_092", f32_alt_092),
                    ("f32_alt_093", f32_alt_093), ("f32_alt_094", f32_alt_094),
                    ("f32_alt_095", f32_alt_095), ("f32_alt_096", f32_alt_096),
                    ("f32_alt_097", f32_alt_097), ("f32_alt_098", f32_alt_098),
                    ("f32_alt_099", f32_alt_099), ("f32_alt_100", f32_alt_100),
                    ("f32_alt_101", f32_alt_101), ("f32_alt_102", f32_alt_102),
                    ("f32_alt_103", f32_alt_103), ("f32_alt_104", f32_alt_104),
                    ("f32_alt_105", f32_alt_105), ("f32_alt_106", f32_alt_106),
                    ("f32_alt_107", f32_alt_107), ("f32_alt_108", f32_alt_108),
                    ("f32_alt_109", f32_alt_109), ("f32_alt_110", f32_alt_110),
                    ("f32_alt_111", f32_alt_111), ("f32_alt_112", f32_alt_112),
                    ("f32_alt_113", f32_alt_113), ("f32_alt_114", f32_alt_114),
                    ("f32_alt_115", f32_alt_115), ("f32_alt_116", f32_alt_116),
                    ("f32_alt_117", f32_alt_117), ("f32_alt_118", f32_alt_118),
                    ("f32_alt_119", f32_alt_119), ("f32_alt_120", f32_alt_120),
                    ("f32_alt_121", f32_alt_121), ("f32_alt_122", f32_alt_122),
                    ("f32_alt_123", f32_alt_123), ("f32_alt_124", f32_alt_124),
                    ("f32_alt_125", f32_alt_125), ("f32_alt_126", f32_alt_126),
                    ("f32_alt_127", f32_alt_127), ("f32_alt_128", f32_alt_128),
                    ("f32_alt_129", f32_alt_129), ("f32_alt_130", f32_alt_130),
                    ("f32_alt_131", f32_alt_131), ("f32_alt_132", f32_alt_132),
                    ("f32_alt_133", f32_alt_133), ("f32_alt_134", f32_alt_134),
                    ("f32_alt_135", f32_alt_135), ("f32_alt_136", f32_alt_136),
                    ("f32_alt_137", f32_alt_137), ("f32_alt_138", f32_alt_138),
                    ("f32_alt_139", f32_alt_139), ("f32_alt_140", f32_alt_140),
                    ("f32_alt_141", f32_alt_141), ("f32_alt_142", f32_alt_142),
                    ("f32_alt_143", f32_alt_143), ("f32_alt_144", f32_alt_144),
                    ("f32_alt_145", f32_alt_145), ("f32_alt_146", f32_alt_146),
                    ("f32_alt_147", f32_alt_147), ("f32_alt_148", f32_alt_148),
                    ("f32_alt_149", f32_alt_149), ("f32_alt_150", f32_alt_150),
                    ("f32_alt_151", f32_alt_151), ("f32_alt_152", f32_alt_152),
                    ("f32_alt_153", f32_alt_153), ("f32_alt_154", f32_alt_154),
                    ("f32_alt_155", f32_alt_155), ("f32_alt_156", f32_alt_156),
                    ("f32_alt_157", f32_alt_157), ("f32_alt_158", f32_alt_158),
                    ("f32_alt_159", f32_alt_159), ("f32_alt_160", f32_alt_160),
                    ("f32_alt_161", f32_alt_161), ("f32_alt_162", f32_alt_162),
                    ("f32_alt_163", f32_alt_163), ("f32_alt_164", f32_alt_164),
                    ("f32_alt_165", f32_alt_165), ("f32_alt_166", f32_alt_166),
                    ("f32_alt_167", f32_alt_167), ("f32_alt_168", f32_alt_168),
                    ("f32_alt_169", f32_alt_169), ("f32_alt_170", f32_alt_170),
                    ("f32_alt_171", f32_alt_171), ("f32_alt_172", f32_alt_172),
                    ("f32_alt_173", f32_alt_173), ("f32_alt_174", f32_alt_174),
                    ("f32_alt_175", f32_alt_175), ("f32_alt_176", f32_alt_176),
                    ("f32_alt_177", f32_alt_177), ("f32_alt_178", f32_alt_178),
                    ("f32_alt_179", f32_alt_179), ("f32_alt_180", f32_alt_180),
                    ("f32_alt_181", f32_alt_181), ("f32_alt_182", f32_alt_182),
                    ("f32_alt_183", f32_alt_183), ("f32_alt_184", f32_alt_184),
                    ("f32_alt_185", f32_alt_185), ("f32_alt_186", f32_alt_186),
                    ("f32_alt_187", f32_alt_187), ("f32_alt_188", f32_alt_188),
                    ("f32_alt_189", f32_alt_189), ("f32_alt_190", f32_alt_190),
                    ("f32_alt_191", f32_alt_191), ("f32_alt_192", f32_alt_192),
                ] {
                    m.insert(k.to_string(), match v {
                        Some(val) => val.to_json_value(), None => Value::Null });
                }
                m.insert("field_33_u32".to_string(), match field_33_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_34_u32".to_string(), match field_34_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_35_u32_list".to_string(), match field_35_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_36_u32".to_string(), match field_36_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_37_u32".to_string(), match field_37_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_38_u32".to_string(), match field_38_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_39_u32_list".to_string(), match field_39_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                for (k, v) in [
                    ("f39_alt_001", f39_alt_001), ("f39_alt_002", f39_alt_002),
                    ("f39_alt_003", f39_alt_003), ("f39_alt_004", f39_alt_004),
                    ("f39_alt_005", f39_alt_005), ("f39_alt_006", f39_alt_006),
                    ("f39_alt_007", f39_alt_007), ("f39_alt_008", f39_alt_008),
                    ("f39_alt_009", f39_alt_009), ("f39_alt_010", f39_alt_010),
                    ("f39_alt_011", f39_alt_011), ("f39_alt_012", f39_alt_012),
                    ("f39_alt_013", f39_alt_013), ("f39_alt_014", f39_alt_014),
                    ("f39_alt_015", f39_alt_015), ("f39_alt_016", f39_alt_016),
                    ("f39_alt_017", f39_alt_017), ("f39_alt_018", f39_alt_018),
                    ("f39_alt_019", f39_alt_019), ("f39_alt_020", f39_alt_020),
                    ("f39_alt_021", f39_alt_021), ("f39_alt_022", f39_alt_022),
                    ("f39_alt_023", f39_alt_023), ("f39_alt_024", f39_alt_024),
                    ("f39_alt_025", f39_alt_025), ("f39_alt_026", f39_alt_026),
                    ("f39_alt_027", f39_alt_027), ("f39_alt_028", f39_alt_028),
                    ("f39_alt_029", f39_alt_029), ("f39_alt_030", f39_alt_030),
                    ("f39_alt_031", f39_alt_031), ("f39_alt_032", f39_alt_032),
                    ("f39_alt_033", f39_alt_033), ("f39_alt_034", f39_alt_034),
                    ("f39_alt_035", f39_alt_035), ("f39_alt_036", f39_alt_036),
                    ("f39_alt_037", f39_alt_037), ("f39_alt_038", f39_alt_038),
                    ("f39_alt_039", f39_alt_039), ("f39_alt_040", f39_alt_040),
                    ("f39_alt_041", f39_alt_041), ("f39_alt_042", f39_alt_042),
                    ("f39_alt_043", f39_alt_043), ("f39_alt_044", f39_alt_044),
                    ("f39_alt_045", f39_alt_045), ("f39_alt_046", f39_alt_046),
                    ("f39_alt_047", f39_alt_047), ("f39_alt_048", f39_alt_048),
                    ("f39_alt_049", f39_alt_049), ("f39_alt_050", f39_alt_050),
                    ("f39_alt_051", f39_alt_051), ("f39_alt_052", f39_alt_052),
                    ("f39_alt_053", f39_alt_053), ("f39_alt_054", f39_alt_054),
                    ("f39_alt_055", f39_alt_055), ("f39_alt_056", f39_alt_056),
                    ("f39_alt_057", f39_alt_057), ("f39_alt_058", f39_alt_058),
                    ("f39_alt_059", f39_alt_059), ("f39_alt_060", f39_alt_060),
                    ("f39_alt_061", f39_alt_061), ("f39_alt_062", f39_alt_062),
                    ("f39_alt_063", f39_alt_063), ("f39_alt_064", f39_alt_064),
                    ("f39_alt_065", f39_alt_065), ("f39_alt_066", f39_alt_066),
                    ("f39_alt_067", f39_alt_067), ("f39_alt_068", f39_alt_068),
                    ("f39_alt_069", f39_alt_069), ("f39_alt_070", f39_alt_070),
                    ("f39_alt_071", f39_alt_071), ("f39_alt_072", f39_alt_072),
                    ("f39_alt_073", f39_alt_073), ("f39_alt_074", f39_alt_074),
                    ("f39_alt_075", f39_alt_075), ("f39_alt_076", f39_alt_076),
                    ("f39_alt_077", f39_alt_077), ("f39_alt_078", f39_alt_078),
                    ("f39_alt_079", f39_alt_079), ("f39_alt_080", f39_alt_080),
                    ("f39_alt_081", f39_alt_081), ("f39_alt_082", f39_alt_082),
                    ("f39_alt_083", f39_alt_083), ("f39_alt_084", f39_alt_084),
                    ("f39_alt_085", f39_alt_085), ("f39_alt_086", f39_alt_086),
                    ("f39_alt_087", f39_alt_087), ("f39_alt_088", f39_alt_088),
                    ("f39_alt_089", f39_alt_089), ("f39_alt_090", f39_alt_090),
                    ("f39_alt_091", f39_alt_091), ("f39_alt_092", f39_alt_092),
                    ("f39_alt_093", f39_alt_093), ("f39_alt_094", f39_alt_094),
                    ("f39_alt_095", f39_alt_095), ("f39_alt_096", f39_alt_096),
                    ("f39_alt_097", f39_alt_097), ("f39_alt_098", f39_alt_098),
                    ("f39_alt_099", f39_alt_099), ("f39_alt_100", f39_alt_100),
                    ("f39_alt_101", f39_alt_101), ("f39_alt_102", f39_alt_102),
                    ("f39_alt_103", f39_alt_103), ("f39_alt_104", f39_alt_104),
                    ("f39_alt_105", f39_alt_105), ("f39_alt_106", f39_alt_106),
                    ("f39_alt_107", f39_alt_107), ("f39_alt_108", f39_alt_108),
                    ("f39_alt_109", f39_alt_109), ("f39_alt_110", f39_alt_110),
                    ("f39_alt_111", f39_alt_111), ("f39_alt_112", f39_alt_112),
                    ("f39_alt_113", f39_alt_113), ("f39_alt_114", f39_alt_114),
                    ("f39_alt_115", f39_alt_115), ("f39_alt_116", f39_alt_116),
                    ("f39_alt_117", f39_alt_117), ("f39_alt_118", f39_alt_118),
                    ("f39_alt_119", f39_alt_119), ("f39_alt_120", f39_alt_120),
                    ("f39_alt_121", f39_alt_121), ("f39_alt_122", f39_alt_122),
                    ("f39_alt_123", f39_alt_123), ("f39_alt_124", f39_alt_124),
                    ("f39_alt_125", f39_alt_125), ("f39_alt_126", f39_alt_126),
                    ("f39_alt_127", f39_alt_127), ("f39_alt_128", f39_alt_128),
                    ("f39_alt_129", f39_alt_129), ("f39_alt_130", f39_alt_130),
                    ("f39_alt_131", f39_alt_131), ("f39_alt_132", f39_alt_132),
                    ("f39_alt_133", f39_alt_133), ("f39_alt_134", f39_alt_134),
                    ("f39_alt_135", f39_alt_135), ("f39_alt_136", f39_alt_136),
                    ("f39_alt_137", f39_alt_137), ("f39_alt_138", f39_alt_138),
                    ("f39_alt_139", f39_alt_139), ("f39_alt_140", f39_alt_140),
                    ("f39_alt_141", f39_alt_141), ("f39_alt_142", f39_alt_142),
                    ("f39_alt_143", f39_alt_143), ("f39_alt_144", f39_alt_144),
                    ("f39_alt_145", f39_alt_145), ("f39_alt_146", f39_alt_146),
                    ("f39_alt_147", f39_alt_147), ("f39_alt_148", f39_alt_148),
                    ("f39_alt_149", f39_alt_149), ("f39_alt_150", f39_alt_150),
                    ("f39_alt_151", f39_alt_151), ("f39_alt_152", f39_alt_152),
                    ("f39_alt_153", f39_alt_153), ("f39_alt_154", f39_alt_154),
                    ("f39_alt_155", f39_alt_155), ("f39_alt_156", f39_alt_156),
                    ("f39_alt_157", f39_alt_157), ("f39_alt_158", f39_alt_158),
                    ("f39_alt_159", f39_alt_159), ("f39_alt_160", f39_alt_160),
                    ("f39_alt_161", f39_alt_161), ("f39_alt_162", f39_alt_162),
                    ("f39_alt_163", f39_alt_163), ("f39_alt_164", f39_alt_164),
                    ("f39_alt_165", f39_alt_165), ("f39_alt_166", f39_alt_166),
                    ("f39_alt_167", f39_alt_167), ("f39_alt_168", f39_alt_168),
                    ("f39_alt_169", f39_alt_169), ("f39_alt_170", f39_alt_170),
                    ("f39_alt_171", f39_alt_171), ("f39_alt_172", f39_alt_172),
                    ("f39_alt_173", f39_alt_173), ("f39_alt_174", f39_alt_174),
                    ("f39_alt_175", f39_alt_175), ("f39_alt_176", f39_alt_176),
                    ("f39_alt_177", f39_alt_177), ("f39_alt_178", f39_alt_178),
                    ("f39_alt_179", f39_alt_179), ("f39_alt_180", f39_alt_180),
                    ("f39_alt_181", f39_alt_181), ("f39_alt_182", f39_alt_182),
                    ("f39_alt_183", f39_alt_183), ("f39_alt_184", f39_alt_184),
                    ("f39_alt_185", f39_alt_185), ("f39_alt_186", f39_alt_186),
                    ("f39_alt_187", f39_alt_187), ("f39_alt_188", f39_alt_188),
                    ("f39_alt_189", f39_alt_189), ("f39_alt_190", f39_alt_190),
                    ("f39_alt_191", f39_alt_191), ("f39_alt_192", f39_alt_192),
                ] {
                    m.insert(k.to_string(), match v {
                        Some(val) => val.to_json_value(), None => Value::Null });
                }
                m.insert("field_40_u32_list".to_string(), match field_40_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_41_u32".to_string(), match field_41_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_42_u32".to_string(), match field_42_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_43_u32".to_string(), match field_43_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_44_u32".to_string(), match field_44_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_45_u32".to_string(), match field_45_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_46_u32".to_string(), match field_46_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_47_u32".to_string(), match field_47_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_48_u32".to_string(), match field_48_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_49_u32_list".to_string(), match field_49_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_50_u32_list".to_string(), match field_50_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_51_u32_list".to_string(), match field_51_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_52_u32_list".to_string(), match field_52_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_53_u32_list".to_string(), match field_53_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_54_u32_list".to_string(), match field_54_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_55_u32_list".to_string(), match field_55_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_56_u32_list".to_string(), match field_56_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_57_u32_list".to_string(), match field_57_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_58_u32_list".to_string(), match field_58_u32_list {
                    Some(arr) => arr.to_json_value(), None => Value::Null });
                m.insert("field_59_u32".to_string(), match field_59_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_60_u32".to_string(), match field_60_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_61_u32".to_string(), match field_61_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_62_u32".to_string(), match field_62_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_63_u32".to_string(), match field_63_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_64_u32".to_string(), match field_64_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_65_u32".to_string(), match field_65_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_66_u32".to_string(), match field_66_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_67_u32".to_string(), match field_67_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_68_u32".to_string(), match field_68_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_69_u32".to_string(), match field_69_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_70_u32".to_string(), match field_70_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_71_u32".to_string(), match field_71_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_72_u32".to_string(), match field_72_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_73_u32".to_string(), match field_73_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_74_u32".to_string(), match field_74_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_75_u32".to_string(), match field_75_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_76_u32".to_string(), match field_76_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_77_u32".to_string(), match field_77_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_78_u32".to_string(), match field_78_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_79_u32".to_string(), match field_79_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_80_u32".to_string(), match field_80_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_81_u32".to_string(), match field_81_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_82_u32".to_string(), match field_82_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_83_u32".to_string(), match field_83_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_84_u32".to_string(), match field_84_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_85_u32".to_string(), match field_85_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_86_u32".to_string(), match field_86_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_87_u32".to_string(), match field_87_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_88_u32".to_string(), match field_88_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_89_u32".to_string(), match field_89_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_90_u32".to_string(), match field_90_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_91_u32".to_string(), match field_91_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_92_u32".to_string(), match field_92_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_93_u32".to_string(), match field_93_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_94_u32".to_string(), match field_94_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_95_u32".to_string(), match field_95_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_96_u32".to_string(), match field_96_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_97_u32".to_string(), match field_97_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_98_u32".to_string(), match field_98_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_99_u32".to_string(), match field_99_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_100_u32".to_string(), match field_100_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_101_u32".to_string(), match field_101_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_102_u32".to_string(), match field_102_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_103_u32".to_string(), match field_103_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_104_u32".to_string(), match field_104_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_105_u32".to_string(), match field_105_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_106_u32".to_string(), match field_106_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_107_u32".to_string(), match field_107_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_108_u32".to_string(), match field_108_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_109_u32".to_string(), match field_109_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_110_u32".to_string(), match field_110_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_111_u32".to_string(), match field_111_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_112_u32".to_string(), match field_112_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_113_u32".to_string(), match field_113_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_114_u32".to_string(), match field_114_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_115_u32".to_string(), match field_115_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_116_u32".to_string(), match field_116_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_117_u32".to_string(), match field_117_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_118_u32".to_string(), match field_118_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_119_u32".to_string(), match field_119_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_120_u32".to_string(), match field_120_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_121_u32".to_string(), match field_121_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_122_u32".to_string(), match field_122_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_123_u32".to_string(), match field_123_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                for (k, v) in [("field_124_u32", field_124_u32),
                               ("field_125_u32", field_125_u32),
                               ("field_126_u32", field_126_u32),
                               ("field_127_u32", field_127_u32),
                               ("field_128_u32", field_128_u32),
                               ("field_129_u32", field_129_u32),
                               ("field_130_u32", field_130_u32),
                               ("field_131_u32", field_131_u32),
                               ("field_132_u32", field_132_u32),
                               ("field_133_u32", field_133_u32),
                               ("field_134_u32", field_134_u32),
                               ("field_135_u32", field_135_u32),
                               ("field_136_u32", field_136_u32),
                               ("field_137_u32", field_137_u32),
                               ("field_138_u32", field_138_u32),
                               ("field_139_u32", field_139_u32),
                               ("field_140_u32", field_140_u32),
                               ("field_141_u32", field_141_u32),
                               ("field_142_u32", field_142_u32),
                               ("field_143_u32", field_143_u32),
                               ("field_144_u32", field_144_u32),
                               ("field_145_u32", field_145_u32),
                               ("field_146_u32", field_146_u32),
                               ("field_147_u32", field_147_u32),
                               ("field_148_u32", field_148_u32),
                               ("field_149_u32", field_149_u32),
                               ("field_150_u32", field_150_u32),
                               ("field_151_u32", field_151_u32),
                               ("field_152_u32", field_152_u32),
                               ("field_153_u32", field_153_u32),
                               ("field_154_u32", field_154_u32),
                               ("field_155_u32", field_155_u32),
                               ("field_156_u32", field_156_u32),
                               ("field_157_u32", field_157_u32),
                               ("field_158_u32", field_158_u32),
                               ("field_159_u32", field_159_u32),
                               ("field_160_u32", field_160_u32),
                               ("field_161_u32", field_161_u32),
                               ("field_162_u32", field_162_u32),
                               ("field_163_u32", field_163_u32),
                               ("field_164_u32", field_164_u32),
                               ("field_165_u32", field_165_u32),
                               ("field_166_u32", field_166_u32),
                               ("field_167_u32", field_167_u32),
                               ("field_168_u32", field_168_u32),
                               ("field_169_u32", field_169_u32),
                               ("field_170_u32", field_170_u32),
                               ("field_171_u32", field_171_u32),
                               ("field_172_u32", field_172_u32),
                               ("field_173_u32", field_173_u32),
                               ("field_174_u32", field_174_u32),
                               ("field_175_u32", field_175_u32),
                               ("field_176_u32", field_176_u32),
                               ("field_177_u32", field_177_u32),
                               ("field_178_u32", field_178_u32),
                               ("field_179_u32", field_179_u32),
                               ("field_180_u32", field_180_u32),
                               ("field_181_u32", field_181_u32),
                               ("field_182_u32", field_182_u32),
                               ("field_183_u32", field_183_u32),
                               ("field_184_u32", field_184_u32),
                               ("field_185_u32", field_185_u32),
                               ("field_186_u32", field_186_u32),
                               ("field_187_u32", field_187_u32),
                               ("field_188_u32", field_188_u32),
                               ("field_189_u32", field_189_u32),
                               ("field_190_u32", field_190_u32),
                               ("field_191_u32", field_191_u32),
                               ("field_192_u32", field_192_u32),
                               ("field_193_u32", field_193_u32),
                               ("field_194_u32", field_194_u32),
                               ("field_195_u32", field_195_u32),
                               ("field_196_u32", field_196_u32),
                               ("field_197_u32", field_197_u32),
                               ("field_198_u32", field_198_u32),
                               ("field_199_u32", field_199_u32),
                               ("field_200_u32", field_200_u32),
                               ("field_201_u32", field_201_u32),
                               ("field_202_u32", field_202_u32),
                               ("field_203_u32", field_203_u32),
                               ("field_204_u32", field_204_u32),
                               ("field_205_u32", field_205_u32),
                               ("field_206_u32", field_206_u32),
                               ("field_207_u32", field_207_u32),
                               ("field_208_u32", field_208_u32),
                               ("field_209_u32", field_209_u32),
                               ("field_210_u32", field_210_u32),
                               ("field_211_u32", field_211_u32),
                               ("field_212_u32", field_212_u32),
                               ("field_213_u32", field_213_u32),
                               ("field_214_u32", field_214_u32),
                               ("field_215_u32", field_215_u32),
                               ("field_216_u32", field_216_u32),
                               ("field_217_u32", field_217_u32),
                               ("field_218_u32", field_218_u32),
                               ("field_219_u32", field_219_u32),
                               ("field_220_u32", field_220_u32),
                               ("field_221_u32", field_221_u32),
                               ("field_222_u32", field_222_u32),
                               ("field_223_u32", field_223_u32),
                               ("field_224_u32", field_224_u32),
                               ("field_225_u32", field_225_u32),
                               ("field_226_u32", field_226_u32),
                               ("field_227_u32", field_227_u32),
                               ("field_228_u32", field_228_u32),
                               ("field_229_u32", field_229_u32),
                               ("field_230_u32", field_230_u32),
                               ("field_231_u32", field_231_u32),
                               ("field_232_u32", field_232_u32),
                               ("field_233_u32", field_233_u32),
                               ("field_234_u32", field_234_u32),
                               ("field_235_u32", field_235_u32),
                               ("field_236_u32", field_236_u32),
                               ("field_237_u32", field_237_u32),
                               ("field_238_u32", field_238_u32),
                               ("field_239_u32", field_239_u32),
                               ("field_240_u32", field_240_u32),
                               ("field_241_u32", field_241_u32),
                               ("field_242_u32", field_242_u32),
                               ("field_243_u32", field_243_u32),
                               ("field_244_u32", field_244_u32),
                               ("field_245_u32", field_245_u32),
                               ("field_246_u32", field_246_u32),
                               ("field_247_u32", field_247_u32),
                               ("field_248_u32", field_248_u32),
                               ("field_249_u32", field_249_u32),
                               ("field_250_u32", field_250_u32),
                               ("field_251_u32", field_251_u32),
                               ("field_252_u32", field_252_u32),
                               ("field_253_u32", field_253_u32),
                               ("field_254_u32", field_254_u32),
                               ("field_255_u32", field_255_u32),
                               ("field_256_u32", field_256_u32),
                               ("field_257_u32", field_257_u32),
                               ("field_258_u32", field_258_u32),
                               ("field_259_u32", field_259_u32),
                               ("field_260_u32", field_260_u32),
                               ("field_261_u32", field_261_u32),
                               ("field_262_u32", field_262_u32),
                               ("field_263_u32", field_263_u32),
                               ("field_264_u32", field_264_u32),
                               ("field_265_u32", field_265_u32),
                               ("field_266_u32", field_266_u32),
                               ("field_267_u32", field_267_u32),
                               ("field_268_u32", field_268_u32),
                               ("field_269_u32", field_269_u32),
                               ("field_270_u32", field_270_u32),
                               ("field_271_u32", field_271_u32),
                               ("field_272_u32", field_272_u32),
                               ("field_273_u32", field_273_u32),
                               ("field_274_u32", field_274_u32),
                               ("field_275_u32", field_275_u32),
                               ("field_276_u32", field_276_u32),
                               ("field_277_u32", field_277_u32),
                               ("field_278_u32", field_278_u32),
                               ("field_279_u32", field_279_u32),
                               ("field_280_u32", field_280_u32),
                               ("field_281_u32", field_281_u32),
                               ("field_282_u32", field_282_u32),
                               ("field_283_u32", field_283_u32),
                               ("field_284_u32", field_284_u32),
                               ("field_285_u32", field_285_u32),
                               ("field_286_u32", field_286_u32),
                               ("field_287_u32", field_287_u32),
                               ("field_288_u32", field_288_u32),
                               ("field_289_u32", field_289_u32),
                               ("field_290_u32", field_290_u32),
                               ("field_291_u32", field_291_u32),
                               ("field_292_u32", field_292_u32),
                               ("field_293_u32", field_293_u32),
                               ("field_294_u32", field_294_u32),
                               ("field_295_u32", field_295_u32),
                               ("field_296_u32", field_296_u32),
                               ("field_297_u32", field_297_u32),
                               ("field_298_u32", field_298_u32),
                               ("field_299_u32", field_299_u32),
                               ("field_300_u32", field_300_u32),
                               ("field_301_u32", field_301_u32),
                               ("field_302_u32", field_302_u32),
                               ("field_303_u32", field_303_u32),
                               ("field_304_u32", field_304_u32),
                               ("field_305_u32", field_305_u32),
                               ("field_306_u32", field_306_u32),
                               ("field_307_u32", field_307_u32),
                               ("field_308_u32", field_308_u32),
                               ("field_309_u32", field_309_u32),
                               ("field_310_u32", field_310_u32),
                               ("field_311_u32", field_311_u32),
                               ("field_312_u32", field_312_u32),
                               ("field_313_u32", field_313_u32),
                               ("field_314_u32", field_314_u32),
                               ("field_315_u32", field_315_u32),
                               ("field_316_u32", field_316_u32),
                               ("field_317_u32", field_317_u32),
                               ("field_318_u32", field_318_u32),
                               ("field_319_u32", field_319_u32),
                               ("field_320_u32", field_320_u32),
                               ("field_321_u32", field_321_u32),
                               ("field_322_u32", field_322_u32),
                               ("field_323_u32", field_323_u32),
                               ("field_324_u32", field_324_u32),
                               ("field_325_u32", field_325_u32),
                               ("field_326_u32", field_326_u32),
                               ("field_327_u32", field_327_u32),
                               ("field_328_u32", field_328_u32),
                               ("field_329_u32", field_329_u32),
                               ("field_330_u32", field_330_u32),
                               ("field_331_u32", field_331_u32),
                               ("field_332_u32", field_332_u32),
                               ("field_333_u32", field_333_u32),
                               ("field_334_u32", field_334_u32),
                               ("field_335_u32", field_335_u32),
                               ("field_336_u32", field_336_u32),
                               ("field_337_u32", field_337_u32),
                               ("field_338_u32", field_338_u32),
                               ("field_339_u32", field_339_u32),
                               ("field_340_u32", field_340_u32),
                               ("field_341_u32", field_341_u32),
                               ("field_342_u32_count", field_342_u32_count)] {
                    m.insert(k.to_string(), match v {
                        Some(val) => val.to_json_value(), None => Value::Null });
                }
                m.insert("field_343_u8_flag".to_string(), match field_343_u8_flag {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("field_344_u32".to_string(), match field_344_u32 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                for (k, v) in [("field_345_u32", field_345_u32),
                               ("field_346_u32", field_346_u32),
                               ("field_347_u32", field_347_u32),
                               ("field_348_u32", field_348_u32),
                               ("field_349_u32", field_349_u32),
                               ("field_350_u32", field_350_u32),
                               ("field_351_u32", field_351_u32),
                               ("field_352_u32", field_352_u32),
                               ("field_353_u32", field_353_u32),
                               ("field_354_u32", field_354_u32),
                               ("field_355_u32", field_355_u32),
                               ("field_356_u32", field_356_u32),
                               ("field_357_u32", field_357_u32),
                               ("field_358_u32", field_358_u32),
                               ("field_359_u32", field_359_u32),
                               ("field_360_u32", field_360_u32),
                               ("field_361_u32", field_361_u32),
                               ("field_362_u32", field_362_u32),
                               ("field_363_u32", field_363_u32),
                               ("field_364_u32", field_364_u32),
                               ("field_365_u32", field_365_u32),
                               ("field_366_u32", field_366_u32),
                               ("field_367_u32", field_367_u32),
                               ("field_368_u32", field_368_u32),
                               ("field_369_u32", field_369_u32),
                               ("field_370_u32", field_370_u32),
                               ("field_371_u32", field_371_u32),
                               ("field_372_u32", field_372_u32),
                               ("field_373_u32", field_373_u32),
                               ("field_374_u32", field_374_u32),
                               ("field_375_u32", field_375_u32),
                               ("field_376_u32", field_376_u32),
                               ("field_377_u32", field_377_u32),
                               ("field_378_u32", field_378_u32),
                               ("field_379_u32", field_379_u32),
                               ("field_380_u32", field_380_u32),
                               ("field_381_u32", field_381_u32),
                               ("field_382_u32", field_382_u32),
                               ("field_383_u32", field_383_u32),
                               ("field_384_u32", field_384_u32),
                               ("field_385_u32", field_385_u32),
                               ("field_386_u32", field_386_u32),
                               ("field_387_u32", field_387_u32),
                               ("field_388_u32", field_388_u32),
                               ("field_389_u32", field_389_u32),
                               ("field_390_u32", field_390_u32),
                               ("field_391_u32", field_391_u32),
                               ("field_392_u32", field_392_u32),
                               ("field_393_u32", field_393_u32),
                               ("field_394_u32", field_394_u32),
                               ("field_395_u32", field_395_u32),
                               ("field_396_u32", field_396_u32),
                               ("field_397_u32", field_397_u32),
                               ("field_398_u32", field_398_u32),
                               ("field_399_u32", field_399_u32),
                               ("field_400_u32", field_400_u32),
                               ("field_401_u32", field_401_u32),
                               ("field_402_u32", field_402_u32),
                               ("field_403_u32", field_403_u32),
                               ("field_404_u32", field_404_u32),
                               ("field_405_u32", field_405_u32),
                               ("field_406_u32", field_406_u32),
                               ("field_407_u32", field_407_u32),
                               ("field_408_u32", field_408_u32),
                               ("field_409_u32", field_409_u32),
                               ("field_410_u32", field_410_u32),
                               ("field_411_u32", field_411_u32),
                               ("field_412_u32", field_412_u32),
                               ("field_413_u32", field_413_u32),
                               ("field_414_u32", field_414_u32),
                               ("field_415_u32", field_415_u32),
                               ("field_416_u32", field_416_u32),
                               ("field_417_u32", field_417_u32),
                               ("field_418_u32", field_418_u32),
                               ("field_419_u32", field_419_u32),
                               ("field_420_u32", field_420_u32),
                               ("field_421_u32", field_421_u32),
                               ("field_422_u32", field_422_u32),
                               ("field_423_u32", field_423_u32),
                               ("field_424_u32", field_424_u32),
                               ("field_425_u32", field_425_u32),
                               ("field_426_u32", field_426_u32),
                               ("field_427_u32", field_427_u32),
                               ("field_428_u32", field_428_u32),
                               ("field_429_u32", field_429_u32),
                               ("field_430_u32", field_430_u32),
                               ("field_431_u32", field_431_u32),
                               ("field_432_u32", field_432_u32),
                               ("field_433_u32", field_433_u32),
                               ("field_434_u32", field_434_u32),
                               ("field_435_u32", field_435_u32),
                               ("field_436_u32", field_436_u32),
                               ("field_437_u32", field_437_u32),
                               ("field_438_u32", field_438_u32),
                               ("field_439_u32", field_439_u32),
                               ("field_440_u32", field_440_u32),
                               ("field_441_u32", field_441_u32),
                               ("field_442_u32", field_442_u32),
                               ("field_443_u32", field_443_u32),
                               ("field_444_u32", field_444_u32),
                               ("field_445_u32", field_445_u32),
                               ("field_446_u32", field_446_u32),
                               ("field_447_u32", field_447_u32),
                               ("field_448_u32", field_448_u32),
                               ("field_449_u32", field_449_u32),
                               ("field_450_u32", field_450_u32),
                               ("field_451_u32", field_451_u32),
                               ("field_452_u32", field_452_u32),
                               ("field_453_u32", field_453_u32),
                               ("field_454_u32", field_454_u32),
                               ("field_455_u32", field_455_u32),
                               ("field_456_u32", field_456_u32),
                               ("field_457_u32", field_457_u32),
                               ("field_458_u32", field_458_u32),
                               ("field_459_u32", field_459_u32),
                               ("field_460_u32", field_460_u32),
                               ("field_461_u32", field_461_u32),
                               ("field_462_u32", field_462_u32),
                               ("field_463_u32", field_463_u32),
                               ("field_464_u32", field_464_u32),
                               ("field_465_u32", field_465_u32),
                               ("field_466_u32", field_466_u32),
                               ("field_467_u32", field_467_u32),
                               ("field_468_u32", field_468_u32),
                               ("field_469_u32", field_469_u32),
                               ("field_470_u32", field_470_u32),
                               ("field_471_u32", field_471_u32),
                               ("field_472_u32", field_472_u32),
                               ("field_473_u32", field_473_u32),
                               ("field_474_u32", field_474_u32),
                               ("field_475_u32", field_475_u32),
                               ("field_476_u32", field_476_u32),
                               ("field_477_u32", field_477_u32),
                               ("field_478_u32", field_478_u32),
                               ("field_479_u32", field_479_u32),
                               ("field_480_u32", field_480_u32),
                               ("field_481_u32", field_481_u32),
                               ("field_482_u32", field_482_u32),
                               ("field_483_u32", field_483_u32),
                               ("field_484_u32", field_484_u32),
                               ("field_485_u32", field_485_u32),
                               ("field_486_u32", field_486_u32),
                               ("field_487_u32", field_487_u32),
                               ("field_488_u32", field_488_u32),
                               ("field_489_u32", field_489_u32),
                               ("field_490_u32", field_490_u32),
                               ("field_491_u32", field_491_u32),
                               ("field_492_u32", field_492_u32),
                               ("field_493_u32", field_493_u32),
                               ("field_494_u32", field_494_u32),
                               ("field_495_u32", field_495_u32),
                               ("field_496_u32", field_496_u32),
                               ("field_497_u32", field_497_u32),
                               ("field_498_u32", field_498_u32),
                               ("field_499_u32", field_499_u32),
                               ("field_500_u32", field_500_u32),
                               ("field_501_u32", field_501_u32),
                               ("field_502_u32", field_502_u32),
                               ("field_503_u32", field_503_u32),
                               ("field_504_u32", field_504_u32),
                               ("field_505_u32", field_505_u32),
                               ("field_506_u32", field_506_u32),
                               ("field_507_u32", field_507_u32),
                               ("field_508_u32", field_508_u32),
                               ("field_509_u32", field_509_u32),
                               ("field_510_u32", field_510_u32),
                               ("field_511_u32", field_511_u32),
                               ("field_512_u32", field_512_u32),
                               ("field_513_u32", field_513_u32),
                               ("field_514_u32", field_514_u32),
                               ("field_515_u32", field_515_u32),
                               ("field_516_u32", field_516_u32),
                               ("field_517_u32", field_517_u32),
                               ("field_518_u32", field_518_u32),
                               ("field_519_u32", field_519_u32),
                               ("field_520_u32", field_520_u32),
                               ("field_521_u32", field_521_u32),
                               ("field_522_u32", field_522_u32),
                               ("field_523_u32", field_523_u32),
                               ("field_524_u32", field_524_u32),
                               ("field_525_u32", field_525_u32),
                               ("field_526_u32", field_526_u32),
                               ("field_527_u32", field_527_u32),
                               ("field_528_u32", field_528_u32),
                               ("field_529_u32", field_529_u32),
                               ("field_530_u32", field_530_u32),
                               ("field_531_u32", field_531_u32),
                               ("field_532_u32", field_532_u32),
                               ("field_533_u32", field_533_u32),
                               ("field_534_u32", field_534_u32),
                               ("field_535_u32", field_535_u32),
                               ("field_536_u32", field_536_u32),
                               ("field_537_u32", field_537_u32), ("field_538_u32", field_538_u32),
                               ("field_539_u32", field_539_u32), ("field_540_u32", field_540_u32),
                               ("field_541_u32", field_541_u32), ("field_542_u32", field_542_u32),
                               ("field_543_u32", field_543_u32), ("field_544_u32", field_544_u32),
                               ("field_545_u32", field_545_u32), ("field_546_u32", field_546_u32),
                               ("field_547_u32", field_547_u32), ("field_548_u32", field_548_u32),
                               ("field_549_u32", field_549_u32), ("field_550_u32", field_550_u32),
                               ("field_551_u32", field_551_u32), ("field_552_u32", field_552_u32),
                               ("field_553_u32", field_553_u32), ("field_554_u32", field_554_u32),
                               ("field_555_u32", field_555_u32), ("field_556_u32", field_556_u32),
                               ("field_557_u32", field_557_u32), ("field_558_u32", field_558_u32),
                               ("field_559_u32", field_559_u32), ("field_560_u32", field_560_u32),
                               ("field_561_u32", field_561_u32), ("field_562_u32", field_562_u32),
                               ("field_563_u32", field_563_u32), ("field_564_u32", field_564_u32),
                               ("field_565_u32", field_565_u32), ("field_566_u32", field_566_u32),
                               ("field_567_u32", field_567_u32), ("field_568_u32", field_568_u32),
                               ("field_569_u32", field_569_u32), ("field_570_u32", field_570_u32),
                               ("field_571_u32", field_571_u32), ("field_572_u32", field_572_u32),
                               ("field_573_u32", field_573_u32), ("field_574_u32", field_574_u32),
                               ("field_575_u32", field_575_u32), ("field_576_u32", field_576_u32),
                               ("field_577_u32", field_577_u32), ("field_578_u32", field_578_u32),
                               ("field_579_u32", field_579_u32), ("field_580_u32", field_580_u32),
                               ("field_581_u32", field_581_u32), ("field_582_u32", field_582_u32),
                               ("field_583_u32", field_583_u32), ("field_584_u32", field_584_u32),
                               ("field_585_u32", field_585_u32), ("field_586_u32", field_586_u32),
                               ("field_587_u32", field_587_u32), ("field_588_u32", field_588_u32),
                               ("field_589_u32", field_589_u32), ("field_590_u32", field_590_u32),
                               ("field_591_u32", field_591_u32), ("field_592_u32", field_592_u32),
                               ("field_593_u32", field_593_u32), ("field_594_u32", field_594_u32),
                               ("field_595_u32", field_595_u32), ("field_596_u32", field_596_u32),
                               ("field_597_u32", field_597_u32), ("field_598_u32", field_598_u32),
                               ("field_599_u32", field_599_u32), ("field_600_u32", field_600_u32),
                               ("field_601_u32", field_601_u32), ("field_602_u32", field_602_u32),
                               ("field_603_u32", field_603_u32), ("field_604_u32", field_604_u32),
                               ("field_605_u32", field_605_u32), ("field_606_u32", field_606_u32),
                               ("field_607_u32", field_607_u32), ("field_608_u32", field_608_u32),
                               ("field_609_u32", field_609_u32), ("field_610_u32", field_610_u32),
                               ("field_611_u32", field_611_u32), ("field_612_u32", field_612_u32),
                               ("field_613_u32", field_613_u32), ("field_614_u32", field_614_u32),
                               ("field_615_u32", field_615_u32), ("field_616_u32", field_616_u32),
                               ("field_617_u32", field_617_u32), ("field_618_u32", field_618_u32),
                               ("field_619_u32", field_619_u32), ("field_620_u32", field_620_u32),
                               ("field_621_u32", field_621_u32), ("field_622_u32", field_622_u32),
                               ("field_623_u32", field_623_u32), ("field_624_u32", field_624_u32),
                               ("field_625_u32", field_625_u32), ("field_626_u32", field_626_u32),
                               ("field_627_u32", field_627_u32), ("field_628_u32", field_628_u32),
                               ("field_629_u32", field_629_u32), ("field_630_u32", field_630_u32),
                               ("field_631_u32", field_631_u32), ("field_632_u32", field_632_u32),
                               ("field_633_u32", field_633_u32), ("field_634_u32", field_634_u32),
                               ("field_635_u32", field_635_u32), ("field_636_u32", field_636_u32),
                               ("field_637_u32", field_637_u32), ("field_638_u32", field_638_u32),
                               ("field_639_u32", field_639_u32), ("field_640_u32", field_640_u32),
                               ("field_641_u32", field_641_u32), ("field_642_u32", field_642_u32),
                               ("field_643_u32", field_643_u32), ("field_644_u32", field_644_u32),
                               ("field_645_u32", field_645_u32), ("field_646_u32", field_646_u32),
                               ("field_647_u32", field_647_u32), ("field_648_u32", field_648_u32),
                               ("field_649_u32", field_649_u32), ("field_650_u32", field_650_u32),
                               ("field_651_u32", field_651_u32), ("field_652_u32", field_652_u32),
                               ("field_653_u32", field_653_u32), ("field_654_u32", field_654_u32),
                               ("field_655_u32", field_655_u32), ("field_656_u32", field_656_u32),
                               ("field_657_u32", field_657_u32), ("field_658_u32", field_658_u32),
                               ("field_659_u32", field_659_u32), ("field_660_u32", field_660_u32),
                               ("field_661_u32", field_661_u32), ("field_662_u32", field_662_u32),
                               ("field_663_u32", field_663_u32), ("field_664_u32", field_664_u32),
                               ("alt_trigger_count", alt_trigger_count),
                               ("field_665_u32", field_665_u32), ("field_666_u32", field_666_u32),
                               ("field_667_u32", field_667_u32), ("field_668_u32", field_668_u32),
                               ("field_669_u32", field_669_u32), ("field_670_u32", field_670_u32),
                               ("field_671_u32", field_671_u32), ("field_672_u32", field_672_u32),
                               ("field_673_u32", field_673_u32), ("field_674_u32", field_674_u32),
                               ("field_675_u32", field_675_u32), ("field_676_u32", field_676_u32),
                               ("field_677_u32", field_677_u32), ("field_678_u32", field_678_u32),
                               ("field_679_u32", field_679_u32), ("field_680_u32", field_680_u32),
                               ("field_681_u32", field_681_u32), ("field_682_u32", field_682_u32),
                               ("field_683_u32", field_683_u32), ("field_684_u32", field_684_u32),
                               ("field_685_u32", field_685_u32), ("field_686_u32", field_686_u32),
                               ("field_687_u32", field_687_u32), ("field_688_u32", field_688_u32),
                               ("field_689_u32", field_689_u32), ("field_690_u32", field_690_u32),
                               ("field_691_u32", field_691_u32), ("field_692_u32", field_692_u32),
                               ("field_693_u32", field_693_u32), ("field_694_u32", field_694_u32),
                               ("field_695_u32", field_695_u32), ("field_696_u32", field_696_u32),
                               ("field_697_u32", field_697_u32), ("field_698_u32", field_698_u32),
                               ("field_699_u32", field_699_u32), ("field_700_u32", field_700_u32),
                               ("field_701_u32", field_701_u32), ("field_702_u32", field_702_u32),
                               ("field_703_u32", field_703_u32), ("field_704_u32", field_704_u32),
                               ("field_705_u32", field_705_u32), ("field_706_u32", field_706_u32),
                               ("field_707_u32", field_707_u32), ("field_708_u32", field_708_u32),
                               ("field_709_u32", field_709_u32), ("field_710_u32", field_710_u32),
                               ("field_711_u32", field_711_u32), ("field_712_u32", field_712_u32),
                               ("field_713_u32", field_713_u32), ("field_714_u32", field_714_u32),
                               ("field_715_u32", field_715_u32), ("field_716_u32", field_716_u32),
                               ("field_717_u32", field_717_u32), ("field_718_u32", field_718_u32),
                               ("field_719_u32", field_719_u32), ("field_720_u32", field_720_u32),
                               ("field_721_u32", field_721_u32), ("field_722_u32", field_722_u32),
                               ("field_723_u32", field_723_u32), ("field_724_u32", field_724_u32),
                               ("field_725_u32", field_725_u32), ("field_726_u32", field_726_u32),
                               ("field_727_u32", field_727_u32), ("field_728_u32", field_728_u32)] {
                    m.insert(k.to_string(), match v {
                        Some(val) => val.to_json_value(), None => Value::Null });
                }
                m.insert("tail_pad_001".to_string(), match tail_pad_001 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("tail_pad_002".to_string(), match tail_pad_002 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("tail_pad_003".to_string(), match tail_pad_003 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("tail_pad_004".to_string(), match tail_pad_004 {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("alt_trigger_flag".to_string(), match alt_trigger_flag {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("alt_trigger_name".to_string(), match alt_trigger_name {
                    Some(s) => s.to_json_value(), None => Value::Null });
                m.insert("alt_inner_count".to_string(), match alt_inner_count {
                    Some(v) => v.to_json_value(), None => Value::Null });
                m.insert("alt_inner_name".to_string(), match alt_inner_name {
                    Some(s) => s.to_json_value(), None => Value::Null });
                m.insert("alt_inner_flag".to_string(), match alt_inner_flag {
                    Some(v) => v.to_json_value(), None => Value::Null });
                for (k, v) in [
                    ("alt_body_001", alt_body_001), ("alt_body_002", alt_body_002),
                    ("alt_body_003", alt_body_003), ("alt_body_004", alt_body_004),
                    ("alt_body_005", alt_body_005), ("alt_body_006", alt_body_006),
                    ("alt_body_007", alt_body_007), ("alt_body_008", alt_body_008),
                    ("alt_body_009", alt_body_009), ("alt_body_010", alt_body_010),
                    ("alt_body_011", alt_body_011), ("alt_body_012", alt_body_012),
                    ("alt_body_013", alt_body_013), ("alt_body_014", alt_body_014),
                    ("alt_body_015", alt_body_015), ("alt_body_016", alt_body_016),
                    ("alt_body_017", alt_body_017), ("alt_body_018", alt_body_018),
                    ("alt_body_019", alt_body_019), ("alt_body_020", alt_body_020),
                    ("alt_body_021", alt_body_021), ("alt_body_022", alt_body_022),
                    ("alt_body_023", alt_body_023), ("alt_body_024", alt_body_024),
                    ("alt_body_025", alt_body_025), ("alt_body_026", alt_body_026),
                    ("alt_body_027", alt_body_027), ("alt_body_028", alt_body_028),
                    ("alt_body_029", alt_body_029), ("alt_body_030", alt_body_030),
                    ("alt_body_031", alt_body_031), ("alt_body_032", alt_body_032),
                    ("alt_body_033", alt_body_033), ("alt_body_034", alt_body_034),
                    ("alt_body_035", alt_body_035), ("alt_body_036", alt_body_036),
                    ("alt_body_037", alt_body_037), ("alt_body_038", alt_body_038),
                    ("alt_body_039", alt_body_039), ("alt_body_040", alt_body_040),
                    ("alt_body_041", alt_body_041), ("alt_body_042", alt_body_042),
                    ("alt_body_043", alt_body_043), ("alt_body_044", alt_body_044),
                    ("alt_body_045", alt_body_045), ("alt_body_046", alt_body_046),
                    ("alt_body_047", alt_body_047), ("alt_body_048", alt_body_048),
                    ("alt_body_049", alt_body_049), ("alt_body_050", alt_body_050),
                    ("alt_body_051", alt_body_051), ("alt_body_052", alt_body_052),
                    ("alt_body_053", alt_body_053), ("alt_body_054", alt_body_054),
                    ("alt_body_055", alt_body_055), ("alt_body_056", alt_body_056),
                    ("alt_body_057", alt_body_057), ("alt_body_058", alt_body_058),
                    ("alt_body_059", alt_body_059), ("alt_body_060", alt_body_060),
                    ("alt_body_061", alt_body_061), ("alt_body_062", alt_body_062),
                    ("alt_body_063", alt_body_063), ("alt_body_064", alt_body_064),
                    ("alt_body_065", alt_body_065), ("alt_body_066", alt_body_066),
                    ("alt_body_067", alt_body_067), ("alt_body_068", alt_body_068),
                    ("alt_body_069", alt_body_069), ("alt_body_070", alt_body_070),
                    ("alt_body_071", alt_body_071), ("alt_body_072", alt_body_072),
                    ("alt_body_073", alt_body_073), ("alt_body_074", alt_body_074),
                    ("alt_body_075", alt_body_075), ("alt_body_076", alt_body_076),
                    ("alt_body_077", alt_body_077), ("alt_body_078", alt_body_078),
                    ("alt_body_079", alt_body_079), ("alt_body_080", alt_body_080),
                    ("alt_body_081", alt_body_081), ("alt_body_082", alt_body_082),
                    ("alt_body_083", alt_body_083), ("alt_body_084", alt_body_084),
                    ("alt_body_085", alt_body_085), ("alt_body_086", alt_body_086),
                    ("alt_body_087", alt_body_087), ("alt_body_088", alt_body_088),
                    ("alt_body_089", alt_body_089), ("alt_body_090", alt_body_090),
                    ("alt_body_091", alt_body_091), ("alt_body_092", alt_body_092),
                    ("alt_body_093", alt_body_093), ("alt_body_094", alt_body_094),
                    ("alt_body_095", alt_body_095), ("alt_body_096", alt_body_096),
                    ("alt_body_097", alt_body_097), ("alt_body_098", alt_body_098),
                    ("alt_body_099", alt_body_099), ("alt_body_100", alt_body_100),
                    ("alt_body_101", alt_body_101), ("alt_body_102", alt_body_102),
                    ("alt_body_103", alt_body_103), ("alt_body_104", alt_body_104),
                    ("alt_body_105", alt_body_105), ("alt_body_106", alt_body_106),
                    ("alt_body_107", alt_body_107), ("alt_body_108", alt_body_108),
                    ("alt_body_109", alt_body_109), ("alt_body_110", alt_body_110),
                    ("alt_body_111", alt_body_111), ("alt_body_112", alt_body_112),
                    ("alt_body_113", alt_body_113), ("alt_body_114", alt_body_114),
                    ("alt_body_115", alt_body_115), ("alt_body_116", alt_body_116),
                    ("alt_body_117", alt_body_117), ("alt_body_118", alt_body_118),
                    ("alt_body_119", alt_body_119), ("alt_body_120", alt_body_120),
                    ("alt_body_121", alt_body_121), ("alt_body_122", alt_body_122),
                    ("alt_body_123", alt_body_123), ("alt_body_124", alt_body_124),
                    ("alt_body_125", alt_body_125), ("alt_body_126", alt_body_126),
                    ("alt_body_127", alt_body_127), ("alt_body_128", alt_body_128),
                    ("alt_body_129", alt_body_129), ("alt_body_130", alt_body_130),
                    ("alt_body_131", alt_body_131), ("alt_body_132", alt_body_132),
                    ("alt_body_133", alt_body_133), ("alt_body_134", alt_body_134),
                    ("alt_body_135", alt_body_135), ("alt_body_136", alt_body_136),
                    ("alt_body_137", alt_body_137), ("alt_body_138", alt_body_138),
                    ("alt_body_139", alt_body_139), ("alt_body_140", alt_body_140),
                    ("alt_body_141", alt_body_141), ("alt_body_142", alt_body_142),
                    ("alt_body_143", alt_body_143), ("alt_body_144", alt_body_144),
                    ("alt_body_145", alt_body_145), ("alt_body_146", alt_body_146),
                    ("alt_body_147", alt_body_147), ("alt_body_148", alt_body_148),
                    ("alt_body_149", alt_body_149), ("alt_body_150", alt_body_150),
                    ("alt_body_151", alt_body_151), ("alt_body_152", alt_body_152),
                    ("alt_body_153", alt_body_153), ("alt_body_154", alt_body_154),
                    ("alt_body_155", alt_body_155), ("alt_body_156", alt_body_156),
                    ("alt_body_157", alt_body_157), ("alt_body_158", alt_body_158),
                    ("alt_body_159", alt_body_159), ("alt_body_160", alt_body_160),
                    ("alt_body_161", alt_body_161), ("alt_body_162", alt_body_162),
                    ("alt_body_163", alt_body_163), ("alt_body_164", alt_body_164),
                    ("alt_body_165", alt_body_165), ("alt_body_166", alt_body_166),
                    ("alt_body_167", alt_body_167), ("alt_body_168", alt_body_168),
                    ("alt_body_169", alt_body_169), ("alt_body_170", alt_body_170),
                    ("alt_body_171", alt_body_171), ("alt_body_172", alt_body_172),
                    ("alt_body_173", alt_body_173), ("alt_body_174", alt_body_174),
                    ("alt_body_175", alt_body_175), ("alt_body_176", alt_body_176),
                    ("alt_body_177", alt_body_177), ("alt_body_178", alt_body_178),
                    ("alt_body_179", alt_body_179), ("alt_body_180", alt_body_180),
                    ("alt_body_181", alt_body_181), ("alt_body_182", alt_body_182),
                    ("alt_body_183", alt_body_183), ("alt_body_184", alt_body_184),
                    ("alt_body_185", alt_body_185), ("alt_body_186", alt_body_186),
                    ("alt_body_187", alt_body_187), ("alt_body_188", alt_body_188),
                    ("alt_body_189", alt_body_189), ("alt_body_190", alt_body_190),
                    ("alt_body_191", alt_body_191), ("alt_body_192", alt_body_192),
                    ("alt_body_193", alt_body_193), ("alt_body_194", alt_body_194),
                    ("alt_body_195", alt_body_195), ("alt_body_196", alt_body_196),
                    ("alt_body_197", alt_body_197), ("alt_body_198", alt_body_198),
                    ("alt_body_199", alt_body_199), ("alt_body_200", alt_body_200),
                    ("alt_body_201", alt_body_201), ("alt_body_202", alt_body_202),
                    ("alt_body_203", alt_body_203), ("alt_body_204", alt_body_204),
                    ("alt_body_205", alt_body_205), ("alt_body_206", alt_body_206),
                    ("alt_body_207", alt_body_207), ("alt_body_208", alt_body_208),
                    ("alt_body_209", alt_body_209), ("alt_body_210", alt_body_210),
                    ("alt_body_211", alt_body_211), ("alt_body_212", alt_body_212),
                    ("alt_body_213", alt_body_213), ("alt_body_214", alt_body_214),
                    ("alt_body_215", alt_body_215), ("alt_body_216", alt_body_216),
                    ("alt_body_217", alt_body_217), ("alt_body_218", alt_body_218),
                    ("alt_body_219", alt_body_219), ("alt_body_220", alt_body_220),
                    ("alt_body_221", alt_body_221), ("alt_body_222", alt_body_222),
                    ("alt_body_223", alt_body_223), ("alt_body_224", alt_body_224),
                    ("alt_body_225", alt_body_225), ("alt_body_226", alt_body_226),
                    ("alt_body_227", alt_body_227), ("alt_body_228", alt_body_228),
                    ("alt_body_229", alt_body_229), ("alt_body_230", alt_body_230),
                    ("alt_body_231", alt_body_231), ("alt_body_232", alt_body_232),
                    ("alt_body_233", alt_body_233), ("alt_body_234", alt_body_234),
                    ("alt_body_235", alt_body_235), ("alt_body_236", alt_body_236),
                    ("alt_body_237", alt_body_237), ("alt_body_238", alt_body_238),
                    ("alt_body_239", alt_body_239), ("alt_body_240", alt_body_240),
                    ("alt_body_241", alt_body_241), ("alt_body_242", alt_body_242),
                    ("alt_body_243", alt_body_243), ("alt_body_244", alt_body_244),
                    ("alt_body_245", alt_body_245), ("alt_body_246", alt_body_246),
                    ("alt_body_247", alt_body_247), ("alt_body_248", alt_body_248),
                    ("alt_body_249", alt_body_249), ("alt_body_250", alt_body_250),
                    ("alt_body_251", alt_body_251), ("alt_body_252", alt_body_252),
                    ("alt_body_253", alt_body_253), ("alt_body_254", alt_body_254),
                    ("alt_body_255", alt_body_255), ("alt_body_256", alt_body_256),
                    ("alt_body_257", alt_body_257), ("alt_body_258", alt_body_258),
                    ("alt_body_259", alt_body_259), ("alt_body_260", alt_body_260),
                    ("alt_body_261", alt_body_261), ("alt_body_262", alt_body_262),
                    ("alt_body_263", alt_body_263), ("alt_body_264", alt_body_264),
                    ("alt_body_265", alt_body_265), ("alt_body_266", alt_body_266),
                    ("alt_body_267", alt_body_267), ("alt_body_268", alt_body_268),
                    ("alt_body_269", alt_body_269), ("alt_body_270", alt_body_270),
                    ("alt_body_271", alt_body_271), ("alt_body_272", alt_body_272),
                    ("alt_body_273", alt_body_273), ("alt_body_274", alt_body_274),
                    ("alt_body_275", alt_body_275), ("alt_body_276", alt_body_276),
                    ("alt_body_277", alt_body_277), ("alt_body_278", alt_body_278),
                    ("alt_body_279", alt_body_279), ("alt_body_280", alt_body_280),
                    ("alt_body_281", alt_body_281), ("alt_body_282", alt_body_282),
                    ("alt_body_283", alt_body_283), ("alt_body_284", alt_body_284),
                    ("alt_body_285", alt_body_285), ("alt_body_286", alt_body_286),
                    ("alt_body_287", alt_body_287), ("alt_body_288", alt_body_288),
                    ("alt_body_289", alt_body_289), ("alt_body_290", alt_body_290),
                    ("alt_body_291", alt_body_291), ("alt_body_292", alt_body_292),
                    ("alt_body_293", alt_body_293), ("alt_body_294", alt_body_294),
                    ("alt_body_295", alt_body_295), ("alt_body_296", alt_body_296),
                    ("alt_body_297", alt_body_297), ("alt_body_298", alt_body_298),
                    ("alt_body_299", alt_body_299), ("alt_body_300", alt_body_300),
                    ("alt_body_301", alt_body_301), ("alt_body_302", alt_body_302),
                    ("alt_body_303", alt_body_303), ("alt_body_304", alt_body_304),
                    ("alt_body_305", alt_body_305), ("alt_body_306", alt_body_306),
                    ("alt_body_307", alt_body_307), ("alt_body_308", alt_body_308),
                    ("alt_body_309", alt_body_309), ("alt_body_310", alt_body_310),
                    ("alt_body_311", alt_body_311), ("alt_body_312", alt_body_312),
                    ("alt_body_313", alt_body_313), ("alt_body_314", alt_body_314),
                    ("alt_body_315", alt_body_315), ("alt_body_316", alt_body_316),
                    ("alt_body_317", alt_body_317), ("alt_body_318", alt_body_318),
                    ("alt_body_319", alt_body_319), ("alt_body_320", alt_body_320),
                    ("alt_body_321", alt_body_321), ("alt_body_322", alt_body_322),
                    ("alt_body_323", alt_body_323), ("alt_body_324", alt_body_324),
                    ("alt_body_325", alt_body_325), ("alt_body_326", alt_body_326),
                    ("alt_body_327", alt_body_327), ("alt_body_328", alt_body_328),
                    ("alt_body_329", alt_body_329), ("alt_body_330", alt_body_330),
                    ("alt_body_331", alt_body_331), ("alt_body_332", alt_body_332),
                    ("alt_body_333", alt_body_333), ("alt_body_334", alt_body_334),
                    ("alt_body_335", alt_body_335), ("alt_body_336", alt_body_336),
                    ("alt_body_337", alt_body_337), ("alt_body_338", alt_body_338),
                    ("alt_body_339", alt_body_339), ("alt_body_340", alt_body_340),
                    ("alt_body_341", alt_body_341), ("alt_body_342", alt_body_342),
                    ("alt_body_343", alt_body_343), ("alt_body_344", alt_body_344),
                    ("alt_body_345", alt_body_345), ("alt_body_346", alt_body_346),
                    ("alt_body_347", alt_body_347), ("alt_body_348", alt_body_348),
                    ("alt_body_349", alt_body_349), ("alt_body_350", alt_body_350),
                    ("alt_body_351", alt_body_351), ("alt_body_352", alt_body_352),
                    ("alt_body_353", alt_body_353), ("alt_body_354", alt_body_354),
                    ("alt_body_355", alt_body_355), ("alt_body_356", alt_body_356),
                    ("alt_body_357", alt_body_357), ("alt_body_358", alt_body_358),
                    ("alt_body_359", alt_body_359), ("alt_body_360", alt_body_360),
                    ("alt_body_361", alt_body_361), ("alt_body_362", alt_body_362),
                    ("alt_body_363", alt_body_363), ("alt_body_364", alt_body_364),
                    ("alt_body_365", alt_body_365), ("alt_body_366", alt_body_366),
                    ("alt_body_367", alt_body_367), ("alt_body_368", alt_body_368),
                    ("alt_body_369", alt_body_369), ("alt_body_370", alt_body_370),
                    ("alt_body_371", alt_body_371), ("alt_body_372", alt_body_372),
                    ("alt_body_373", alt_body_373), ("alt_body_374", alt_body_374),
                    ("alt_body_375", alt_body_375), ("alt_body_376", alt_body_376),
                    ("alt_body_377", alt_body_377), ("alt_body_378", alt_body_378),
                    ("alt_body_379", alt_body_379), ("alt_body_380", alt_body_380),
                    ("alt_body_381", alt_body_381), ("alt_body_382", alt_body_382),
                    ("alt_body_383", alt_body_383), ("alt_body_384", alt_body_384),
                    ("alt_body_385", alt_body_385), ("alt_body_386", alt_body_386),
                    ("alt_body_387", alt_body_387), ("alt_body_388", alt_body_388),
                    ("alt_body_389", alt_body_389), ("alt_body_390", alt_body_390),
                    ("alt_body_391", alt_body_391), ("alt_body_392", alt_body_392),
                    ("alt_body_393", alt_body_393), ("alt_body_394", alt_body_394),
                    ("alt_body_395", alt_body_395), ("alt_body_396", alt_body_396),
                    ("alt_body_397", alt_body_397), ("alt_body_398", alt_body_398),
                    ("alt_body_399", alt_body_399), ("alt_body_400", alt_body_400),
                    ("alt_body_401", alt_body_401), ("alt_body_402", alt_body_402),
                    ("alt_body_403", alt_body_403), ("alt_body_404", alt_body_404),
                    ("alt_body_405", alt_body_405), ("alt_body_406", alt_body_406),
                    ("alt_body_407", alt_body_407), ("alt_body_408", alt_body_408),
                    ("alt_body_409", alt_body_409), ("alt_body_410", alt_body_410),
                    ("alt_body_411", alt_body_411), ("alt_body_412", alt_body_412),
                    ("alt_body_413", alt_body_413), ("alt_body_414", alt_body_414),
                    ("alt_body_415", alt_body_415), ("alt_body_416", alt_body_416),
                    ("alt_body_417", alt_body_417), ("alt_body_418", alt_body_418),
                    ("alt_body_419", alt_body_419), ("alt_body_420", alt_body_420),
                    ("alt_body_421", alt_body_421), ("alt_body_422", alt_body_422),
                    ("alt_body_423", alt_body_423), ("alt_body_424", alt_body_424),
                    ("alt_body_425", alt_body_425), ("alt_body_426", alt_body_426),
                    ("alt_body_427", alt_body_427), ("alt_body_428", alt_body_428),
                    ("alt_body_429", alt_body_429), ("alt_body_430", alt_body_430),
                    ("alt_body_431", alt_body_431), ("alt_body_432", alt_body_432),
                    ("alt_body_433", alt_body_433), ("alt_body_434", alt_body_434),
                    ("alt_body_435", alt_body_435), ("alt_body_436", alt_body_436),
                    ("alt_body_437", alt_body_437), ("alt_body_438", alt_body_438),
                    ("alt_body_439", alt_body_439), ("alt_body_440", alt_body_440),
                    ("alt_body_441", alt_body_441), ("alt_body_442", alt_body_442),
                    ("alt_body_443", alt_body_443), ("alt_body_444", alt_body_444),
                    ("alt_body_445", alt_body_445), ("alt_body_446", alt_body_446),
                    ("alt_body_447", alt_body_447), ("alt_body_448", alt_body_448),
                    ("alt_body_449", alt_body_449), ("alt_body_450", alt_body_450),
                    ("alt_body_451", alt_body_451), ("alt_body_452", alt_body_452),
                    ("alt_body_453", alt_body_453), ("alt_body_454", alt_body_454),
                    ("alt_body_455", alt_body_455), ("alt_body_456", alt_body_456),
                    ("alt_body_457", alt_body_457), ("alt_body_458", alt_body_458),
                    ("alt_body_459", alt_body_459), ("alt_body_460", alt_body_460),
                    ("alt_body_461", alt_body_461), ("alt_body_462", alt_body_462),
                    ("alt_body_463", alt_body_463), ("alt_body_464", alt_body_464),
                    ("alt_body_465", alt_body_465), ("alt_body_466", alt_body_466),
                    ("alt_body_467", alt_body_467), ("alt_body_468", alt_body_468),
                    ("alt_body_469", alt_body_469), ("alt_body_470", alt_body_470),
                    ("alt_body_471", alt_body_471), ("alt_body_472", alt_body_472),
                    ("alt_body_473", alt_body_473), ("alt_body_474", alt_body_474),
                    ("alt_body_475", alt_body_475), ("alt_body_476", alt_body_476),
                    ("alt_body_477", alt_body_477), ("alt_body_478", alt_body_478),
                    ("alt_body_479", alt_body_479), ("alt_body_480", alt_body_480),
                    ("alt_body_481", alt_body_481), ("alt_body_482", alt_body_482),
                    ("alt_body_483", alt_body_483), ("alt_body_484", alt_body_484),
                    ("alt_body_485", alt_body_485), ("alt_body_486", alt_body_486),
                    ("alt_body_487", alt_body_487), ("alt_body_488", alt_body_488),
                    ("alt_body_489", alt_body_489), ("alt_body_490", alt_body_490),
                    ("alt_body_491", alt_body_491), ("alt_body_492", alt_body_492),
                    ("alt_body_493", alt_body_493), ("alt_body_494", alt_body_494),
                    ("alt_body_495", alt_body_495), ("alt_body_496", alt_body_496),
                    ("alt_body_497", alt_body_497), ("alt_body_498", alt_body_498),
                    ("alt_body_499", alt_body_499), ("alt_body_500", alt_body_500),
                    ("alt_body_501", alt_body_501), ("alt_body_502", alt_body_502),
                    ("alt_body_503", alt_body_503), ("alt_body_504", alt_body_504),
                    ("alt_body_505", alt_body_505), ("alt_body_506", alt_body_506),
                    ("alt_body_507", alt_body_507), ("alt_body_508", alt_body_508),
                    ("alt_body_509", alt_body_509), ("alt_body_510", alt_body_510),
                    ("alt_body_511", alt_body_511), ("alt_body_512", alt_body_512),
                    ("alt_body_513", alt_body_513), ("alt_body_514", alt_body_514),
                    ("alt_body_515", alt_body_515), ("alt_body_516", alt_body_516),
                    ("alt_body_517", alt_body_517), ("alt_body_518", alt_body_518),
                    ("alt_body_519", alt_body_519), ("alt_body_520", alt_body_520),
                    ("alt_body_521", alt_body_521), ("alt_body_522", alt_body_522),
                    ("alt_body_523", alt_body_523), ("alt_body_524", alt_body_524),
                    ("alt_body_525", alt_body_525), ("alt_body_526", alt_body_526),
                    ("alt_body_527", alt_body_527), ("alt_body_528", alt_body_528),
                    ("alt_body_529", alt_body_529), ("alt_body_530", alt_body_530),
                    ("alt_body_531", alt_body_531), ("alt_body_532", alt_body_532),
                    ("alt_body_533", alt_body_533), ("alt_body_534", alt_body_534),
                    ("alt_body_535", alt_body_535), ("alt_body_536", alt_body_536),
                    ("alt_body_537", alt_body_537), ("alt_body_538", alt_body_538),
                    ("alt_body_539", alt_body_539), ("alt_body_540", alt_body_540),
                    ("alt_body_541", alt_body_541), ("alt_body_542", alt_body_542),
                    ("alt_body_543", alt_body_543), ("alt_body_544", alt_body_544),
                    ("alt_body_545", alt_body_545), ("alt_body_546", alt_body_546),
                    ("alt_body_547", alt_body_547), ("alt_body_548", alt_body_548),
                    ("alt_body_549", alt_body_549), ("alt_body_550", alt_body_550),
                    ("alt_body_551", alt_body_551), ("alt_body_552", alt_body_552),
                    ("alt_body_553", alt_body_553), ("alt_body_554", alt_body_554),
                    ("alt_body_555", alt_body_555), ("alt_body_556", alt_body_556),
                    ("alt_body_557", alt_body_557), ("alt_body_558", alt_body_558),
                    ("alt_body_559", alt_body_559), ("alt_body_560", alt_body_560),
                    ("alt_body_561", alt_body_561), ("alt_body_562", alt_body_562),
                    ("alt_body_563", alt_body_563), ("alt_body_564", alt_body_564),
                    ("alt_body_565", alt_body_565), ("alt_body_566", alt_body_566),
                    ("alt_body_567", alt_body_567), ("alt_body_568", alt_body_568),
                    ("alt_body_569", alt_body_569), ("alt_body_570", alt_body_570),
                    ("alt_body_571", alt_body_571), ("alt_body_572", alt_body_572),
                    ("alt_body_573", alt_body_573), ("alt_body_574", alt_body_574),
                    ("alt_body_575", alt_body_575), ("alt_body_576", alt_body_576),
                    ("alt_body_577", alt_body_577), ("alt_body_578", alt_body_578),
                    ("alt_body_579", alt_body_579), ("alt_body_580", alt_body_580),
                    ("alt_body_581", alt_body_581), ("alt_body_582", alt_body_582),
                    ("alt_body_583", alt_body_583), ("alt_body_584", alt_body_584),
                    ("alt_body_585", alt_body_585), ("alt_body_586", alt_body_586),
                    ("alt_body_587", alt_body_587), ("alt_body_588", alt_body_588),
                    ("alt_body_589", alt_body_589), ("alt_body_590", alt_body_590),
                    ("alt_body_591", alt_body_591), ("alt_body_592", alt_body_592),
                    ("alt_body_593", alt_body_593), ("alt_body_594", alt_body_594),
                    ("alt_body_595", alt_body_595), ("alt_body_596", alt_body_596),
                    ("alt_body_597", alt_body_597), ("alt_body_598", alt_body_598),
                    ("alt_body_599", alt_body_599), ("alt_body_600", alt_body_600),
                    ("alt_body_601", alt_body_601), ("alt_body_602", alt_body_602),
                    ("alt_body_603", alt_body_603), ("alt_body_604", alt_body_604),
                    ("alt_body_605", alt_body_605), ("alt_body_606", alt_body_606),
                    ("alt_body_607", alt_body_607), ("alt_body_608", alt_body_608),
                    ("alt_body_609", alt_body_609), ("alt_body_610", alt_body_610),
                    ("alt_body_611", alt_body_611), ("alt_body_612", alt_body_612),
                    ("alt_body_613", alt_body_613), ("alt_body_614", alt_body_614),
                    ("alt_body_615", alt_body_615), ("alt_body_616", alt_body_616),
                    ("alt_body_617", alt_body_617), ("alt_body_618", alt_body_618),
                    ("alt_body_619", alt_body_619), ("alt_body_620", alt_body_620),
                    ("alt_body_621", alt_body_621), ("alt_body_622", alt_body_622),
                    ("alt_body_623", alt_body_623), ("alt_body_624", alt_body_624),
                    ("alt_body_625", alt_body_625), ("alt_body_626", alt_body_626),
                    ("alt_body_627", alt_body_627), ("alt_body_628", alt_body_628),
                    ("alt_body_629", alt_body_629), ("alt_body_630", alt_body_630),
                    ("alt_body_631", alt_body_631), ("alt_body_632", alt_body_632),
                    ("alt_body_633", alt_body_633), ("alt_body_634", alt_body_634),
                    ("alt_body_635", alt_body_635), ("alt_body_636", alt_body_636),
                    ("alt_body_637", alt_body_637), ("alt_body_638", alt_body_638),
                    ("alt_body_639", alt_body_639), ("alt_body_640", alt_body_640),
                    ("alt_body_641", alt_body_641), ("alt_body_642", alt_body_642),
                    ("alt_body_643", alt_body_643), ("alt_body_644", alt_body_644),
                    ("alt_body_645", alt_body_645), ("alt_body_646", alt_body_646),
                    ("alt_body_647", alt_body_647), ("alt_body_648", alt_body_648),
                    ("alt_body_649", alt_body_649), ("alt_body_650", alt_body_650),
                    ("alt_body_651", alt_body_651), ("alt_body_652", alt_body_652),
                    ("alt_body_653", alt_body_653), ("alt_body_654", alt_body_654),
                    ("alt_body_655", alt_body_655), ("alt_body_656", alt_body_656),
                    ("alt_body_657", alt_body_657), ("alt_body_658", alt_body_658),
                    ("alt_body_659", alt_body_659), ("alt_body_660", alt_body_660),
                    ("alt_body_661", alt_body_661), ("alt_body_662", alt_body_662),
                    ("alt_body_663", alt_body_663), ("alt_body_664", alt_body_664),
                    ("alt_body_665", alt_body_665), ("alt_body_666", alt_body_666),
                    ("alt_body_667", alt_body_667), ("alt_body_668", alt_body_668),
                    ("alt_body_669", alt_body_669), ("alt_body_670", alt_body_670),
                    ("alt_body_671", alt_body_671), ("alt_body_672", alt_body_672),
                    ("alt_body_673", alt_body_673), ("alt_body_674", alt_body_674),
                    ("alt_body_675", alt_body_675), ("alt_body_676", alt_body_676),
                    ("alt_body_677", alt_body_677), ("alt_body_678", alt_body_678),
                    ("alt_body_679", alt_body_679), ("alt_body_680", alt_body_680),
                    ("alt_body_681", alt_body_681), ("alt_body_682", alt_body_682),
                    ("alt_body_683", alt_body_683), ("alt_body_684", alt_body_684),
                    ("alt_body_685", alt_body_685), ("alt_body_686", alt_body_686),
                    ("alt_body_687", alt_body_687), ("alt_body_688", alt_body_688),
                    ("alt_body_689", alt_body_689), ("alt_body_690", alt_body_690),
                    ("alt_body_691", alt_body_691), ("alt_body_692", alt_body_692),
                    ("alt_body_693", alt_body_693), ("alt_body_694", alt_body_694),
                    ("alt_body_695", alt_body_695), ("alt_body_696", alt_body_696),
                    ("alt_body_697", alt_body_697), ("alt_body_698", alt_body_698),
                    ("alt_body_699", alt_body_699), ("alt_body_700", alt_body_700),
                    ("alt_body_701", alt_body_701), ("alt_body_702", alt_body_702),
                    ("alt_body_703", alt_body_703), ("alt_body_704", alt_body_704),
                    ("alt_body_705", alt_body_705), ("alt_body_706", alt_body_706),
                    ("alt_body_707", alt_body_707), ("alt_body_708", alt_body_708),
                    ("alt_body_709", alt_body_709), ("alt_body_710", alt_body_710),
                    ("alt_body_711", alt_body_711), ("alt_body_712", alt_body_712),
                    ("alt_body_713", alt_body_713), ("alt_body_714", alt_body_714),
                    ("alt_body_715", alt_body_715), ("alt_body_716", alt_body_716),
                    ("alt_body_717", alt_body_717), ("alt_body_718", alt_body_718),
                    ("alt_body_719", alt_body_719), ("alt_body_720", alt_body_720),
                    ("alt_body_721", alt_body_721), ("alt_body_722", alt_body_722),
                    ("alt_body_723", alt_body_723), ("alt_body_724", alt_body_724),
                    ("alt_body_725", alt_body_725), ("alt_body_726", alt_body_726),
                    ("alt_body_727", alt_body_727), ("alt_body_728", alt_body_728),
                    ("alt_body_729", alt_body_729), ("alt_body_730", alt_body_730),
                    ("alt_body_731", alt_body_731), ("alt_body_732", alt_body_732),
                    ("alt_body_733", alt_body_733), ("alt_body_734", alt_body_734),
                    ("alt_body_735", alt_body_735), ("alt_body_736", alt_body_736),
                    ("alt_body_737", alt_body_737), ("alt_body_738", alt_body_738),
                    ("alt_body_739", alt_body_739), ("alt_body_740", alt_body_740),
                    ("alt_body_741", alt_body_741), ("alt_body_742", alt_body_742),
                    ("alt_body_743", alt_body_743), ("alt_body_744", alt_body_744),
                    ("alt_body_745", alt_body_745), ("alt_body_746", alt_body_746),
                    ("alt_body_747", alt_body_747), ("alt_body_748", alt_body_748),
                    ("alt_body_749", alt_body_749), ("alt_body_750", alt_body_750),
                    ("alt_body_751", alt_body_751), ("alt_body_752", alt_body_752),
                    ("alt_body_753", alt_body_753), ("alt_body_754", alt_body_754),
                    ("alt_body_755", alt_body_755), ("alt_body_756", alt_body_756),
                    ("alt_body_757", alt_body_757), ("alt_body_758", alt_body_758),
                    ("alt_body_759", alt_body_759), ("alt_body_760", alt_body_760),
                    ("alt_body_761", alt_body_761), ("alt_body_762", alt_body_762),
                    ("alt_body_763", alt_body_763), ("alt_body_764", alt_body_764),
                    ("alt_body_765", alt_body_765), ("alt_body_766", alt_body_766),
                    ("alt_body_767", alt_body_767), ("alt_body_768", alt_body_768),
                    ("alt_body_769", alt_body_769), ("alt_body_770", alt_body_770),
                    ("alt_body_771", alt_body_771), ("alt_body_772", alt_body_772),
                    ("alt_body_773", alt_body_773), ("alt_body_774", alt_body_774),
                    ("alt_body_775", alt_body_775), ("alt_body_776", alt_body_776),
                    ("alt_body_777", alt_body_777), ("alt_body_778", alt_body_778),
                    ("alt_body_779", alt_body_779), ("alt_body_780", alt_body_780),
                    ("alt_body_781", alt_body_781), ("alt_body_782", alt_body_782),
                    ("alt_body_783", alt_body_783), ("alt_body_784", alt_body_784),
                    ("alt_body_785", alt_body_785), ("alt_body_786", alt_body_786),
                    ("alt_body_787", alt_body_787), ("alt_body_788", alt_body_788),
                    ("alt_body_789", alt_body_789), ("alt_body_790", alt_body_790),
                    ("alt_body_791", alt_body_791), ("alt_body_792", alt_body_792),
                    ("alt_body_793", alt_body_793), ("alt_body_794", alt_body_794),
                    ("alt_body_795", alt_body_795), ("alt_body_796", alt_body_796),
                    ("alt_body_797", alt_body_797), ("alt_body_798", alt_body_798),
                    ("alt_body_799", alt_body_799), ("alt_body_800", alt_body_800),
                    ("alt_body_801", alt_body_801), ("alt_body_802", alt_body_802),
                    ("alt_body_803", alt_body_803), ("alt_body_804", alt_body_804),
                    ("alt_body_805", alt_body_805), ("alt_body_806", alt_body_806),
                    ("alt_body_807", alt_body_807), ("alt_body_808", alt_body_808),
                    ("alt_body_809", alt_body_809), ("alt_body_810", alt_body_810),
                    ("alt_body_811", alt_body_811), ("alt_body_812", alt_body_812),
                    ("alt_body_813", alt_body_813), ("alt_body_814", alt_body_814),
                    ("alt_body_815", alt_body_815), ("alt_body_816", alt_body_816),
                    ("alt_body_817", alt_body_817), ("alt_body_818", alt_body_818),
                    ("alt_body_819", alt_body_819), ("alt_body_820", alt_body_820),
                    ("alt_body_821", alt_body_821), ("alt_body_822", alt_body_822),
                    ("alt_body_823", alt_body_823), ("alt_body_824", alt_body_824),
                    ("alt_body_825", alt_body_825), ("alt_body_826", alt_body_826),
                    ("alt_body_827", alt_body_827), ("alt_body_828", alt_body_828),
                    ("alt_body_829", alt_body_829), ("alt_body_830", alt_body_830),
                    ("alt_body_831", alt_body_831), ("alt_body_832", alt_body_832),
                    ("alt_body_833", alt_body_833), ("alt_body_834", alt_body_834),
                    ("alt_body_835", alt_body_835), ("alt_body_836", alt_body_836),
                    ("alt_body_837", alt_body_837), ("alt_body_838", alt_body_838),
                    ("alt_body_839", alt_body_839), ("alt_body_840", alt_body_840),
                    ("alt_body_841", alt_body_841), ("alt_body_842", alt_body_842),
                    ("alt_body_843", alt_body_843), ("alt_body_844", alt_body_844),
                    ("alt_body_845", alt_body_845), ("alt_body_846", alt_body_846),
                    ("alt_body_847", alt_body_847), ("alt_body_848", alt_body_848),
                    ("alt_body_849", alt_body_849), ("alt_body_850", alt_body_850),
                    ("alt_body_851", alt_body_851), ("alt_body_852", alt_body_852),
                    ("alt_body_853", alt_body_853), ("alt_body_854", alt_body_854),
                    ("alt_body_855", alt_body_855), ("alt_body_856", alt_body_856),
                    ("alt_body_857", alt_body_857), ("alt_body_858", alt_body_858),
                    ("alt_body_859", alt_body_859), ("alt_body_860", alt_body_860),
                    ("alt_body_861", alt_body_861), ("alt_body_862", alt_body_862),
                    ("alt_body_863", alt_body_863), ("alt_body_864", alt_body_864),
                    ("alt_body_865", alt_body_865), ("alt_body_866", alt_body_866),
                    ("alt_body_867", alt_body_867), ("alt_body_868", alt_body_868),
                    ("alt_body_869", alt_body_869), ("alt_body_870", alt_body_870),
                    ("alt_body_871", alt_body_871), ("alt_body_872", alt_body_872),
                    ("alt_body_873", alt_body_873), ("alt_body_874", alt_body_874),
                    ("alt_body_875", alt_body_875), ("alt_body_876", alt_body_876),
                    ("alt_body_877", alt_body_877), ("alt_body_878", alt_body_878),
                    ("alt_body_879", alt_body_879), ("alt_body_880", alt_body_880),
                    ("alt_body_881", alt_body_881), ("alt_body_882", alt_body_882),
                    ("alt_body_883", alt_body_883), ("alt_body_884", alt_body_884),
                    ("alt_body_885", alt_body_885), ("alt_body_886", alt_body_886),
                    ("alt_body_887", alt_body_887), ("alt_body_888", alt_body_888),
                    ("alt_body_889", alt_body_889), ("alt_body_890", alt_body_890),
                    ("alt_body_891", alt_body_891), ("alt_body_892", alt_body_892),
                    ("alt_body_893", alt_body_893), ("alt_body_894", alt_body_894),
                    ("alt_body_895", alt_body_895), ("alt_body_896", alt_body_896),
                    ("alt_body_897", alt_body_897), ("alt_body_898", alt_body_898),
                    ("alt_body_899", alt_body_899), ("alt_body_900", alt_body_900),
                    ("alt_body_901", alt_body_901), ("alt_body_902", alt_body_902),
                    ("alt_body_903", alt_body_903), ("alt_body_904", alt_body_904),
                    ("alt_body_905", alt_body_905), ("alt_body_906", alt_body_906),
                    ("alt_body_907", alt_body_907), ("alt_body_908", alt_body_908),
                    ("alt_body_909", alt_body_909), ("alt_body_910", alt_body_910),
                    ("alt_body_911", alt_body_911), ("alt_body_912", alt_body_912),
                    ("alt_body_913", alt_body_913), ("alt_body_914", alt_body_914),
                    ("alt_body_915", alt_body_915), ("alt_body_916", alt_body_916),
                    ("alt_body_917", alt_body_917), ("alt_body_918", alt_body_918),
                    ("alt_body_919", alt_body_919), ("alt_body_920", alt_body_920),
                    ("alt_body_921", alt_body_921), ("alt_body_922", alt_body_922),
                    ("alt_body_923", alt_body_923), ("alt_body_924", alt_body_924),
                    ("alt_body_925", alt_body_925), ("alt_body_926", alt_body_926),
                    ("alt_body_927", alt_body_927), ("alt_body_928", alt_body_928),
                    ("alt_body_929", alt_body_929), ("alt_body_930", alt_body_930),
                    ("alt_body_931", alt_body_931), ("alt_body_932", alt_body_932),
                    ("alt_body_933", alt_body_933), ("alt_body_934", alt_body_934),
                    ("alt_body_935", alt_body_935), ("alt_body_936", alt_body_936),
                    ("alt_body_937", alt_body_937), ("alt_body_938", alt_body_938),
                    ("alt_body_939", alt_body_939), ("alt_body_940", alt_body_940),
                    ("alt_body_941", alt_body_941), ("alt_body_942", alt_body_942),
                    ("alt_body_943", alt_body_943), ("alt_body_944", alt_body_944),
                    ("alt_body_945", alt_body_945), ("alt_body_946", alt_body_946),
                    ("alt_body_947", alt_body_947), ("alt_body_948", alt_body_948),
                    ("alt_body_949", alt_body_949), ("alt_body_950", alt_body_950),
                    ("alt_body_951", alt_body_951), ("alt_body_952", alt_body_952),
                    ("alt_body_953", alt_body_953), ("alt_body_954", alt_body_954),
                    ("alt_body_955", alt_body_955), ("alt_body_956", alt_body_956),
                    ("alt_body_957", alt_body_957), ("alt_body_958", alt_body_958),
                    ("alt_body_959", alt_body_959), ("alt_body_960", alt_body_960),
                    ("alt_body_961", alt_body_961), ("alt_body_962", alt_body_962),
                    ("alt_body_963", alt_body_963), ("alt_body_964", alt_body_964),
                    ("alt_body_965", alt_body_965), ("alt_body_966", alt_body_966),
                    ("alt_body_967", alt_body_967), ("alt_body_968", alt_body_968),
                    ("alt_body_969", alt_body_969), ("alt_body_970", alt_body_970),
                    ("alt_body_971", alt_body_971), ("alt_body_972", alt_body_972),
                    ("alt_body_973", alt_body_973), ("alt_body_974", alt_body_974),
                    ("alt_body_975", alt_body_975), ("alt_body_976", alt_body_976),
                    ("alt_body_977", alt_body_977), ("alt_body_978", alt_body_978),
                    ("alt_body_979", alt_body_979), ("alt_body_980", alt_body_980),
                    ("alt_body_981", alt_body_981), ("alt_body_982", alt_body_982),
                    ("alt_body_983", alt_body_983), ("alt_body_984", alt_body_984),
                    ("alt_body_985", alt_body_985), ("alt_body_986", alt_body_986),
                    ("alt_body_987", alt_body_987), ("alt_body_988", alt_body_988),
                    ("alt_body_989", alt_body_989), ("alt_body_990", alt_body_990),
                    ("alt_body_991", alt_body_991), ("alt_body_992", alt_body_992),
                    ("alt_body_993", alt_body_993), ("alt_body_994", alt_body_994),
                    ("alt_body_995", alt_body_995), ("alt_body_996", alt_body_996),
                    ("alt_body_997", alt_body_997), ("alt_body_998", alt_body_998),
                    ("alt_body_999", alt_body_999), ("alt_body_1000", alt_body_1000),
                    ("alt_body_1001", alt_body_1001), ("alt_body_1002", alt_body_1002),
                    ("alt_body_1003", alt_body_1003), ("alt_body_1004", alt_body_1004),
                    ("alt_body_1005", alt_body_1005), ("alt_body_1006", alt_body_1006),
                    ("alt_body_1007", alt_body_1007), ("alt_body_1008", alt_body_1008),
                    ("alt_body_1009", alt_body_1009), ("alt_body_1010", alt_body_1010),
                    ("alt_body_1011", alt_body_1011), ("alt_body_1012", alt_body_1012),
                    ("alt_body_1013", alt_body_1013), ("alt_body_1014", alt_body_1014),
                    ("alt_body_1015", alt_body_1015), ("alt_body_1016", alt_body_1016),
                    ("alt_body_1017", alt_body_1017), ("alt_body_1018", alt_body_1018),
                    ("alt_body_1019", alt_body_1019), ("alt_body_1020", alt_body_1020),
                    ("alt_body_1021", alt_body_1021), ("alt_body_1022", alt_body_1022),
                    ("alt_body_1023", alt_body_1023), ("alt_body_1024", alt_body_1024),
                    ("alt_body_1025", alt_body_1025), ("alt_body_1026", alt_body_1026),
                    ("alt_body_1027", alt_body_1027), ("alt_body_1028", alt_body_1028),
                    ("alt_body_1029", alt_body_1029), ("alt_body_1030", alt_body_1030),
                    ("alt_body_1031", alt_body_1031), ("alt_body_1032", alt_body_1032),
                    ("alt_body_1033", alt_body_1033), ("alt_body_1034", alt_body_1034),
                    ("alt_body_1035", alt_body_1035), ("alt_body_1036", alt_body_1036),
                    ("alt_body_1037", alt_body_1037), ("alt_body_1038", alt_body_1038),
                    ("alt_body_1039", alt_body_1039), ("alt_body_1040", alt_body_1040),
                    ("alt_body_1041", alt_body_1041), ("alt_body_1042", alt_body_1042),
                    ("alt_body_1043", alt_body_1043), ("alt_body_1044", alt_body_1044),
                    ("alt_body_1045", alt_body_1045), ("alt_body_1046", alt_body_1046),
                    ("alt_body_1047", alt_body_1047), ("alt_body_1048", alt_body_1048),
                    ("alt_body_1049", alt_body_1049), ("alt_body_1050", alt_body_1050),
                    ("alt_body_1051", alt_body_1051), ("alt_body_1052", alt_body_1052),
                    ("alt_body_1053", alt_body_1053), ("alt_body_1054", alt_body_1054),
                    ("alt_body_1055", alt_body_1055), ("alt_body_1056", alt_body_1056),
                    ("alt_body_1057", alt_body_1057), ("alt_body_1058", alt_body_1058),
                    ("alt_body_1059", alt_body_1059), ("alt_body_1060", alt_body_1060),
                    ("alt_body_1061", alt_body_1061), ("alt_body_1062", alt_body_1062),
                    ("alt_body_1063", alt_body_1063), ("alt_body_1064", alt_body_1064),
                    ("alt_body_1065", alt_body_1065), ("alt_body_1066", alt_body_1066),
                    ("alt_body_1067", alt_body_1067), ("alt_body_1068", alt_body_1068),
                    ("alt_body_1069", alt_body_1069), ("alt_body_1070", alt_body_1070),
                    ("alt_body_1071", alt_body_1071), ("alt_body_1072", alt_body_1072),
                    ("alt_body_1073", alt_body_1073), ("alt_body_1074", alt_body_1074),
                    ("alt_body_1075", alt_body_1075), ("alt_body_1076", alt_body_1076),
                    ("alt_body_1077", alt_body_1077), ("alt_body_1078", alt_body_1078),
                    ("alt_body_1079", alt_body_1079), ("alt_body_1080", alt_body_1080),
                    ("alt_body_1081", alt_body_1081), ("alt_body_1082", alt_body_1082),
                    ("alt_body_1083", alt_body_1083), ("alt_body_1084", alt_body_1084),
                    ("alt_body_1085", alt_body_1085), ("alt_body_1086", alt_body_1086),
                    ("alt_body_1087", alt_body_1087), ("alt_body_1088", alt_body_1088),
                    ("alt_body_1089", alt_body_1089), ("alt_body_1090", alt_body_1090),
                    ("alt_body_1091", alt_body_1091), ("alt_body_1092", alt_body_1092),
                    ("alt_body_1093", alt_body_1093), ("alt_body_1094", alt_body_1094),
                    ("alt_body_1095", alt_body_1095), ("alt_body_1096", alt_body_1096),
                    ("alt_body_1097", alt_body_1097), ("alt_body_1098", alt_body_1098),
                    ("alt_body_1099", alt_body_1099), ("alt_body_1100", alt_body_1100),
                    ("alt_body_1101", alt_body_1101), ("alt_body_1102", alt_body_1102),
                    ("alt_body_1103", alt_body_1103), ("alt_body_1104", alt_body_1104),
                    ("alt_body_1105", alt_body_1105), ("alt_body_1106", alt_body_1106),
                    ("alt_body_1107", alt_body_1107), ("alt_body_1108", alt_body_1108),
                    ("alt_body_1109", alt_body_1109), ("alt_body_1110", alt_body_1110),
                    ("alt_body_1111", alt_body_1111), ("alt_body_1112", alt_body_1112),
                    ("alt_body_1113", alt_body_1113), ("alt_body_1114", alt_body_1114),
                    ("alt_body_1115", alt_body_1115), ("alt_body_1116", alt_body_1116),
                    ("alt_body_1117", alt_body_1117), ("alt_body_1118", alt_body_1118),
                    ("alt_body_1119", alt_body_1119), ("alt_body_1120", alt_body_1120),
                    ("alt_body_1121", alt_body_1121), ("alt_body_1122", alt_body_1122),
                    ("alt_body_1123", alt_body_1123), ("alt_body_1124", alt_body_1124),
                    ("alt_body_1125", alt_body_1125), ("alt_body_1126", alt_body_1126),
                    ("alt_body_1127", alt_body_1127), ("alt_body_1128", alt_body_1128),
                    ("alt_body_1129", alt_body_1129), ("alt_body_1130", alt_body_1130),
                    ("alt_body_1131", alt_body_1131), ("alt_body_1132", alt_body_1132),
                    ("alt_body_1133", alt_body_1133), ("alt_body_1134", alt_body_1134),
                    ("alt_body_1135", alt_body_1135), ("alt_body_1136", alt_body_1136),
                    ("alt_body_1137", alt_body_1137), ("alt_body_1138", alt_body_1138),
                    ("alt_body_1139", alt_body_1139), ("alt_body_1140", alt_body_1140),
                    ("alt_body_1141", alt_body_1141), ("alt_body_1142", alt_body_1142),
                    ("alt_body_1143", alt_body_1143), ("alt_body_1144", alt_body_1144),
                    ("alt_body_1145", alt_body_1145), ("alt_body_1146", alt_body_1146),
                    ("alt_body_1147", alt_body_1147), ("alt_body_1148", alt_body_1148),
                    ("alt_body_1149", alt_body_1149), ("alt_body_1150", alt_body_1150),
                    ("alt_body_1151", alt_body_1151), ("alt_body_1152", alt_body_1152),
                    ("alt_body_1153", alt_body_1153), ("alt_body_1154", alt_body_1154),
                    ("alt_body_1155", alt_body_1155), ("alt_body_1156", alt_body_1156),
                    ("alt_body_1157", alt_body_1157), ("alt_body_1158", alt_body_1158),
                    ("alt_body_1159", alt_body_1159), ("alt_body_1160", alt_body_1160),
                    ("alt_body_1161", alt_body_1161), ("alt_body_1162", alt_body_1162),
                    ("alt_body_1163", alt_body_1163), ("alt_body_1164", alt_body_1164),
                    ("alt_body_1165", alt_body_1165), ("alt_body_1166", alt_body_1166),
                    ("alt_body_1167", alt_body_1167), ("alt_body_1168", alt_body_1168),
                    ("alt_body_1169", alt_body_1169), ("alt_body_1170", alt_body_1170),
                    ("alt_body_1171", alt_body_1171), ("alt_body_1172", alt_body_1172),
                    ("alt_body_1173", alt_body_1173), ("alt_body_1174", alt_body_1174),
                    ("alt_body_1175", alt_body_1175), ("alt_body_1176", alt_body_1176),
                    ("alt_body_1177", alt_body_1177), ("alt_body_1178", alt_body_1178),
                    ("alt_body_1179", alt_body_1179), ("alt_body_1180", alt_body_1180),
                    ("alt_body_1181", alt_body_1181), ("alt_body_1182", alt_body_1182),
                    ("alt_body_1183", alt_body_1183), ("alt_body_1184", alt_body_1184),
                    ("alt_body_1185", alt_body_1185), ("alt_body_1186", alt_body_1186),
                    ("alt_body_1187", alt_body_1187), ("alt_body_1188", alt_body_1188),
                    ("alt_body_1189", alt_body_1189), ("alt_body_1190", alt_body_1190),
                    ("alt_body_1191", alt_body_1191), ("alt_body_1192", alt_body_1192),
                    ("alt_body_1193", alt_body_1193), ("alt_body_1194", alt_body_1194),
                    ("alt_body_1195", alt_body_1195), ("alt_body_1196", alt_body_1196),
                    ("alt_body_1197", alt_body_1197), ("alt_body_1198", alt_body_1198),
                    ("alt_body_1199", alt_body_1199), ("alt_body_1200", alt_body_1200),
                    ("alt_body_1201", alt_body_1201), ("alt_body_1202", alt_body_1202),
                    ("alt_body_1203", alt_body_1203), ("alt_body_1204", alt_body_1204),
                    ("alt_body_1205", alt_body_1205), ("alt_body_1206", alt_body_1206),
                    ("alt_body_1207", alt_body_1207), ("alt_body_1208", alt_body_1208),
                    ("alt_body_1209", alt_body_1209), ("alt_body_1210", alt_body_1210),
                    ("alt_body_1211", alt_body_1211), ("alt_body_1212", alt_body_1212),
                    ("alt_body_1213", alt_body_1213), ("alt_body_1214", alt_body_1214),
                    ("alt_body_1215", alt_body_1215), ("alt_body_1216", alt_body_1216),
                    ("alt_body_1217", alt_body_1217), ("alt_body_1218", alt_body_1218),
                    ("alt_body_1219", alt_body_1219), ("alt_body_1220", alt_body_1220),
                    ("alt_body_1221", alt_body_1221), ("alt_body_1222", alt_body_1222),
                    ("alt_body_1223", alt_body_1223), ("alt_body_1224", alt_body_1224),
                    ("alt_body_1225", alt_body_1225), ("alt_body_1226", alt_body_1226),
                    ("alt_body_1227", alt_body_1227), ("alt_body_1228", alt_body_1228),
                    ("alt_body_1229", alt_body_1229), ("alt_body_1230", alt_body_1230),
                    ("alt_body_1231", alt_body_1231), ("alt_body_1232", alt_body_1232),
                    ("alt_body_1233", alt_body_1233), ("alt_body_1234", alt_body_1234),
                    ("alt_body_1235", alt_body_1235), ("alt_body_1236", alt_body_1236),
                    ("alt_body_1237", alt_body_1237), ("alt_body_1238", alt_body_1238),
                    ("alt_body_1239", alt_body_1239), ("alt_body_1240", alt_body_1240),
                    ("alt_body_1241", alt_body_1241), ("alt_body_1242", alt_body_1242),
                    ("alt_body_1243", alt_body_1243), ("alt_body_1244", alt_body_1244),
                    ("alt_body_1245", alt_body_1245), ("alt_body_1246", alt_body_1246),
                    ("alt_body_1247", alt_body_1247), ("alt_body_1248", alt_body_1248),
                    ("alt_body_1249", alt_body_1249), ("alt_body_1250", alt_body_1250),
                    ("alt_body_1251", alt_body_1251), ("alt_body_1252", alt_body_1252),
                    ("alt_body_1253", alt_body_1253), ("alt_body_1254", alt_body_1254),
                    ("alt_body_1255", alt_body_1255), ("alt_body_1256", alt_body_1256),
                    ("alt_body_1257", alt_body_1257), ("alt_body_1258", alt_body_1258),
                    ("alt_body_1259", alt_body_1259), ("alt_body_1260", alt_body_1260),
                    ("alt_body_1261", alt_body_1261), ("alt_body_1262", alt_body_1262),
                    ("alt_body_1263", alt_body_1263), ("alt_body_1264", alt_body_1264),
                    ("alt_body_1265", alt_body_1265), ("alt_body_1266", alt_body_1266),
                    ("alt_body_1267", alt_body_1267), ("alt_body_1268", alt_body_1268),
                    ("alt_body_1269", alt_body_1269), ("alt_body_1270", alt_body_1270),
                    ("alt_body_1271", alt_body_1271), ("alt_body_1272", alt_body_1272),
                    ("alt_body_1273", alt_body_1273), ("alt_body_1274", alt_body_1274),
                    ("alt_body_1275", alt_body_1275), ("alt_body_1276", alt_body_1276),
                    ("alt_body_1277", alt_body_1277), ("alt_body_1278", alt_body_1278),
                    ("alt_body_1279", alt_body_1279), ("alt_body_1280", alt_body_1280),
                    ("alt_body_1281", alt_body_1281), ("alt_body_1282", alt_body_1282),
                    ("alt_body_1283", alt_body_1283), ("alt_body_1284", alt_body_1284),
                    ("alt_body_1285", alt_body_1285), ("alt_body_1286", alt_body_1286),
                    ("alt_body_1287", alt_body_1287), ("alt_body_1288", alt_body_1288),
                    ("alt_body_1289", alt_body_1289), ("alt_body_1290", alt_body_1290),
                    ("alt_body_1291", alt_body_1291), ("alt_body_1292", alt_body_1292),
                    ("alt_body_1293", alt_body_1293), ("alt_body_1294", alt_body_1294),
                    ("alt_body_1295", alt_body_1295), ("alt_body_1296", alt_body_1296),
                    ("alt_body_1297", alt_body_1297), ("alt_body_1298", alt_body_1298),
                    ("alt_body_1299", alt_body_1299), ("alt_body_1300", alt_body_1300),
                    ("alt_body_1301", alt_body_1301), ("alt_body_1302", alt_body_1302),
                    ("alt_body_1303", alt_body_1303), ("alt_body_1304", alt_body_1304),
                    ("alt_body_1305", alt_body_1305), ("alt_body_1306", alt_body_1306),
                    ("alt_body_1307", alt_body_1307), ("alt_body_1308", alt_body_1308),
                    ("alt_body_1309", alt_body_1309), ("alt_body_1310", alt_body_1310),
                    ("alt_body_1311", alt_body_1311), ("alt_body_1312", alt_body_1312),
                    ("alt_body_1313", alt_body_1313), ("alt_body_1314", alt_body_1314),
                    ("alt_body_1315", alt_body_1315), ("alt_body_1316", alt_body_1316),
                    ("alt_body_1317", alt_body_1317), ("alt_body_1318", alt_body_1318),
                    ("alt_body_1319", alt_body_1319), ("alt_body_1320", alt_body_1320),
                    ("alt_body_1321", alt_body_1321), ("alt_body_1322", alt_body_1322),
                    ("alt_body_1323", alt_body_1323), ("alt_body_1324", alt_body_1324),
                    ("alt_body_1325", alt_body_1325), ("alt_body_1326", alt_body_1326),
                    ("alt_body_1327", alt_body_1327), ("alt_body_1328", alt_body_1328),
                    ("alt_body_1329", alt_body_1329), ("alt_body_1330", alt_body_1330),
                    ("alt_body_1331", alt_body_1331), ("alt_body_1332", alt_body_1332),
                    ("alt_body_1333", alt_body_1333), ("alt_body_1334", alt_body_1334),
                    ("alt_body_1335", alt_body_1335), ("alt_body_1336", alt_body_1336),
                    ("alt_body_1337", alt_body_1337), ("alt_body_1338", alt_body_1338),
                    ("alt_body_1339", alt_body_1339), ("alt_body_1340", alt_body_1340),
                    ("alt_body_1341", alt_body_1341), ("alt_body_1342", alt_body_1342),
                    ("alt_body_1343", alt_body_1343), ("alt_body_1344", alt_body_1344),
                    ("alt_body_1345", alt_body_1345), ("alt_body_1346", alt_body_1346),
                    ("alt_body_1347", alt_body_1347), ("alt_body_1348", alt_body_1348),
                    ("alt_body_1349", alt_body_1349), ("alt_body_1350", alt_body_1350),
                    ("alt_body_1351", alt_body_1351), ("alt_body_1352", alt_body_1352),
                    ("alt_body_1353", alt_body_1353), ("alt_body_1354", alt_body_1354),
                    ("alt_body_1355", alt_body_1355), ("alt_body_1356", alt_body_1356),
                    ("alt_body_1357", alt_body_1357), ("alt_body_1358", alt_body_1358),
                    ("alt_body_1359", alt_body_1359), ("alt_body_1360", alt_body_1360),
                    ("alt_body_1361", alt_body_1361), ("alt_body_1362", alt_body_1362),
                    ("alt_body_1363", alt_body_1363), ("alt_body_1364", alt_body_1364),
                    ("alt_body_1365", alt_body_1365), ("alt_body_1366", alt_body_1366),
                    ("alt_body_1367", alt_body_1367), ("alt_body_1368", alt_body_1368),
                    ("alt_body_1369", alt_body_1369), ("alt_body_1370", alt_body_1370),
                    ("alt_body_1371", alt_body_1371), ("alt_body_1372", alt_body_1372),
                    ("alt_body_1373", alt_body_1373), ("alt_body_1374", alt_body_1374),
                    ("alt_body_1375", alt_body_1375), ("alt_body_1376", alt_body_1376),
                    ("alt_body_1377", alt_body_1377), ("alt_body_1378", alt_body_1378),
                    ("alt_body_1379", alt_body_1379), ("alt_body_1380", alt_body_1380),
                    ("alt_body_1381", alt_body_1381), ("alt_body_1382", alt_body_1382),
                    ("alt_body_1383", alt_body_1383), ("alt_body_1384", alt_body_1384),
                    ("alt_body_1385", alt_body_1385), ("alt_body_1386", alt_body_1386),
                    ("alt_body_1387", alt_body_1387), ("alt_body_1388", alt_body_1388),
                    ("alt_body_1389", alt_body_1389), ("alt_body_1390", alt_body_1390),
                    ("alt_body_1391", alt_body_1391), ("alt_body_1392", alt_body_1392),
                    ("alt_body_1393", alt_body_1393), ("alt_body_1394", alt_body_1394),
                    ("alt_body_1395", alt_body_1395), ("alt_body_1396", alt_body_1396),
                    ("alt_body_1397", alt_body_1397), ("alt_body_1398", alt_body_1398),
                    ("alt_body_1399", alt_body_1399), ("alt_body_1400", alt_body_1400),
                    ("alt_body_1401", alt_body_1401), ("alt_body_1402", alt_body_1402),
                    ("alt_body_1403", alt_body_1403), ("alt_body_1404", alt_body_1404),
                    ("alt_body_1405", alt_body_1405), ("alt_body_1406", alt_body_1406),
                    ("alt_body_1407", alt_body_1407), ("alt_body_1408", alt_body_1408),
                    ("alt_body_1409", alt_body_1409), ("alt_body_1410", alt_body_1410),
                    ("alt_body_1411", alt_body_1411), ("alt_body_1412", alt_body_1412),
                    ("alt_body_1413", alt_body_1413), ("alt_body_1414", alt_body_1414),
                    ("alt_body_1415", alt_body_1415), ("alt_body_1416", alt_body_1416),
                    ("alt_body_1417", alt_body_1417), ("alt_body_1418", alt_body_1418),
                    ("alt_body_1419", alt_body_1419), ("alt_body_1420", alt_body_1420),
                    ("alt_body_1421", alt_body_1421), ("alt_body_1422", alt_body_1422),
                    ("alt_body_1423", alt_body_1423), ("alt_body_1424", alt_body_1424),
                    ("alt_body_1425", alt_body_1425), ("alt_body_1426", alt_body_1426),
                    ("alt_body_1427", alt_body_1427), ("alt_body_1428", alt_body_1428),
                    ("alt_body_1429", alt_body_1429), ("alt_body_1430", alt_body_1430),
                    ("alt_body_1431", alt_body_1431), ("alt_body_1432", alt_body_1432),
                    ("alt_body_1433", alt_body_1433), ("alt_body_1434", alt_body_1434),
                    ("alt_body_1435", alt_body_1435), ("alt_body_1436", alt_body_1436),
                    ("alt_body_1437", alt_body_1437), ("alt_body_1438", alt_body_1438),
                    ("alt_body_1439", alt_body_1439), ("alt_body_1440", alt_body_1440),
                    ("alt_body_1441", alt_body_1441), ("alt_body_1442", alt_body_1442),
                    ("alt_body_1443", alt_body_1443), ("alt_body_1444", alt_body_1444),
                    ("alt_body_1445", alt_body_1445), ("alt_body_1446", alt_body_1446),
                    ("alt_body_1447", alt_body_1447), ("alt_body_1448", alt_body_1448),
                    ("alt_body_1449", alt_body_1449), ("alt_body_1450", alt_body_1450),
                    ("alt_body_1451", alt_body_1451), ("alt_body_1452", alt_body_1452),
                    ("alt_body_1453", alt_body_1453), ("alt_body_1454", alt_body_1454),
                    ("alt_body_1455", alt_body_1455), ("alt_body_1456", alt_body_1456),
                    ("alt_body_1457", alt_body_1457), ("alt_body_1458", alt_body_1458),
                    ("alt_body_1459", alt_body_1459), ("alt_body_1460", alt_body_1460),
                    ("alt_body_1461", alt_body_1461), ("alt_body_1462", alt_body_1462),
                    ("alt_body_1463", alt_body_1463), ("alt_body_1464", alt_body_1464),
                    ("alt_body_1465", alt_body_1465), ("alt_body_1466", alt_body_1466),
                    ("alt_body_1467", alt_body_1467), ("alt_body_1468", alt_body_1468),
                    ("alt_body_1469", alt_body_1469), ("alt_body_1470", alt_body_1470),
                    ("alt_body_1471", alt_body_1471), ("alt_body_1472", alt_body_1472),
                    ("alt_body_1473", alt_body_1473), ("alt_body_1474", alt_body_1474),
                    ("alt_body_1475", alt_body_1475), ("alt_body_1476", alt_body_1476),
                    ("alt_body_1477", alt_body_1477), ("alt_body_1478", alt_body_1478),
                    ("alt_body_1479", alt_body_1479), ("alt_body_1480", alt_body_1480),
                    ("alt_body_1481", alt_body_1481), ("alt_body_1482", alt_body_1482),
                    ("alt_body_1483", alt_body_1483), ("alt_body_1484", alt_body_1484),
                    ("alt_body_1485", alt_body_1485), ("alt_body_1486", alt_body_1486),
                    ("alt_body_1487", alt_body_1487), ("alt_body_1488", alt_body_1488),
                    ("alt_body_1489", alt_body_1489), ("alt_body_1490", alt_body_1490),
                    ("alt_body_1491", alt_body_1491), ("alt_body_1492", alt_body_1492),
                    ("alt_body_1493", alt_body_1493), ("alt_body_1494", alt_body_1494),
                    ("alt_body_1495", alt_body_1495), ("alt_body_1496", alt_body_1496),
                    ("alt_body_1497", alt_body_1497), ("alt_body_1498", alt_body_1498),
                    ("alt_body_1499", alt_body_1499), ("alt_body_1500", alt_body_1500),
                    ("alt_body_1501", alt_body_1501), ("alt_body_1502", alt_body_1502),
                    ("alt_body_1503", alt_body_1503), ("alt_body_1504", alt_body_1504),
                    ("alt_body_1505", alt_body_1505), ("alt_body_1506", alt_body_1506),
                    ("alt_body_1507", alt_body_1507), ("alt_body_1508", alt_body_1508),
                    ("alt_body_1509", alt_body_1509), ("alt_body_1510", alt_body_1510),
                    ("alt_body_1511", alt_body_1511), ("alt_body_1512", alt_body_1512),
                    ("alt_body_1513", alt_body_1513), ("alt_body_1514", alt_body_1514),
                    ("alt_body_1515", alt_body_1515), ("alt_body_1516", alt_body_1516),
                    ("alt_body_1517", alt_body_1517), ("alt_body_1518", alt_body_1518),
                    ("alt_body_1519", alt_body_1519), ("alt_body_1520", alt_body_1520),
                    ("alt_body_1521", alt_body_1521), ("alt_body_1522", alt_body_1522),
                    ("alt_body_1523", alt_body_1523), ("alt_body_1524", alt_body_1524),
                    ("alt_body_1525", alt_body_1525), ("alt_body_1526", alt_body_1526),
                    ("alt_body_1527", alt_body_1527), ("alt_body_1528", alt_body_1528),
                    ("alt_body_1529", alt_body_1529), ("alt_body_1530", alt_body_1530),
                    ("alt_body_1531", alt_body_1531), ("alt_body_1532", alt_body_1532),
                    ("alt_body_1533", alt_body_1533), ("alt_body_1534", alt_body_1534),
                    ("alt_body_1535", alt_body_1535), ("alt_body_1536", alt_body_1536),
                ] {
                    m.insert(k.to_string(), match v {
                        Some(val) => val.to_json_value(), None => Value::Null });
                }
                m.insert("alt_post_cstr_a".to_string(), match alt_post_cstr_a {
                    Some(s) => s.to_json_value(), None => Value::Null });
                m.insert("alt_post_cstr_b".to_string(), match alt_post_cstr_b {
                    Some(s) => s.to_json_value(), None => Value::Null });
                for (k, v) in [
                    ("__dummy_unused_a", None as Option<u32>), ("__dummy_unused_b", None as Option<u32>),
                ] {
                    m.insert(k.to_string(), match v {
                        Some(val) => val.to_json_value(), None => Value::Null });
                }
                m.insert("_post_blob_b64".to_string(), Value::String(B64.encode(post_blob)));
                Value::Object(m)
            }
            GimmickTail::Raw(b) => {
                let mut m = Map::new();
                m.insert("kind".to_string(), Value::String("Raw".to_string()));
                m.insert("_b64".to_string(), Value::String(B64.encode(b)));
                Value::Object(m)
            }
        }
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "GimmickTail: expected object",
        ))?;
        let kind = json_get_field(obj, "kind")?.as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "GimmickTail.kind: expected string"))?;
        match kind {
            "Decoded" => {
                <GimmickInteractionOverrideCArray as WriteJsonValue>::write_from_json(
                    w, json_get_field(obj, "gimmick_interaction_override_list")?,
                )?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_interaction_ui_socket")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "use_sub_part_for_interaction")?)?;
                <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "property_list")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "gimmick_name_hash")?)?;
                <LocalizableString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "gimmick_name")?)?;
                <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "emoji_texture_id")?)?;
                <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "dev_memo")?)?;
                <CArray<GimmickHashPair> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "hash_pair_list")?)?;
                <CArray<GimmickHashSingle> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "hash_single_list")?)?;
                let teh = json_get_field(obj, "trigger_event_handler_list")?;
                if !teh.is_null() {
                    <CArray<OptionalTriggerGamePlayEventHandlerData> as WriteJsonValue>::write_from_json(w, teh)?;
                }
                let gcp = json_get_field(obj, "gimmick_chart_parameter_list")?;
                if !gcp.is_null() {
                    <CArray<GimmickChartParameter> as WriteJsonValue>::write_from_json(w, gcp)?;
                }
                let f19 = json_get_field(obj, "field_19_u32_list")?;
                if !f19.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f19)?;
                }
                let f20 = json_get_field(obj, "field_20_u32_list")?;
                if !f20.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f20)?;
                }
                let f21 = json_get_field(obj, "field_21_u32_list")?;
                if !f21.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f21)?;
                }
                let f22 = json_get_field(obj, "field_22_u32_list")?;
                if !f22.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f22)?;
                }
                let f23 = json_get_field(obj, "field_23_u32_list")?;
                if !f23.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f23)?;
                }
                let f24 = json_get_field(obj, "field_24_u32_list")?;
                if !f24.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f24)?;
                }
                let efa = json_get_field(obj, "field_24_emissive_flag_a")?;
                if !efa.is_null() {
                    <u8 as WriteJsonValue>::write_from_json(w, efa)?;
                }
                let eva = json_get_field(obj, "field_24_emissive_value_a")?;
                if !eva.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, eva)?;
                }
                let efb = json_get_field(obj, "field_24_emissive_flag_b")?;
                if !efb.is_null() {
                    <u8 as WriteJsonValue>::write_from_json(w, efb)?;
                }
                let en = json_get_field(obj, "field_24_emissive_name")?;
                if !en.is_null() {
                    <CString as WriteJsonValue>::write_from_json(w, en)?;
                }
                let evb = json_get_field(obj, "field_24_emissive_value_b")?;
                if !evb.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, evb)?;
                }
                let f25 = json_get_field(obj, "field_25_u32_list")?;
                if !f25.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f25)?;
                }
                let f26 = json_get_field(obj, "field_26_u32")?;
                if !f26.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f26)?;
                }
                let f27 = json_get_field(obj, "field_27_u32_list")?;
                if !f27.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f27)?;
                }
                let f28 = json_get_field(obj, "field_28_u32")?;
                if !f28.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f28)?;
                }
                for k in &["field_29_u32_list", "field_30_u32_list",
                           "field_31_u32_list"] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <CArray<u32> as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                for k in &[
                    "f31_alt_001", "f31_alt_002", "f31_alt_003", "f31_alt_004",
                    "f31_alt_005", "f31_alt_006", "f31_alt_007", "f31_alt_008",
                    "f31_alt_009", "f31_alt_010", "f31_alt_011", "f31_alt_012",
                    "f31_alt_013", "f31_alt_014", "f31_alt_015", "f31_alt_016",
                    "f31_alt_017", "f31_alt_018", "f31_alt_019", "f31_alt_020",
                    "f31_alt_021", "f31_alt_022", "f31_alt_023", "f31_alt_024",
                    "f31_alt_025", "f31_alt_026", "f31_alt_027", "f31_alt_028",
                    "f31_alt_029", "f31_alt_030", "f31_alt_031", "f31_alt_032",
                    "f31_alt_033", "f31_alt_034", "f31_alt_035", "f31_alt_036",
                    "f31_alt_037", "f31_alt_038", "f31_alt_039", "f31_alt_040",
                    "f31_alt_041", "f31_alt_042", "f31_alt_043", "f31_alt_044",
                    "f31_alt_045", "f31_alt_046", "f31_alt_047", "f31_alt_048",
                    "f31_alt_049", "f31_alt_050", "f31_alt_051", "f31_alt_052",
                    "f31_alt_053", "f31_alt_054", "f31_alt_055", "f31_alt_056",
                    "f31_alt_057", "f31_alt_058", "f31_alt_059", "f31_alt_060",
                    "f31_alt_061", "f31_alt_062", "f31_alt_063", "f31_alt_064",
                    "f31_alt_065", "f31_alt_066", "f31_alt_067", "f31_alt_068",
                    "f31_alt_069", "f31_alt_070", "f31_alt_071", "f31_alt_072",
                    "f31_alt_073", "f31_alt_074", "f31_alt_075", "f31_alt_076",
                    "f31_alt_077", "f31_alt_078", "f31_alt_079", "f31_alt_080",
                    "f31_alt_081", "f31_alt_082", "f31_alt_083", "f31_alt_084",
                    "f31_alt_085", "f31_alt_086", "f31_alt_087", "f31_alt_088",
                    "f31_alt_089", "f31_alt_090", "f31_alt_091", "f31_alt_092",
                    "f31_alt_093", "f31_alt_094", "f31_alt_095", "f31_alt_096",
                    "f31_alt_097", "f31_alt_098", "f31_alt_099", "f31_alt_100",
                    "f31_alt_101", "f31_alt_102", "f31_alt_103", "f31_alt_104",
                    "f31_alt_105", "f31_alt_106", "f31_alt_107", "f31_alt_108",
                    "f31_alt_109", "f31_alt_110", "f31_alt_111", "f31_alt_112",
                    "f31_alt_113", "f31_alt_114", "f31_alt_115", "f31_alt_116",
                    "f31_alt_117", "f31_alt_118", "f31_alt_119", "f31_alt_120",
                    "f31_alt_121", "f31_alt_122", "f31_alt_123", "f31_alt_124",
                    "f31_alt_125", "f31_alt_126", "f31_alt_127", "f31_alt_128",
                    "f31_alt_129", "f31_alt_130", "f31_alt_131", "f31_alt_132",
                    "f31_alt_133", "f31_alt_134", "f31_alt_135", "f31_alt_136",
                    "f31_alt_137", "f31_alt_138", "f31_alt_139", "f31_alt_140",
                    "f31_alt_141", "f31_alt_142", "f31_alt_143", "f31_alt_144",
                    "f31_alt_145", "f31_alt_146", "f31_alt_147", "f31_alt_148",
                    "f31_alt_149", "f31_alt_150", "f31_alt_151", "f31_alt_152",
                    "f31_alt_153", "f31_alt_154", "f31_alt_155", "f31_alt_156",
                    "f31_alt_157", "f31_alt_158", "f31_alt_159", "f31_alt_160",
                    "f31_alt_161", "f31_alt_162", "f31_alt_163", "f31_alt_164",
                    "f31_alt_165", "f31_alt_166", "f31_alt_167", "f31_alt_168",
                    "f31_alt_169", "f31_alt_170", "f31_alt_171", "f31_alt_172",
                    "f31_alt_173", "f31_alt_174", "f31_alt_175", "f31_alt_176",
                    "f31_alt_177", "f31_alt_178", "f31_alt_179", "f31_alt_180",
                    "f31_alt_181", "f31_alt_182", "f31_alt_183", "f31_alt_184",
                    "f31_alt_185", "f31_alt_186", "f31_alt_187", "f31_alt_188",
                    "f31_alt_189", "f31_alt_190", "f31_alt_191", "f31_alt_192",
                    "f31_alt_193", "f31_alt_194", "f31_alt_195", "f31_alt_196",
                    "f31_alt_197", "f31_alt_198", "f31_alt_199", "f31_alt_200",
                    "f31_alt_201", "f31_alt_202", "f31_alt_203", "f31_alt_204",
                    "f31_alt_205", "f31_alt_206", "f31_alt_207", "f31_alt_208",
                    "f31_alt_209", "f31_alt_210", "f31_alt_211", "f31_alt_212",
                    "f31_alt_213", "f31_alt_214", "f31_alt_215", "f31_alt_216",
                    "f31_alt_217", "f31_alt_218", "f31_alt_219", "f31_alt_220",
                    "f31_alt_221", "f31_alt_222", "f31_alt_223", "f31_alt_224",
                    "f31_alt_225", "f31_alt_226", "f31_alt_227", "f31_alt_228",
                    "f31_alt_229", "f31_alt_230", "f31_alt_231", "f31_alt_232",
                    "f31_alt_233", "f31_alt_234", "f31_alt_235", "f31_alt_236",
                    "f31_alt_237", "f31_alt_238", "f31_alt_239", "f31_alt_240",
                    "f31_alt_241", "f31_alt_242", "f31_alt_243", "f31_alt_244",
                    "f31_alt_245", "f31_alt_246", "f31_alt_247", "f31_alt_248",
                    "f31_alt_249", "f31_alt_250", "f31_alt_251", "f31_alt_252",
                    "f31_alt_253", "f31_alt_254", "f31_alt_255", "f31_alt_256",
                ] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <u32 as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                let f32 = json_get_field(obj, "field_32_u32_list")?;
                if !f32.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f32)?;
                }
                for k in &[
                    "f32_alt_001", "f32_alt_002", "f32_alt_003", "f32_alt_004",
                    "f32_alt_005", "f32_alt_006", "f32_alt_007", "f32_alt_008",
                    "f32_alt_009", "f32_alt_010", "f32_alt_011", "f32_alt_012",
                    "f32_alt_013", "f32_alt_014", "f32_alt_015", "f32_alt_016",
                    "f32_alt_017", "f32_alt_018", "f32_alt_019", "f32_alt_020",
                    "f32_alt_021", "f32_alt_022", "f32_alt_023", "f32_alt_024",
                    "f32_alt_025", "f32_alt_026", "f32_alt_027", "f32_alt_028",
                    "f32_alt_029", "f32_alt_030", "f32_alt_031", "f32_alt_032",
                    "f32_alt_033", "f32_alt_034", "f32_alt_035", "f32_alt_036",
                    "f32_alt_037", "f32_alt_038", "f32_alt_039", "f32_alt_040",
                    "f32_alt_041", "f32_alt_042", "f32_alt_043", "f32_alt_044",
                    "f32_alt_045", "f32_alt_046", "f32_alt_047", "f32_alt_048",
                    "f32_alt_049", "f32_alt_050", "f32_alt_051", "f32_alt_052",
                    "f32_alt_053", "f32_alt_054", "f32_alt_055", "f32_alt_056",
                    "f32_alt_057", "f32_alt_058", "f32_alt_059", "f32_alt_060",
                    "f32_alt_061", "f32_alt_062", "f32_alt_063", "f32_alt_064",
                    "f32_alt_065", "f32_alt_066", "f32_alt_067", "f32_alt_068",
                    "f32_alt_069", "f32_alt_070", "f32_alt_071", "f32_alt_072",
                    "f32_alt_073", "f32_alt_074", "f32_alt_075", "f32_alt_076",
                    "f32_alt_077", "f32_alt_078", "f32_alt_079", "f32_alt_080",
                    "f32_alt_081", "f32_alt_082", "f32_alt_083", "f32_alt_084",
                    "f32_alt_085", "f32_alt_086", "f32_alt_087", "f32_alt_088",
                    "f32_alt_089", "f32_alt_090", "f32_alt_091", "f32_alt_092",
                    "f32_alt_093", "f32_alt_094", "f32_alt_095", "f32_alt_096",
                    "f32_alt_097", "f32_alt_098", "f32_alt_099", "f32_alt_100",
                    "f32_alt_101", "f32_alt_102", "f32_alt_103", "f32_alt_104",
                    "f32_alt_105", "f32_alt_106", "f32_alt_107", "f32_alt_108",
                    "f32_alt_109", "f32_alt_110", "f32_alt_111", "f32_alt_112",
                    "f32_alt_113", "f32_alt_114", "f32_alt_115", "f32_alt_116",
                    "f32_alt_117", "f32_alt_118", "f32_alt_119", "f32_alt_120",
                    "f32_alt_121", "f32_alt_122", "f32_alt_123", "f32_alt_124",
                    "f32_alt_125", "f32_alt_126", "f32_alt_127", "f32_alt_128",
                    "f32_alt_129", "f32_alt_130", "f32_alt_131", "f32_alt_132",
                    "f32_alt_133", "f32_alt_134", "f32_alt_135", "f32_alt_136",
                    "f32_alt_137", "f32_alt_138", "f32_alt_139", "f32_alt_140",
                    "f32_alt_141", "f32_alt_142", "f32_alt_143", "f32_alt_144",
                    "f32_alt_145", "f32_alt_146", "f32_alt_147", "f32_alt_148",
                    "f32_alt_149", "f32_alt_150", "f32_alt_151", "f32_alt_152",
                    "f32_alt_153", "f32_alt_154", "f32_alt_155", "f32_alt_156",
                    "f32_alt_157", "f32_alt_158", "f32_alt_159", "f32_alt_160",
                    "f32_alt_161", "f32_alt_162", "f32_alt_163", "f32_alt_164",
                    "f32_alt_165", "f32_alt_166", "f32_alt_167", "f32_alt_168",
                    "f32_alt_169", "f32_alt_170", "f32_alt_171", "f32_alt_172",
                    "f32_alt_173", "f32_alt_174", "f32_alt_175", "f32_alt_176",
                    "f32_alt_177", "f32_alt_178", "f32_alt_179", "f32_alt_180",
                    "f32_alt_181", "f32_alt_182", "f32_alt_183", "f32_alt_184",
                    "f32_alt_185", "f32_alt_186", "f32_alt_187", "f32_alt_188",
                    "f32_alt_189", "f32_alt_190", "f32_alt_191", "f32_alt_192",
                ] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <u32 as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                let f33 = json_get_field(obj, "field_33_u32")?;
                if !f33.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f33)?;
                }
                let f34 = json_get_field(obj, "field_34_u32")?;
                if !f34.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f34)?;
                }
                let f35 = json_get_field(obj, "field_35_u32_list")?;
                if !f35.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f35)?;
                }
                let f36 = json_get_field(obj, "field_36_u32")?;
                if !f36.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f36)?;
                }
                let f37 = json_get_field(obj, "field_37_u32")?;
                if !f37.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f37)?;
                }
                let f38 = json_get_field(obj, "field_38_u32")?;
                if !f38.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f38)?;
                }
                let f39 = json_get_field(obj, "field_39_u32_list")?;
                if !f39.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f39)?;
                }
                for k in &[
                    "f39_alt_001", "f39_alt_002", "f39_alt_003", "f39_alt_004",
                    "f39_alt_005", "f39_alt_006", "f39_alt_007", "f39_alt_008",
                    "f39_alt_009", "f39_alt_010", "f39_alt_011", "f39_alt_012",
                    "f39_alt_013", "f39_alt_014", "f39_alt_015", "f39_alt_016",
                    "f39_alt_017", "f39_alt_018", "f39_alt_019", "f39_alt_020",
                    "f39_alt_021", "f39_alt_022", "f39_alt_023", "f39_alt_024",
                    "f39_alt_025", "f39_alt_026", "f39_alt_027", "f39_alt_028",
                    "f39_alt_029", "f39_alt_030", "f39_alt_031", "f39_alt_032",
                    "f39_alt_033", "f39_alt_034", "f39_alt_035", "f39_alt_036",
                    "f39_alt_037", "f39_alt_038", "f39_alt_039", "f39_alt_040",
                    "f39_alt_041", "f39_alt_042", "f39_alt_043", "f39_alt_044",
                    "f39_alt_045", "f39_alt_046", "f39_alt_047", "f39_alt_048",
                    "f39_alt_049", "f39_alt_050", "f39_alt_051", "f39_alt_052",
                    "f39_alt_053", "f39_alt_054", "f39_alt_055", "f39_alt_056",
                    "f39_alt_057", "f39_alt_058", "f39_alt_059", "f39_alt_060",
                    "f39_alt_061", "f39_alt_062", "f39_alt_063", "f39_alt_064",
                    "f39_alt_065", "f39_alt_066", "f39_alt_067", "f39_alt_068",
                    "f39_alt_069", "f39_alt_070", "f39_alt_071", "f39_alt_072",
                    "f39_alt_073", "f39_alt_074", "f39_alt_075", "f39_alt_076",
                    "f39_alt_077", "f39_alt_078", "f39_alt_079", "f39_alt_080",
                    "f39_alt_081", "f39_alt_082", "f39_alt_083", "f39_alt_084",
                    "f39_alt_085", "f39_alt_086", "f39_alt_087", "f39_alt_088",
                    "f39_alt_089", "f39_alt_090", "f39_alt_091", "f39_alt_092",
                    "f39_alt_093", "f39_alt_094", "f39_alt_095", "f39_alt_096",
                    "f39_alt_097", "f39_alt_098", "f39_alt_099", "f39_alt_100",
                    "f39_alt_101", "f39_alt_102", "f39_alt_103", "f39_alt_104",
                    "f39_alt_105", "f39_alt_106", "f39_alt_107", "f39_alt_108",
                    "f39_alt_109", "f39_alt_110", "f39_alt_111", "f39_alt_112",
                    "f39_alt_113", "f39_alt_114", "f39_alt_115", "f39_alt_116",
                    "f39_alt_117", "f39_alt_118", "f39_alt_119", "f39_alt_120",
                    "f39_alt_121", "f39_alt_122", "f39_alt_123", "f39_alt_124",
                    "f39_alt_125", "f39_alt_126", "f39_alt_127", "f39_alt_128",
                    "f39_alt_129", "f39_alt_130", "f39_alt_131", "f39_alt_132",
                    "f39_alt_133", "f39_alt_134", "f39_alt_135", "f39_alt_136",
                    "f39_alt_137", "f39_alt_138", "f39_alt_139", "f39_alt_140",
                    "f39_alt_141", "f39_alt_142", "f39_alt_143", "f39_alt_144",
                    "f39_alt_145", "f39_alt_146", "f39_alt_147", "f39_alt_148",
                    "f39_alt_149", "f39_alt_150", "f39_alt_151", "f39_alt_152",
                    "f39_alt_153", "f39_alt_154", "f39_alt_155", "f39_alt_156",
                    "f39_alt_157", "f39_alt_158", "f39_alt_159", "f39_alt_160",
                    "f39_alt_161", "f39_alt_162", "f39_alt_163", "f39_alt_164",
                    "f39_alt_165", "f39_alt_166", "f39_alt_167", "f39_alt_168",
                    "f39_alt_169", "f39_alt_170", "f39_alt_171", "f39_alt_172",
                    "f39_alt_173", "f39_alt_174", "f39_alt_175", "f39_alt_176",
                    "f39_alt_177", "f39_alt_178", "f39_alt_179", "f39_alt_180",
                    "f39_alt_181", "f39_alt_182", "f39_alt_183", "f39_alt_184",
                    "f39_alt_185", "f39_alt_186", "f39_alt_187", "f39_alt_188",
                    "f39_alt_189", "f39_alt_190", "f39_alt_191", "f39_alt_192",
                ] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <u32 as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                let f40 = json_get_field(obj, "field_40_u32_list")?;
                if !f40.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f40)?;
                }
                let f41 = json_get_field(obj, "field_41_u32")?;
                if !f41.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f41)?;
                }
                let f42 = json_get_field(obj, "field_42_u32")?;
                if !f42.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f42)?;
                }
                let f43 = json_get_field(obj, "field_43_u32")?;
                if !f43.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f43)?;
                }
                let f44 = json_get_field(obj, "field_44_u32")?;
                if !f44.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f44)?;
                }
                let f45 = json_get_field(obj, "field_45_u32")?;
                if !f45.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f45)?;
                }
                let f46 = json_get_field(obj, "field_46_u32")?;
                if !f46.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f46)?;
                }
                let f47 = json_get_field(obj, "field_47_u32")?;
                if !f47.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f47)?;
                }
                let f48 = json_get_field(obj, "field_48_u32")?;
                if !f48.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f48)?;
                }
                let f49 = json_get_field(obj, "field_49_u32_list")?;
                if !f49.is_null() {
                    <CArray<u32> as WriteJsonValue>::write_from_json(w, f49)?;
                }
                for k in &["field_50_u32_list", "field_51_u32_list",
                           "field_52_u32_list", "field_53_u32_list",
                           "field_54_u32_list", "field_55_u32_list",
                           "field_56_u32_list", "field_57_u32_list",
                           "field_58_u32_list"] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <CArray<u32> as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                for k in &["field_59_u32", "field_60_u32", "field_61_u32",
                           "field_62_u32", "field_63_u32", "field_64_u32",
                           "field_65_u32", "field_66_u32", "field_67_u32",
                           "field_68_u32", "field_69_u32", "field_70_u32",
                           "field_71_u32", "field_72_u32", "field_73_u32",
                           "field_74_u32", "field_75_u32", "field_76_u32",
                           "field_77_u32", "field_78_u32", "field_79_u32",
                           "field_80_u32", "field_81_u32", "field_82_u32",
                           "field_83_u32", "field_84_u32", "field_85_u32",
                           "field_86_u32", "field_87_u32", "field_88_u32",
                           "field_89_u32", "field_90_u32"] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <u32 as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                for k in &["field_91_u32", "field_92_u32", "field_93_u32",
                           "field_94_u32", "field_95_u32", "field_96_u32",
                           "field_97_u32", "field_98_u32", "field_99_u32",
                           "field_100_u32", "field_101_u32", "field_102_u32",
                           "field_103_u32", "field_104_u32", "field_105_u32",
                           "field_106_u32", "field_107_u32", "field_108_u32",
                           "field_109_u32", "field_110_u32", "field_111_u32",
                           "field_112_u32", "field_113_u32", "field_114_u32",
                           "field_115_u32", "field_116_u32", "field_117_u32",
                           "field_118_u32", "field_119_u32", "field_120_u32",
                           "field_121_u32", "field_122_u32", "field_123_u32",
                           "field_124_u32", "field_125_u32", "field_126_u32",
                           "field_127_u32", "field_128_u32", "field_129_u32",
                           "field_130_u32", "field_131_u32", "field_132_u32",
                           "field_133_u32", "field_134_u32", "field_135_u32",
                           "field_136_u32", "field_137_u32", "field_138_u32",
                           "field_139_u32", "field_140_u32", "field_141_u32",
                           "field_142_u32", "field_143_u32", "field_144_u32",
                           "field_145_u32", "field_146_u32", "field_147_u32",
                           "field_148_u32", "field_149_u32", "field_150_u32",
                           "field_151_u32", "field_152_u32", "field_153_u32",
                           "field_154_u32", "field_155_u32", "field_156_u32",
                           "field_157_u32", "field_158_u32", "field_159_u32",
                           "field_160_u32", "field_161_u32", "field_162_u32",
                           "field_163_u32", "field_164_u32", "field_165_u32",
                           "field_166_u32", "field_167_u32", "field_168_u32",
                           "field_169_u32", "field_170_u32", "field_171_u32",
                           "field_172_u32", "field_173_u32", "field_174_u32",
                           "field_175_u32", "field_176_u32", "field_177_u32",
                           "field_178_u32", "field_179_u32", "field_180_u32",
                           "field_181_u32", "field_182_u32", "field_183_u32",
                           "field_184_u32", "field_185_u32", "field_186_u32",
                           "field_187_u32", "field_188_u32", "field_189_u32",
                           "field_190_u32", "field_191_u32", "field_192_u32",
                           "field_193_u32", "field_194_u32", "field_195_u32",
                           "field_196_u32", "field_197_u32", "field_198_u32",
                           "field_199_u32", "field_200_u32", "field_201_u32",
                           "field_202_u32", "field_203_u32", "field_204_u32",
                           "field_205_u32", "field_206_u32", "field_207_u32",
                           "field_208_u32", "field_209_u32", "field_210_u32",
                           "field_211_u32", "field_212_u32", "field_213_u32",
                           "field_214_u32", "field_215_u32", "field_216_u32",
                           "field_217_u32", "field_218_u32", "field_219_u32",
                           "field_220_u32", "field_221_u32", "field_222_u32",
                           "field_223_u32", "field_224_u32", "field_225_u32",
                           "field_226_u32", "field_227_u32", "field_228_u32",
                           "field_229_u32", "field_230_u32", "field_231_u32",
                           "field_232_u32", "field_233_u32", "field_234_u32",
                           "field_235_u32", "field_236_u32", "field_237_u32",
                           "field_238_u32", "field_239_u32", "field_240_u32",
                           "field_241_u32", "field_242_u32", "field_243_u32",
                           "field_244_u32", "field_245_u32", "field_246_u32",
                           "field_247_u32", "field_248_u32", "field_249_u32",
                           "field_250_u32", "field_251_u32", "field_252_u32",
                           "field_253_u32", "field_254_u32", "field_255_u32",
                           "field_256_u32", "field_257_u32", "field_258_u32",
                           "field_259_u32", "field_260_u32", "field_261_u32",
                           "field_262_u32", "field_263_u32", "field_264_u32",
                           "field_265_u32", "field_266_u32", "field_267_u32",
                           "field_268_u32", "field_269_u32", "field_270_u32",
                           "field_271_u32", "field_272_u32", "field_273_u32",
                           "field_274_u32", "field_275_u32", "field_276_u32",
                           "field_277_u32", "field_278_u32", "field_279_u32",
                           "field_280_u32", "field_281_u32", "field_282_u32",
                           "field_283_u32", "field_284_u32", "field_285_u32",
                           "field_286_u32", "field_287_u32", "field_288_u32",
                           "field_289_u32", "field_290_u32", "field_291_u32",
                           "field_292_u32", "field_293_u32", "field_294_u32",
                           "field_295_u32", "field_296_u32", "field_297_u32",
                           "field_298_u32", "field_299_u32", "field_300_u32",
                           "field_301_u32", "field_302_u32", "field_303_u32",
                           "field_304_u32", "field_305_u32", "field_306_u32",
                           "field_307_u32", "field_308_u32", "field_309_u32",
                           "field_310_u32", "field_311_u32", "field_312_u32",
                           "field_313_u32", "field_314_u32", "field_315_u32",
                           "field_316_u32", "field_317_u32", "field_318_u32",
                           "field_319_u32", "field_320_u32", "field_321_u32",
                           "field_322_u32", "field_323_u32", "field_324_u32",
                           "field_325_u32", "field_326_u32", "field_327_u32",
                           "field_328_u32", "field_329_u32", "field_330_u32",
                           "field_331_u32", "field_332_u32", "field_333_u32",
                           "field_334_u32", "field_335_u32", "field_336_u32",
                           "field_337_u32", "field_338_u32", "field_339_u32",
                           "field_340_u32", "field_341_u32", "field_342_u32_count"] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <u32 as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                let f343 = json_get_field(obj, "field_343_u8_flag")?;
                if !f343.is_null() {
                    <u8 as WriteJsonValue>::write_from_json(w, f343)?;
                }
                let f344 = json_get_field(obj, "field_344_u32")?;
                if !f344.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, f344)?;
                }
                for k in &["field_345_u32", "field_346_u32", "field_347_u32",
                           "field_348_u32", "field_349_u32", "field_350_u32",
                           "field_351_u32", "field_352_u32", "field_353_u32",
                           "field_354_u32", "field_355_u32", "field_356_u32",
                           "field_357_u32", "field_358_u32", "field_359_u32",
                           "field_360_u32", "field_361_u32", "field_362_u32",
                           "field_363_u32", "field_364_u32", "field_365_u32",
                           "field_366_u32", "field_367_u32", "field_368_u32",
                           "field_369_u32", "field_370_u32", "field_371_u32",
                           "field_372_u32", "field_373_u32", "field_374_u32",
                           "field_375_u32", "field_376_u32", "field_377_u32",
                           "field_378_u32", "field_379_u32", "field_380_u32",
                           "field_381_u32", "field_382_u32", "field_383_u32",
                           "field_384_u32", "field_385_u32", "field_386_u32",
                           "field_387_u32", "field_388_u32", "field_389_u32",
                           "field_390_u32", "field_391_u32", "field_392_u32",
                           "field_393_u32", "field_394_u32", "field_395_u32",
                           "field_396_u32", "field_397_u32", "field_398_u32",
                           "field_399_u32", "field_400_u32", "field_401_u32",
                           "field_402_u32", "field_403_u32", "field_404_u32",
                           "field_405_u32", "field_406_u32", "field_407_u32",
                           "field_408_u32", "field_409_u32", "field_410_u32",
                           "field_411_u32", "field_412_u32", "field_413_u32",
                           "field_414_u32", "field_415_u32", "field_416_u32",
                           "field_417_u32", "field_418_u32", "field_419_u32",
                           "field_420_u32", "field_421_u32", "field_422_u32",
                           "field_423_u32", "field_424_u32", "field_425_u32",
                           "field_426_u32", "field_427_u32", "field_428_u32",
                           "field_429_u32", "field_430_u32", "field_431_u32",
                           "field_432_u32", "field_433_u32", "field_434_u32",
                           "field_435_u32", "field_436_u32", "field_437_u32",
                           "field_438_u32", "field_439_u32", "field_440_u32",
                           "field_441_u32", "field_442_u32", "field_443_u32",
                           "field_444_u32", "field_445_u32", "field_446_u32",
                           "field_447_u32", "field_448_u32", "field_449_u32",
                           "field_450_u32", "field_451_u32", "field_452_u32",
                           "field_453_u32", "field_454_u32", "field_455_u32",
                           "field_456_u32", "field_457_u32", "field_458_u32",
                           "field_459_u32", "field_460_u32", "field_461_u32",
                           "field_462_u32", "field_463_u32", "field_464_u32",
                           "field_465_u32", "field_466_u32", "field_467_u32",
                           "field_468_u32", "field_469_u32", "field_470_u32",
                           "field_471_u32", "field_472_u32",
                           "field_473_u32", "field_474_u32", "field_475_u32",
                           "field_476_u32", "field_477_u32", "field_478_u32",
                           "field_479_u32", "field_480_u32", "field_481_u32",
                           "field_482_u32", "field_483_u32", "field_484_u32",
                           "field_485_u32", "field_486_u32", "field_487_u32",
                           "field_488_u32", "field_489_u32", "field_490_u32",
                           "field_491_u32", "field_492_u32", "field_493_u32",
                           "field_494_u32", "field_495_u32", "field_496_u32",
                           "field_497_u32", "field_498_u32", "field_499_u32",
                           "field_500_u32", "field_501_u32", "field_502_u32",
                           "field_503_u32", "field_504_u32", "field_505_u32",
                           "field_506_u32", "field_507_u32", "field_508_u32",
                           "field_509_u32", "field_510_u32", "field_511_u32",
                           "field_512_u32", "field_513_u32", "field_514_u32",
                           "field_515_u32", "field_516_u32", "field_517_u32",
                           "field_518_u32", "field_519_u32", "field_520_u32",
                           "field_521_u32", "field_522_u32", "field_523_u32",
                           "field_524_u32", "field_525_u32", "field_526_u32",
                           "field_527_u32", "field_528_u32", "field_529_u32",
                           "field_530_u32", "field_531_u32", "field_532_u32",
                           "field_533_u32", "field_534_u32", "field_535_u32",
                           "field_536_u32",
                           "field_537_u32", "field_538_u32", "field_539_u32", "field_540_u32",
                           "field_541_u32", "field_542_u32", "field_543_u32", "field_544_u32",
                           "field_545_u32", "field_546_u32", "field_547_u32", "field_548_u32",
                           "field_549_u32", "field_550_u32", "field_551_u32", "field_552_u32",
                           "field_553_u32", "field_554_u32", "field_555_u32", "field_556_u32",
                           "field_557_u32", "field_558_u32", "field_559_u32", "field_560_u32",
                           "field_561_u32", "field_562_u32", "field_563_u32", "field_564_u32",
                           "field_565_u32", "field_566_u32", "field_567_u32", "field_568_u32",
                           "field_569_u32", "field_570_u32", "field_571_u32", "field_572_u32",
                           "field_573_u32", "field_574_u32", "field_575_u32", "field_576_u32",
                           "field_577_u32", "field_578_u32", "field_579_u32", "field_580_u32",
                           "field_581_u32", "field_582_u32", "field_583_u32", "field_584_u32",
                           "field_585_u32", "field_586_u32", "field_587_u32", "field_588_u32",
                           "field_589_u32", "field_590_u32", "field_591_u32", "field_592_u32",
                           "field_593_u32", "field_594_u32", "field_595_u32", "field_596_u32",
                           "field_597_u32", "field_598_u32", "field_599_u32", "field_600_u32",
                           "field_601_u32", "field_602_u32", "field_603_u32", "field_604_u32",
                           "field_605_u32", "field_606_u32", "field_607_u32", "field_608_u32",
                           "field_609_u32", "field_610_u32", "field_611_u32", "field_612_u32",
                           "field_613_u32", "field_614_u32", "field_615_u32", "field_616_u32",
                           "field_617_u32", "field_618_u32", "field_619_u32", "field_620_u32",
                           "field_621_u32", "field_622_u32", "field_623_u32", "field_624_u32",
                           "field_625_u32", "field_626_u32", "field_627_u32", "field_628_u32",
                           "field_629_u32", "field_630_u32", "field_631_u32", "field_632_u32",
                           "field_633_u32", "field_634_u32", "field_635_u32", "field_636_u32",
                           "field_637_u32", "field_638_u32", "field_639_u32", "field_640_u32",
                           "field_641_u32", "field_642_u32", "field_643_u32", "field_644_u32",
                           "field_645_u32", "field_646_u32", "field_647_u32", "field_648_u32",
                           "field_649_u32", "field_650_u32", "field_651_u32", "field_652_u32",
                           "field_653_u32", "field_654_u32", "field_655_u32", "field_656_u32",
                           "field_657_u32", "field_658_u32", "field_659_u32", "field_660_u32",
                           "field_661_u32", "field_662_u32", "field_663_u32", "field_664_u32",
                           "alt_trigger_count",
                           "field_665_u32", "field_666_u32", "field_667_u32", "field_668_u32",
                           "field_669_u32", "field_670_u32", "field_671_u32", "field_672_u32",
                           "field_673_u32", "field_674_u32", "field_675_u32", "field_676_u32",
                           "field_677_u32", "field_678_u32", "field_679_u32", "field_680_u32",
                           "field_681_u32", "field_682_u32", "field_683_u32", "field_684_u32",
                           "field_685_u32", "field_686_u32", "field_687_u32", "field_688_u32",
                           "field_689_u32", "field_690_u32", "field_691_u32", "field_692_u32",
                           "field_693_u32", "field_694_u32", "field_695_u32", "field_696_u32",
                           "field_697_u32", "field_698_u32", "field_699_u32", "field_700_u32",
                           "field_701_u32", "field_702_u32", "field_703_u32", "field_704_u32",
                           "field_705_u32", "field_706_u32", "field_707_u32", "field_708_u32",
                           "field_709_u32", "field_710_u32", "field_711_u32", "field_712_u32",
                           "field_713_u32", "field_714_u32", "field_715_u32", "field_716_u32",
                           "field_717_u32", "field_718_u32", "field_719_u32", "field_720_u32",
                           "field_721_u32", "field_722_u32", "field_723_u32", "field_724_u32",
                           "field_725_u32", "field_726_u32", "field_727_u32", "field_728_u32"] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <u32 as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                let alt_flag = json_get_field(obj, "alt_trigger_flag")?;
                if !alt_flag.is_null() {
                    <u8 as WriteJsonValue>::write_from_json(w, alt_flag)?;
                }
                let alt_name = json_get_field(obj, "alt_trigger_name")?;
                if !alt_name.is_null() {
                    <CString as WriteJsonValue>::write_from_json(w, alt_name)?;
                }
                let aic = json_get_field(obj, "alt_inner_count")?;
                if !aic.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, aic)?;
                }
                let ain = json_get_field(obj, "alt_inner_name")?;
                if !ain.is_null() {
                    <CString as WriteJsonValue>::write_from_json(w, ain)?;
                }
                let aif = json_get_field(obj, "alt_inner_flag")?;
                if !aif.is_null() {
                    <u32 as WriteJsonValue>::write_from_json(w, aif)?;
                }
                for k in &[
                    "alt_body_001", "alt_body_002", "alt_body_003", "alt_body_004",
                    "alt_body_005", "alt_body_006", "alt_body_007", "alt_body_008",
                    "alt_body_009", "alt_body_010", "alt_body_011", "alt_body_012",
                    "alt_body_013", "alt_body_014", "alt_body_015", "alt_body_016",
                    "alt_body_017", "alt_body_018", "alt_body_019", "alt_body_020",
                    "alt_body_021", "alt_body_022", "alt_body_023", "alt_body_024",
                    "alt_body_025", "alt_body_026", "alt_body_027", "alt_body_028",
                    "alt_body_029", "alt_body_030", "alt_body_031", "alt_body_032",
                    "alt_body_033", "alt_body_034", "alt_body_035", "alt_body_036",
                    "alt_body_037", "alt_body_038", "alt_body_039", "alt_body_040",
                    "alt_body_041", "alt_body_042", "alt_body_043", "alt_body_044",
                    "alt_body_045", "alt_body_046", "alt_body_047", "alt_body_048",
                    "alt_body_049", "alt_body_050", "alt_body_051", "alt_body_052",
                    "alt_body_053", "alt_body_054", "alt_body_055", "alt_body_056",
                    "alt_body_057", "alt_body_058", "alt_body_059", "alt_body_060",
                    "alt_body_061", "alt_body_062", "alt_body_063", "alt_body_064",
                    "alt_body_065", "alt_body_066", "alt_body_067", "alt_body_068",
                    "alt_body_069", "alt_body_070", "alt_body_071", "alt_body_072",
                    "alt_body_073", "alt_body_074", "alt_body_075", "alt_body_076",
                    "alt_body_077", "alt_body_078", "alt_body_079", "alt_body_080",
                    "alt_body_081", "alt_body_082", "alt_body_083", "alt_body_084",
                    "alt_body_085", "alt_body_086", "alt_body_087", "alt_body_088",
                    "alt_body_089", "alt_body_090", "alt_body_091", "alt_body_092",
                    "alt_body_093", "alt_body_094", "alt_body_095", "alt_body_096",
                    "alt_body_097", "alt_body_098", "alt_body_099", "alt_body_100",
                    "alt_body_101", "alt_body_102", "alt_body_103", "alt_body_104",
                    "alt_body_105", "alt_body_106", "alt_body_107", "alt_body_108",
                    "alt_body_109", "alt_body_110", "alt_body_111", "alt_body_112",
                    "alt_body_113", "alt_body_114", "alt_body_115", "alt_body_116",
                    "alt_body_117", "alt_body_118", "alt_body_119", "alt_body_120",
                    "alt_body_121", "alt_body_122", "alt_body_123", "alt_body_124",
                    "alt_body_125", "alt_body_126", "alt_body_127", "alt_body_128",
                    "alt_body_129", "alt_body_130", "alt_body_131", "alt_body_132",
                    "alt_body_133", "alt_body_134", "alt_body_135", "alt_body_136",
                    "alt_body_137", "alt_body_138", "alt_body_139", "alt_body_140",
                    "alt_body_141", "alt_body_142", "alt_body_143", "alt_body_144",
                    "alt_body_145", "alt_body_146", "alt_body_147", "alt_body_148",
                    "alt_body_149", "alt_body_150", "alt_body_151", "alt_body_152",
                    "alt_body_153", "alt_body_154", "alt_body_155", "alt_body_156",
                    "alt_body_157", "alt_body_158", "alt_body_159", "alt_body_160",
                    "alt_body_161", "alt_body_162", "alt_body_163", "alt_body_164",
                    "alt_body_165", "alt_body_166", "alt_body_167", "alt_body_168",
                    "alt_body_169", "alt_body_170", "alt_body_171", "alt_body_172",
                    "alt_body_173", "alt_body_174", "alt_body_175", "alt_body_176",
                    "alt_body_177", "alt_body_178", "alt_body_179", "alt_body_180",
                    "alt_body_181", "alt_body_182", "alt_body_183", "alt_body_184",
                    "alt_body_185", "alt_body_186", "alt_body_187", "alt_body_188",
                    "alt_body_189", "alt_body_190", "alt_body_191", "alt_body_192",
                    "alt_body_193", "alt_body_194", "alt_body_195", "alt_body_196",
                    "alt_body_197", "alt_body_198", "alt_body_199", "alt_body_200",
                    "alt_body_201", "alt_body_202", "alt_body_203", "alt_body_204",
                    "alt_body_205", "alt_body_206", "alt_body_207", "alt_body_208",
                    "alt_body_209", "alt_body_210", "alt_body_211", "alt_body_212",
                    "alt_body_213", "alt_body_214", "alt_body_215", "alt_body_216",
                    "alt_body_217", "alt_body_218", "alt_body_219", "alt_body_220",
                    "alt_body_221", "alt_body_222", "alt_body_223", "alt_body_224",
                    "alt_body_225", "alt_body_226", "alt_body_227", "alt_body_228",
                    "alt_body_229", "alt_body_230", "alt_body_231", "alt_body_232",
                    "alt_body_233", "alt_body_234", "alt_body_235", "alt_body_236",
                    "alt_body_237", "alt_body_238", "alt_body_239", "alt_body_240",
                    "alt_body_241", "alt_body_242", "alt_body_243", "alt_body_244",
                    "alt_body_245", "alt_body_246", "alt_body_247", "alt_body_248",
                    "alt_body_249", "alt_body_250", "alt_body_251", "alt_body_252",
                    "alt_body_253", "alt_body_254", "alt_body_255", "alt_body_256",
                    "alt_body_257", "alt_body_258", "alt_body_259", "alt_body_260",
                    "alt_body_261", "alt_body_262", "alt_body_263", "alt_body_264",
                    "alt_body_265", "alt_body_266", "alt_body_267", "alt_body_268",
                    "alt_body_269", "alt_body_270", "alt_body_271", "alt_body_272",
                    "alt_body_273", "alt_body_274", "alt_body_275", "alt_body_276",
                    "alt_body_277", "alt_body_278", "alt_body_279", "alt_body_280",
                    "alt_body_281", "alt_body_282", "alt_body_283", "alt_body_284",
                    "alt_body_285", "alt_body_286", "alt_body_287", "alt_body_288",
                    "alt_body_289", "alt_body_290", "alt_body_291", "alt_body_292",
                    "alt_body_293", "alt_body_294", "alt_body_295", "alt_body_296",
                    "alt_body_297", "alt_body_298", "alt_body_299", "alt_body_300",
                    "alt_body_301", "alt_body_302", "alt_body_303", "alt_body_304",
                    "alt_body_305", "alt_body_306", "alt_body_307", "alt_body_308",
                    "alt_body_309", "alt_body_310", "alt_body_311", "alt_body_312",
                    "alt_body_313", "alt_body_314", "alt_body_315", "alt_body_316",
                    "alt_body_317", "alt_body_318", "alt_body_319", "alt_body_320",
                    "alt_body_321", "alt_body_322", "alt_body_323", "alt_body_324",
                    "alt_body_325", "alt_body_326", "alt_body_327", "alt_body_328",
                    "alt_body_329", "alt_body_330", "alt_body_331", "alt_body_332",
                    "alt_body_333", "alt_body_334", "alt_body_335", "alt_body_336",
                    "alt_body_337", "alt_body_338", "alt_body_339", "alt_body_340",
                    "alt_body_341", "alt_body_342", "alt_body_343", "alt_body_344",
                    "alt_body_345", "alt_body_346", "alt_body_347", "alt_body_348",
                    "alt_body_349", "alt_body_350", "alt_body_351", "alt_body_352",
                    "alt_body_353", "alt_body_354", "alt_body_355", "alt_body_356",
                    "alt_body_357", "alt_body_358", "alt_body_359", "alt_body_360",
                    "alt_body_361", "alt_body_362", "alt_body_363", "alt_body_364",
                    "alt_body_365", "alt_body_366", "alt_body_367", "alt_body_368",
                    "alt_body_369", "alt_body_370", "alt_body_371", "alt_body_372",
                    "alt_body_373", "alt_body_374", "alt_body_375", "alt_body_376",
                    "alt_body_377", "alt_body_378", "alt_body_379", "alt_body_380",
                    "alt_body_381", "alt_body_382", "alt_body_383", "alt_body_384",
                    "alt_body_385", "alt_body_386", "alt_body_387", "alt_body_388",
                    "alt_body_389", "alt_body_390", "alt_body_391", "alt_body_392",
                    "alt_body_393", "alt_body_394", "alt_body_395", "alt_body_396",
                    "alt_body_397", "alt_body_398", "alt_body_399", "alt_body_400",
                    "alt_body_401", "alt_body_402", "alt_body_403", "alt_body_404",
                    "alt_body_405", "alt_body_406", "alt_body_407", "alt_body_408",
                    "alt_body_409", "alt_body_410", "alt_body_411", "alt_body_412",
                    "alt_body_413", "alt_body_414", "alt_body_415", "alt_body_416",
                    "alt_body_417", "alt_body_418", "alt_body_419", "alt_body_420",
                    "alt_body_421", "alt_body_422", "alt_body_423", "alt_body_424",
                    "alt_body_425", "alt_body_426", "alt_body_427", "alt_body_428",
                    "alt_body_429", "alt_body_430", "alt_body_431", "alt_body_432",
                    "alt_body_433", "alt_body_434", "alt_body_435", "alt_body_436",
                    "alt_body_437", "alt_body_438", "alt_body_439", "alt_body_440",
                    "alt_body_441", "alt_body_442", "alt_body_443", "alt_body_444",
                    "alt_body_445", "alt_body_446", "alt_body_447", "alt_body_448",
                    "alt_body_449", "alt_body_450", "alt_body_451", "alt_body_452",
                    "alt_body_453", "alt_body_454", "alt_body_455", "alt_body_456",
                    "alt_body_457", "alt_body_458", "alt_body_459", "alt_body_460",
                    "alt_body_461", "alt_body_462", "alt_body_463", "alt_body_464",
                    "alt_body_465", "alt_body_466", "alt_body_467", "alt_body_468",
                    "alt_body_469", "alt_body_470", "alt_body_471", "alt_body_472",
                    "alt_body_473", "alt_body_474", "alt_body_475", "alt_body_476",
                    "alt_body_477", "alt_body_478", "alt_body_479", "alt_body_480",
                    "alt_body_481", "alt_body_482", "alt_body_483", "alt_body_484",
                    "alt_body_485", "alt_body_486", "alt_body_487", "alt_body_488",
                    "alt_body_489", "alt_body_490", "alt_body_491", "alt_body_492",
                    "alt_body_493", "alt_body_494", "alt_body_495", "alt_body_496",
                    "alt_body_497", "alt_body_498", "alt_body_499", "alt_body_500",
                    "alt_body_501", "alt_body_502", "alt_body_503", "alt_body_504",
                    "alt_body_505", "alt_body_506", "alt_body_507", "alt_body_508",
                    "alt_body_509", "alt_body_510", "alt_body_511", "alt_body_512",
                    "alt_body_513", "alt_body_514", "alt_body_515", "alt_body_516",
                    "alt_body_517", "alt_body_518", "alt_body_519", "alt_body_520",
                    "alt_body_521", "alt_body_522", "alt_body_523", "alt_body_524",
                    "alt_body_525", "alt_body_526", "alt_body_527", "alt_body_528",
                    "alt_body_529", "alt_body_530", "alt_body_531", "alt_body_532",
                    "alt_body_533", "alt_body_534", "alt_body_535", "alt_body_536",
                    "alt_body_537", "alt_body_538", "alt_body_539", "alt_body_540",
                    "alt_body_541", "alt_body_542", "alt_body_543", "alt_body_544",
                    "alt_body_545", "alt_body_546", "alt_body_547", "alt_body_548",
                    "alt_body_549", "alt_body_550", "alt_body_551", "alt_body_552",
                    "alt_body_553", "alt_body_554", "alt_body_555", "alt_body_556",
                    "alt_body_557", "alt_body_558", "alt_body_559", "alt_body_560",
                    "alt_body_561", "alt_body_562", "alt_body_563", "alt_body_564",
                    "alt_body_565", "alt_body_566", "alt_body_567", "alt_body_568",
                    "alt_body_569", "alt_body_570", "alt_body_571", "alt_body_572",
                    "alt_body_573", "alt_body_574", "alt_body_575", "alt_body_576",
                    "alt_body_577", "alt_body_578", "alt_body_579", "alt_body_580",
                    "alt_body_581", "alt_body_582", "alt_body_583", "alt_body_584",
                    "alt_body_585", "alt_body_586", "alt_body_587", "alt_body_588",
                    "alt_body_589", "alt_body_590", "alt_body_591", "alt_body_592",
                    "alt_body_593", "alt_body_594", "alt_body_595", "alt_body_596",
                    "alt_body_597", "alt_body_598", "alt_body_599", "alt_body_600",
                    "alt_body_601", "alt_body_602", "alt_body_603", "alt_body_604",
                    "alt_body_605", "alt_body_606", "alt_body_607", "alt_body_608",
                    "alt_body_609", "alt_body_610", "alt_body_611", "alt_body_612",
                    "alt_body_613", "alt_body_614", "alt_body_615", "alt_body_616",
                    "alt_body_617", "alt_body_618", "alt_body_619", "alt_body_620",
                    "alt_body_621", "alt_body_622", "alt_body_623", "alt_body_624",
                    "alt_body_625", "alt_body_626", "alt_body_627", "alt_body_628",
                    "alt_body_629", "alt_body_630", "alt_body_631", "alt_body_632",
                    "alt_body_633", "alt_body_634", "alt_body_635", "alt_body_636",
                    "alt_body_637", "alt_body_638", "alt_body_639", "alt_body_640",
                    "alt_body_641", "alt_body_642", "alt_body_643", "alt_body_644",
                    "alt_body_645", "alt_body_646", "alt_body_647", "alt_body_648",
                    "alt_body_649", "alt_body_650", "alt_body_651", "alt_body_652",
                    "alt_body_653", "alt_body_654", "alt_body_655", "alt_body_656",
                    "alt_body_657", "alt_body_658", "alt_body_659", "alt_body_660",
                    "alt_body_661", "alt_body_662", "alt_body_663", "alt_body_664",
                    "alt_body_665", "alt_body_666", "alt_body_667", "alt_body_668",
                    "alt_body_669", "alt_body_670", "alt_body_671", "alt_body_672",
                    "alt_body_673", "alt_body_674", "alt_body_675", "alt_body_676",
                    "alt_body_677", "alt_body_678", "alt_body_679", "alt_body_680",
                    "alt_body_681", "alt_body_682", "alt_body_683", "alt_body_684",
                    "alt_body_685", "alt_body_686", "alt_body_687", "alt_body_688",
                    "alt_body_689", "alt_body_690", "alt_body_691", "alt_body_692",
                    "alt_body_693", "alt_body_694", "alt_body_695", "alt_body_696",
                    "alt_body_697", "alt_body_698", "alt_body_699", "alt_body_700",
                    "alt_body_701", "alt_body_702", "alt_body_703", "alt_body_704",
                    "alt_body_705", "alt_body_706", "alt_body_707", "alt_body_708",
                    "alt_body_709", "alt_body_710", "alt_body_711", "alt_body_712",
                    "alt_body_713", "alt_body_714", "alt_body_715", "alt_body_716",
                    "alt_body_717", "alt_body_718", "alt_body_719", "alt_body_720",
                    "alt_body_721", "alt_body_722", "alt_body_723", "alt_body_724",
                    "alt_body_725", "alt_body_726", "alt_body_727", "alt_body_728",
                    "alt_body_729", "alt_body_730", "alt_body_731", "alt_body_732",
                    "alt_body_733", "alt_body_734", "alt_body_735", "alt_body_736",
                    "alt_body_737", "alt_body_738", "alt_body_739", "alt_body_740",
                    "alt_body_741", "alt_body_742", "alt_body_743", "alt_body_744",
                    "alt_body_745", "alt_body_746", "alt_body_747", "alt_body_748",
                    "alt_body_749", "alt_body_750", "alt_body_751", "alt_body_752",
                    "alt_body_753", "alt_body_754", "alt_body_755", "alt_body_756",
                    "alt_body_757", "alt_body_758", "alt_body_759", "alt_body_760",
                    "alt_body_761", "alt_body_762", "alt_body_763", "alt_body_764",
                    "alt_body_765", "alt_body_766", "alt_body_767", "alt_body_768",
                    "alt_body_769", "alt_body_770", "alt_body_771", "alt_body_772",
                    "alt_body_773", "alt_body_774", "alt_body_775", "alt_body_776",
                    "alt_body_777", "alt_body_778", "alt_body_779", "alt_body_780",
                    "alt_body_781", "alt_body_782", "alt_body_783", "alt_body_784",
                    "alt_body_785", "alt_body_786", "alt_body_787", "alt_body_788",
                    "alt_body_789", "alt_body_790", "alt_body_791", "alt_body_792",
                    "alt_body_793", "alt_body_794", "alt_body_795", "alt_body_796",
                    "alt_body_797", "alt_body_798", "alt_body_799", "alt_body_800",
                    "alt_body_801", "alt_body_802", "alt_body_803", "alt_body_804",
                    "alt_body_805", "alt_body_806", "alt_body_807", "alt_body_808",
                    "alt_body_809", "alt_body_810", "alt_body_811", "alt_body_812",
                    "alt_body_813", "alt_body_814", "alt_body_815", "alt_body_816",
                    "alt_body_817", "alt_body_818", "alt_body_819", "alt_body_820",
                    "alt_body_821", "alt_body_822", "alt_body_823", "alt_body_824",
                    "alt_body_825", "alt_body_826", "alt_body_827", "alt_body_828",
                    "alt_body_829", "alt_body_830", "alt_body_831", "alt_body_832",
                    "alt_body_833", "alt_body_834", "alt_body_835", "alt_body_836",
                    "alt_body_837", "alt_body_838", "alt_body_839", "alt_body_840",
                    "alt_body_841", "alt_body_842", "alt_body_843", "alt_body_844",
                    "alt_body_845", "alt_body_846", "alt_body_847", "alt_body_848",
                    "alt_body_849", "alt_body_850", "alt_body_851", "alt_body_852",
                    "alt_body_853", "alt_body_854", "alt_body_855", "alt_body_856",
                    "alt_body_857", "alt_body_858", "alt_body_859", "alt_body_860",
                    "alt_body_861", "alt_body_862", "alt_body_863", "alt_body_864",
                    "alt_body_865", "alt_body_866", "alt_body_867", "alt_body_868",
                    "alt_body_869", "alt_body_870", "alt_body_871", "alt_body_872",
                    "alt_body_873", "alt_body_874", "alt_body_875", "alt_body_876",
                    "alt_body_877", "alt_body_878", "alt_body_879", "alt_body_880",
                    "alt_body_881", "alt_body_882", "alt_body_883", "alt_body_884",
                    "alt_body_885", "alt_body_886", "alt_body_887", "alt_body_888",
                    "alt_body_889", "alt_body_890", "alt_body_891", "alt_body_892",
                    "alt_body_893", "alt_body_894", "alt_body_895", "alt_body_896",
                    "alt_body_897", "alt_body_898", "alt_body_899", "alt_body_900",
                    "alt_body_901", "alt_body_902", "alt_body_903", "alt_body_904",
                    "alt_body_905", "alt_body_906", "alt_body_907", "alt_body_908",
                    "alt_body_909", "alt_body_910", "alt_body_911", "alt_body_912",
                    "alt_body_913", "alt_body_914", "alt_body_915", "alt_body_916",
                    "alt_body_917", "alt_body_918", "alt_body_919", "alt_body_920",
                    "alt_body_921", "alt_body_922", "alt_body_923", "alt_body_924",
                    "alt_body_925", "alt_body_926", "alt_body_927", "alt_body_928",
                    "alt_body_929", "alt_body_930", "alt_body_931", "alt_body_932",
                    "alt_body_933", "alt_body_934", "alt_body_935", "alt_body_936",
                    "alt_body_937", "alt_body_938", "alt_body_939", "alt_body_940",
                    "alt_body_941", "alt_body_942", "alt_body_943", "alt_body_944",
                    "alt_body_945", "alt_body_946", "alt_body_947", "alt_body_948",
                    "alt_body_949", "alt_body_950", "alt_body_951", "alt_body_952",
                    "alt_body_953", "alt_body_954", "alt_body_955", "alt_body_956",
                    "alt_body_957", "alt_body_958", "alt_body_959", "alt_body_960",
                    "alt_body_961", "alt_body_962", "alt_body_963", "alt_body_964",
                    "alt_body_965", "alt_body_966", "alt_body_967", "alt_body_968",
                    "alt_body_969", "alt_body_970", "alt_body_971", "alt_body_972",
                    "alt_body_973", "alt_body_974", "alt_body_975", "alt_body_976",
                    "alt_body_977", "alt_body_978", "alt_body_979", "alt_body_980",
                    "alt_body_981", "alt_body_982", "alt_body_983", "alt_body_984",
                    "alt_body_985", "alt_body_986", "alt_body_987", "alt_body_988",
                    "alt_body_989", "alt_body_990", "alt_body_991", "alt_body_992",
                    "alt_body_993", "alt_body_994", "alt_body_995", "alt_body_996",
                    "alt_body_997", "alt_body_998", "alt_body_999", "alt_body_1000",
                    "alt_body_1001", "alt_body_1002", "alt_body_1003", "alt_body_1004",
                    "alt_body_1005", "alt_body_1006", "alt_body_1007", "alt_body_1008",
                    "alt_body_1009", "alt_body_1010", "alt_body_1011", "alt_body_1012",
                    "alt_body_1013", "alt_body_1014", "alt_body_1015", "alt_body_1016",
                    "alt_body_1017", "alt_body_1018", "alt_body_1019", "alt_body_1020",
                    "alt_body_1021", "alt_body_1022", "alt_body_1023", "alt_body_1024",
                    "alt_body_1025", "alt_body_1026", "alt_body_1027", "alt_body_1028",
                    "alt_body_1029", "alt_body_1030", "alt_body_1031", "alt_body_1032",
                    "alt_body_1033", "alt_body_1034", "alt_body_1035", "alt_body_1036",
                    "alt_body_1037", "alt_body_1038", "alt_body_1039", "alt_body_1040",
                    "alt_body_1041", "alt_body_1042", "alt_body_1043", "alt_body_1044",
                    "alt_body_1045", "alt_body_1046", "alt_body_1047", "alt_body_1048",
                    "alt_body_1049", "alt_body_1050", "alt_body_1051", "alt_body_1052",
                    "alt_body_1053", "alt_body_1054", "alt_body_1055", "alt_body_1056",
                    "alt_body_1057", "alt_body_1058", "alt_body_1059", "alt_body_1060",
                    "alt_body_1061", "alt_body_1062", "alt_body_1063", "alt_body_1064",
                    "alt_body_1065", "alt_body_1066", "alt_body_1067", "alt_body_1068",
                    "alt_body_1069", "alt_body_1070", "alt_body_1071", "alt_body_1072",
                    "alt_body_1073", "alt_body_1074", "alt_body_1075", "alt_body_1076",
                    "alt_body_1077", "alt_body_1078", "alt_body_1079", "alt_body_1080",
                    "alt_body_1081", "alt_body_1082", "alt_body_1083", "alt_body_1084",
                    "alt_body_1085", "alt_body_1086", "alt_body_1087", "alt_body_1088",
                    "alt_body_1089", "alt_body_1090", "alt_body_1091", "alt_body_1092",
                    "alt_body_1093", "alt_body_1094", "alt_body_1095", "alt_body_1096",
                    "alt_body_1097", "alt_body_1098", "alt_body_1099", "alt_body_1100",
                    "alt_body_1101", "alt_body_1102", "alt_body_1103", "alt_body_1104",
                    "alt_body_1105", "alt_body_1106", "alt_body_1107", "alt_body_1108",
                    "alt_body_1109", "alt_body_1110", "alt_body_1111", "alt_body_1112",
                    "alt_body_1113", "alt_body_1114", "alt_body_1115", "alt_body_1116",
                    "alt_body_1117", "alt_body_1118", "alt_body_1119", "alt_body_1120",
                    "alt_body_1121", "alt_body_1122", "alt_body_1123", "alt_body_1124",
                    "alt_body_1125", "alt_body_1126", "alt_body_1127", "alt_body_1128",
                    "alt_body_1129", "alt_body_1130", "alt_body_1131", "alt_body_1132",
                    "alt_body_1133", "alt_body_1134", "alt_body_1135", "alt_body_1136",
                    "alt_body_1137", "alt_body_1138", "alt_body_1139", "alt_body_1140",
                    "alt_body_1141", "alt_body_1142", "alt_body_1143", "alt_body_1144",
                    "alt_body_1145", "alt_body_1146", "alt_body_1147", "alt_body_1148",
                    "alt_body_1149", "alt_body_1150", "alt_body_1151", "alt_body_1152",
                    "alt_body_1153", "alt_body_1154", "alt_body_1155", "alt_body_1156",
                    "alt_body_1157", "alt_body_1158", "alt_body_1159", "alt_body_1160",
                    "alt_body_1161", "alt_body_1162", "alt_body_1163", "alt_body_1164",
                    "alt_body_1165", "alt_body_1166", "alt_body_1167", "alt_body_1168",
                    "alt_body_1169", "alt_body_1170", "alt_body_1171", "alt_body_1172",
                    "alt_body_1173", "alt_body_1174", "alt_body_1175", "alt_body_1176",
                    "alt_body_1177", "alt_body_1178", "alt_body_1179", "alt_body_1180",
                    "alt_body_1181", "alt_body_1182", "alt_body_1183", "alt_body_1184",
                    "alt_body_1185", "alt_body_1186", "alt_body_1187", "alt_body_1188",
                    "alt_body_1189", "alt_body_1190", "alt_body_1191", "alt_body_1192",
                    "alt_body_1193", "alt_body_1194", "alt_body_1195", "alt_body_1196",
                    "alt_body_1197", "alt_body_1198", "alt_body_1199", "alt_body_1200",
                    "alt_body_1201", "alt_body_1202", "alt_body_1203", "alt_body_1204",
                    "alt_body_1205", "alt_body_1206", "alt_body_1207", "alt_body_1208",
                    "alt_body_1209", "alt_body_1210", "alt_body_1211", "alt_body_1212",
                    "alt_body_1213", "alt_body_1214", "alt_body_1215", "alt_body_1216",
                    "alt_body_1217", "alt_body_1218", "alt_body_1219", "alt_body_1220",
                    "alt_body_1221", "alt_body_1222", "alt_body_1223", "alt_body_1224",
                    "alt_body_1225", "alt_body_1226", "alt_body_1227", "alt_body_1228",
                    "alt_body_1229", "alt_body_1230", "alt_body_1231", "alt_body_1232",
                    "alt_body_1233", "alt_body_1234", "alt_body_1235", "alt_body_1236",
                    "alt_body_1237", "alt_body_1238", "alt_body_1239", "alt_body_1240",
                    "alt_body_1241", "alt_body_1242", "alt_body_1243", "alt_body_1244",
                    "alt_body_1245", "alt_body_1246", "alt_body_1247", "alt_body_1248",
                    "alt_body_1249", "alt_body_1250", "alt_body_1251", "alt_body_1252",
                    "alt_body_1253", "alt_body_1254", "alt_body_1255", "alt_body_1256",
                    "alt_body_1257", "alt_body_1258", "alt_body_1259", "alt_body_1260",
                    "alt_body_1261", "alt_body_1262", "alt_body_1263", "alt_body_1264",
                    "alt_body_1265", "alt_body_1266", "alt_body_1267", "alt_body_1268",
                    "alt_body_1269", "alt_body_1270", "alt_body_1271", "alt_body_1272",
                    "alt_body_1273", "alt_body_1274", "alt_body_1275", "alt_body_1276",
                    "alt_body_1277", "alt_body_1278", "alt_body_1279", "alt_body_1280",
                    "alt_body_1281", "alt_body_1282", "alt_body_1283", "alt_body_1284",
                    "alt_body_1285", "alt_body_1286", "alt_body_1287", "alt_body_1288",
                    "alt_body_1289", "alt_body_1290", "alt_body_1291", "alt_body_1292",
                    "alt_body_1293", "alt_body_1294", "alt_body_1295", "alt_body_1296",
                    "alt_body_1297", "alt_body_1298", "alt_body_1299", "alt_body_1300",
                    "alt_body_1301", "alt_body_1302", "alt_body_1303", "alt_body_1304",
                    "alt_body_1305", "alt_body_1306", "alt_body_1307", "alt_body_1308",
                    "alt_body_1309", "alt_body_1310", "alt_body_1311", "alt_body_1312",
                    "alt_body_1313", "alt_body_1314", "alt_body_1315", "alt_body_1316",
                    "alt_body_1317", "alt_body_1318", "alt_body_1319", "alt_body_1320",
                    "alt_body_1321", "alt_body_1322", "alt_body_1323", "alt_body_1324",
                    "alt_body_1325", "alt_body_1326", "alt_body_1327", "alt_body_1328",
                    "alt_body_1329", "alt_body_1330", "alt_body_1331", "alt_body_1332",
                    "alt_body_1333", "alt_body_1334", "alt_body_1335", "alt_body_1336",
                    "alt_body_1337", "alt_body_1338", "alt_body_1339", "alt_body_1340",
                    "alt_body_1341", "alt_body_1342", "alt_body_1343", "alt_body_1344",
                    "alt_body_1345", "alt_body_1346", "alt_body_1347", "alt_body_1348",
                    "alt_body_1349", "alt_body_1350", "alt_body_1351", "alt_body_1352",
                    "alt_body_1353", "alt_body_1354", "alt_body_1355", "alt_body_1356",
                    "alt_body_1357", "alt_body_1358", "alt_body_1359", "alt_body_1360",
                    "alt_body_1361", "alt_body_1362", "alt_body_1363", "alt_body_1364",
                    "alt_body_1365", "alt_body_1366", "alt_body_1367", "alt_body_1368",
                    "alt_body_1369", "alt_body_1370", "alt_body_1371", "alt_body_1372",
                    "alt_body_1373", "alt_body_1374", "alt_body_1375", "alt_body_1376",
                    "alt_body_1377", "alt_body_1378", "alt_body_1379", "alt_body_1380",
                    "alt_body_1381", "alt_body_1382", "alt_body_1383", "alt_body_1384",
                    "alt_body_1385", "alt_body_1386", "alt_body_1387", "alt_body_1388",
                    "alt_body_1389", "alt_body_1390", "alt_body_1391", "alt_body_1392",
                    "alt_body_1393", "alt_body_1394", "alt_body_1395", "alt_body_1396",
                    "alt_body_1397", "alt_body_1398", "alt_body_1399", "alt_body_1400",
                    "alt_body_1401", "alt_body_1402", "alt_body_1403", "alt_body_1404",
                    "alt_body_1405", "alt_body_1406", "alt_body_1407", "alt_body_1408",
                    "alt_body_1409", "alt_body_1410", "alt_body_1411", "alt_body_1412",
                    "alt_body_1413", "alt_body_1414", "alt_body_1415", "alt_body_1416",
                    "alt_body_1417", "alt_body_1418", "alt_body_1419", "alt_body_1420",
                    "alt_body_1421", "alt_body_1422", "alt_body_1423", "alt_body_1424",
                    "alt_body_1425", "alt_body_1426", "alt_body_1427", "alt_body_1428",
                    "alt_body_1429", "alt_body_1430", "alt_body_1431", "alt_body_1432",
                    "alt_body_1433", "alt_body_1434", "alt_body_1435", "alt_body_1436",
                    "alt_body_1437", "alt_body_1438", "alt_body_1439", "alt_body_1440",
                    "alt_body_1441", "alt_body_1442", "alt_body_1443", "alt_body_1444",
                    "alt_body_1445", "alt_body_1446", "alt_body_1447", "alt_body_1448",
                    "alt_body_1449", "alt_body_1450", "alt_body_1451", "alt_body_1452",
                    "alt_body_1453", "alt_body_1454", "alt_body_1455", "alt_body_1456",
                    "alt_body_1457", "alt_body_1458", "alt_body_1459", "alt_body_1460",
                    "alt_body_1461", "alt_body_1462", "alt_body_1463", "alt_body_1464",
                    "alt_body_1465", "alt_body_1466", "alt_body_1467", "alt_body_1468",
                    "alt_body_1469", "alt_body_1470", "alt_body_1471", "alt_body_1472",
                    "alt_body_1473", "alt_body_1474", "alt_body_1475", "alt_body_1476",
                    "alt_body_1477", "alt_body_1478", "alt_body_1479", "alt_body_1480",
                    "alt_body_1481", "alt_body_1482", "alt_body_1483", "alt_body_1484",
                    "alt_body_1485", "alt_body_1486", "alt_body_1487", "alt_body_1488",
                    "alt_body_1489", "alt_body_1490", "alt_body_1491", "alt_body_1492",
                    "alt_body_1493", "alt_body_1494", "alt_body_1495", "alt_body_1496",
                    "alt_body_1497", "alt_body_1498", "alt_body_1499", "alt_body_1500",
                    "alt_body_1501", "alt_body_1502", "alt_body_1503", "alt_body_1504",
                    "alt_body_1505", "alt_body_1506", "alt_body_1507", "alt_body_1508",
                    "alt_body_1509", "alt_body_1510", "alt_body_1511", "alt_body_1512",
                    "alt_body_1513", "alt_body_1514", "alt_body_1515", "alt_body_1516",
                    "alt_body_1517", "alt_body_1518", "alt_body_1519", "alt_body_1520",
                    "alt_body_1521", "alt_body_1522", "alt_body_1523", "alt_body_1524",
                    "alt_body_1525", "alt_body_1526", "alt_body_1527", "alt_body_1528",
                    "alt_body_1529", "alt_body_1530", "alt_body_1531", "alt_body_1532",
                    "alt_body_1533", "alt_body_1534", "alt_body_1535", "alt_body_1536",
                ] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <u32 as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                let acsa = json_get_field(obj, "alt_post_cstr_a")?;
                if !acsa.is_null() {
                    <CString as WriteJsonValue>::write_from_json(w, acsa)?;
                }
                let acsb = json_get_field(obj, "alt_post_cstr_b")?;
                if !acsb.is_null() {
                    <CString as WriteJsonValue>::write_from_json(w, acsb)?;
                }
                for k in &["tail_pad_001", "tail_pad_002", "tail_pad_003", "tail_pad_004"] {
                    let v = json_get_field(obj, k)?;
                    if !v.is_null() {
                        <u8 as WriteJsonValue>::write_from_json(w, v)?;
                    }
                }
                let b64 = json_get_field(obj, "_post_blob_b64")?.as_str()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                        "GimmickTail.Decoded._post_blob_b64: expected string"))?;
                let bytes = B64.decode(b64).map_err(|e| io::Error::new(io::ErrorKind::InvalidData,
                    format!("GimmickTail.Decoded._post_blob_b64: invalid base64: {}", e)))?;
                w.extend_from_slice(&bytes);
                Ok(())
            }
            "Raw" => {
                let b64 = json_get_field(obj, "_b64")?.as_str()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                        "GimmickTail.Raw._b64: expected string"))?;
                let bytes = B64.decode(b64).map_err(|e| io::Error::new(io::ErrorKind::InvalidData,
                    format!("GimmickTail.Raw._b64: invalid base64: {}", e)))?;
                w.extend_from_slice(&bytes);
                Ok(())
            }
            other => Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("GimmickTail.kind: unknown variant {:?}", other))),
        }
    }
}

#[derive(Debug)]
pub struct GimmickInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub prefab_path: CString<'a>,
    pub gimmick_group_info: u32,
    pub breakable_object_info: u16,
    pub tail: GimmickTail<'a>,
}

impl<'a> GimmickInfo<'a> {
    pub fn read_with_size(
        data: &'a [u8],
        offset: &mut usize,
        entry_size: usize,
    ) -> io::Result<Self> {
        let entry_start = *offset;
        let entry_end = entry_start + entry_size;

        let key = u32::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let prefab_path = CString::read_from(data, offset)?;
        let gimmick_group_info = u32::read_from(data, offset)?;
        let breakable_object_info = u16::read_from(data, offset)?;
        let tail = GimmickTail::read_with_size(data, offset, entry_end)?;

        Ok(Self {
            key, string_key, is_blocked, prefab_path,
            gimmick_group_info, breakable_object_info, tail,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.prefab_path.write_to(w)?;
        self.gimmick_group_info.write_to(w)?;
        self.breakable_object_info.write_to(w)?;
        self.tail.write_to(w)
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("prefab_path".to_string(), self.prefab_path.to_json_value());
        m.insert("gimmick_group_info".to_string(), self.gimmick_group_info.to_json_value());
        m.insert("breakable_object_info".to_string(), self.breakable_object_info.to_json_value());
        m.insert("tail".to_string(), self.tail.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "prefab_path")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "gimmick_group_info")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "breakable_object_info")?)?;
        GimmickTail::write_from_json(w, json_get_field(obj, "tail")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        let mut decoded = 0usize;
        let mut raw = 0usize;
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = GimmickInfo::read_with_size(&data, &mut c, e - s)
                .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er));
            assert_eq!(c, *e);
            match &item.tail {
                GimmickTail::Decoded { .. } => decoded += 1,
                GimmickTail::Raw(_) => raw += 1,
            }
            items.push(item);
        }
        eprintln!("gimmickinfo: decoded={} raw={} (total={})", decoded, raw, ranges.len());
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "gimmickinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
        let Ok(data) = std::fs::read(PABGB) else {
            eprintln!("SKIP: missing fixture {}", PABGB);
            return;
        };
        let Some(entries) = load_pabgh_offsets(PABGH) else {
            eprintln!("SKIP: missing pabgh fixture {}", PABGH);
            return;
        };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = GimmickInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            GimmickInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
