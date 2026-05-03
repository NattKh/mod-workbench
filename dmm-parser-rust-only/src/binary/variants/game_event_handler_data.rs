// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! GameEventHandlerData polymorphic family wrapper — per-sub_tag typed.
//!
//! Per Win-IDA dispatcher `sub_1415BE5E0`, the wire format is:
//!   - u8 sub_tag (0-4)
//!     - 0 → SetSceneObjectParameterBySceneLevel (32B runtime)
//!     - 1 → SetSceneObjectParameter            (32B runtime)
//!     - 2 → SetUIPlayGuideParameter            (32B runtime)
//!     - 3 → SetUIFullscreenGuideParameter      (24B runtime)
//!     - 4 → MakeSnapshotForDev                 (24B runtime)
//!     - 5+ → error (returns null)
//!   - body bytes per sub_tag-specific reader (vtable[4])
//!
//! ## Anti-disassembly territory
//!
//! Each subclass's vtable[4] reader (e.g. `sub_141446260` for sub_tag 2) lives
//! in the obfuscated/self-modifying region of the binary — IDA's decompiler
//! can't recover their structure cleanly (raw bytes start with 0xBC,
//! incompatible with a standard x86-64 prologue). Field shapes here are
//! recovered **empirically** from the wire byte patterns of all 682 vanilla
//! entries (422 sub_tag 2 + 260 sub_tag 3) and cross-checked against the
//! dispatcher's runtime-init constants:
//!
//! - sub_tag 2 (SetUIPlayGuideParameter): 12-byte body. Init constants
//!   `*(_DWORD *)(v11 + 16) = 0; *(_WORD *)(v11 + 20) = -1; *(_DWORD *)(v11 + 24) = 0`
//!   imply runtime layout u32 + u16(hash sentinel) + u32. Wire is 12 bytes
//!   forming `play_guide_key: u32`, `lookup_hash: u32`, `duration_seconds: f32`.
//!   Empirical findings across 422 vanilla entries:
//!     * `play_guide_key` mirrors the entry key in 339/422 — a self-reference
//!       in the common case. The 83 mismatches are entries with synthetic
//!       high keys (0xfffe-style) referencing a normal-range guide key.
//!     * `lookup_hash` is high-entropy random pattern (string-content hash).
//!     * `duration_seconds` clusters at 0.0 (184 entries), 30.0 (181), 20.0
//!       (45), with a long tail (60.0, 120.0, 9999.0, etc.) — classic
//!       game-side timeout/duration distribution.
//!
//! - sub_tag 3 (SetUIFullscreenGuideParameter): 6-byte body. Init constant
//!   `*(_DWORD *)(v11 + 16) = -65536` → bytes `00 00 FF FF` → numeric u16 at
//!   +16 (default 0) + hash-sentinel u16 at +18. Wire is u16 + u32 = 6 bytes:
//!   `fullscreen_guide_key: u16` + `lookup_hash: u32`. Empirically,
//!   `fullscreen_guide_key` equals the entry key in 260/260 entries.
//!
//! Sub_tags 0, 1 don't appear in vanilla data; the Raw fallback handles
//! them byte-perfect if a future build introduces them. Sub_tag 4
//! (MakeSnapshotForDev) is typed as a no-body variant because the
//! dispatcher fully fills the 24-byte runtime struct via constructor
//! (vftable + sub_tag + static pointer at +16) — no wire reads required.
//! If a future build adds wire bytes for sub_tag 4, the typed read will
//! fall to Raw automatically (read_from checks probe == data.len()).
//!
//! ## Decode strategy: Decoded(Body) | Raw fallback
//!
//! Same pattern as GlobalGameEventExecuteData and GameCondition. Typed decode
//! per known sub_tag; byte-perfect Raw fallback for anything else.
//!
//! The consuming table (GameEventHandlerInfo) reads a trailing u8 AFTER this
//! wrapper. The wrapper struct here owns the sub_tag + body; the consuming
//! table owns the trailing byte separately.

use crate::binary::*;
use crate::json_traits::get_field as json_get_field;
use crate::py_binary_struct;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{Map, Value};
use std::io::{self, Write};

// ── Per-sub_tag payloads ──────────────────────────────────────────────────

py_binary_struct! {
    /// sub_tag 2 body (12 bytes). Three u32-wide wire fields:
    /// - `play_guide_key`: foreign-key reference to a play-guide entry
    ///   (matches the consuming entry's own `key` in 339/422 vanilla cases;
    ///    the rest are synthetic-key entries pointing to a normal-range
    ///    guide).
    /// - `lookup_hash`: u32 hash key resolved at runtime to a u16 at
    ///   offset +20 (init sentinel 0xFFFF for "not found").
    /// - `duration_seconds`: f32 timeout/duration. Clusters at 0.0 (184
    ///   entries), 30.0 (181), 20.0 (45) with a long tail.
    pub struct SetUIPlayGuideParameterPayload {
        pub play_guide_key: u32,
        pub lookup_hash: u32,
        pub duration_seconds: f32,
    }
}

py_binary_struct! {
    /// sub_tag 3 body (6 bytes). u16 self-key + u32 hash-key:
    /// - `fullscreen_guide_key`: matches the entry's own `key` in 260/260
    ///   vanilla entries (data-redundancy self-reference).
    /// - `lookup_hash`: u32 hash key resolved at runtime to a u16 at
    ///   offset +18 (init sentinel 0xFFFF for "not found").
    pub struct SetUIFullscreenGuideParameterPayload {
        pub fullscreen_guide_key: u16,
        pub lookup_hash: u32,
    }
}

// ── Body enum (per-sub_tag dispatch) ───────────────────────────────────────

#[derive(Debug)]
pub enum GameEventHandlerDataBody {
    /// sub_tag 2
    SetUIPlayGuideParameter(SetUIPlayGuideParameterPayload),
    /// sub_tag 3
    SetUIFullscreenGuideParameter(SetUIFullscreenGuideParameterPayload),
    /// sub_tag 4 — no wire body bytes (dispatcher fills via constructor)
    MakeSnapshotForDev,
}

impl GameEventHandlerDataBody {
    pub fn sub_tag(&self) -> u8 {
        match self {
            Self::SetUIPlayGuideParameter(_) => 2,
            Self::SetUIFullscreenGuideParameter(_) => 3,
            Self::MakeSnapshotForDev => 4,
        }
    }
}

// ── Wrapper enum ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum GameEventHandlerData {
    /// Recognized sub_tag (2, 3, or 4); body fields are typed per
    /// sub_tag. On wire: `[sub_tag, ...body]`.
    Decoded(GameEventHandlerDataBody),
    /// Fallback for unrecognized sub_tag (0/1 in dispatcher but not in
    /// vanilla data — readers obfuscated, no empirical samples to type),
    /// short data, or any decode failure. Bytes preserved verbatim —
    /// round-trips byte-perfect.
    Raw(Vec<u8>),
}

impl GameEventHandlerData {
    /// `data` should be sized to exactly the wrapper bytes (sub_tag +
    /// body, NOT including any consumer-owned trailing fields). The
    /// consumer is responsible for slicing off any post-wrapper bytes
    /// before calling this.
    pub fn read_from(data: &[u8], offset: &mut usize) -> io::Result<Self> {
        let start = *offset;
        if start >= data.len() {
            return Ok(Self::Raw(Vec::new()));
        }
        let sub_tag = data[start];
        let mut probe = start + 1;
        let typed = match sub_tag {
            2 => SetUIPlayGuideParameterPayload::read_from(data, &mut probe)
                .map(GameEventHandlerDataBody::SetUIPlayGuideParameter),
            3 => SetUIFullscreenGuideParameterPayload::read_from(data, &mut probe)
                .map(GameEventHandlerDataBody::SetUIFullscreenGuideParameter),
            4 => Ok(GameEventHandlerDataBody::MakeSnapshotForDev),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("GameEventHandlerData: untyped sub_tag {}", sub_tag),
            )),
        };
        match typed {
            Ok(body) if probe == data.len() => {
                *offset = data.len();
                Ok(Self::Decoded(body))
            }
            _ => {
                let raw = data[start..].to_vec();
                *offset = data.len();
                Ok(Self::Raw(raw))
            }
        }
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Decoded(body) => {
                body.sub_tag().write_to(w)?;
                match body {
                    GameEventHandlerDataBody::SetUIPlayGuideParameter(p) => p.write_to(w),
                    GameEventHandlerDataBody::SetUIFullscreenGuideParameter(p) => p.write_to(w),
                    GameEventHandlerDataBody::MakeSnapshotForDev => Ok(()),
                }
            }
            Self::Raw(bytes) => w.write_all(bytes),
        }
    }

    /// JSON shape:
    /// - `kind`: "decoded" | "raw"
    /// - when "decoded": `sub_tag` (u8), `body_type` (string),
    ///   `body` (typed object with the per-sub_tag fields, omitted for
    ///   no-body variants like sub_tag 4)
    /// - when "raw": `raw_b64` (base64 string)
    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        match self {
            Self::Decoded(body) => {
                m.insert("kind".into(), Value::String("decoded".into()));
                m.insert("sub_tag".into(), Value::Number(body.sub_tag().into()));
                match body {
                    GameEventHandlerDataBody::SetUIPlayGuideParameter(p) => {
                        m.insert(
                            "body_type".into(),
                            Value::String("set_ui_play_guide_parameter".into()),
                        );
                        m.insert("body".into(), Value::Object(p.to_json_dict()));
                    }
                    GameEventHandlerDataBody::SetUIFullscreenGuideParameter(p) => {
                        m.insert(
                            "body_type".into(),
                            Value::String("set_ui_fullscreen_guide_parameter".into()),
                        );
                        m.insert("body".into(), Value::Object(p.to_json_dict()));
                    }
                    GameEventHandlerDataBody::MakeSnapshotForDev => {
                        m.insert(
                            "body_type".into(),
                            Value::String("make_snapshot_for_dev".into()),
                        );
                    }
                }
            }
            Self::Raw(bytes) => {
                m.insert("kind".into(), Value::String("raw".into()));
                m.insert("raw_b64".into(), Value::String(B64.encode(bytes)));
            }
        }
        Value::Object(m)
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "GameEventHandlerData: expected object",
            )
        })?;
        let kind = json_get_field(obj, "kind")?
            .as_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GameEventHandlerData.kind: expected string",
                )
            })?;
        match kind {
            "decoded" => {
                let sub_tag_v = json_get_field(obj, "sub_tag")?
                    .as_u64()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "GameEventHandlerData.sub_tag: expected u8",
                        )
                    })?;
                if sub_tag_v > u8::MAX as u64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("sub_tag {} out of u8 range", sub_tag_v),
                    ));
                }
                let sub_tag = sub_tag_v as u8;
                w.push(sub_tag);
                match sub_tag {
                    2 => {
                        let body = json_get_field(obj, "body")?.as_object().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "GameEventHandlerData.body: expected object for sub_tag 2",
                            )
                        })?;
                        SetUIPlayGuideParameterPayload::write_from_json_dict(w, body)
                    }
                    3 => {
                        let body = json_get_field(obj, "body")?.as_object().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "GameEventHandlerData.body: expected object for sub_tag 3",
                            )
                        })?;
                        SetUIFullscreenGuideParameterPayload::write_from_json_dict(w, body)
                    }
                    4 => Ok(()),
                    other => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("GameEventHandlerData: untyped sub_tag {}", other),
                    )),
                }
            }
            "raw" => {
                let b64 = json_get_field(obj, "raw_b64")?
                    .as_str()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "GameEventHandlerData.raw_b64: expected base64 string",
                        )
                    })?;
                let bytes = B64.decode(b64).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("GameEventHandlerData.raw_b64: invalid base64: {}", e),
                    )
                })?;
                w.extend_from_slice(&bytes);
                Ok(())
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("GameEventHandlerData.kind: unknown value {:?}", other),
            )),
        }
    }
}
