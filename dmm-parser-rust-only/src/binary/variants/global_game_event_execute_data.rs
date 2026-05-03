#![allow(clippy::doc_overindented_list_items)]
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! GlobalGameEventExecuteData polymorphic family wrapper — per-sub_tag typed.
//!
//! Per Win-IDA dispatcher `sub_141156680`, the wire format is:
//!   - u8 presence (0 = absent, 1 = present)
//!   - if present:
//!     - u8 sub_tag
//!         - 0 → ConstructorVaryTradeItemPrice (88-byte runtime struct)
//!         - 1 → ConstructorOpenRoyalSupply    (32-byte runtime struct)
//!         - 2 → in-place reuse of existing pointer (no body bytes)
//!         - other → error (return 0)
//!     - body bytes per sub_tag-specific reader
//!
//! Body wire shapes (decompiled from the per-vtable readers + cross-checked
//! against reflection-binding strings extracted from the Mac binary):
//!
//! - sub_tag 0 / VaryTradeItemPrice (`sub_141155000` calls these in order):
//!     * `target_item_group_keys`: CArray<u16>  (sub_1410FFAC0, qword_DA80
//!                                              ItemGroupKey hash; matches
//!                                              `_targetItemGroupList`)
//!     * `price_list`:             CArray<VaryTradeItemPriceData>
//!                                              (sub_141155530; matches
//!                                              `_priceList`)
//!     * `item_lookup`:            u32          (read_u32_lookup_DA30 —
//!                                              asset/category hash; wire u32
//!                                              resolves to u16)
//!     * `description`:            LocalizableString (read_LocalizableString)
//!
//!   Per element of `price_list` (sub_141155530's loop body):
//!     * `target_region_keys`:  CArray<u16> (sub_1411022B0, qword_DA20 region
//!                                          hash; matches `_targetRegionList`)
//!     * `min_price`:           i64
//!     * `max_price`:           i64
//!
//!   Empirical price patterns (matches `_minPrice`/`_maxPrice` reflection
//!   strings): trade-up entries `min=500000, max=800000`; inverse trade-down
//!   entries `min=-800000, max=-500000`. min ≤ max holds for all 80 entries.
//!
//! - sub_tag 1 / OpenRoyalSupply (`sub_141155300` → `sub_1411553D0`):
//!     * `target_region_keys`: CArray<u16> (sub_1411553D0, qword_113A0 hash)
//!
//! - sub_tag 2 / InPlace: no body bytes. The dispatcher only handles this when
//!   the caller already has a previously-constructed object; for fresh-pointer
//!   table reads (our case) sub_tag 2 effectively produces an empty body.
//!
//! ## Decode strategy: Decoded | Raw fallback
//!
//! `read_from` tries the typed shape per sub_tag and falls back to `Raw(bytes)`
//! on any decode failure or under-consume. That guarantees byte-perfect
//! round-trip even if a future build of the game introduces a new sub_tag.
//!
//! ### Lookup-table fields
//!
//! Several fields (`region_codes` u16 entries, `item_lookup` u32) are
//! game-side hash keys that the runtime resolves via global hash tables. We
//! store the **wire** values verbatim (no resolution) — the table's read/write
//! cycle is byte-perfect, and downstream tooling can re-resolve at use time.

use crate::binary::*;
use crate::json_traits::get_field as json_get_field;
use crate::py_binary_struct;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{Map, Value};
use std::io::{self, Write};

// ── Per-sub_tag payload structs ────────────────────────────────────────────

py_binary_struct! {
    /// One element of `VaryTradeItemPricePayload.price_list` (sub_141155530's
    /// loop). Wire: CArray<u16> region keys + two i64 price boundaries (16
    /// bytes total). Field names match the Mac-binary reflection metadata
    /// (`_targetRegionList`, `_minPrice`, `_maxPrice`).
    pub struct VaryTradeItemPriceData {
        pub target_region_keys: CArray<u16>,
        pub min_price: i64,
        pub max_price: i64,
    }
}

py_binary_struct! {
    /// sub_tag 0 body, per `sub_141155000`. Field names match Mac-binary
    /// reflection metadata where known (`_targetItemGroupList`, `_priceList`).
    /// `item_lookup` is a u32 asset/category hash key (qword_DA30 lookup;
    /// runtime resolves to u16 at offset +48; specific reflection name not
    /// recovered).
    pub struct VaryTradeItemPricePayload<'a> {
        pub target_item_group_keys: CArray<u16>,
        pub price_list: CArray<VaryTradeItemPriceData>,
        pub item_lookup: u32,
        pub description: LocalizableString<'a>,
    }
}

py_binary_struct! {
    /// sub_tag 1 body, per `sub_141155300` → `sub_1411553D0`. Single
    /// `target_region_keys` array (qword_113A0 region hash).
    pub struct OpenRoyalSupplyPayload {
        pub target_region_keys: CArray<u16>,
    }
}

// ── Body enum (per-sub_tag dispatch) ───────────────────────────────────────

#[derive(Debug)]
pub enum GlobalGameEventExecuteDataBody<'a> {
    /// sub_tag 0
    VaryTradeItemPrice(VaryTradeItemPricePayload<'a>),
    /// sub_tag 1
    OpenRoyalSupply(OpenRoyalSupplyPayload),
    /// sub_tag 2 — no body bytes
    InPlace,
}

impl GlobalGameEventExecuteDataBody<'_> {
    pub fn sub_tag(&self) -> u8 {
        match self {
            Self::VaryTradeItemPrice(_) => 0,
            Self::OpenRoyalSupply(_) => 1,
            Self::InPlace => 2,
        }
    }
}

// ── Wrapper enum ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum GlobalGameEventExecuteData<'a> {
    /// Wrapper has presence byte == 0; no sub_tag, no body.
    /// On wire: `[0x00]`.
    Absent,
    /// Wrapper has presence byte == 1; sub_tag-driven typed body.
    /// On wire: `[0x01, sub_tag, ...body]`.
    Present(GlobalGameEventExecuteDataBody<'a>),
    /// Fallback for unrecognized presence/sub_tag, decode failure, or
    /// trailing bytes the typed reader didn't consume.
    /// Bytes preserved verbatim — round-trips byte-perfect.
    Raw(Vec<u8>),
}

impl<'a> GlobalGameEventExecuteData<'a> {
    /// `data` should be sized to exactly the wrapper bytes (table-level
    /// tail_blob). Any decode that doesn't cleanly consume all bytes
    /// produces a Raw fallback.
    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let start = *offset;
        if start >= data.len() {
            return Ok(Self::Raw(Vec::new()));
        }
        let presence = data[start];
        match presence {
            0 if data.len() - start == 1 => {
                *offset = data.len();
                Ok(Self::Absent)
            }
            1 if data.len() - start >= 2 => {
                let sub_tag = data[start + 1];
                let mut probe = start + 2;
                let typed = match sub_tag {
                    0 => VaryTradeItemPricePayload::read_from(data, &mut probe)
                        .map(GlobalGameEventExecuteDataBody::VaryTradeItemPrice),
                    1 => OpenRoyalSupplyPayload::read_from(data, &mut probe)
                        .map(GlobalGameEventExecuteDataBody::OpenRoyalSupply),
                    2 => Ok(GlobalGameEventExecuteDataBody::InPlace),
                    _ => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("GlobalGameEventExecuteData: unknown sub_tag {}", sub_tag),
                    )),
                };
                match typed {
                    Ok(body) if probe == data.len() => {
                        *offset = data.len();
                        Ok(Self::Present(body))
                    }
                    _ => {
                        let raw = data[start..].to_vec();
                        *offset = data.len();
                        Ok(Self::Raw(raw))
                    }
                }
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
            Self::Absent => 0u8.write_to(w),
            Self::Present(body) => {
                1u8.write_to(w)?;
                body.sub_tag().write_to(w)?;
                match body {
                    GlobalGameEventExecuteDataBody::VaryTradeItemPrice(p) => p.write_to(w),
                    GlobalGameEventExecuteDataBody::OpenRoyalSupply(p) => p.write_to(w),
                    GlobalGameEventExecuteDataBody::InPlace => Ok(()),
                }
            }
            Self::Raw(bytes) => w.write_all(bytes),
        }
    }

    /// JSON shape:
    /// - `kind`: "absent" | "present" | "raw"
    /// - when "present": `sub_tag` (u8), `body_type` (string), `body` (typed object)
    /// - when "raw": `raw_b64` (base64 string)
    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        match self {
            Self::Absent => {
                m.insert("kind".into(), Value::String("absent".into()));
            }
            Self::Present(body) => {
                m.insert("kind".into(), Value::String("present".into()));
                m.insert("sub_tag".into(), Value::Number(body.sub_tag().into()));
                match body {
                    GlobalGameEventExecuteDataBody::VaryTradeItemPrice(p) => {
                        m.insert(
                            "body_type".into(),
                            Value::String("vary_trade_item_price".into()),
                        );
                        m.insert("body".into(), Value::Object(p.to_json_dict()));
                    }
                    GlobalGameEventExecuteDataBody::OpenRoyalSupply(p) => {
                        m.insert(
                            "body_type".into(),
                            Value::String("open_royal_supply".into()),
                        );
                        m.insert("body".into(), Value::Object(p.to_json_dict()));
                    }
                    GlobalGameEventExecuteDataBody::InPlace => {
                        m.insert("body_type".into(), Value::String("in_place".into()));
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
                "GlobalGameEventExecuteData: expected object",
            )
        })?;
        let kind = json_get_field(obj, "kind")?
            .as_str()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "GlobalGameEventExecuteData.kind: expected string",
                )
            })?;
        match kind {
            "absent" => {
                w.push(0);
                Ok(())
            }
            "present" => {
                let sub_tag_v = json_get_field(obj, "sub_tag")?
                    .as_u64()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "GlobalGameEventExecuteData.sub_tag: expected u8",
                        )
                    })?;
                if sub_tag_v > u8::MAX as u64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("sub_tag {} out of u8 range", sub_tag_v),
                    ));
                }
                let sub_tag = sub_tag_v as u8;
                w.push(1);
                w.push(sub_tag);
                match sub_tag {
                    0 => {
                        let body = json_get_field(obj, "body")?.as_object().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "GlobalGameEventExecuteData.body: expected object for sub_tag 0",
                            )
                        })?;
                        VaryTradeItemPricePayload::write_from_json_dict(w, body)
                    }
                    1 => {
                        let body = json_get_field(obj, "body")?.as_object().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "GlobalGameEventExecuteData.body: expected object for sub_tag 1",
                            )
                        })?;
                        OpenRoyalSupplyPayload::write_from_json_dict(w, body)
                    }
                    2 => Ok(()),
                    other => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("GlobalGameEventExecuteData: unknown sub_tag {}", other),
                    )),
                }
            }
            "raw" => {
                let b64 = json_get_field(obj, "raw_b64")?
                    .as_str()
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "GlobalGameEventExecuteData.raw_b64: expected base64 string",
                        )
                    })?;
                let bytes = B64.decode(b64).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("GlobalGameEventExecuteData.raw_b64: invalid base64: {}", e),
                    )
                })?;
                w.extend_from_slice(&bytes);
                Ok(())
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("GlobalGameEventExecuteData.kind: unknown value {:?}", other),
            )),
        }
    }
}
