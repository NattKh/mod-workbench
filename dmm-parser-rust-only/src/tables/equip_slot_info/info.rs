// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! `equipslotinfo.pabgb` (EquipSlotInfo) — per-class equip-slot rules.
//!
//! Reverse-engineered from IDA decompilation of `sub_141048F10` (record reader)
//! and `sub_141048B40` (EquipInfoData reader). Cross-validated against the
//! Python parser at
//! `CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS/CrimsonGameMods/equipslotinfo_parser.py`
//! which round-trips byte-perfect on vanilla 1.04.
//!
//! ## Why this exists
//! Each pabgh key is a character/class identifier. Per record, an array of
//! `EquipInfoData` entries declares which `equip_type_info` hashes the class
//! may equip in each slot. Adding hashes to `etl_hashes` lets a class wield
//! more weapon/armor categories — this is the data path that "Universal
//! Proficiency" / "Super Mega Mod" / "any-character-holds-any-weapon" mods
//! modify. Field-level v3 mod intents address `entries[i].etl_hashes` to
//! grant new equip permissions without rebuilding the full overlay.
//!
//! ## Wire format (post lane-c 2026-04-30 Tier 1.5 → Tier 1 promotion)
//!
//! Record (per pabgh key, length = pabgh-derived `entry_size`):
//! ```text
//!   key            u32
//!   header         CArray<u8>            (sub_1410830B0 prefix; always
//!                                          empty in vanilla but typed
//!                                          for JSON addressability)
//!   flag_u8        u8
//!   flag_u16       u16
//!   list_count     u32
//!   entries        EquipInfoData[list_count]
//!   extra_entries  CArray<EquipExtraEntry>   (5× u32 per entry; empty
//!                                              in 12/13 vanilla records,
//!                                              5 entries in k=0x2bd)
//!   tail_magic     u32                    (always 0xb954d87c)
//! ```
//!
//! `EquipInfoData` (sub_141048B40), 56 bytes plus variable etl_hashes + complex_blob:
//! ```text
//!   etl_hashes   CArray<u32>           ← UNLOCK FIELD: equip_type_info hashes accepted
//!   category_a   u32
//!   category_b   u32
//!   name_hash    u32
//!   slot_index   u16
//!   field_u64    u64
//!   name_hash_2  u32
//!   fields_u32   [u32; 4]
//!   complex_u8   u8
//!   complex_u64  u64
//!   complex_blob CArray<u8>            (u32 size + bytes)
//!   tail_byte_0..1 + tail_pad_u32 + tail_byte_6..10  (8 named tail fields)
//! ```
//!
//! ## Self-delimitation
//! Records are NOT self-delimiting — even with the `tail_magic` sentinel
//! the record length must come from the pabgh index because
//! `extra_entries` has variable size. Always call
//! `parse_equip_slot_info_to_json_with_pabgh` or `read_with_size` with
//! a known `entry_size`. The new typed `tail_magic` field is
//! sanity-checked against `0xb954d87c` after the read.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{json, Value};
use std::io::{self, Write};

// ── EquipInfoData ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct EquipInfoData {
    /// equip_type_info hashes the slot accepts. Add hashes to grant new equip permissions.
    pub etl_hashes: CArray<u32>,
    pub category_a: u32,
    pub category_b: u32,
    pub name_hash: u32,
    pub slot_index: u16,
    pub field_u64: u64,
    pub name_hash_2: u32,
    pub fields_u32: [u32; 4],
    pub complex_u8: u8,
    pub complex_u64: u64,
    pub complex_blob: CArray<u8>,
    /// 11-byte tail composite split into 8 named fields. Empirical sweep
    /// shows: byte 0 = small flag (0/1), byte 1 = small count (0-9),
    /// bytes 2-5 = u32 (always 0 in vanilla), bytes 6-10 = 5× small u8
    /// flags (0/1).
    pub tail_byte_0: u8,
    pub tail_byte_1: u8,
    pub tail_pad_u32: u32,
    pub tail_byte_6: u8,
    pub tail_byte_7: u8,
    pub tail_byte_8: u8,
    pub tail_byte_9: u8,
    pub tail_byte_10: u8,
}

impl<'a> BinaryRead<'a> for EquipInfoData {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let etl_hashes = CArray::<u32>::read_from(data, offset)?;
        let category_a = u32::read_from(data, offset)?;
        let category_b = u32::read_from(data, offset)?;
        let name_hash = u32::read_from(data, offset)?;
        let slot_index = u16::read_from(data, offset)?;
        let field_u64 = u64::read_from(data, offset)?;
        let name_hash_2 = u32::read_from(data, offset)?;
        let fields_u32 = <[u32; 4]>::read_from(data, offset)?;
        let complex_u8 = u8::read_from(data, offset)?;
        let complex_u64 = u64::read_from(data, offset)?;
        let complex_blob = CArray::<u8>::read_from(data, offset)?;
        let tail_byte_0 = u8::read_from(data, offset)?;
        let tail_byte_1 = u8::read_from(data, offset)?;
        let tail_pad_u32 = u32::read_from(data, offset)?;
        let tail_byte_6 = u8::read_from(data, offset)?;
        let tail_byte_7 = u8::read_from(data, offset)?;
        let tail_byte_8 = u8::read_from(data, offset)?;
        let tail_byte_9 = u8::read_from(data, offset)?;
        let tail_byte_10 = u8::read_from(data, offset)?;
        Ok(Self {
            etl_hashes, category_a, category_b, name_hash, slot_index,
            field_u64, name_hash_2, fields_u32, complex_u8, complex_u64,
            complex_blob,
            tail_byte_0, tail_byte_1, tail_pad_u32,
            tail_byte_6, tail_byte_7, tail_byte_8, tail_byte_9, tail_byte_10,
        })
    }
}

impl BinaryWrite for EquipInfoData {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.etl_hashes.write_to(w)?;
        self.category_a.write_to(w)?;
        self.category_b.write_to(w)?;
        self.name_hash.write_to(w)?;
        self.slot_index.write_to(w)?;
        self.field_u64.write_to(w)?;
        self.name_hash_2.write_to(w)?;
        self.fields_u32.write_to(w)?;
        self.complex_u8.write_to(w)?;
        self.complex_u64.write_to(w)?;
        self.complex_blob.write_to(w)?;
        self.tail_byte_0.write_to(w)?;
        self.tail_byte_1.write_to(w)?;
        self.tail_pad_u32.write_to(w)?;
        self.tail_byte_6.write_to(w)?;
        self.tail_byte_7.write_to(w)?;
        self.tail_byte_8.write_to(w)?;
        self.tail_byte_9.write_to(w)?;
        self.tail_byte_10.write_to(w)?;
        Ok(())
    }
}

impl ToJsonValue for EquipInfoData {
    fn to_json_value(&self) -> Value {
        json!({
            "etl_hashes": self.etl_hashes.to_json_value(),
            "category_a": self.category_a,
            "category_b": self.category_b,
            "name_hash": self.name_hash,
            "slot_index": self.slot_index,
            "field_u64": self.field_u64,
            "name_hash_2": self.name_hash_2,
            "fields_u32": self.fields_u32.to_json_value(),
            "complex_u8": self.complex_u8,
            "complex_u64": self.complex_u64,
            "complex_blob": self.complex_blob.to_json_value(),
            "tail_byte_0": self.tail_byte_0,
            "tail_byte_1": self.tail_byte_1,
            "tail_pad_u32": self.tail_pad_u32,
            "tail_byte_6": self.tail_byte_6,
            "tail_byte_7": self.tail_byte_7,
            "tail_byte_8": self.tail_byte_8,
            "tail_byte_9": self.tail_byte_9,
            "tail_byte_10": self.tail_byte_10,
        })
    }
}

impl WriteJsonValue for EquipInfoData {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "EquipInfoData: expected object"))?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "etl_hashes")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "category_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "category_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "name_hash")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "slot_index")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_u64")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "name_hash_2")?)?;
        <[u32; 4] as WriteJsonValue>::write_from_json(w, json_get_field(obj, "fields_u32")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "complex_u8")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "complex_u64")?)?;
        <CArray<u8> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "complex_blob")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_byte_0")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_byte_1")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_pad_u32")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_byte_6")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_byte_7")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_byte_8")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_byte_9")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_byte_10")?)?;
        Ok(())
    }
}

// ── Footer structure ────────────────────────────────────────────────────────
//
// Lane-c 2026-04-30: vanilla probe (13 records) showed `header_blob` is
// always 0-length and `footer` is `CArray<EquipExtraEntry>(stride=20) +
// u32 tail_magic = 0xb954d87c`. 12/13 records have count=0; record k=0x2bd
// has count=5 (5 × 20-byte EquipExtraEntry rows). Field-typing brings the
// trailing per-class data into JSON addressability.

py_binary_struct! {
    /// Trailing per-record extra entry (20 bytes / 5 × u32). Field semantics
    /// not yet fully reversed (only 1 record has nonzero entries in vanilla);
    /// generically exposed as 5 named u32 fields so JSON consumers can edit
    /// any byte. Empirical layout from k=0x2bd's 5 rows:
    ///   - field_a: small int / signed sentinel (e.g. 0, 2, 4, -744, -745)
    ///   - field_b: small int OR hash (e.g. 1, 2, 0x4425304d, 0x0bb2ba9b)
    ///   - field_c: u32 (often 0)
    ///   - field_d: u32 hash-like (e.g. 0xa02a, 0x1550, 0xfc000, 0x750be4d5)
    ///   - field_e: u8-style flag widened to u32 (0 or 1)
    pub struct EquipExtraEntry {
        pub field_a: u32,
        pub field_b: u32,
        pub field_c: u32,
        pub field_d: u32,
        pub field_e: u32,
    }
}

/// Tail magic that terminates every EquipSlotInfo record. Constant
/// `0xb954d87c` (wire bytes `7c d8 54 b9`). Preserved as a typed `u32`
/// so JSON consumers can sanity-check it.
pub const EQUIP_SLOT_TAIL_MAGIC: u32 = 0xb954d87c;

// ── EquipSlotInfo (top-level record) ────────────────────────────────────────

#[derive(Debug)]
pub struct EquipSlotInfo {
    pub key: u32,
    /// Header byte list (sub_1410830B0). Wire format = `CArray<u8>` (u32 count
    /// + bytes). Empirically always empty in vanilla 1.04 (count=0 across all
    /// 13 records); typed to allow growth via mods.
    pub header: CArray<u8>,
    pub flag_u8: u8,
    pub flag_u16: u16,
    pub entries: Vec<EquipInfoData>,
    /// Trailing per-class extra entries (typed via field_a..field_e per row).
    /// Empty in 12/13 vanilla records; record k=0x2bd has 5 rows.
    pub extra_entries: CArray<EquipExtraEntry>,
    /// Constant tail terminator = `EQUIP_SLOT_TAIL_MAGIC` (0xb954d87c).
    pub tail_magic: u32,
}

impl EquipSlotInfo {
    /// Parse a single record. `entry_size` is the pabgh-declared record length;
    /// without it we cannot validate the trailing magic terminator position.
    pub fn read_with_size(
        data: &[u8],
        offset: &mut usize,
        entry_size: usize,
    ) -> io::Result<Self> {
        let entry_start = *offset;
        let entry_end = entry_start
            .checked_add(entry_size)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "EquipSlotInfo: entry_size overflow"))?;
        if entry_end > data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof,
                format!("EquipSlotInfo: record extends past body ({} > {})", entry_end, data.len())));
        }

        let key = u32::read_from(data, offset)?;
        let header = CArray::<u8>::read_from(data, offset)?;
        let flag_u8 = u8::read_from(data, offset)?;
        let flag_u16 = u16::read_from(data, offset)?;
        let list_count = u32::read_from(data, offset)? as usize;

        let mut entries = Vec::with_capacity(list_count);
        for i in 0..list_count {
            let e = EquipInfoData::read_from(data, offset).map_err(|e| io::Error::new(
                e.kind(),
                format!("EquipSlotInfo k={}: entries[{}]: {}", key, i, e),
            ))?;
            entries.push(e);
        }

        let extra_entries = CArray::<EquipExtraEntry>::read_from(data, offset)?;
        let tail_magic = u32::read_from(data, offset)?;

        if *offset != entry_end {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("EquipSlotInfo k={}: under/over-read ({} of {} bytes; tail_magic=0x{:x})",
                    key, *offset - entry_start, entry_size, tail_magic)));
        }
        if tail_magic != EQUIP_SLOT_TAIL_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("EquipSlotInfo k={}: tail_magic = 0x{:x}, expected 0x{:x}",
                    key, tail_magic, EQUIP_SLOT_TAIL_MAGIC)));
        }

        Ok(Self { key, header, flag_u8, flag_u16, entries, extra_entries, tail_magic })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.header.write_to(w)?;
        self.flag_u8.write_to(w)?;
        self.flag_u16.write_to(w)?;
        (self.entries.len() as u32).write_to(w)?;
        for e in &self.entries {
            e.write_to(w)?;
        }
        self.extra_entries.write_to(w)?;
        self.tail_magic.write_to(w)?;
        Ok(())
    }
}

impl ToJsonValue for EquipSlotInfo {
    fn to_json_value(&self) -> Value {
        // string_key: empty placeholder so DMM's apply pipeline (which builds
        // by_name and by_key indexes) finds an entry under both maps. Vanilla
        // equipslotinfo records have no native string_key, so by_name lookup
        // resolves to "" for all records — intent authors must address by
        // numeric `key` (the class id), which falls through the by_name miss
        // into the by_key fallback in apply_one_intent.
        json!({
            "key": self.key,
            "string_key": "",
            "header": self.header.to_json_value(),
            "flag_u8": self.flag_u8,
            "flag_u16": self.flag_u16,
            "entries": Value::Array(self.entries.iter().map(|e| e.to_json_value()).collect()),
            "extra_entries": self.extra_entries.to_json_value(),
            "tail_magic": self.tail_magic,
        })
    }
}

impl WriteJsonValue for EquipSlotInfo {
    fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "EquipSlotInfo: expected object"))?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CArray<u8> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "header")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_u8")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_u16")?)?;
        // entries: explicit u32 count + EquipInfoData each (Vec<...>, not CArray).
        let entries = json_get_field(obj, "entries")?
            .as_array().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EquipSlotInfo.entries: expected array"))?;
        w.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            <EquipInfoData as WriteJsonValue>::write_from_json(w, e).map_err(|err| io::Error::new(
                err.kind(), format!("entries[{}]: {}", i, err)))?;
        }
        <CArray<EquipExtraEntry> as WriteJsonValue>::write_from_json(
            w, json_get_field(obj, "extra_entries")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "tail_magic")?)?;
        Ok(())
    }
}

// ── Public parse/serialize API ──────────────────────────────────────────────

/// Parse equipslotinfo.pabgb — REQUIRES pabgh because records are not
/// self-delimiting (the trailing `footer` has no length prefix). Calling
/// without pabgh returns a clear error. Use
/// `parse_equip_slot_info_to_json_with_pabgh` directly for the normal path.
pub fn parse_equip_slot_info_to_json(_data: &[u8]) -> io::Result<Vec<Value>> {
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "equip_slot_info records are not self-delimiting; call \
         parse_equip_slot_info_to_json_with_pabgh(body, pabgh) instead",
    ))
}

/// Parse equipslotinfo.pabgb using the sister pabgh index for record
/// boundaries. Returns a JSON dict per record (one per pabgh key), in pabgh
/// order. Output shape mirrors `parse_skill_to_json` so the v3 apply pipeline
/// in DMM treats it uniformly.
pub fn parse_equip_slot_info_to_json_with_pabgh(
    data: &[u8],
    pabgh: &[u8],
) -> io::Result<Vec<Value>> {
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets_from_bytes};
    let entries = load_pabgh_offsets_from_bytes(pabgh).ok_or_else(|| io::Error::new(
        io::ErrorKind::InvalidData, "equip_slot_info: pabgh parse failed"))?;
    let ranges = entry_ranges(&entries, data.len());
    let mut out = Vec::with_capacity(ranges.len());
    for (k, s, e) in ranges {
        let mut c = s;
        let item = EquipSlotInfo::read_with_size(data, &mut c, e - s).map_err(|err| io::Error::new(
            err.kind(),
            format!("equip_slot_info k=0x{:x}: {}", k, err),
        ))?;
        if c != e {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("equip_slot_info k=0x{:x}: under/over-consumed {}/{}", k, c - s, e - s)));
        }
        out.push(item.to_json_value());
    }
    Ok(out)
}

/// Inverse of `parse_equip_slot_info_to_json_with_pabgh`. Writes records back
/// to pabgb bytes in the order given. The pabgh sister file must be rebuilt
/// separately from the resulting offsets — this function does not produce one.
pub fn serialize_equip_slot_info_from_json(items: &[Value]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(items.len() * 1024);
    for (i, v) in items.iter().enumerate() {
        EquipSlotInfo::write_from_json(&mut out, v).map_err(|e| io::Error::new(
            e.kind(), format!("equip_slot_info[{}]: {}", i, e)))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB: &str = r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\equipslotinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD JSON Mod Manager\Unpacked\0008\gamedata\equipslotinfo.pabgh";


    #[test]
    fn roundtrip_bytes() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP: pabgb missing"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP: pabgh missing"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            let item = EquipSlotInfo::read_with_size(&data, &mut c, *e - *s)
                .unwrap_or_else(|err| panic!("e{} k=0x{:x}: {}", i, k, err));
            assert_eq!(c, *e, "e{} k=0x{:x}: under/over-consumed {}/{}", i, k, c - *s, *e - *s);
            items.push(item);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "EquipSlotInfo binary round-trip mismatch");
    }

    #[test]
    fn roundtrip_json() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP: pabgb missing"); return; };
        let Ok(pabgh) = std::fs::read(PABGH) else { eprintln!("SKIP: pabgh missing"); return; };
        let json = parse_equip_slot_info_to_json_with_pabgh(&data, &pabgh)
            .expect("parse_equip_slot_info_to_json_with_pabgh");
        let out = serialize_equip_slot_info_from_json(&json)
            .expect("serialize_equip_slot_info_from_json");
        assert_eq!(out, data, "EquipSlotInfo JSON round-trip mismatch");
    }

    #[test]
    fn etl_hashes_addressable() {
        // Smoke test: the field that mod intents will target must be reachable
        // by name from JSON output. Without this, "set entries[0].etl_hashes"
        // intents would silently drop on apply.
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP: pabgb missing"); return; };
        let Ok(pabgh) = std::fs::read(PABGH) else { eprintln!("SKIP: pabgh missing"); return; };
        let json = parse_equip_slot_info_to_json_with_pabgh(&data, &pabgh).unwrap();
        let first = json.first().expect("at least one record");
        let entries = first.get("entries").and_then(|v| v.as_array()).expect("entries array");
        let first_entry = entries.first().expect("at least one entry");
        let etl = first_entry.get("etl_hashes").and_then(|v| v.as_array()).expect("etl_hashes array");
        // vanilla key=1 record's first entry has 3 etl_hashes
        assert!(!etl.is_empty(), "etl_hashes must not be empty for class 1 entry 0");
    }
}
