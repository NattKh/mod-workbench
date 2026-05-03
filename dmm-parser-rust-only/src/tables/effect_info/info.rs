// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `EffectInfo.pabgb`.
//!
//! Per Win-IDA `sub_1410DBFC0` (entry parser):
//!   1. u32 key
//!   2. CString string_key
//!   3. u8 is_blocked
//!   4. effect_data: CArray<EffectDataElement> via sub_141116A70 — each
//!      element exposes 10 named fields plus a typed `core_block` (47
//!      named sub-fields) and a fully typed `inner_map`
//!      (CArray<{u32 key, EffectDataInner}>).
//!   5. mesh_effect_data: u32 count + N × 50-byte MeshEffectData (read
//!      by sub_1410DBD90). Fully typed below.
//!   6. u8 has_equip_type
//!   7. u8 has_preset
//!   8. u8 target_color_lerp_type
//!
//! Both lists are now per-element typed. The combined opaque blob from
//! earlier sessions is gone.
//!
//! ## MeshEffectData wire (per sub_1410DBD90)
//!
//! 50 bytes fixed:
//!   - u8   field_a       (1)
//!   - u32  field_b       (5)
//!   - u32  field_c       (9)
//!   - u32  field_d       (13)
//!   - u32  field_e       (17)
//!   - u32  field_f       (21)
//!   - u32  field_g       (25)
//!   - u32  field_h       (29)
//!   - u32  field_i       (33)
//!   - u8   field_flag    (37)
//!   - u32  lookup_a      (41) ← u32 hash → u16 in memory
//!   - u32  lookup_b      (45)
//!   - u32  lookup_c      (49)
//!   - u32  lookup_d      (50)?
//!
//! Wait, the four u32 lookups land at consecutive WORD offsets (memory
//! 38/40/42/44) but each reads 4 bytes from the wire. So wire size is
//! 1 + 8*4 + 1 + 4*4 = 50 bytes total.

use crate::binary::variants::effect_data::EffectDataElement;
use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use serde_json::{Map, Value};
use std::io::{self, Write};

const TAIL_SIZE: usize = 3;
const MESH_ELEMENT_WIRE_SIZE: usize = 50;

/// One entry in `EffectInfo._meshEffectDataList`. Wire format read by
/// `sub_1410DBD90`: fixed 50 bytes per element. Typed below.
#[derive(Debug, Clone)]
pub struct MeshEffectData {
    pub field_a: u8,
    pub field_b: u32,
    pub field_c: u32,
    pub field_d: u32,
    pub field_e: u32,
    pub field_f: u32,
    pub field_g: u32,
    pub field_h: u32,
    pub field_i: u32,
    pub field_flag: u8,
    pub lookup_a: u32,
    pub lookup_b: u32,
    pub lookup_c: u32,
    pub lookup_d: u32,
}

impl MeshEffectData {
    pub fn read_from(data: &[u8], offset: &mut usize) -> io::Result<Self> {
        let field_a = u8::read_from(data, offset)?;
        let field_b = u32::read_from(data, offset)?;
        let field_c = u32::read_from(data, offset)?;
        let field_d = u32::read_from(data, offset)?;
        let field_e = u32::read_from(data, offset)?;
        let field_f = u32::read_from(data, offset)?;
        let field_g = u32::read_from(data, offset)?;
        let field_h = u32::read_from(data, offset)?;
        let field_i = u32::read_from(data, offset)?;
        let field_flag = u8::read_from(data, offset)?;
        let lookup_a = u32::read_from(data, offset)?;
        let lookup_b = u32::read_from(data, offset)?;
        let lookup_c = u32::read_from(data, offset)?;
        let lookup_d = u32::read_from(data, offset)?;
        Ok(Self {
            field_a, field_b, field_c, field_d, field_e, field_f, field_g, field_h, field_i,
            field_flag, lookup_a, lookup_b, lookup_c, lookup_d,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.field_a.write_to(w)?;
        self.field_b.write_to(w)?;
        self.field_c.write_to(w)?;
        self.field_d.write_to(w)?;
        self.field_e.write_to(w)?;
        self.field_f.write_to(w)?;
        self.field_g.write_to(w)?;
        self.field_h.write_to(w)?;
        self.field_i.write_to(w)?;
        self.field_flag.write_to(w)?;
        self.lookup_a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.lookup_c.write_to(w)?;
        self.lookup_d.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("field_a".to_string(), self.field_a.to_json_value());
        m.insert("field_b".to_string(), self.field_b.to_json_value());
        m.insert("field_c".to_string(), self.field_c.to_json_value());
        m.insert("field_d".to_string(), self.field_d.to_json_value());
        m.insert("field_e".to_string(), self.field_e.to_json_value());
        m.insert("field_f".to_string(), self.field_f.to_json_value());
        m.insert("field_g".to_string(), self.field_g.to_json_value());
        m.insert("field_h".to_string(), self.field_h.to_json_value());
        m.insert("field_i".to_string(), self.field_i.to_json_value());
        m.insert("field_flag".to_string(), self.field_flag.to_json_value());
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        m.insert("lookup_c".to_string(), self.lookup_c.to_json_value());
        m.insert("lookup_d".to_string(), self.lookup_d.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_d")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_e")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_f")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_g")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_h")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_i")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "field_flag")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_d")?)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct EffectInfo<'a> {
    pub key: u32,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    /// Effect-data CArray, fully typed per element. Each element exposes
    /// 10 named fields plus a typed `core_block` (47 sub-fields) and a
    /// typed `inner_map` of `(u32 key, EffectDataInner)` pairs.
    pub effect_data: Vec<EffectDataElement<'a>>,
    /// Mesh-effect data — fully typed. Each element is 50 bytes on wire.
    pub mesh_effect_data: Vec<MeshEffectData>,
    pub has_equip_type: u8,
    pub has_preset: u8,
    pub target_color_lerp_type: u8,
}

/// Locate the boundary between effect_data_blob and the mesh CArray by
/// reverse probing. The blob ends with `[N_mesh: u32][N_mesh × 50 bytes]`,
/// so we iterate candidate N_mesh values until the count at the implied
/// position matches the candidate AND the candidate fits cleanly.
///
/// On real vanilla data this converges to a unique answer per entry.
fn find_mesh_split(blob: &[u8]) -> io::Result<usize> {
    let blob_len = blob.len();
    // Smallest valid layout: 4 bytes effect count + 4 bytes mesh count + 0 mesh
    // = 8 bytes total. Anything shorter is malformed.
    if blob_len < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("effectinfo: combined blob too short ({}) for mesh+effect split", blob_len),
        ));
    }
    let max_mesh = (blob_len - 8) / MESH_ELEMENT_WIRE_SIZE;
    // Prefer the largest candidate that satisfies the constraint — that
    // keeps the effect side tight and matches the actual writer's layout.
    // Iterate descending so we early-out on the first match.
    for n_mesh in (0..=max_mesh).rev() {
        let mesh_total = MESH_ELEMENT_WIRE_SIZE * n_mesh;
        let mesh_offset = blob_len - mesh_total - 4;
        if mesh_offset < 4 {
            continue;
        }
        let n_at_offset = u32::from_le_bytes(
            blob[mesh_offset..mesh_offset + 4]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "effectinfo: short read"))?,
        ) as usize;
        if n_at_offset == n_mesh {
            return Ok(mesh_offset);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "effectinfo: could not locate mesh CArray split in {}-byte blob",
            blob_len
        ),
    ))
}

impl<'a> EffectInfo<'a> {
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

        if *offset + TAIL_SIZE > entry_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "effectinfo: entry too small for tail",
            ));
        }
        let blob_end = entry_end - TAIL_SIZE;
        let mesh_split = find_mesh_split(&data[*offset..blob_end])? + *offset;

        // Effect data list: u32 count + N × variable-size element
        let mut cur = *offset;
        let n_effect = u32::read_from(data, &mut cur)? as usize;
        let mut effect_data = Vec::with_capacity(n_effect);
        for _ in 0..n_effect {
            effect_data.push(EffectDataElement::read_from(data, &mut cur)?);
        }
        if cur != mesh_split {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "effectinfo: effect_data under/over-consumed: cursor {} != mesh_split {}",
                    cur, mesh_split
                ),
            ));
        }

        let n_mesh = u32::read_from(data, &mut cur)? as usize;
        let mut mesh_effect_data = Vec::with_capacity(n_mesh);
        for _ in 0..n_mesh {
            mesh_effect_data.push(MeshEffectData::read_from(data, &mut cur)?);
        }
        if cur != blob_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "effectinfo: mesh data under/over-consumed: cursor {} != blob_end {}",
                    cur, blob_end
                ),
            ));
        }
        *offset = blob_end;

        let has_equip_type = u8::read_from(data, offset)?;
        let has_preset = u8::read_from(data, offset)?;
        let target_color_lerp_type = u8::read_from(data, offset)?;

        Ok(Self {
            key, string_key, is_blocked, effect_data, mesh_effect_data,
            has_equip_type, has_preset, target_color_lerp_type,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        (self.effect_data.len() as u32).write_to(w)?;
        for e in &self.effect_data { e.write_to(w)?; }
        (self.mesh_effect_data.len() as u32).write_to(w)?;
        for m in &self.mesh_effect_data {
            m.write_to(w)?;
        }
        self.has_equip_type.write_to(w)?;
        self.has_preset.write_to(w)?;
        self.target_color_lerp_type.write_to(w)?;
        Ok(())
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert(
            "effect_data".to_string(),
            Value::Array(
                self.effect_data.iter().map(|e| Value::Object(e.to_json_dict())).collect(),
            ),
        );
        m.insert(
            "mesh_effect_data".to_string(),
            Value::Array(
                self.mesh_effect_data.iter().map(|x| Value::Object(x.to_json_dict())).collect(),
            ),
        );
        m.insert("has_equip_type".to_string(), self.has_equip_type.to_json_value());
        m.insert("has_preset".to_string(), self.has_preset.to_json_value());
        m.insert("target_color_lerp_type".to_string(), self.target_color_lerp_type.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        let effects = json_get_field(obj, "effect_data")?
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectInfo: effect_data must be a JSON array"))?;
        (effects.len() as u32).write_to(w)?;
        for entry in effects {
            let m = entry.as_object().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "EffectInfo: each effect_data entry must be an object"))?;
            EffectDataElement::write_from_json_dict(w, m)?;
        }
        let meshes = json_get_field(obj, "mesh_effect_data")?
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData,
                "EffectInfo: mesh_effect_data must be a JSON array"))?;
        (meshes.len() as u32).write_to(w)?;
        for entry in meshes {
            let m = entry.as_object().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData,
                "EffectInfo: each mesh_effect_data entry must be an object"))?;
            MeshEffectData::write_from_json_dict(w, m)?;
        }
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "has_equip_type")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "has_preset")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "target_color_lerp_type")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\effectinfo.pabgb";
    const PABGH_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\effectinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP: {}", PABGB_PATH); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP: {}", PABGH_PATH); return; };
        let ranges = entry_ranges(&entries, data.len());

        let mut items = Vec::with_capacity(ranges.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = EffectInfo::read_with_size(&data, &mut cursor, end - start)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x} off=0x{:x} size={}: {}", i, key, start, end-start, e));
            assert_eq!(cursor, *end);
            items.push(item);
        }

        let mut out = Vec::with_capacity(data.len());
        for item in &items { item.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "effectinfo roundtrip bytes mismatch");
    }

    /// JSON round-trip — read → to_json_dict → write_from_json_dict
    /// should produce identical bytes to the typed write_to() output.
    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = EffectInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            let dict = item.to_json_dict();
            let mut typed = Vec::new();
            item.write_to(&mut typed).unwrap();
            let mut from_json = Vec::new();
            EffectInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: {}", i, key, e));
            assert_eq!(from_json, typed, "entry {} key=0x{:x}: JSON RT divergence", i, key);
        }
    }

    /// Sanity stat — confirms typed effect/mesh decoding finds elements.
    #[test]
    fn count_distribution() {
        let Ok(data) = std::fs::read(PABGB_PATH) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH_PATH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut total_mesh = 0usize;
        let mut total_effect = 0usize;
        let mut total_cstrings = 0usize;
        let mut total_fixed144 = 0usize;
        let mut entries_with_inner_map = 0usize;
        for (_k, s, e) in ranges.iter() {
            let mut c = *s;
            let it = EffectInfo::read_with_size(&data, &mut c, e - s).unwrap();
            total_mesh += it.mesh_effect_data.len();
            total_effect += it.effect_data.len();
            for ed in &it.effect_data {
                total_cstrings += ed.cstring_list.len();
                total_fixed144 += ed.fixed144_list.len();
                if !ed.inner_map.is_empty() {
                    entries_with_inner_map += 1;
                }
            }
        }
        eprintln!(
            "effectinfo: {} entries, {} effect elements, {} mesh elements, \
             {} cstrings inside effects, {} fixed144s inside effects, \
             {} effects with non-empty inner_map",
            ranges.len(), total_effect, total_mesh, total_cstrings, total_fixed144,
            entries_with_inner_map,
        );
    }
}
