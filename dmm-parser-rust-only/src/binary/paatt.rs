// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Parser for `.paatt` (PA Attack Info) files.
//!
//! These files contain per-weapon attack data: hitboxes, damage, frame
//! events, hit timing, target types, etc. Located in
//! `0010/actionchart/bin__/attackinfo/{upper,lower}action/<class>/<weapon>.paatt`.
//!
//! Format reverse-engineered from `pa::sub_100C38E88` (loader) and
//! `pa::sub_100C39A10` (per-attack-info parser) in the Mac binary.
//!
//! ## Wire format
//!
//! ```text
//! Header:
//!   u32   info_count
//!
//! Per info (×info_count):
//!   u8    version           (0..4 — picks BaseData size)
//!   N     base_data         (264 / 528 / 296 / 288 / 264 bytes by version)
//!   For child_frame_idx in 0..9:
//!     u8  count
//!     16*count bytes        (per-frame data)
//!
//! String tables (×7, all same shape):
//!   u16   string_count
//!   per string:
//!     u8  length
//!     u8[length]
//!
//! Frame event buffer:
//!   u32   size
//!   u8[size]
//! ```
//!
//! Tables in order: StringTable, EffectNameTable, EffectInfoKeyTable,
//! SocketNameTable, PartNameTable, SequencerNameTable, PrefabNameTable.
//!
//! ## What's in BaseData?
//!
//! The reflect property strings (`pa::AttackInfoDataDesc`) reveal:
//! - AttackCommonDataDesc (nested)
//! - AttackHitDataDesc (nested)
//! - AttackDelayDataDesc (frame timing)
//! - float fields (RepeatDegreeWeight, etc.)
//! - u8 fields (RepeatCount)
//! - u32 fields (IgnoreDefenceTypeFlag, ExcludeTargetTypeFlag,
//!   ActionHashCode, StaticInfoKey)
//! - bool fields
//! - u16 fields (SocketName)
//! - enum fields (TargetType, AttackHitCheckType, AttackDivideType)
//! - float3 (vec3)
//!
//! Sub-variants exist: `AttackInfo_Attack`, `AttackInfo_AttackThrow`,
//! `AttackInfo_AttackCatch`, `AttackInfo_ReleaseCatch` — each adding
//! their own fields.
//!
//! Per-byte field decoding of BaseData is NOT yet done — that requires
//! decompiling the reflect-property setters individually. For now we
//! preserve BaseData as raw bytes.

use std::io;

#[derive(Debug, Clone)]
pub struct PaattFile {
    pub infos: Vec<AttackInfo>,
    pub string_table: Vec<String>,
    pub effect_name_table: Vec<String>,
    pub effect_info_key_table: Vec<String>,
    pub socket_name_table: Vec<String>,
    pub part_name_table: Vec<String>,
    pub sequencer_name_table: Vec<String>,
    pub prefab_name_table: Vec<String>,
    pub frame_event_buffer: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AttackInfo {
    pub version: u8,
    /// BaseData bytes — size depends on version (264/528/296/288/264).
    /// Field-level layout via `pa::AttackInfoDataDesc` reflection — TODO.
    pub base_data: Vec<u8>,
    /// 9 child frame slots; each is a count-prefixed stride-16 block.
    pub child_frames: [ChildFrame; 9],
}

#[derive(Debug, Clone, Default)]
pub struct ChildFrame {
    pub count: u8,
    /// `count × 16` bytes.
    pub data: Vec<u8>,
}

fn version_to_base_size(v: u8) -> io::Result<usize> {
    Ok(match v {
        0 => 264,
        1 => 528,
        2 => 296,
        3 => 288,
        4 => 264,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown AttackInfoData version {}", other),
            ));
        }
    })
}

fn read_bytes<'a>(data: &'a [u8], cursor: &mut usize, n: usize) -> io::Result<&'a [u8]> {
    if *cursor + n > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("read {} at {} but file is {} bytes", n, cursor, data.len()),
        ));
    }
    let s = &data[*cursor..*cursor + n];
    *cursor += n;
    Ok(s)
}

fn read_u8(data: &[u8], cursor: &mut usize) -> io::Result<u8> {
    Ok(read_bytes(data, cursor, 1)?[0])
}

fn read_u16(data: &[u8], cursor: &mut usize) -> io::Result<u16> {
    Ok(u16::from_le_bytes(read_bytes(data, cursor, 2)?.try_into().unwrap()))
}

fn read_u32(data: &[u8], cursor: &mut usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(read_bytes(data, cursor, 4)?.try_into().unwrap()))
}

fn read_string_table(data: &[u8], cursor: &mut usize) -> io::Result<Vec<String>> {
    let count = read_u16(data, cursor)? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u8(data, cursor)? as usize;
        let bytes = read_bytes(data, cursor, len)?;
        let s = std::str::from_utf8(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .to_string();
        out.push(s);
    }
    Ok(out)
}

fn read_attack_info(data: &[u8], cursor: &mut usize) -> io::Result<AttackInfo> {
    let version = read_u8(data, cursor)?;
    let base_size = version_to_base_size(version)?;
    let base_data = read_bytes(data, cursor, base_size)?.to_vec();

    let mut child_frames: [ChildFrame; 9] = Default::default();
    for cf in child_frames.iter_mut() {
        let count = read_u8(data, cursor)?;
        cf.count = count;
        if count > 0 {
            cf.data = read_bytes(data, cursor, 16 * count as usize)?.to_vec();
        }
    }

    Ok(AttackInfo {
        version,
        base_data,
        child_frames,
    })
}

impl PaattFile {
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        let mut cursor = 0usize;

        let info_count = read_u32(data, &mut cursor)? as usize;

        let mut infos = Vec::with_capacity(info_count);
        for _ in 0..info_count {
            infos.push(read_attack_info(data, &mut cursor)?);
        }

        let string_table = read_string_table(data, &mut cursor)?;
        let effect_name_table = read_string_table(data, &mut cursor)?;
        let effect_info_key_table = read_string_table(data, &mut cursor)?;
        let socket_name_table = read_string_table(data, &mut cursor)?;
        let part_name_table = read_string_table(data, &mut cursor)?;
        let sequencer_name_table = read_string_table(data, &mut cursor)?;
        let prefab_name_table = read_string_table(data, &mut cursor)?;

        let buf_size = read_u32(data, &mut cursor)? as usize;
        let frame_event_buffer = read_bytes(data, &mut cursor, buf_size)?.to_vec();

        Ok(PaattFile {
            infos,
            string_table,
            effect_name_table,
            effect_info_key_table,
            socket_name_table,
            part_name_table,
            sequencer_name_table,
            prefab_name_table,
            frame_event_buffer,
        })
    }

    /// True if every byte of the input was consumed by `parse`.
    /// Reports trailing-byte count if not.
    pub fn parse_strict(data: &[u8]) -> io::Result<(Self, usize)> {
        let mut cursor = 0usize;
        let info_count = read_u32(data, &mut cursor)? as usize;
        let mut infos = Vec::with_capacity(info_count);
        for _ in 0..info_count {
            infos.push(read_attack_info(data, &mut cursor)?);
        }
        let string_table = read_string_table(data, &mut cursor)?;
        let effect_name_table = read_string_table(data, &mut cursor)?;
        let effect_info_key_table = read_string_table(data, &mut cursor)?;
        let socket_name_table = read_string_table(data, &mut cursor)?;
        let part_name_table = read_string_table(data, &mut cursor)?;
        let sequencer_name_table = read_string_table(data, &mut cursor)?;
        let prefab_name_table = read_string_table(data, &mut cursor)?;
        let buf_size = read_u32(data, &mut cursor)? as usize;
        let frame_event_buffer = read_bytes(data, &mut cursor, buf_size)?.to_vec();
        let trailing = data.len() - cursor;
        Ok((
            PaattFile {
                infos,
                string_table,
                effect_name_table,
                effect_info_key_table,
                socket_name_table,
                part_name_table,
                sequencer_name_table,
                prefab_name_table,
                frame_event_buffer,
            },
            trailing,
        ))
    }
}
