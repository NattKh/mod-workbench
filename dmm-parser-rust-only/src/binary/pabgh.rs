// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! PABGH (PA Binary Group Header) — index file describing entry boundaries
//! within a sister .pabgb data file.
//!
//! Three on-disk formats:
//!  - 8-byte entry: u16 count + N × {u32 key, u32 offset}
//!  - 6-byte entry: u16 count + N × {u16 key, u32 offset}
//!  - 8-byte entry, u32 count: u32 count + N × {u32 key, u32 offset}
//!
//! The format is auto-detected from the file size against the count value.

use std::io::{self, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PabghFormat {
    /// u16 count, u32 key, u32 offset (8 bytes per entry).
    U16CountU32Key,
    /// u16 count, u16 key, u32 offset (6 bytes per entry).
    U16CountU16Key,
    /// u32 count, u32 key, u32 offset (8 bytes per entry).
    U32CountU32Key,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PabghEntry {
    pub key: u32,
    pub offset: u32,
}

#[derive(Debug, Clone)]
pub struct Pabgh {
    pub format: PabghFormat,
    pub entries: Vec<PabghEntry>,
}

impl Pabgh {
    /// Auto-detect format and parse the index. Returns Err if the layout
    /// doesn't match any of the three known formats.
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        if data.len() < 4 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "pabgh too short"));
        }
        let c16 = u16::from_le_bytes(data[0..2].try_into().unwrap()) as usize;
        let c32 = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;

        // Format 1: u16 count + N × 8-byte entries
        if 2 + c16 * 8 == data.len() {
            return Ok(Self::parse_inner(data, 2, c16, PabghFormat::U16CountU32Key));
        }
        // Format 2: u16 count + N × 6-byte entries
        if 2 + c16 * 6 == data.len() {
            return Ok(Self::parse_inner(data, 2, c16, PabghFormat::U16CountU16Key));
        }
        // Format 3: u32 count + N × 8-byte entries
        if 4 + c32 * 8 == data.len() {
            return Ok(Self::parse_inner(data, 4, c32, PabghFormat::U32CountU32Key));
        }
        Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("pabgh size {} doesn't match any known layout (c16={}, c32={})",
                data.len(), c16, c32)))
    }

    fn parse_inner(data: &[u8], idx_start: usize, count: usize, format: PabghFormat) -> Self {
        let mut entries = Vec::with_capacity(count);
        let entry_size = match format {
            PabghFormat::U16CountU32Key | PabghFormat::U32CountU32Key => 8,
            PabghFormat::U16CountU16Key => 6,
        };
        for i in 0..count {
            let pos = idx_start + i * entry_size;
            let (key, offset) = match format {
                PabghFormat::U16CountU16Key => {
                    let k = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as u32;
                    let o = u32::from_le_bytes(data[pos + 2..pos + 6].try_into().unwrap());
                    (k, o)
                }
                _ => {
                    let k = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
                    let o = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap());
                    (k, o)
                }
            };
            entries.push(PabghEntry { key, offset });
        }
        Self { format, entries }
    }

    /// Serialize back to the original byte layout. Round-trips byte-identical
    /// against the source file.
    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self.format {
            PabghFormat::U16CountU32Key => {
                w.write_all(&(self.entries.len() as u16).to_le_bytes())?;
                for e in &self.entries {
                    w.write_all(&e.key.to_le_bytes())?;
                    w.write_all(&e.offset.to_le_bytes())?;
                }
            }
            PabghFormat::U16CountU16Key => {
                w.write_all(&(self.entries.len() as u16).to_le_bytes())?;
                for e in &self.entries {
                    w.write_all(&(e.key as u16).to_le_bytes())?;
                    w.write_all(&e.offset.to_le_bytes())?;
                }
            }
            PabghFormat::U32CountU32Key => {
                w.write_all(&(self.entries.len() as u32).to_le_bytes())?;
                for e in &self.entries {
                    w.write_all(&e.key.to_le_bytes())?;
                    w.write_all(&e.offset.to_le_bytes())?;
                }
            }
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        self.write_to(&mut out)?;
        Ok(out)
    }
}
