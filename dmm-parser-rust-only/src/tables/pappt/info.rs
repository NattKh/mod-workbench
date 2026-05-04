// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Part-prefab table file parser.
//!
//! Field naming follows the spec in
//! `tools/mod-workbench/PAPPT_FORMAT_RESEARCH.md`. Layout:
//!
//! ```text
//! +0x00 u8[8]  opaque header (read-discarded by the loader,
//!              preserved verbatim on round-trip)
//! +0x08 u32    primary_count
//!       primary_entry[primary_count]
//!       u32    secondary_count
//!       secondary_entry[secondary_count]
//! EOF
//! ```
//!
//! Primary entry:
//!
//! ```text
//! pstr key_a
//! pstr key_b
//! pstr key_c     // read and discarded by the loader; preserved here
//! pstr asset_id
//! u8   flag
//! u8   child_count
//! { pstr sub_key, u8 sub_flag } * child_count
//! ```
//!
//! Secondary entry:
//!
//! ```text
//! pstr alias_a
//! pstr alias_b
//! ```
//!
//! `pstr` is a `u8` length prefix followed by `len` bytes of UTF-8
//! payload. The engine treats the bytes as C strings — no NUL is
//! written to the file. Maximum length is 255 bytes.
//!
//! The parser round-trips byte-for-byte against vanilla:
//! `PapptFile::parse(bytes)?.write() == bytes`.

use std::io;

/// Length-prefixed UTF-8 child variant inside a [`PrimaryEntry`].
///
/// `sub_key` is hashed by the loader through `sub_10055E114` into the
/// global string-intern table; we keep the raw string here so an editor
/// can rewrite it cleanly without depending on the live intern table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrimaryChild {
    /// Variant key, length-prefixed in the file.
    pub sub_key: String,
    /// Variant flag byte. Semantics unknown — preserved verbatim.
    pub sub_flag: u8,
}

/// One primary part-prefab definition. Holds four short strings, one
/// flag byte, and a length-prefixed list of child variants.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrimaryEntry {
    /// Primary registry key (typically tribe / race name in vanilla).
    pub key_a: String,
    /// Secondary registry key (typically part-slot name in vanilla).
    pub key_b: String,
    /// Legacy / dev-only field. Read and discarded by the runtime
    /// loader, but preserved here so round-trip is byte-clean.
    pub key_c: String,
    /// Cross-cutting asset handle. Hashed into the global string
    /// intern table — same namespace as `_partPrefabKey`.
    pub asset_id: String,
    /// Entry-level flag byte. Stored at runtime offset `+0x14`.
    pub flag: u8,
    /// Variant children. Count is encoded as a `u8` in the file, so up
    /// to 255 children are addressable per primary entry.
    pub children: Vec<PrimaryChild>,
}

/// One secondary alias pair. The runtime registers both directions of
/// the alias so a lookup by either string returns the partner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecondaryEntry {
    /// First alias string.
    pub alias_a: String,
    /// Second alias string.
    pub alias_b: String,
}

/// Parsed `.pappt` file. Round-trips byte-for-byte against vanilla.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PapptFile {
    /// Opaque 8-byte header — read but never inspected by the loader.
    /// Preserved verbatim on round-trip so a modded file diffs cleanly
    /// against vanilla.
    pub header: [u8; 8],
    /// Primary entries (per-character / per-tribe part definitions).
    pub primary: Vec<PrimaryEntry>,
    /// Secondary alias pairs.
    pub secondary: Vec<SecondaryEntry>,
}

impl PapptFile {
    /// Parse a `.pappt` byte buffer. Returns the parsed structure or an
    /// `io::Error` describing the truncation / overrun on malformed
    /// input.
    pub fn parse(bytes: &[u8]) -> io::Result<PapptFile> {
        let mut offset = 0usize;

        // Header: 8 bytes, opaque.
        if bytes.len() < 8 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("pappt header needs 8 bytes, file has {}", bytes.len()),
            ));
        }
        let mut header = [0u8; 8];
        header.copy_from_slice(&bytes[..8]);
        offset += 8;

        // Primary count + entries.
        let primary_count = read_u32(bytes, &mut offset)?;
        let mut primary = Vec::with_capacity(primary_count as usize);
        for i in 0..primary_count {
            primary.push(read_primary_entry(bytes, &mut offset).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("primary entry #{}: {}", i, e),
                )
            })?);
        }

        // Secondary count + entries.
        let secondary_count = read_u32(bytes, &mut offset)?;
        let mut secondary = Vec::with_capacity(secondary_count as usize);
        for i in 0..secondary_count {
            secondary.push(read_secondary_entry(bytes, &mut offset).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("secondary entry #{}: {}", i, e),
                )
            })?);
        }

        if offset != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "trailing bytes after pappt body: consumed {} of {}",
                    offset,
                    bytes.len()
                ),
            ));
        }

        Ok(PapptFile {
            header,
            primary,
            secondary,
        })
    }

    /// Serialize back to bytes. Reciprocal of [`Self::parse`] — the
    /// returned `Vec<u8>` is byte-identical to the input on round-trip.
    pub fn write(&self) -> Vec<u8> {
        // Pre-size the output to avoid mid-write reallocations.
        let mut out = Vec::with_capacity(self.serialized_size());
        out.extend_from_slice(&self.header);

        let primary_count = self.primary.len() as u32;
        out.extend_from_slice(&primary_count.to_le_bytes());
        for entry in &self.primary {
            write_primary_entry(&mut out, entry);
        }

        let secondary_count = self.secondary.len() as u32;
        out.extend_from_slice(&secondary_count.to_le_bytes());
        for entry in &self.secondary {
            write_secondary_entry(&mut out, entry);
        }

        out
    }

    /// Conservative size estimate for the serialized output. Used to
    /// pre-size the writer's buffer; not authoritative.
    fn serialized_size(&self) -> usize {
        let mut sz = 8 + 4 + 4; // header + primary_count + secondary_count
        for entry in &self.primary {
            sz += pstr_size(&entry.key_a)
                + pstr_size(&entry.key_b)
                + pstr_size(&entry.key_c)
                + pstr_size(&entry.asset_id)
                + 1 // flag
                + 1; // child_count
            for child in &entry.children {
                sz += pstr_size(&child.sub_key) + 1;
            }
        }
        for entry in &self.secondary {
            sz += pstr_size(&entry.alias_a) + pstr_size(&entry.alias_b);
        }
        sz
    }
}

// ── pstr helpers ─────────────────────────────────────────────────────

/// Read a `u8`-prefixed length-counted byte string and decode as UTF-8.
/// On success returns `(decoded_string, bytes_consumed)` so callers can
/// advance their cursor without re-scanning.
///
/// The engine treats the bytes as C strings — no NUL terminator is
/// written to the file. UTF-8 decode is lossy on bad sequences (the
/// loader's `strlen` would terminate at a NUL but won't validate
/// encoding), but real shipped files appear to be ASCII / UTF-8.
pub fn pstr_read(bytes: &[u8], offset: usize) -> io::Result<(String, usize)> {
    if offset >= bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "pstr length byte out of bounds at offset {} (file size {})",
                offset,
                bytes.len()
            ),
        ));
    }
    let len = bytes[offset] as usize;
    let data_start = offset + 1;
    let data_end = data_start + len;
    if data_end > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "pstr body of length {} would overrun: needs {} bytes, have {}",
                len,
                data_end,
                bytes.len()
            ),
        ));
    }
    // Lossy UTF-8 decode mirrors the engine's relaxed treatment of
    // these bytes. A round-trip writer doesn't depend on the decode
    // being perfect — it re-encodes the `String` as UTF-8 and rewrites
    // the same byte sequence for ASCII payloads, which is what every
    // observed file uses.
    let s = String::from_utf8_lossy(&bytes[data_start..data_end]).into_owned();
    Ok((s, 1 + len))
}

/// Write a `u8`-prefixed length-counted byte string. Panics if the
/// UTF-8 byte length exceeds 255 — callers that accept user input
/// should validate before calling.
pub fn pstr_write(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    assert!(
        bytes.len() <= 255,
        "pstr exceeds u8 length cap: {} bytes",
        bytes.len()
    );
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
}

/// Byte size of the on-disk encoding of `s` as a pstr (length byte +
/// payload). Used by the size estimator.
fn pstr_size(s: &str) -> usize {
    1 + s.as_bytes().len()
}

// ── Internal helpers ────────────────────────────────────────────────

fn read_u32(bytes: &[u8], offset: &mut usize) -> io::Result<u32> {
    if *offset + 4 > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "u32 read at offset {} needs 4 bytes, have {}",
                *offset,
                bytes.len() - *offset
            ),
        ));
    }
    let v = u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    Ok(v)
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> io::Result<u8> {
    if *offset >= bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("u8 read at offset {} past EOF", *offset),
        ));
    }
    let v = bytes[*offset];
    *offset += 1;
    Ok(v)
}

fn read_pstr(bytes: &[u8], offset: &mut usize) -> io::Result<String> {
    let (s, consumed) = pstr_read(bytes, *offset)?;
    *offset += consumed;
    Ok(s)
}

fn read_primary_entry(bytes: &[u8], offset: &mut usize) -> io::Result<PrimaryEntry> {
    let key_a = read_pstr(bytes, offset)?;
    let key_b = read_pstr(bytes, offset)?;
    let key_c = read_pstr(bytes, offset)?;
    let asset_id = read_pstr(bytes, offset)?;
    let flag = read_u8(bytes, offset)?;
    let child_count = read_u8(bytes, offset)?;

    let mut children = Vec::with_capacity(child_count as usize);
    for i in 0..child_count {
        let sub_key = read_pstr(bytes, offset).map_err(|e| {
            io::Error::new(e.kind(), format!("child #{} sub_key: {}", i, e))
        })?;
        let sub_flag = read_u8(bytes, offset).map_err(|e| {
            io::Error::new(e.kind(), format!("child #{} sub_flag: {}", i, e))
        })?;
        children.push(PrimaryChild { sub_key, sub_flag });
    }

    Ok(PrimaryEntry {
        key_a,
        key_b,
        key_c,
        asset_id,
        flag,
        children,
    })
}

fn read_secondary_entry(bytes: &[u8], offset: &mut usize) -> io::Result<SecondaryEntry> {
    let alias_a = read_pstr(bytes, offset)?;
    let alias_b = read_pstr(bytes, offset)?;
    Ok(SecondaryEntry { alias_a, alias_b })
}

fn write_primary_entry(out: &mut Vec<u8>, entry: &PrimaryEntry) {
    pstr_write(out, &entry.key_a);
    pstr_write(out, &entry.key_b);
    pstr_write(out, &entry.key_c);
    pstr_write(out, &entry.asset_id);
    out.push(entry.flag);
    // child_count is a u8 in the wire format — assert before truncation
    // so a faulty editor bug surfaces as a panic rather than a silent
    // partial write.
    let child_count = entry.children.len();
    assert!(
        child_count <= 255,
        "primary entry has {} children; wire format caps at 255",
        child_count
    );
    out.push(child_count as u8);
    for child in &entry.children {
        pstr_write(out, &child.sub_key);
        out.push(child.sub_flag);
    }
}

fn write_secondary_entry(out: &mut Vec<u8>, entry: &SecondaryEntry) {
    pstr_write(out, &entry.alias_a);
    pstr_write(out, &entry.alias_b);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal synthetic file: two primary entries each with
    /// one child, two secondary aliases. Exercises the basic
    /// parse/write round-trip.
    #[test]
    fn synthetic_two_primary_two_secondary_roundtrips() {
        let original = PapptFile {
            header: [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03],
            primary: vec![
                PrimaryEntry {
                    key_a: "Kliff".into(),
                    key_b: "hair".into(),
                    key_c: "src/kliff_hair.pmod".into(),
                    asset_id: "kliff_hair_default".into(),
                    flag: 0x01,
                    children: vec![PrimaryChild {
                        sub_key: "kliff_hair_long".into(),
                        sub_flag: 0x02,
                    }],
                },
                PrimaryEntry {
                    key_a: "Damiane".into(),
                    key_b: "face".into(),
                    key_c: "".into(),
                    asset_id: "damiane_face_default".into(),
                    flag: 0x00,
                    children: vec![PrimaryChild {
                        sub_key: "damiane_face_battle".into(),
                        sub_flag: 0x10,
                    }],
                },
            ],
            secondary: vec![
                SecondaryEntry {
                    alias_a: "old_kliff_hair".into(),
                    alias_b: "kliff_hair_default".into(),
                },
                SecondaryEntry {
                    alias_a: "legacy_face".into(),
                    alias_b: "damiane_face_default".into(),
                },
            ],
        };

        let bytes = original.write();
        let parsed = PapptFile::parse(&bytes).expect("parse synthetic");
        assert_eq!(parsed, original);

        // Byte-identical re-emit.
        let reemitted = parsed.write();
        assert_eq!(
            reemitted, bytes,
            "round-trip diverged at len {} vs {}",
            reemitted.len(),
            bytes.len()
        );
    }

    /// A single primary entry with the maximum addressable child count
    /// (`u8::MAX = 255`) must round-trip cleanly. Catches off-by-one
    /// errors in the child-count writer / reader.
    #[test]
    fn primary_with_255_children_roundtrips() {
        let mut children = Vec::with_capacity(255);
        for i in 0..255u8 {
            children.push(PrimaryChild {
                sub_key: format!("variant_{:03}", i),
                sub_flag: i,
            });
        }
        let original = PapptFile {
            header: [0u8; 8],
            primary: vec![PrimaryEntry {
                key_a: "Common".into(),
                key_b: "torso".into(),
                key_c: "".into(),
                asset_id: "common_torso".into(),
                flag: 0xFF,
                children,
            }],
            secondary: Vec::new(),
        };

        let bytes = original.write();
        let parsed = PapptFile::parse(&bytes).expect("parse 255-child entry");
        assert_eq!(parsed.primary.len(), 1);
        assert_eq!(parsed.primary[0].children.len(), 255);
        assert_eq!(parsed, original);
        assert_eq!(parsed.write(), bytes);
    }

    /// Empty file (header + zero primary + zero secondary) round-trips.
    #[test]
    fn empty_file_roundtrips() {
        let original = PapptFile {
            header: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            primary: Vec::new(),
            secondary: Vec::new(),
        };
        let bytes = original.write();
        // 8 (header) + 4 (primary_count=0) + 4 (secondary_count=0) = 16
        assert_eq!(bytes.len(), 16);
        let parsed = PapptFile::parse(&bytes).expect("parse empty");
        assert_eq!(parsed, original);
        assert_eq!(parsed.write(), bytes);
    }

    /// Truncated body (declared primary count larger than available
    /// data) should produce a clean `UnexpectedEof` error rather than
    /// panicking.
    #[test]
    fn truncated_body_errors_clean() {
        // Header + primary_count=1 + (no body)
        let mut bytes = vec![0u8; 8];
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let err = PapptFile::parse(&bytes).expect_err("expected EOF error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// pstr_read / pstr_write are public helpers; smoke-test them
    /// directly against the in-spec encoding.
    #[test]
    fn pstr_helpers_roundtrip() {
        let inputs = ["", "a", "hello", "kliff_hair_long_v2"];
        for s in inputs {
            let mut buf = Vec::new();
            pstr_write(&mut buf, s);
            let (decoded, consumed) = pstr_read(&buf, 0).expect("read pstr");
            assert_eq!(decoded, s);
            assert_eq!(consumed, buf.len());
        }
    }
}
