// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Model property header collection file parser.
//!
//! Field naming follows the spec in
//! `tools/mod-workbench/PALEVEL_PAMHC_PAB_FORMAT_RESEARCH.md`. Layout:
//!
//! ```text
//! +0x00 u8[8]  opaque header (read-discarded by the loader,
//!              preserved verbatim on round-trip)
//! +0x08 u32    section_a_size  (must satisfy `(size & 3) == 0`)
//! +0x0C u32    section_b_size
//! +0x10 u32    section_c_size
//! +0x14 u32    section_d_size
//! +0x18 u32    section_e_size
//! +0x1C var    payload — section A, B, C, D, E bytes concatenated
//! ```
//!
//! Section A is decoded as a `u32` array — the loader stores
//! `section_a_size / 4` as the entry count at runtime offset `+36`.
//! The other four sections are kept as opaque byte ranges; their
//! element schemas haven't been walked, so editing them at the
//! workbench level is byte-level only.
//!
//! The parser round-trips byte-for-byte against vanilla:
//! `PamhcFile::parse(bytes)?.write() == bytes`.

use std::io;

/// Number of bytes of opaque header at the start of the file.
const HEADER_LEN: usize = 8;

/// Total bytes of fixed-size prologue (opaque header + five `u32`
/// section sizes). Sums to 28 — files smaller than this are rejected
/// as truncated.
const PROLOGUE_LEN: usize = HEADER_LEN + 5 * 4;

/// Parsed `.pamhc` file. Round-trips byte-for-byte against vanilla.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PamhcFile {
    /// Opaque 8-byte header — read but never inspected by the loader.
    /// Preserved verbatim on round-trip so a modded file diffs cleanly
    /// against vanilla.
    pub header: [u8; 8],
    /// Section A: typed `u32` array. The loader divides
    /// `section_a_size` by 4 to get the entry count, and the size
    /// field must be a multiple of 4 — `parse` enforces both.
    pub section_a_u32: Vec<u32>,
    /// Section B — opaque byte range. Element schema not decoded.
    pub section_b: Vec<u8>,
    /// Section C — opaque byte range. Element schema not decoded.
    pub section_c: Vec<u8>,
    /// Section D — opaque byte range. Element schema not decoded.
    pub section_d: Vec<u8>,
    /// Section E — opaque byte range. Element schema not decoded.
    pub section_e: Vec<u8>,
}

impl PamhcFile {
    /// Parse a `.pamhc` byte buffer. Returns the parsed structure or an
    /// `io::Error` describing the truncation / overrun / alignment
    /// violation on malformed input.
    ///
    /// Rejects:
    /// - Files smaller than the 28-byte prologue.
    /// - Files where `section_a_size & 3 != 0` (matches the loader's
    ///   `(v9 & 3) != 0` check).
    /// - Files where the declared section sizes overrun the buffer.
    pub fn parse(bytes: &[u8]) -> io::Result<PamhcFile> {
        if bytes.len() < PROLOGUE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "pamhc prologue needs {} bytes, file has {}",
                    PROLOGUE_LEN,
                    bytes.len()
                ),
            ));
        }

        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&bytes[..HEADER_LEN]);

        let mut offset = HEADER_LEN;
        let size_a = read_u32(bytes, &mut offset)?;
        let size_b = read_u32(bytes, &mut offset)?;
        let size_c = read_u32(bytes, &mut offset)?;
        let size_d = read_u32(bytes, &mut offset)?;
        let size_e = read_u32(bytes, &mut offset)?;
        debug_assert_eq!(offset, PROLOGUE_LEN);

        // Loader gate: `(section_a_size & 3) != 0` aborts the load.
        if size_a & 3 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "pamhc section_a_size ({}) is not a multiple of 4",
                    size_a
                ),
            ));
        }

        // Use u64 arithmetic to avoid overflow on adversarial size
        // declarations on 32-bit targets — the four u32s could each
        // approach `u32::MAX` and overflow `usize` math otherwise.
        let total_payload = size_a as u64
            + size_b as u64
            + size_c as u64
            + size_d as u64
            + size_e as u64;
        let total_required = PROLOGUE_LEN as u64 + total_payload;
        if total_required > bytes.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "pamhc payload requires {} bytes (28 + {} a + {} b + {} c + {} d + {} e), \
                     file has {}",
                    total_required, size_a, size_b, size_c, size_d, size_e, bytes.len()
                ),
            ));
        }

        // Section A is a u32 array. We pre-validated the alignment
        // above, so this loop is allocation-bounded by `size_a / 4`.
        let entry_count = (size_a / 4) as usize;
        let mut section_a_u32 = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            section_a_u32.push(read_u32(bytes, &mut offset)?);
        }

        let section_b = read_bytes(bytes, &mut offset, size_b as usize)?;
        let section_c = read_bytes(bytes, &mut offset, size_c as usize)?;
        let section_d = read_bytes(bytes, &mut offset, size_d as usize)?;
        let section_e = read_bytes(bytes, &mut offset, size_e as usize)?;

        // Trailing-bytes guard: the prologue + declared sections may
        // be shorter than the file (the loader stops after section E),
        // but a stricter parser surfaces this as data the editor
        // should preserve. Mirror pappt's behaviour and reject.
        if offset != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "trailing bytes after pamhc body: consumed {} of {}",
                    offset,
                    bytes.len()
                ),
            ));
        }

        Ok(PamhcFile {
            header,
            section_a_u32,
            section_b,
            section_c,
            section_d,
            section_e,
        })
    }

    /// Serialize back to bytes. Reciprocal of [`Self::parse`] — the
    /// returned `Vec<u8>` is byte-identical to the input on round-trip.
    pub fn write(&self) -> Vec<u8> {
        let size_a = (self.section_a_u32.len() * 4) as u32;
        let size_b = self.section_b.len() as u32;
        let size_c = self.section_c.len() as u32;
        let size_d = self.section_d.len() as u32;
        let size_e = self.section_e.len() as u32;

        let total = PROLOGUE_LEN
            + size_a as usize
            + size_b as usize
            + size_c as usize
            + size_d as usize
            + size_e as usize;
        let mut out = Vec::with_capacity(total);

        out.extend_from_slice(&self.header);
        out.extend_from_slice(&size_a.to_le_bytes());
        out.extend_from_slice(&size_b.to_le_bytes());
        out.extend_from_slice(&size_c.to_le_bytes());
        out.extend_from_slice(&size_d.to_le_bytes());
        out.extend_from_slice(&size_e.to_le_bytes());

        for &v in &self.section_a_u32 {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&self.section_b);
        out.extend_from_slice(&self.section_c);
        out.extend_from_slice(&self.section_d);
        out.extend_from_slice(&self.section_e);

        out
    }
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

fn read_bytes(bytes: &[u8], offset: &mut usize, len: usize) -> io::Result<Vec<u8>> {
    if *offset + len > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "byte read at offset {} needs {} bytes, have {}",
                *offset,
                len,
                bytes.len() - *offset
            ),
        ));
    }
    let out = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a small synthetic file: 8-byte header, four u32 entries
    /// in section A, 8 bytes in section B, sections C/D/E empty.
    /// Exercises the basic parse/write round-trip.
    #[test]
    fn synthetic_file_roundtrips() {
        let original = PamhcFile {
            header: [0xDE, 0xAD, 0xBE, 0xEF, 0x10, 0x20, 0x30, 0x40],
            section_a_u32: vec![0x11111111, 0x22222222, 0x33333333, 0x44444444],
            section_b: vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01],
            section_c: Vec::new(),
            section_d: Vec::new(),
            section_e: Vec::new(),
        };

        let bytes = original.write();
        // 28 prologue + 16 section A + 8 section B = 52
        assert_eq!(bytes.len(), 52);

        let parsed = PamhcFile::parse(&bytes).expect("parse synthetic");
        assert_eq!(parsed, original);
        assert_eq!(parsed.section_a_u32.len(), 4);
        assert_eq!(parsed.section_b.len(), 8);

        let reemitted = parsed.write();
        assert_eq!(
            reemitted, bytes,
            "round-trip diverged at len {} vs {}",
            reemitted.len(),
            bytes.len()
        );
    }

    /// Empty payload (all five section sizes zero) round-trips with
    /// just the 28-byte prologue.
    #[test]
    fn empty_payload_roundtrips() {
        let original = PamhcFile {
            header: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            section_a_u32: Vec::new(),
            section_b: Vec::new(),
            section_c: Vec::new(),
            section_d: Vec::new(),
            section_e: Vec::new(),
        };
        let bytes = original.write();
        assert_eq!(bytes.len(), PROLOGUE_LEN);
        let parsed = PamhcFile::parse(&bytes).expect("parse empty");
        assert_eq!(parsed, original);
        assert_eq!(parsed.write(), bytes);
    }

    /// `section_a_size` not a multiple of 4 must fail with
    /// `InvalidData`, matching the loader's `(v9 & 3) != 0` check.
    #[test]
    fn non_multiple_of_4_section_a_rejected() {
        let mut bytes = vec![0u8; HEADER_LEN];
        // section_a_size = 5 (not a multiple of 4)
        bytes.extend_from_slice(&5u32.to_le_bytes());
        // remaining sizes = 0
        for _ in 0..4 {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        // 5 bytes of payload so the alignment check fires before the
        // length check.
        bytes.extend_from_slice(&[0u8; 5]);

        let err = PamhcFile::parse(&bytes).expect_err("expected alignment error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("multiple of 4"),
            "unexpected error message: {}",
            err
        );
    }

    /// Truncated body (declared section sizes sum to more than the
    /// available data) must fail with `UnexpectedEof`.
    #[test]
    fn truncated_body_rejected() {
        let mut bytes = vec![0u8; HEADER_LEN];
        // Declare 16 bytes of section A (4 u32 entries) but provide
        // only 4 bytes of payload.
        bytes.extend_from_slice(&16u32.to_le_bytes());
        for _ in 0..4 {
            bytes.extend_from_slice(&0u32.to_le_bytes());
        }
        bytes.extend_from_slice(&[0u8; 4]);

        let err = PamhcFile::parse(&bytes).expect_err("expected EOF error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Missing prologue (file shorter than 28 bytes) must fail with
    /// `UnexpectedEof`.
    #[test]
    fn missing_prologue_rejected() {
        // Only 16 bytes — far short of the 28-byte prologue.
        let bytes = vec![0u8; 16];
        let err = PamhcFile::parse(&bytes).expect_err("expected EOF error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// A file with all five sections populated round-trips and
    /// preserves the byte order across the section boundaries.
    #[test]
    fn all_five_sections_roundtrip() {
        let original = PamhcFile {
            header: [0; 8],
            section_a_u32: vec![1, 2, 3],
            section_b: vec![0xB0, 0xB1],
            section_c: vec![0xC0, 0xC1, 0xC2],
            section_d: vec![0xD0],
            section_e: vec![0xE0, 0xE1, 0xE2, 0xE3, 0xE4],
        };
        let bytes = original.write();
        // 28 + 12 + 2 + 3 + 1 + 5 = 51
        assert_eq!(bytes.len(), 51);

        let parsed = PamhcFile::parse(&bytes).expect("parse multi-section");
        assert_eq!(parsed, original);
        assert_eq!(parsed.write(), bytes);
    }
}
