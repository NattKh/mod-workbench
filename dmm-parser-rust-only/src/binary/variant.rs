// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Helpers for pabgh-bounded variant payload reading.
//!
//! Many pabgb tables embed a polymorphic field (e.g. `_gameCondition`,
//! `_buffData`) whose binary length isn't directly encoded in the field.
//! Knowing it requires either:
//!   (a) Fully decoding every variant case (deep recursive tree dispatch).
//!   (b) Using the pabgh sister-file's entry boundaries to bound the
//!       containing entry, then computing the variant size by subtracting
//!       the simpler pre-/post-fields.
//!
//! This module implements (b). The strategy:
//!   1. Read fixed pre-fields forward.
//!   2. For the variant payload, find the smallest byte offset within the
//!      entry such that the bytes from there onward can be parsed as the
//!      known post-field schema and exactly hit the entry boundary.
//!   3. Capture the bytes-between as `Vec<u8>` for byte-perfect round-trip.
//!
//! Round-trip preservation is byte-identical by construction; mods can
//! still target the simple pre/post fields by name. Whole-payload variant
//! mods edit the `Vec<u8>` directly.

use crate::binary::CString;
use std::io;

/// Probe for a variant payload boundary using a trailing-fields validator.
///
/// Returns the offset (relative to `start`) at which the trailing fields begin
/// — i.e., `variant_size` such that `bytes[start + variant_size..end]` parses
/// cleanly as the trailing fields and consumes exactly `end - start -
/// variant_size` bytes.
///
/// `validate` is called with the candidate start offset; it should attempt to
/// parse the trailing fields and return `Some(consumed_bytes)` on success.
/// The probe scans from `min_variant_size` upward and returns the first
/// candidate that passes validation AND consumes exactly the remaining bytes.
pub fn find_variant_boundary<F>(
    data: &[u8],
    start: usize,
    end: usize,
    min_variant_size: usize,
    mut validate: F,
) -> io::Result<usize>
where
    F: FnMut(usize) -> Option<usize>,
{
    if start > end || end > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "variant probe: out-of-range bounds",
        ));
    }
    let max_variant_size = end - start;
    for vs in min_variant_size..=max_variant_size {
        let probe = start + vs;
        if let Some(consumed) = validate(probe)
            && probe + consumed == end {
                return Ok(vs);
            }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "variant probe: no boundary found in [{}..{}] (size {})",
            start, end, end - start
        ),
    ))
}

/// Probe for a CString-then-u8 trailer boundary.
/// Returns the variant payload size (bytes between `start` and the CString).
/// Validates the candidate CString contents as UTF-8 to filter false positives
/// where the variant payload happens to encode a fake length prefix.
pub fn find_cstring_u8_trailer(data: &[u8], start: usize, end: usize) -> io::Result<usize> {
    find_variant_boundary(data, start, end, 0, |probe| {
        if probe + 5 > end {
            return None;
        }
        let len = u32::from_le_bytes(data[probe..probe + 4].try_into().ok()?) as usize;
        let total = 4 + len + 1;
        if probe + total != end {
            return None;
        }
        // Validate the CString contents are real UTF-8 to reject false-positive
        // boundaries where the variant payload happens to start with bytes that
        // look like a CString length prefix.
        let content_start = probe + 4;
        let content_end = content_start + len;
        std::str::from_utf8(&data[content_start..content_end]).ok()?;
        Some(total)
    })
}

/// Probe for a single CString boundary (no extra trailing byte).
pub fn find_cstring_trailer(data: &[u8], start: usize, end: usize) -> io::Result<usize> {
    find_variant_boundary(data, start, end, 0, |probe| {
        if probe + 4 > end {
            return None;
        }
        let len = u32::from_le_bytes(data[probe..probe + 4].try_into().ok()?) as usize;
        let total = 4 + len;
        if probe + total == end {
            Some(total)
        } else {
            None
        }
    })
}

/// Validate that bytes at `[start..end]` form a valid CString (length prefix +
/// content fitting exactly in the range).
pub fn is_valid_cstring(data: &[u8], start: usize, end: usize) -> bool {
    if start + 4 > end || end > data.len() {
        return false;
    }
    let Ok(len_bytes) = data[start..start + 4].try_into() else {
        return false;
    };
    let len = u32::from_le_bytes(len_bytes) as usize;
    start + 4 + len == end
}

/// Helper: load pabgh sister file and return sorted (key, byte_offset) entries.
/// Returns None if the file is missing.
pub fn load_pabgh_offsets(pabgh_path: &str) -> Option<Vec<(u32, usize)>> {
    let bytes = std::fs::read(pabgh_path).ok()?;
    load_pabgh_offsets_from_bytes(&bytes)
}

/// Same as `load_pabgh_offsets` but accepts a pre-loaded byte slice. Used by
/// in-memory mod application where the caller already has the pabgh bytes.
pub fn load_pabgh_offsets_from_bytes(bytes: &[u8]) -> Option<Vec<(u32, usize)>> {
    let pabgh = parse_pabgh_inline(bytes)?;
    let mut entries = pabgh;
    entries.sort_by_key(|e| e.1);
    Some(entries)
}

/// Define a "blob-tail" table struct with `key + string_key + is_blocked` pre-
/// fields and the rest of the entry captured as a `Vec<u8>` byte-blob. Round-
/// trips byte-perfectly via pabgh entry sizes; field-level mod targeting is
/// limited to the 3 prefix fields. For tables with deeply polymorphic content
/// where a granular schema isn't yet reverse-engineered.
#[macro_export]
macro_rules! pabgh_blob_table {
    (
        $(#[$meta:meta])*
        pub struct $name:ident<'a> {
            key: $key_ty:ty,
            blob_field: $blob:ident,
        }
        $($fixture_dir:literal $fixture_name:literal)?
    ) => {
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $name<'a> {
            pub key: $key_ty,
            pub string_key: $crate::binary::CString<'a>,
            pub is_blocked: u8,
            pub $blob: Vec<u8>,
        }

        impl<'a> $name<'a> {
            pub fn read_with_size(
                data: &'a [u8],
                offset: &mut usize,
                entry_size: usize,
            ) -> std::io::Result<Self> {
                use $crate::binary::BinaryRead;
                let entry_start = *offset;
                let entry_end = entry_start + entry_size;
                let key = <$key_ty as BinaryRead>::read_from(data, offset)?;
                let string_key = $crate::binary::CString::read_from(data, offset)?;
                let is_blocked = u8::read_from(data, offset)?;
                let $blob = data[*offset..entry_end].to_vec();
                *offset = entry_end;
                Ok(Self { key, string_key, is_blocked, $blob })
            }

            pub fn write_to(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
                use $crate::binary::BinaryWrite;
                self.key.write_to(w)?;
                self.string_key.write_to(w)?;
                self.is_blocked.write_to(w)?;
                w.write_all(&self.$blob)?;
                Ok(())
            }
        }
    };
}

/// "Tier 1.5" hybrid table: explicit typed prefix fields followed by an
/// opaque `tail_blob: Vec<u8>` covering everything from the first un-decoded
/// helper to the end of the entry. Round-trips byte-perfectly via pabgh
/// entry sizes (the tail captures whatever the typed prefix didn't consume).
///
/// Field-level mod targeting works for every typed prefix field; the tail
/// stays a single byte-blob until the next decode pass extends the schema.
///
/// JSON output: each typed prefix field appears by name; `_tail_b64` is
/// emitted only when the tail Vec is non-empty (Tier 1 promotions where
/// the typed prefix consumes every byte get a clean, tail-free dict).
/// `write_from_json_dict` accepts dicts with or without `_tail_b64`.
///
/// Usage:
/// ```ignore
/// pabgh_typed_blob_table! {
///     pub struct MyInfo<'a> {
///         pub key: u16,
///         pub string_key: CString<'a>,
///         pub is_blocked: u8,
///         pub lookup_a: u32,
///         // ... any number of typed BinaryRead/BinaryWrite fields ...
///     }
///     tail: tail_blob;
/// }
/// ```
///
/// The macro emits `read_with_size(data, &mut offset, entry_size)` and
/// `write_to(&self, w)` directly on the struct. Use the same pabgh-driven
/// loop pattern as the original `pabgh_blob_table!` to round-trip.
#[macro_export]
macro_rules! pabgh_typed_blob_table {
    (
        $(#[$meta:meta])*
        pub struct $name:ident<'a> {
            $(pub $field:ident : $ty:ty),* $(,)?
        }
        tail: $tail:ident;
    ) => {
        $(#[$meta])*
        #[derive(Debug)]
        pub struct $name<'a> {
            $(pub $field: $ty,)*
            pub $tail: Vec<u8>,
        }

        impl<'a> $name<'a> {
            pub fn read_with_size(
                data: &'a [u8],
                offset: &mut usize,
                entry_size: usize,
            ) -> std::io::Result<Self> {
                use $crate::binary::BinaryRead;
                let entry_start = *offset;
                let entry_end = entry_start + entry_size;
                $(let $field = <$ty as BinaryRead>::read_from(data, offset)?;)*
                if *offset > entry_end {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "{} typed prefix overran entry: consumed {} of {} bytes",
                            stringify!($name), *offset - entry_start, entry_size
                        ),
                    ));
                }
                let $tail = data[*offset..entry_end].to_vec();
                *offset = entry_end;
                Ok(Self { $($field,)* $tail })
            }

            pub fn write_to(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
                use $crate::binary::BinaryWrite;
                $(self.$field.write_to(w)?;)*
                w.write_all(&self.$tail)?;
                Ok(())
            }

            /// Convert this typed-prefix-plus-tail record to a JSON dict.
            /// Each typed prefix field becomes a named entry; the opaque
            /// tail blob is emitted as base64 under `_tail_b64` *only when
            /// non-empty*. When the typed prefix consumes every byte of
            /// every vanilla entry (Tier 1 in practice), the field is
            /// omitted to keep the JSON shape clean.
            pub fn to_json_dict(&self) -> ::serde_json::Map<String, ::serde_json::Value> {
                use $crate::json_traits::ToJsonValue;
                use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                let mut m = ::serde_json::Map::new();
                $(m.insert(stringify!($field).to_string(), self.$field.to_json_value());)*
                if !self.$tail.is_empty() {
                    m.insert("_tail_b64".to_string(), ::serde_json::Value::String(B64.encode(&self.$tail)));
                }
                m
            }

            /// Write a JSON dict (as produced by `to_json_dict` and possibly
            /// mutated by a v3 mod) back to bytes. Reads each typed prefix
            /// field by name and decodes the tail from `_tail_b64`. The
            /// tail field is optional — missing key is treated as empty
            /// tail (matches the new `to_json_dict` shape for fully-typed
            /// records).
            pub fn write_from_json_dict(
                w: &mut Vec<u8>,
                obj: &::serde_json::Map<String, ::serde_json::Value>,
            ) -> std::io::Result<()> {
                use $crate::json_traits::{WriteJsonValue, get_field as json_get_field};
                use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                $(<$ty as WriteJsonValue>::write_from_json(w, json_get_field(obj, stringify!($field))?)?;)*
                if let Some(tail_v) = obj.get("_tail_b64") {
                    let tail_b64 = tail_v.as_str()
                        .ok_or_else(|| std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("{}: _tail_b64 must be a base64 string", stringify!($name))))?;
                    let tail = B64.decode(tail_b64).map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("{}: _tail_b64 invalid base64: {}", stringify!($name), e)))?;
                    w.extend_from_slice(&tail);
                }
                Ok(())
            }
        }
    };
}

/// Inline minimal pabgh parser supporting all 3 known formats.
/// Returns Vec<(key, offset)> on success, None on unknown layout.
fn parse_pabgh_inline(data: &[u8]) -> Option<Vec<(u32, usize)>> {
    if data.len() < 4 {
        return None;
    }
    let c16 = u16::from_le_bytes(data[0..2].try_into().ok()?) as usize;
    let c32 = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;

    let (idx_start, count, key_size, entry_size) = if 2 + c16 * 8 == data.len() {
        (2usize, c16, 4usize, 8usize)
    } else if 2 + c16 * 6 == data.len() {
        (2usize, c16, 2usize, 6usize)
    } else if 4 + c32 * 8 == data.len() {
        (4usize, c32, 4usize, 8usize)
    } else {
        return None;
    };

    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let pos = idx_start + i * entry_size;
        let key = if key_size == 2 {
            u16::from_le_bytes(data[pos..pos + 2].try_into().ok()?) as u32
        } else {
            u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?)
        };
        let off = u32::from_le_bytes(data[pos + key_size..pos + key_size + 4].try_into().ok()?)
            as usize;
        out.push((key, off));
    }
    Some(out)
}

/// Iterate each entry's (start, end) byte range from pabgh + total file size.
pub fn entry_ranges(entries: &[(u32, usize)], total: usize) -> Vec<(u32, usize, usize)> {
    let mut out = Vec::with_capacity(entries.len());
    for i in 0..entries.len() {
        let (key, start) = entries[i];
        let end = if i + 1 < entries.len() {
            entries[i + 1].1
        } else {
            total
        };
        out.push((key, start, end));
    }
    out
}

// Suppress unused import warning if CString isn't directly used in this file.
#[allow(dead_code)]
fn _force_use_cstring(_: &CString<'_>) {}
