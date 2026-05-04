// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! `.paac` action-chart file parser.
//!
//! Faithful Rust port of `ResearchFolder/paac/paac_parser.py`. Heuristic
//! decisions (minimum condition-graph run length, format-A/B size
//! threshold, identifier regex, etc.) match the Python verbatim — the
//! Python is the spec.
//!
//! ## Format facts (verified, cited from the Python source)
//!
//! - Header is 68 bytes total. `node_count` = u32 @ +0x00. `speed` =
//!   f32 @ +0x08.
//! - State records section begins at +0x44 (right after header).
//! - Each state record is marked by `M0%D` (`4D 30 25 44`) at offset
//!   +2 within the record (record actually starts 2 bytes BEFORE
//!   `M0%D`).
//! - Inline transition record = 16 bytes:
//!   `[f32 threshold (0..1)] [f32 -1.0 sentinel = 00 00 80 BF]
//!    [u32 target_state (0..720)] [u32 sequence (0..100)]`.
//!   Detect via the -1.0 sentinel at offset+4.
//! - Condition records are 260 bytes each, identified by a long run of
//!   `M0%D` markers spaced exactly 260 bytes apart. Bytecode at +0xE0
//!   is opaque per the Python reference and not decoded here.

use std::io;

/// `M0%D` magic — record marker (state, condition).
pub const M0PD_MAGIC: &[u8; 4] = b"M0%D";
/// `-1.0f32` little-endian — transition record discriminator at +4.
pub const TRANSITION_SENTINEL: &[u8; 4] = &[0x00, 0x00, 0x80, 0xBF];
/// `0xA8B7DDAA` little-endian — appears in `commonactioninfo.paac`
/// records.
pub const INFO_SENTINEL: &[u8; 4] = &[0xAA, 0xDD, 0xB7, 0xA8];
/// FF*8 — separates guard sub-blocks within Format B states.
pub const GUARD_BLOCK_SEP: &[u8; 8] = &[0xFF; 8];

/// 68-byte PAAC header.
pub const HEADER_SIZE: usize = 68;
/// State records begin at +0x44 (right after the 68-byte header).
pub const STATE_RECORDS_START: usize = HEADER_SIZE;
/// Each condition record is exactly 260 bytes.
pub const CONDITION_RECORD_SIZE: usize = 260;
/// Each inline transition record is 16 bytes.
pub const INLINE_TRANSITION_SIZE: usize = 16;
/// `M0%D` appears at +2 within a record.
pub const M0PD_OFFSET_IN_RECORD: usize = 2;

/// Sub-format of a `.paac` file. Matches the three string values
/// returned by the Python `sniff_format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaacFormat {
    /// Small file (e.g. `commonactioninfo.paac`) using the `0xA8B7DDAA`
    /// sentinel; no `M0%D` markers. No 68-byte header parsed.
    InfoTable,
    /// Action chart with no `M0%D` markers — uses inline transitions
    /// only (e.g. `pistol_upper.paac`).
    ActionChartV0,
    /// Action chart with `M0%D` state records (e.g. `fist_upper.paac`,
    /// `sword_upper.paac`).
    ActionChartV1,
    /// Anything we couldn't classify (e.g. truncated file).
    Unknown,
}

/// 68-byte PAAC header. Per the Python reference, `raw` carries the
/// full 68 bytes so unverified fields round-trip.
#[derive(Debug, Clone)]
pub struct Header {
    /// u32 @ +0. Observed: 35..721.
    pub node_count: u32,
    /// f32 @ +8. Observed: 1.333 (fist_upper), 3.0 (pistol_upper).
    pub speed: f32,
    /// Full 68-byte header bytes.
    pub raw: Vec<u8>,
}

/// Inline transition record (16 bytes). Detected via the -1.0 sentinel
/// at byte offset +4 within the record.
#[derive(Debug, Clone)]
pub struct InlineTransition {
    /// Absolute byte offset in the file (start of the record).
    pub file_offset: usize,
    /// f32 in [0, 1].
    pub threshold: f32,
    /// u32 in [0, 720].
    pub target_state: u32,
    /// u32 in [0, 100].
    pub sequence: u32,
}

/// A state in an action chart. Format A (attack, ~400-600B) or
/// Format B (guard, ~2000B + FF*8 separators).
#[derive(Debug, Clone)]
pub struct StateRecord {
    /// Offset of the `M0%D` marker.
    pub file_offset: usize,
    /// Offset of the record (M0%D position - 2).
    pub record_start: usize,
    /// End offset (next M0%D or EOF).
    pub end: usize,
    /// Raw bytes spanning `[record_start..end)`.
    pub raw: Vec<u8>,
    /// `'A'` (attack) or `'B'` (guard) — heuristic classification.
    pub fmt: char,
    /// Inline transitions whose `file_offset` lies in this state's
    /// range.
    pub transitions: Vec<InlineTransition>,
    /// Whether the FF*8 separator appears anywhere in `raw` (Format B
    /// guard sub-block marker).
    pub has_guard_subblocks: bool,
    /// Plausible-looking floats found within the record's byte range
    /// (matched per the Python `_extract_floats`).
    pub floats: Vec<(usize, f32)>,
}

/// 260-byte condition graph record. Bytecode at +0xE0 is opaque per
/// the Python reference and not decoded here.
#[derive(Debug, Clone)]
pub struct ConditionRecord {
    /// Offset of the `M0%D` marker.
    pub file_offset: usize,
    /// Full 260 bytes (record_start = file_offset - 2).
    pub raw: Vec<u8>,
    /// u32 @ +152 (probable transition/state ref).
    pub target: Option<u32>,
    /// u32 @ +212.
    pub source_state: Option<u32>,
    /// u32 @ +216 (string-table index).
    pub label_index: Option<u32>,
    /// u32 @ +224.
    pub opcode: Option<u32>,
    /// 4 bytes @ +229..+233.
    pub cond_params: [u8; 4],
    /// 24 bytes @ +0xE0.
    pub bytecode: [u8; 24],
    /// Byte @ +0xE7 (likely an input-key index).
    pub key_index_byte: Option<u8>,
}

/// One identifier-like string scanned from the file.
#[derive(Debug, Clone)]
pub struct StringTableEntry {
    /// Absolute byte offset where the string begins.
    pub file_offset: usize,
    /// The string text (latin-1 decoded, trailing NUL stripped).
    pub text: String,
}

/// A parsed `.paac` file. Mirrors the Python `PaacFile` dataclass.
#[derive(Debug, Clone)]
pub struct PaacFile {
    /// Detected sub-format. `InfoTable` files do not have a parsed
    /// `Header` even though their first 68 bytes are still bytes.
    pub format: PaacFormat,
    /// Total file size in bytes.
    pub size: usize,
    /// Parsed 68-byte header. `None` for `InfoTable` files (matching
    /// the Python: `header = _parse_header(data) if fmt != "info_table"
    /// else None`).
    pub header: Option<Header>,
    /// Walked `M0%D` state records (only populated for `ActionChartV1`).
    pub states: Vec<StateRecord>,
    /// All inline-transition records detected by the -1.0 sentinel
    /// scan. Populated regardless of format.
    pub transitions: Vec<InlineTransition>,
    /// 260-byte condition graph records (only populated for
    /// `ActionChartV1` when a long run is found).
    pub condition_records: Vec<ConditionRecord>,
    /// Identifier-like strings scanned from the file. Populated
    /// regardless of format.
    pub strings: Vec<StringTableEntry>,
    /// Original file bytes (kept so the caller can patch at known
    /// offsets and re-serialize).
    pub raw: Vec<u8>,
}

/// Detect the sub-format of a `.paac` file by counting markers.
///
/// Mirrors the Python `sniff_format` exactly:
/// - `InfoTable` if `INFO_SENTINEL` count > 0 AND `M0%D` count == 0
///   AND `len < 100_000`.
/// - `ActionChartV1` if `M0%D` count > 0.
/// - `ActionChartV0` otherwise (when the file is large enough).
/// - `Unknown` for files smaller than 16 bytes.
pub fn sniff_format(data: &[u8]) -> PaacFormat {
    if data.len() < 16 {
        return PaacFormat::Unknown;
    }
    let info_count = count_occurrences(data, INFO_SENTINEL);
    let m0pd_count = count_occurrences(data, M0PD_MAGIC);
    if info_count > 0 && m0pd_count == 0 && data.len() < 100_000 {
        return PaacFormat::InfoTable;
    }
    if m0pd_count > 0 {
        return PaacFormat::ActionChartV1;
    }
    PaacFormat::ActionChartV0
}

impl PaacFile {
    /// Parse a `.paac` file.
    ///
    /// Always extracts identifier strings and inline transitions
    /// regardless of format (sentinel-based detection works on any
    /// layout). For `ActionChartV1` files we additionally walk state
    /// records and condition records.
    pub fn parse(data: &[u8]) -> PaacFile {
        let format = sniff_format(data);
        let header = if format != PaacFormat::InfoTable {
            Some(parse_header(data))
        } else {
            None
        };
        let mut pf = PaacFile {
            format,
            size: data.len(),
            header,
            states: Vec::new(),
            transitions: Vec::new(),
            condition_records: Vec::new(),
            strings: Vec::new(),
            raw: data.to_vec(),
        };

        scan_identifiers(&mut pf);
        scan_inline_transitions(&mut pf);

        if format == PaacFormat::ActionChartV1 {
            parse_state_records(&mut pf);
            parse_condition_records(&mut pf);
        }
        pf
    }

    /// All inline transitions targeting the given `state_id`.
    pub fn transitions_to_state(&self, state_id: u32) -> Vec<&InlineTransition> {
        self.transitions
            .iter()
            .filter(|t| t.target_state == state_id)
            .collect()
    }

    /// All condition records whose `target` field equals `state_id`.
    pub fn conditions_targeting(&self, state_id: u32) -> Vec<&ConditionRecord> {
        self.condition_records
            .iter()
            .filter(|c| c.target == Some(state_id))
            .collect()
    }

    /// Find every identifier string whose text contains `needle`
    /// (case-insensitive).
    pub fn find_string(&self, needle: &str) -> Vec<&StringTableEntry> {
        let n = needle.to_ascii_lowercase();
        self.strings
            .iter()
            .filter(|s| s.text.to_ascii_lowercase().contains(&n))
            .collect()
    }
}

/// Parse the 68-byte header. Mirrors the Python `_parse_header`. Returns
/// a header with the read fields plus the raw bytes.
fn parse_header(data: &[u8]) -> Header {
    if data.len() < HEADER_SIZE {
        let raw = data[..data.len().min(HEADER_SIZE)].to_vec();
        return Header {
            node_count: 0,
            speed: 0.0,
            raw,
        };
    }
    let nc = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let sp = f32::from_le_bytes(data[8..12].try_into().unwrap());
    Header {
        node_count: nc,
        speed: sp,
        raw: data[..HEADER_SIZE].to_vec(),
    }
}

/// Walk M0%D markers, classify each state Format A/B, attach the
/// transitions whose offsets fall within each state's range. Mirrors
/// the Python `_parse_state_records` exactly.
fn parse_state_records(pf: &mut PaacFile) {
    let data = &pf.raw;
    let markers: Vec<usize> = find_all(data, M0PD_MAGIC)
        .into_iter()
        .filter(|&s| s >= STATE_RECORDS_START)
        .collect();

    for (i, &off) in markers.iter().enumerate() {
        let end = if i + 1 < markers.len() {
            markers[i + 1]
        } else {
            data.len()
        };
        if off < M0PD_OFFSET_IN_RECORD {
            continue;
        }
        let record_start = off - M0PD_OFFSET_IN_RECORD;
        let size = end - record_start;
        let record_bytes = data[record_start..end].to_vec();
        let has_guard = contains(&record_bytes, GUARD_BLOCK_SEP);
        let fmt = if has_guard || size > 1500 { 'B' } else { 'A' };

        let floats = extract_floats(data, record_start, end, 0.001, 10000.0);
        let transitions: Vec<InlineTransition> = pf
            .transitions
            .iter()
            .filter(|t| t.file_offset >= record_start && t.file_offset < end)
            .cloned()
            .collect();

        pf.states.push(StateRecord {
            file_offset: off,
            record_start,
            end,
            raw: record_bytes,
            fmt,
            transitions,
            has_guard_subblocks: has_guard,
            floats,
        });
    }
}

/// Sentinel-based scan for inline transition records. Steps by 4 (word
/// alignment) and validates: -1.0 sentinel at +4, threshold in [0,1],
/// target<=720, sequence<=100. Mirrors the Python
/// `_scan_inline_transitions`.
fn scan_inline_transitions(pf: &mut PaacFile) {
    let data = &pf.raw;
    let mut out = Vec::new();
    if data.len() < INLINE_TRANSITION_SIZE {
        pf.transitions = out;
        return;
    }
    let limit = data.len().saturating_sub(INLINE_TRANSITION_SIZE);
    let mut i = 0usize;
    while i < limit {
        if &data[i + 4..i + 8] == TRANSITION_SENTINEL {
            let thresh = f32::from_le_bytes(data[i..i + 4].try_into().unwrap());
            let target = u32::from_le_bytes(data[i + 8..i + 12].try_into().unwrap());
            let seq = u32::from_le_bytes(data[i + 12..i + 16].try_into().unwrap());
            // NaN check + range matches Python's filter (`thresh == thresh`).
            if !thresh.is_nan()
                && (0.0..=1.0).contains(&thresh)
                && target <= 720
                && seq <= 100
            {
                out.push(InlineTransition {
                    file_offset: i,
                    threshold: thresh,
                    target_state: target,
                    sequence: seq,
                });
            }
        }
        i += 4;
    }
    pf.transitions = out;
}

/// Find runs of M0%D markers exactly 260 bytes apart — that's the
/// condition graph. Walks from the longest run's start. Mirrors the
/// Python `_parse_condition_records` (including the arbitrary "must be
/// >= 50 markers" minimum).
fn parse_condition_records(pf: &mut PaacFile) {
    let data = &pf.raw;
    let markers: Vec<usize> = find_all(data, M0PD_MAGIC);
    if markers.len() < 2 {
        return;
    }

    // Find the longest run of consecutive markers spaced exactly 260 bytes.
    let mut run_start: i64 = -1;
    let mut longest = 0usize;
    let mut cur_start = markers[0];
    let mut cur_len = 1usize;
    for w in markers.windows(2) {
        let prev = w[0];
        let nxt = w[1];
        if nxt - prev == CONDITION_RECORD_SIZE {
            cur_len += 1;
            if cur_len > longest {
                longest = cur_len;
                run_start = cur_start as i64;
            }
        } else {
            cur_start = nxt;
            cur_len = 1;
        }
    }

    if longest < 50 {
        return;
    }

    let mut pos = run_start as usize;
    while pos + CONDITION_RECORD_SIZE <= data.len() {
        if pos + 4 > data.len() || &data[pos..pos + 4] != M0PD_MAGIC {
            break;
        }
        if pos < M0PD_OFFSET_IN_RECORD {
            break;
        }
        let record_start = pos - M0PD_OFFSET_IN_RECORD;
        if record_start + CONDITION_RECORD_SIZE > data.len() {
            break;
        }
        let rec_bytes = &data[record_start..record_start + CONDITION_RECORD_SIZE];
        if rec_bytes.len() < CONDITION_RECORD_SIZE {
            break;
        }

        let target = safe_u32(rec_bytes, 152);
        let source_state = safe_u32(rec_bytes, 212);
        let label_index = safe_u32(rec_bytes, 216);
        let opcode = safe_u32(rec_bytes, 224);
        let mut cond_params = [0u8; 4];
        if rec_bytes.len() >= 233 {
            cond_params.copy_from_slice(&rec_bytes[229..233]);
        }
        let mut bytecode = [0u8; 24];
        if rec_bytes.len() >= 0xE0 + 24 {
            bytecode.copy_from_slice(&rec_bytes[0xE0..0xE0 + 24]);
        }
        let key_index_byte = if rec_bytes.len() > 0xE7 {
            Some(rec_bytes[0xE7])
        } else {
            None
        };

        pf.condition_records.push(ConditionRecord {
            file_offset: pos,
            raw: rec_bytes.to_vec(),
            target,
            source_state,
            label_index,
            opcode,
            cond_params,
            bytecode,
            key_index_byte,
        });
        pos += CONDITION_RECORD_SIZE;
    }
}

fn safe_u32(b: &[u8], off: usize) -> Option<u32> {
    if off + 4 > b.len() {
        return None;
    }
    Some(u32::from_le_bytes(b[off..off + 4].try_into().unwrap()))
}

/// Identifier scan — finds `[A-Za-z_][A-Za-z0-9_]{6,}\x00?` runs.
/// Mirrors the Python `_scan_identifiers` regex (longest-match,
/// greedy, with optional trailing NUL); the NUL is stripped before
/// decoding the bytes as latin-1.
///
/// We hand-roll the scan because we don't depend on the `regex` crate.
/// The matcher walks every position and, when it sees a valid leading
/// byte, greedily consumes a run of `[A-Za-z0-9_]`. If the run length
/// is at least 7 (the regex's `{6,}` plus the leading byte), the run
/// is recorded — the next attempt resumes from the byte AFTER the
/// recorded run (matching the regex's non-overlapping semantics) so
/// trailing alphanumerics are not double-reported.
fn scan_identifiers(pf: &mut PaacFile) {
    let data = &pf.raw;
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        if !is_ident_start(b) {
            i += 1;
            continue;
        }
        let start = i;
        let mut j = i + 1;
        while j < data.len() && is_ident_cont(data[j]) {
            j += 1;
        }
        // Total run length (incl. the leading byte). The regex requires
        // {6,} after the first char, i.e. at least 7 chars total.
        if j - start >= 7 {
            let mut end = j;
            // The Python regex includes an optional trailing \x00 — if
            // the next byte is NUL, consume it then strip before
            // decoding (matches the .rstrip(b"\x00") in Python).
            if end < data.len() && data[end] == 0 {
                end += 1;
            }
            let mut bytes = data[start..end].to_vec();
            if bytes.last() == Some(&0u8) {
                bytes.pop();
            }
            let text: String = bytes.iter().map(|&b| b as char).collect();
            pf.strings.push(StringTableEntry {
                file_offset: start,
                text,
            });
            i = end;
        } else {
            // Run too short — skip past it so we don't restart inside
            // the run.
            i = j;
        }
    }
}

#[inline]
fn is_ident_start(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'_')
}

#[inline]
fn is_ident_cont(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
}

/// Extract plausible-looking floats inside `[start..end)`. Mirrors the
/// Python `_extract_floats` (including its NaN-rejecting `v == v` and
/// the magnitude band `[lo, hi]`).
pub fn extract_floats(
    data: &[u8],
    start: usize,
    end: usize,
    lo: f32,
    hi: f32,
) -> Vec<(usize, f32)> {
    let mut out = Vec::new();
    let mut i = start;
    let cap = end.min(data.len());
    while i + 4 <= cap {
        let v = f32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        if !v.is_nan() && v.abs() >= lo && v.abs() <= hi {
            out.push((i, v));
        }
        i += 4;
    }
    out
}

/// Mirror of the Python `find_floats_near_strings` — finds plausible
/// gameplay floats within `radius` bytes of an identifier string.
///
/// `keyword` filters strings (case-insensitive substring). Returns
/// `(file_offset, value, nearby_string)` triples ordered by
/// `file_offset`.
pub fn find_floats_near_strings(
    pf: &PaacFile,
    keyword: Option<&str>,
    radius: usize,
    lo: f32,
    hi: f32,
) -> Vec<(usize, f32, String)> {
    let kw = keyword.map(|k| k.to_ascii_lowercase());
    let mut string_offs: Vec<usize> = pf
        .strings
        .iter()
        .filter(|s| match &kw {
            Some(k) => s.text.to_ascii_lowercase().contains(k),
            None => true,
        })
        .map(|s| s.file_offset)
        .collect();
    string_offs.sort_unstable();

    if string_offs.is_empty() {
        return Vec::new();
    }

    let raw_floats = extract_floats(&pf.raw, 0, pf.raw.len(), lo, hi);
    let mut out = Vec::new();
    let mut j = 0usize;
    for (off, v) in raw_floats {
        // Advance pointer to first string within radius.
        while j < string_offs.len() && string_offs[j] + radius < off {
            j += 1;
        }
        for k in j..(j + 3).min(string_offs.len()) {
            let so = string_offs[k];
            let dist = if so > off { so - off } else { off - so };
            if dist <= radius {
                let ctx = pf
                    .strings
                    .iter()
                    .find(|s| s.file_offset == so)
                    .map(|s| s.text.clone())
                    .unwrap_or_default();
                out.push((off, v, ctx));
                break;
            }
        }
    }
    out
}

/// Patch a 4-byte little-endian f32 at `file_offset`. Bounds-checked.
///
/// This is an addition to the Python parser — added so the workbench UI
/// can edit floats found by [`find_floats_near_strings`] (or any other
/// scan) and persist the change back to the in-memory bytes before
/// re-serialization.
pub fn patch_float(bytes: &mut [u8], file_offset: usize, new_value: f32) -> io::Result<()> {
    if file_offset + 4 > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "patch_float: offset {} + 4 > len {}",
                file_offset,
                bytes.len()
            ),
        ));
    }
    bytes[file_offset..file_offset + 4].copy_from_slice(&new_value.to_le_bytes());
    Ok(())
}

/// Patch a 16-byte transition record at `t.file_offset`. Bounds-checked.
///
/// Layout (little-endian):
/// ```text
///   +0   threshold (f32, [0,1])
///   +4   sentinel  (f32, -1.0 = 00 00 80 BF)
///   +8   target_state (u32)
///   +12  sequence  (u32)
/// ```
///
/// The UI mutates an [`InlineTransition`] in place and calls this to
/// flush the change back to the raw byte buffer.
pub fn patch_transition(bytes: &mut [u8], t: &InlineTransition) -> io::Result<()> {
    if t.file_offset + INLINE_TRANSITION_SIZE > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "patch_transition: offset {} + {} > len {}",
                t.file_offset,
                INLINE_TRANSITION_SIZE,
                bytes.len()
            ),
        ));
    }
    let off = t.file_offset;
    bytes[off..off + 4].copy_from_slice(&t.threshold.to_le_bytes());
    // -1.0f sentinel — preserved verbatim per the format spec.
    bytes[off + 4..off + 8].copy_from_slice(TRANSITION_SENTINEL);
    bytes[off + 8..off + 12].copy_from_slice(&t.target_state.to_le_bytes());
    bytes[off + 12..off + 16].copy_from_slice(&t.sequence.to_le_bytes());
    Ok(())
}

// ── small byte-search helpers ────────────────────────────────────────

/// Count every (possibly overlapping) occurrence of `needle` in
/// `haystack`. Mirrors Python's `bytes.count` semantics — matches
/// advance by one byte even when a hit was found, so overlapping
/// patterns are counted correctly.
fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || haystack.len() < needle.len() {
        return 0;
    }
    let mut count = 0usize;
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            count += 1;
        }
        i += 1;
    }
    count
}

/// Return the start offset of every occurrence of `needle` in
/// `haystack`. Used by the M0%D state and condition record walkers.
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            out.push(i);
        }
        i += 1;
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample fixtures — guarded with a SKIP message when missing so
    /// the test suite still passes on machines without the research
    /// folder.
    const COMMON_INFO: &str =
        r"C:\Users\Coding\CrimsonDesertModding\ResearchFolder\paac\sample_commonactioninfo.paac";
    const FIST_UPPER: &str =
        r"C:\Users\Coding\CrimsonDesertModding\ResearchFolder\paac\sample_fist_upper.paac";
    const PISTOL_UPPER: &str =
        r"C:\Users\Coding\CrimsonDesertModding\ResearchFolder\paac\sample_pistol_upper.paac";
    const SWORD_UPPER: &str =
        r"C:\Users\Coding\CrimsonDesertModding\ResearchFolder\paac\sample_sword_upper.paac";

    fn maybe_load(path: &str) -> Option<Vec<u8>> {
        match std::fs::read(path) {
            Ok(b) => Some(b),
            Err(_) => {
                eprintln!("SKIP: missing fixture {}", path);
                None
            }
        }
    }

    #[test]
    fn info_table_has_no_header() {
        // The Python reference returns format='info_table' and
        // header=None for this file; our parser must mirror that. The
        // file has zero M0%D markers, zero inline transitions, and (in
        // practice) no identifier-shaped strings either, so we only
        // verify the format + header decisions here. A file with
        // identifiers is exercised by `fist_upper_is_action_chart_v1_with_states`.
        let Some(data) = maybe_load(COMMON_INFO) else {
            return;
        };
        let pf = PaacFile::parse(&data);
        assert_eq!(pf.format, PaacFormat::InfoTable);
        assert!(
            pf.header.is_none(),
            "info_table must not parse a header (Python reference behaviour)"
        );
        assert_eq!(
            pf.states.len(),
            0,
            "info_table has no M0%D state records"
        );
        assert_eq!(
            pf.condition_records.len(),
            0,
            "info_table has no condition records"
        );
    }

    #[test]
    fn fist_upper_is_action_chart_v1_with_states() {
        let Some(data) = maybe_load(FIST_UPPER) else {
            return;
        };
        let pf = PaacFile::parse(&data);
        assert_eq!(pf.format, PaacFormat::ActionChartV1);
        let header = pf
            .header
            .as_ref()
            .expect("ActionChartV1 must have a parsed header");
        assert!(
            header.node_count > 0,
            "node_count should be non-zero for fist_upper"
        );
        assert!(
            !pf.states.is_empty(),
            "expected M0%D state records in fist_upper"
        );
        for s in &pf.states {
            assert!(
                s.fmt == 'A' || s.fmt == 'B',
                "state at offset 0x{:X} has fmt {:?}",
                s.file_offset,
                s.fmt
            );
        }
        // Parity vs the Python reference (paac_parser.py output):
        //   header.node_count = 703, speed = 1.3333
        //   35 states (27 A, 8 B with 7 guard sub-blocks)
        //   371 inline transitions
        //   513 identifier strings
        assert_eq!(header.node_count, 703);
        assert!(
            (header.speed - 1.3333).abs() < 0.01,
            "speed: got {}",
            header.speed
        );
        assert_eq!(pf.states.len(), 35, "state count diverges from Python");
        let a = pf.states.iter().filter(|s| s.fmt == 'A').count();
        let b = pf.states.iter().filter(|s| s.fmt == 'B').count();
        assert_eq!(a, 27, "Format A state count");
        assert_eq!(b, 8, "Format B state count");
        let with_guard = pf
            .states
            .iter()
            .filter(|s| s.has_guard_subblocks)
            .count();
        assert_eq!(with_guard, 7, "Format B states with guard sub-blocks");
        assert_eq!(
            pf.transitions.len(),
            371,
            "inline transition count diverges from Python"
        );
        assert_eq!(
            pf.strings.len(),
            513,
            "identifier string count diverges from Python (got {}, expected 513)",
            pf.strings.len()
        );
    }

    #[test]
    fn pistol_upper_is_action_chart_v0() {
        let Some(data) = maybe_load(PISTOL_UPPER) else {
            return;
        };
        let pf = PaacFile::parse(&data);
        assert_eq!(pf.format, PaacFormat::ActionChartV0);
        // Per Python: v0 has a parsed header but no M0%D state records.
        assert!(pf.header.is_some());
        assert!(
            pf.states.is_empty(),
            "v0 should not have M0%D state records"
        );
        // Parity vs Python: node_count=649, speed=3.0, 1045 transitions,
        // 374 strings, no condition records.
        let h = pf.header.as_ref().unwrap();
        assert_eq!(h.node_count, 649);
        assert!((h.speed - 3.0).abs() < 0.001);
        assert_eq!(pf.transitions.len(), 1045);
        assert_eq!(pf.strings.len(), 374);
        assert_eq!(pf.condition_records.len(), 0);
    }

    #[test]
    fn sword_upper_has_big_condition_graph() {
        let Some(data) = maybe_load(SWORD_UPPER) else {
            return;
        };
        let pf = PaacFile::parse(&data);
        assert_eq!(pf.format, PaacFormat::ActionChartV1);
        assert!(
            pf.condition_records.len() >= 50,
            "expected >=50 condition records in sword_upper, got {}",
            pf.condition_records.len()
        );
        // Parity vs Python: 1018 states, 830 transitions, 316 conditions,
        // 757 strings.
        assert_eq!(pf.states.len(), 1018, "sword_upper state count");
        assert_eq!(pf.transitions.len(), 830, "sword_upper transitions");
        assert_eq!(
            pf.condition_records.len(),
            316,
            "sword_upper condition records"
        );
        assert_eq!(pf.strings.len(), 757, "sword_upper identifier strings");
    }

    #[test]
    fn patch_float_roundtrip() {
        let Some(data) = maybe_load(FIST_UPPER) else {
            return;
        };
        let pf = PaacFile::parse(&data);
        let hits = find_floats_near_strings(&pf, None, 128, 0.001, 10000.0);
        let Some(&(off, _v, _)) = hits.first() else {
            eprintln!("SKIP: no near-string floats found in {}", FIST_UPPER);
            return;
        };

        let mut buf = pf.raw.clone();
        let new_value: f32 = 1.234_5_f32;
        patch_float(&mut buf, off, new_value).expect("patch must succeed");

        let pf2 = PaacFile::parse(&buf);
        let read_back = f32::from_le_bytes(pf2.raw[off..off + 4].try_into().unwrap());
        assert!(
            (read_back - new_value).abs() < f32::EPSILON,
            "patched float at 0x{:X} did not survive a re-parse: got {}",
            off,
            read_back
        );
    }

    #[test]
    fn patch_transition_roundtrip() {
        let Some(data) = maybe_load(FIST_UPPER) else {
            return;
        };
        let pf = PaacFile::parse(&data);
        let Some(t) = pf.transitions.first().cloned() else {
            eprintln!("SKIP: no inline transitions in {}", FIST_UPPER);
            return;
        };
        let mut buf = pf.raw.clone();
        let mut tt = t.clone();
        tt.threshold = 0.5;
        tt.target_state = 42;
        tt.sequence = 7;
        patch_transition(&mut buf, &tt).expect("patch_transition must succeed");

        let pf2 = PaacFile::parse(&buf);
        let mirrored = pf2
            .transitions
            .iter()
            .find(|x| x.file_offset == t.file_offset)
            .expect("re-parse should find the same transition offset");
        assert!((mirrored.threshold - 0.5).abs() < f32::EPSILON);
        assert_eq!(mirrored.target_state, 42);
        assert_eq!(mirrored.sequence, 7);
    }
}
