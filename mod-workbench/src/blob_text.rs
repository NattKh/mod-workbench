//! Heuristics for surfacing readable text inside binary blob fields.
//!
//! Many pabgb tables expose entries that contain a `_blob_b64` (base64-encoded
//! raw bytes) alongside the typed fields the parser was able to decode. Most
//! of those blobs embed Korean strings — game asset paths, dev names, debug
//! descriptions — written as length-prefixed UTF-8.
//!
//! Without help the editor renders the field as `<base64 string>`, which is
//! useless to a human. This module pulls printable text out of the blob so the
//! UI can render `dev_skill_name: "전기 속성 장비 추가 스킬"` instead of
//! `_blob_b64: "AAAA..."`.
//!
//! The detector is conservative: a chunk only counts as "text" if it is
//! valid UTF-8, at least 3 chars long, and either contains Hangul/Kana/Hanzi
//! OR is mostly printable ASCII (i.e. an English asset path). This keeps it
//! from quoting random control bytes as "text".

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

/// A piece of text recovered from a blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractedText {
    /// Byte offset in the blob where this run started.
    pub offset: usize,
    /// The decoded string (always valid UTF-8 by construction).
    pub text: String,
    /// True if the run contained any CJK code points.
    pub has_cjk: bool,
}

/// Pull ASCII-printable / CJK runs of length >= 3 chars out of `bytes`.
///
/// Each run terminates on the first byte that breaks the printable / valid-
/// UTF-8 rule. The detector is intentionally simple: walk byte by byte using
/// `std::str::from_utf8` to advance past well-formed multi-byte sequences,
/// commit a run when we hit anything we don't like.
pub fn extract_text_runs(bytes: &[u8]) -> Vec<ExtractedText> {
    let mut runs = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // Try to read one valid UTF-8 codepoint starting at i. We need to
        // accept up to 4-byte sequences for non-BMP characters but the CJK
        // range we care about is mostly 3-byte.
        let start = i;
        let mut current = String::new();
        let mut has_cjk = false;
        loop {
            if i >= bytes.len() {
                break;
            }
            let max_take = (i + 4).min(bytes.len());
            // Try the longest legal sequence first so we don't get fooled
            // into stopping mid-multibyte.
            let mut consumed = 0;
            for try_len in (1..=max_take - i).rev() {
                if let Ok(s) = std::str::from_utf8(&bytes[i..i + try_len]) {
                    let ch = match s.chars().next() {
                        Some(c) => c,
                        None => break,
                    };
                    if !is_printable_or_cjk(ch) {
                        break;
                    }
                    if is_cjk(ch) {
                        has_cjk = true;
                    }
                    current.push(ch);
                    consumed = try_len;
                    break;
                }
            }
            if consumed == 0 {
                break;
            }
            i += consumed;
        }
        if current.chars().count() >= 3 {
            runs.push(ExtractedText {
                offset: start,
                text: current,
                has_cjk,
            });
        }
        // Skip the byte that broke the run so we don't loop forever.
        if i == start {
            i += 1;
        }
    }
    runs
}

/// Decode a base64 string to bytes, then extract text runs from the result.
/// Returns `None` if the input isn't valid base64.
pub fn extract_from_base64(b64: &str) -> Option<Vec<ExtractedText>> {
    B64.decode(b64.trim()).ok().map(|bytes| extract_text_runs(&bytes))
}

/// Quick yes/no: does this string look like base64-encoded data we should try
/// to decode? The check is rough — base64 chars only, length divisible by 4,
/// at least a few hundred chars to avoid noise on short numeric-looking strings.
pub fn looks_like_blob_base64(s: &str) -> bool {
    if s.len() < 16 {
        return false;
    }
    if s.len() % 4 != 0 {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Printable ASCII (excluding control chars except tab/newline) OR any CJK char.
fn is_printable_or_cjk(c: char) -> bool {
    if is_cjk(c) {
        return true;
    }
    let cp = c as u32;
    // ASCII printable range.
    if (0x20..=0x7E).contains(&cp) {
        return true;
    }
    // Allow common whitespace within a run so phrases keep going.
    matches!(c, '\t' | '\n' | ' ')
}

/// Hangul / Kana / Hanzi (CJK Unified Ideographs + ext A) detection.
fn is_cjk(c: char) -> bool {
    let cp = c as u32;
    // Hangul Syllables.
    (0xAC00..=0xD7A3).contains(&cp)
        // Hangul Jamo.
        || (0x1100..=0x11FF).contains(&cp)
        // Hangul Compatibility Jamo.
        || (0x3130..=0x318F).contains(&cp)
        // CJK Unified Ideographs (covers most Hanzi/Kanji used in-game).
        || (0x4E00..=0x9FFF).contains(&cp)
        // CJK Unified Ideographs Extension A.
        || (0x3400..=0x4DBF).contains(&cp)
        // Hiragana.
        || (0x3040..=0x309F).contains(&cp)
        // Katakana.
        || (0x30A0..=0x30FF).contains(&cp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_korean_run_after_length_prefix() {
        // Simulates a length-prefixed (4-byte LE) Korean string in a blob.
        let mut bytes = vec![0x0F, 0x00, 0x00, 0x00];
        bytes.extend_from_slice("전기 타격".as_bytes());
        bytes.push(0x00);
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        let runs = extract_text_runs(&bytes);
        assert!(
            runs.iter().any(|r| r.text.contains("전기 타격") && r.has_cjk),
            "expected to find Korean run, got {:?}",
            runs
        );
    }

    #[test]
    fn extracts_ascii_asset_path() {
        let bytes = b"\x00\x00\x12cd_seq_funcnpc_butcher\x00\xFF";
        let runs = extract_text_runs(bytes);
        assert!(
            runs.iter().any(|r| r.text.contains("cd_seq_funcnpc_butcher")),
            "expected ASCII run, got {:?}",
            runs
        );
    }

    #[test]
    fn ignores_short_garbage() {
        let bytes = &[0x01, 0x02, b'a', 0xFF, b'b', 0xFE, b'c'];
        let runs = extract_text_runs(bytes);
        // Each isolated 'a' / 'b' / 'c' is too short to count.
        assert!(runs.is_empty(), "expected no runs, got {:?}", runs);
    }

    #[test]
    fn looks_like_base64_basic() {
        assert!(looks_like_blob_base64("AAAAAAAAAAAAAAAA"));
        assert!(!looks_like_blob_base64("nope"));
        assert!(!looks_like_blob_base64("AAA")); // too short
        assert!(!looks_like_blob_base64("AAAA!@#$"));
    }

    #[test]
    fn cjk_detection() {
        assert!(is_cjk('전'));
        assert!(is_cjk('氣'));
        assert!(is_cjk('あ'));
        assert!(!is_cjk('a'));
        assert!(!is_cjk('5'));
    }
}
