"""Insert a json_roundtrip test into each table's info.rs.

Heuristic-based: parses each file to find
  - the outer Info struct name (used in `XInfo::read_from`)
  - the pabgb-path constant name (e.g. PABGB / PABGB_PATH)
  - whether the table parses sequentially (`read_from`) or per-entry
    via `read_with_size` (skipped for now — different test pattern).
Skips tables already containing `fn json_roundtrip`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ROOT / "scripts" / "json_targets.txt"


def emit_test_pabgh(struct: str, pabgb_const: str, pabgh_const: str, key_is_int: bool) -> str:
    if key_is_int:
        panic_fmt = '"entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e'
        diverge_fmt = '"entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key'
    else:
        panic_fmt = '"entry {}: write_from_json_dict: {}", i, e'
        diverge_fmt = '"entry {}: JSON round-trip diverges from typed write", i'
    return f"""
    #[test]
    fn json_roundtrip() {{
        use crate::binary::variant::{{entry_ranges, load_pabgh_offsets}};
        let Ok(data) = std::fs::read({pabgb_const}) else {{
            eprintln!("SKIP: missing fixture {{}}", {pabgb_const});
            return;
        }};
        let Some(entries) = load_pabgh_offsets({pabgh_const}) else {{
            eprintln!("SKIP: missing pabgh fixture {{}}", {pabgh_const});
            return;
        }};
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {{
            let mut c = *start;
            let item = {struct}::read_from(&data, &mut c).unwrap();
            assert_eq!(c, *end, "entry {{}} key=0x{{:x}}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            {struct}::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!({panic_fmt}));
            assert_eq!(
                from_json, from_typed,
                {diverge_fmt}
            );
        }}
    }}
"""


def emit_test(struct: str, pabgb_const: str, key_is_int: bool) -> str:
    if key_is_int:
        key_fmt = '"entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e'
        diverge_fmt = '"entry {} key=0x{:x}: JSON round-trip diverges from typed write",\n                i, item.key'
    else:
        key_fmt = '"entry {}: write_from_json_dict: {}", i, e'
        diverge_fmt = '"entry {}: JSON round-trip diverges from typed write", i'
    return f"""
    #[test]
    fn json_roundtrip() {{
        let Ok(data) = std::fs::read({pabgb_const}) else {{
            eprintln!("SKIP: missing fixture {{}}", {pabgb_const});
            return;
        }};
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {{
            items.push({struct}::read_from(&data, &mut offset).unwrap());
        }}
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {{
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            {struct}::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!({key_fmt}));
            assert_eq!(
                from_json, from_typed,
                {diverge_fmt}
            );
        }}
    }}
"""


INT_KEY_TYPES = {"u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64"}


def parse_table(path: Path):
    """Return (kind, struct, pabgb_const, [pabgh_const], key_is_int) or None.

    kind is 'sequential' (read_from in a `while offset < data.len()` loop),
    'pabgh' (read_from per entry start using load_pabgh_offsets), or
    'pabgh_sized' (read_with_size + load_pabgh_offsets, used for hand-
    written outer structs that consume their pabgh entry size).
    """
    text = path.read_text(encoding="utf-8")
    if "fn json_roundtrip" in text or "fn roundtrip_json" in text:
        return None  # already done (either naming convention counts)
    # Find the outer struct via any reader invocation.
    m_read = re.search(
        r"([A-Z][A-Za-z0-9]*Info)::(read_from|read_with_size)\(&data,\s*&mut\s+[a-z_][A-Za-z0-9_]*",
        text,
    )
    if not m_read:
        return None
    struct = m_read.group(1)
    reader = m_read.group(2)
    # Either the outer struct is in a py_binary_struct! macro (auto-gen
    # JSON methods) or it has a hand-written `to_json_dict` impl. Both
    # are valid; if neither holds, skip.
    in_macro = re.search(
        r"(?:py_binary_struct|pabgh_typed_blob_table)!\s*\{\s*\n\s*pub struct " + re.escape(struct) + r"\b",
        text,
    )
    # Hand-written JSON impl: just check that `fn to_json_dict` appears
    # after the struct's `impl` block opens. Brace-balanced regex is
    # finicky and we're not parsing Rust.
    has_hand_json = False
    m_impl = re.search(
        r"impl(?:<[^>]*>)?\s+" + re.escape(struct) + r"(?:<[^>]*>)?\s*\{",
        text,
    )
    if m_impl and "fn to_json_dict" in text[m_impl.end():]:
        has_hand_json = True
    if not in_macro and not has_hand_json:
        return None
    # Find pabgb const inside the test mod.
    m_pabgb = re.search(
        r"const\s+(PABGB(?:_PATH)?)\s*:\s*&str\s*=\s*r?\"[^\"]*\.pabgb\";",
        text,
    )
    if not m_pabgb:
        return None
    pabgb = m_pabgb.group(1)
    # Determine key type by inspecting the outer struct body. For macro
    # tables we already pinpointed the body via in_macro; for hand-written
    # ones, search globally for `pub key: ...` after `pub struct {NAME}`.
    if in_macro:
        body_start = in_macro.end()
    else:
        m_struct_def = re.search(r"pub struct " + re.escape(struct) + r"\b", text)
        body_start = m_struct_def.end() if m_struct_def else 0
    body_end = text.find("}", body_start)
    body = text[body_start:body_end]
    m_key = re.search(r"pub key:\s*([^,]+?)\s*,", body)
    key_is_int = bool(m_key and m_key.group(1).strip() in INT_KEY_TYPES)
    # Decide test kind from reader type + offsets vs sequential walk.
    has_pabgh = "load_pabgh_offsets" in text
    if reader == "read_with_size":
        if not has_pabgh:
            return None
        m_pabgh = re.search(
            r"const\s+(PABGH(?:_PATH)?)\s*:\s*&str\s*=\s*r?\"[^\"]*\.pabgh\";",
            text,
        )
        if not m_pabgh:
            return None
        return ("pabgh_sized", struct, pabgb, m_pabgh.group(1), key_is_int)
    if has_pabgh:
        m_pabgh = re.search(
            r"const\s+(PABGH(?:_PATH)?)\s*:\s*&str\s*=\s*r?\"[^\"]*\.pabgh\";",
            text,
        )
        if not m_pabgh:
            return None
        return ("pabgh", struct, pabgb, m_pabgh.group(1), key_is_int)
    if "while offset < data.len()" in text:
        return ("sequential", struct, pabgb, None, key_is_int)
    return None


def emit_test_pabgh_sized(struct: str, pabgb: str, pabgh: str, key_is_int: bool) -> str:
    if key_is_int:
        panic_fmt = '"entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e'
        diverge_fmt = '"entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key'
    else:
        panic_fmt = '"entry {}: write_from_json_dict: {}", i, e'
        diverge_fmt = '"entry {}: JSON round-trip diverges from typed write", i'
    return f"""
    #[test]
    fn json_roundtrip() {{
        use crate::binary::variant::{{entry_ranges, load_pabgh_offsets}};
        let Ok(data) = std::fs::read({pabgb}) else {{
            eprintln!("SKIP: missing fixture {{}}", {pabgb});
            return;
        }};
        let Some(entries) = load_pabgh_offsets({pabgh}) else {{
            eprintln!("SKIP: missing pabgh fixture {{}}", {pabgh});
            return;
        }};
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {{
            let mut cursor = *start;
            let item = {struct}::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {{}} key=0x{{:x}}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            {struct}::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!({panic_fmt}));
            assert_eq!(
                from_json, from_typed,
                {diverge_fmt}
            );
        }}
    }}
"""


def insert_test(path: Path, parsed) -> None:
    kind, struct, pabgb, pabgh, key_is_int = parsed
    if kind == "pabgh":
        test = emit_test_pabgh(struct, pabgb, pabgh, key_is_int)
    elif kind == "pabgh_sized":
        test = emit_test_pabgh_sized(struct, pabgb, pabgh, key_is_int)
    else:
        test = emit_test(struct, pabgb, key_is_int)
    text = path.read_text(encoding="utf-8")
    stripped = text.rstrip()
    assert stripped.endswith("}"), path
    body = stripped[:-1].rstrip()  # drop the final `}` (mod-tests close)
    path.write_text(body + "\n" + test + "}\n", encoding="utf-8")


def main():
    targets = [
        line.strip().split("|", 1)
        for line in TARGETS.read_text().splitlines()
        if line.strip()
    ]
    written = 0
    skipped = []
    for dirname, _ in targets:
        info = ROOT / "src" / "tables" / dirname / "info.rs"
        if not info.exists():
            skipped.append((dirname, "missing"))
            continue
        parsed = parse_table(info)
        if parsed is None:
            skipped.append((dirname, "skip-by-shape"))
            continue
        kind, struct, pabgb, pabgh, key_is_int = parsed
        insert_test(info, parsed)
        written += 1
        keytag = "int" if key_is_int else "non-int"
        extra = f"+{pabgh}" if pabgh else ""
        print(f"+ [{kind:10}] {dirname:45} {struct} ({pabgb}{extra}, {keytag} key)")
    print(f"\ninserted {written}, skipped {len(skipped)}")
    for d, why in skipped:
        print(f"  - {d}: {why}")


if __name__ == "__main__":
    main()
