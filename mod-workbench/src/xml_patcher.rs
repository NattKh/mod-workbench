//! XML patcher for game config files.
//!
//! Loads an XML file, applies a list of operations, writes the modified
//! result. Operations are simple element-text / attribute / append-child
//! mutations against a slash-separated tag path. Used for the modding flows
//! where game data is XML rather than pabgb (e.g. dye texture palettes,
//! prefab data).
//!
//! Reference behaviour: see
//! `ResearchFolder/Perfect Mod Loader/CdModCreator/XmlPatchApplier.cs` for
//! the much richer XPath-based version. This v1 keeps the path resolver
//! simple — slash-separated tag walking only — so the entire patch lifecycle
//! (load JSON, run, save bytes) works without depending on a full XPath
//! engine. We can grow toward XPath later if real-world patches need it.

use std::io;
use std::path::Path;

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::reader::Reader;
use quick_xml::writer::Writer;
use serde::{Deserialize, Serialize};

/// One patch operation. Matches against elements at a slash-separated tag
/// path (e.g. `"Root/Item/Name"`). The first segment must equal the document
/// root; subsequent segments name nested children to walk into.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op")]
pub enum XmlOp {
    /// Replace the text content of every element matching `path`.
    #[serde(rename = "set_text")]
    SetText { path: String, value: String },

    /// Set an attribute on every element matching `path`. Creates the
    /// attribute when it doesn't already exist.
    #[serde(rename = "set_attr")]
    SetAttr {
        path: String,
        attr: String,
        value: String,
    },

    /// Append a child XML fragment under every element matching `path`.
    /// `fragment` is parsed and reserialized so it must be well-formed XML
    /// (a single root element with optional children).
    #[serde(rename = "append_child")]
    AppendChild { path: String, fragment: String },
}

/// A complete patch: which file to apply against, and the ops to run.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct XmlPatch {
    /// Path relative to the PAZ root — typically
    /// `gamedata/binary__/client/bin/foo.xml` or similar. Stored on the
    /// patch so deploy flows can route to the right file inside the
    /// archive without the user having to remember.
    pub target: String,
    /// Free-form patch description for the UI. Optional and not used by
    /// `apply_patch`.
    #[serde(default)]
    pub description: String,
    /// Operations applied in order. Later ops see the document mutated by
    /// earlier ones — useful when you want to set multiple attributes on
    /// the same node.
    pub ops: Vec<XmlOp>,
}

impl XmlPatch {
    /// Construct a patch with a target path and an empty op list.
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            description: String::new(),
            ops: Vec::new(),
        }
    }
}

/// Apply a patch to the given XML bytes. Returns the rewritten document.
///
/// Errors include malformed input XML, an op pointing at a path that
/// doesn't resolve (which we surface with `InvalidInput` so callers can
/// distinguish from a real parser failure), and malformed `append_child`
/// fragments.
pub fn apply_patch(xml_bytes: &[u8], patch: &XmlPatch) -> io::Result<Vec<u8>> {
    // Parse the input into our intermediate tree representation. Working
    // off a tree (instead of streaming events twice per op) keeps the v1
    // implementation simple and lets us mutate by path naturally.
    let mut tree = parse_to_tree(xml_bytes)?;

    for (i, op) in patch.ops.iter().enumerate() {
        apply_op(&mut tree, op).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("op[{}] ({}): {}", i, op_kind(op), e),
            )
        })?;
    }

    serialize_tree(&tree)
}

/// Deserialize an [`XmlPatch`] from a JSON file on disk.
pub fn load_patch(path: &Path) -> io::Result<XmlPatch> {
    let data = std::fs::read(path)?;
    serde_json::from_slice::<XmlPatch>(&data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("patch json: {}", e)))
}

/// Serialize a patch to JSON on disk (pretty-printed for human review).
pub fn save_patch(patch: &XmlPatch, path: &Path) -> io::Result<()> {
    let data = serde_json::to_vec_pretty(patch).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("patch json: {}", e))
    })?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, data)
}

// ---------------------------------------------------------------------------
// Tree representation + walkers
//
// Public so the XML tree editor (src/ui/xml_panel.rs) can mutate the document
// directly. Pre-editor, this was internal scaffolding for `apply_patch`; the
// patch path still uses the same types.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlNode {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            attrs: Vec::new(),
            text: String::new(),
            children: Vec::new(),
        }
    }

    /// Walk a slash-separated path from this node. Returns the first match
    /// found by depth-first walk. Used by the tree editor to focus the
    /// node selected from the breadcrumb path.
    pub fn find_by_path<'a>(&'a self, segments: &[&str]) -> Option<&'a XmlNode> {
        if segments.is_empty() {
            return Some(self);
        }
        for child in &self.children {
            if child.name == segments[0] {
                if let Some(hit) = child.find_by_path(&segments[1..]) {
                    return Some(hit);
                }
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
pub struct XmlTree {
    /// Optional XML declaration (e.g. `<?xml version="1.0" ?>`) preserved
    /// so a roundtrip doesn't strip it. Stored as raw bytes minus the
    /// `<?` `?>` framing.
    pub declaration: Option<Vec<u8>>,
    pub root: XmlNode,
    /// Set when [`parse_to_tree`] wrapped a multi-root game XML in a
    /// sentinel `<__cdmm_root__>` element so the parser had a single
    /// document root. Re-serialisation strips the wrapper. Mirrors
    /// `XmlPatchApplier.NormaliseGameXml` from CdModCreator.
    pub sentinel_wrapped: bool,
}

/// Parse XML bytes into the editor's tree representation. Handles two
/// game-XML quirks before quick-xml gets involved:
///
/// 1. `</>` shorthand — a non-standard closing tag that means "close the
///    innermost open element". We rewrite it to `</TagName>` based on the
///    open-tag stack so quick-xml can parse the result.
/// 2. Multiple root elements — wrap the whole document in
///    `<__cdmm_root__>...</__cdmm_root__>` so quick-xml sees a single root.
///    [`serialize_tree`] removes the wrapper on the way back out.
///
/// Reference behaviour ported from CdModCreator's `NormaliseGameXml` /
/// `HasMultipleRoots`.
pub fn parse_to_tree(xml_bytes: &[u8]) -> io::Result<XmlTree> {
    let raw = std::str::from_utf8(xml_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("xml utf8: {}", e)))?;
    let normalised = resolve_short_close_tags(raw);
    let (final_text, wrapped) = wrap_multi_root(&normalised);
    let mut tree = parse_to_tree_inner(final_text.as_bytes())?;
    tree.sentinel_wrapped = wrapped;
    Ok(tree)
}

fn parse_to_tree_inner(xml_bytes: &[u8]) -> io::Result<XmlTree> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(false);

    let mut declaration: Option<Vec<u8>> = None;
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root: Option<XmlNode> = None;

    loop {
        match reader.read_event() {
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("xml parse: {}", e),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(Event::Decl(d)) => {
                // BytesDecl derefs to &[u8] (the inner BytesStart payload).
                // Copy the raw declaration content so we can re-emit it on
                // serialize without depending on the lifetime of `reader`.
                let bytes: &[u8] = &d;
                declaration = Some(bytes.to_vec());
            }
            Ok(Event::Start(start)) => {
                let mut node = node_from_start(&start)?;
                node.children.clear();
                stack.push(node);
            }
            Ok(Event::Empty(start)) => {
                let node = node_from_start(&start)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.is_none() {
                    root = Some(node);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "xml parse: multiple root elements not supported",
                    ));
                }
            }
            Ok(Event::End(_)) => {
                let Some(top) = stack.pop() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "xml parse: unmatched closing tag",
                    ));
                };
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(top);
                } else if root.is_none() {
                    root = Some(top);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "xml parse: multiple root elements not supported",
                    ));
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(top) = stack.last_mut() {
                    let txt = t.unescape().map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("xml text unescape: {}", e),
                        )
                    })?;
                    top.text.push_str(txt.as_ref());
                }
            }
            Ok(Event::CData(c)) => {
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&String::from_utf8_lossy(c.as_ref()));
                }
            }
            Ok(Event::Comment(_)) | Ok(Event::PI(_)) | Ok(Event::DocType(_)) => {
                // Best-effort: drop comments / DOCTYPE / processing
                // instructions during the v1 round-trip. The patcher's
                // remit is structural edits; preserving these is a
                // separate effort.
            }
        }
    }

    let root = root.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "xml parse: no root element found",
        )
    })?;

    Ok(XmlTree {
        declaration,
        root,
        sentinel_wrapped: false,
    })
}

/// Sentinel root tag the multi-root wrapper uses. Mirrors CdModCreator.
const SENTINEL_ROOT: &str = "__cdmm_root__";

/// Replace every `</>` (the non-standard "close innermost" shorthand) with
/// the proper closing tag based on the current open-tag stack. No-op when
/// the input doesn't contain `</>`.
fn resolve_short_close_tags(xml: &str) -> String {
    if !xml.contains("</>") {
        return xml.to_string();
    }
    let bytes = xml.as_bytes();
    let mut out = String::with_capacity(xml.len() + 64);
    let mut stack: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'<' {
            let Some(end_rel) = xml[i..].find('>') else {
                out.push_str(&xml[i..]);
                break;
            };
            let end = i + end_rel;
            let tag = &xml[i..=end];
            if tag == "</>" {
                if let Some(name) = stack.pop() {
                    out.push_str("</");
                    out.push_str(&name);
                    out.push('>');
                } else {
                    out.push_str(tag); // pathological — leave as-is
                }
            } else if tag.starts_with("</") {
                stack.pop();
                out.push_str(tag);
            } else if tag.starts_with("<?") || tag.starts_with("<!") {
                out.push_str(tag);
            } else if tag.ends_with("/>") {
                out.push_str(tag);
            } else {
                let inner = &tag[1..tag.len() - 1];
                let name_end = inner
                    .find(|c: char| c.is_whitespace() || c == '/')
                    .unwrap_or(inner.len());
                stack.push(inner[..name_end].to_string());
                out.push_str(tag);
            }
            i = end + 1;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

/// Wrap multi-root XML (multiple top-level elements after the optional
/// `<?xml?>` declaration) in a sentinel root element so quick-xml can
/// parse it. Returns `(possibly-wrapped, was_wrapped)`.
fn wrap_multi_root(xml: &str) -> (String, bool) {
    if !has_multiple_roots(xml) {
        return (xml.to_string(), false);
    }
    // Keep the declaration outside the sentinel wrapper if present.
    let trimmed = xml.trim_start();
    if let Some(decl_end) = trimmed.find("?>") {
        let decl_end_abs = (xml.len() - trimmed.len()) + decl_end + 2;
        let decl_part = &xml[..decl_end_abs];
        let body = &xml[decl_end_abs..];
        return (
            format!("{}<{}>{}</{}>", decl_part, SENTINEL_ROOT, body, SENTINEL_ROOT),
            true,
        );
    }
    (
        format!("<{}>{}</{}>", SENTINEL_ROOT, xml, SENTINEL_ROOT),
        true,
    )
}

/// Quick check for two consecutive non-comment, non-PI top-level open tags.
fn has_multiple_roots(xml: &str) -> bool {
    let bytes = xml.as_bytes();
    let mut depth: i32 = 0;
    let mut roots = 0;
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        let Some(end_rel) = xml[i..].find('>') else {
            break;
        };
        let end = i + end_rel;
        let tag = &xml[i..=end];
        if tag.starts_with("<?") || tag.starts_with("<!--") || tag.starts_with("<!") {
            i = end + 1;
            continue;
        }
        if tag.starts_with("</") {
            depth -= 1;
            i = end + 1;
            continue;
        }
        let self_close = tag.ends_with("/>");
        if depth == 0 {
            roots += 1;
            if roots > 1 {
                return true;
            }
        }
        if !self_close {
            depth += 1;
        }
        i = end + 1;
    }
    false
}

fn node_from_start(start: &BytesStart) -> io::Result<XmlNode> {
    let name = std::str::from_utf8(start.name().as_ref())
        .map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("xml: non-utf8 element name: {}", e),
            )
        })?
        .to_string();
    let mut node = XmlNode::new(name);
    for attr in start.attributes() {
        let attr = attr.map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("xml: bad attribute: {}", e),
            )
        })?;
        let key = std::str::from_utf8(attr.key.as_ref())
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("xml: non-utf8 attr name: {}", e),
                )
            })?
            .to_string();
        let value = attr
            .unescape_value()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("xml: bad attr value: {}", e),
                )
            })?
            .to_string();
        node.attrs.push((key, value));
    }
    Ok(node)
}

fn apply_op(tree: &mut XmlTree, op: &XmlOp) -> io::Result<()> {
    let path_str = match op {
        XmlOp::SetText { path, .. }
        | XmlOp::SetAttr { path, .. }
        | XmlOp::AppendChild { path, .. } => path,
    };
    let segments = split_path(path_str)?;
    if segments.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty path",
        ));
    }
    let (root_name, rest) = segments.split_first().expect("non-empty");
    if &tree.root.name != root_name {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "first path segment '{}' does not match document root '{}'",
                root_name, tree.root.name
            ),
        ));
    }

    let mut targets: Vec<&mut XmlNode> = vec![&mut tree.root];
    for seg in rest {
        let mut next: Vec<&mut XmlNode> = Vec::new();
        for node in targets.drain(..) {
            for child in node.children.iter_mut() {
                if &child.name == seg {
                    next.push(child);
                }
            }
        }
        targets = next;
        if targets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("path '{}' did not match any element", path_str),
            ));
        }
    }

    match op {
        XmlOp::SetText { value, .. } => {
            for n in targets {
                n.text = value.clone();
            }
        }
        XmlOp::SetAttr { attr, value, .. } => {
            for n in targets {
                if let Some(slot) = n.attrs.iter_mut().find(|(k, _)| k == attr) {
                    slot.1 = value.clone();
                } else {
                    n.attrs.push((attr.clone(), value.clone()));
                }
            }
        }
        XmlOp::AppendChild { fragment, .. } => {
            let child = parse_fragment(fragment)?;
            for n in targets {
                n.children.push(child.clone());
            }
        }
    }

    Ok(())
}

fn parse_fragment(fragment: &str) -> io::Result<XmlNode> {
    let tree = parse_to_tree(fragment.as_bytes())?;
    Ok(tree.root)
}

fn op_kind(op: &XmlOp) -> &'static str {
    match op {
        XmlOp::SetText { .. } => "set_text",
        XmlOp::SetAttr { .. } => "set_attr",
        XmlOp::AppendChild { .. } => "append_child",
    }
}

fn split_path(path: &str) -> io::Result<Vec<String>> {
    let trimmed = path.trim().trim_start_matches('/').trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must contain at least the root element name",
        ));
    }
    Ok(trimmed.split('/').map(|s| s.to_string()).collect())
}

/// Serialise the tree back to XML bytes. If the tree was wrapped in a
/// sentinel root during parsing (multi-root original), the wrapper is
/// stripped here so the output is byte-compatible with the source.
pub fn serialize_tree(tree: &XmlTree) -> io::Result<Vec<u8>> {
    let raw = serialize_tree_raw(tree)?;
    if !tree.sentinel_wrapped {
        return Ok(raw);
    }
    let text = std::str::from_utf8(&raw).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("xml utf8: {}", e))
    })?;
    let open = format!("<{}>", SENTINEL_ROOT);
    let close = format!("</{}>", SENTINEL_ROOT);
    let Some(open_at) = text.find(&open) else {
        return Ok(raw);
    };
    let Some(close_at) = text.rfind(&close) else {
        return Ok(raw);
    };
    let before = &text[..open_at];
    let inner = &text[open_at + open.len()..close_at];
    let after = &text[close_at + close.len()..];
    Ok(format!("{}{}{}", before, inner, after).into_bytes())
}

fn serialize_tree_raw(tree: &XmlTree) -> io::Result<Vec<u8>> {
    let mut writer = Writer::new(Vec::new());

    if let Some(decl) = &tree.declaration {
        let decl_event = quick_xml::events::BytesDecl::from_start(BytesStart::from_content(
            std::str::from_utf8(decl).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("xml decl utf8: {}", e),
                )
            })?,
            0,
        ));
        writer
            .write_event(Event::Decl(decl_event))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("xml write decl: {}", e)))?;
    }

    write_node(&tree.root, &mut writer)?;

    Ok(writer.into_inner())
}

fn write_node(node: &XmlNode, writer: &mut Writer<Vec<u8>>) -> io::Result<()> {
    let has_children = !node.children.is_empty();
    let has_text = !node.text.is_empty();

    if !has_children && !has_text {
        let mut start = BytesStart::new(node.name.as_str());
        for (k, v) in &node.attrs {
            start.push_attribute((k.as_str(), v.as_str()));
        }
        writer
            .write_event(Event::Empty(start))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("xml write empty: {}", e)))?;
        return Ok(());
    }

    let mut start = BytesStart::new(node.name.as_str());
    for (k, v) in &node.attrs {
        start.push_attribute((k.as_str(), v.as_str()));
    }
    writer
        .write_event(Event::Start(start))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("xml write start: {}", e)))?;

    if has_text {
        writer
            .write_event(Event::Text(BytesText::new(node.text.as_str())))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("xml write text: {}", e)))?;
    }

    for child in &node.children {
        write_node(child, writer)?;
    }

    writer
        .write_event(Event::End(BytesEnd::new(node.name.as_str())))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("xml write end: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(input: &[u8]) -> String {
        String::from_utf8(input.to_vec()).unwrap()
    }

    #[test]
    fn set_text_replaces_element_content() {
        let xml = br#"<Root><Item><Name>Old</Name></Item></Root>"#;
        let patch = XmlPatch {
            target: "foo.xml".into(),
            description: String::new(),
            ops: vec![XmlOp::SetText {
                path: "Root/Item/Name".into(),
                value: "New".into(),
            }],
        };
        let out = apply_patch(xml, &patch).unwrap();
        let out_str = s(&out);
        assert!(out_str.contains("<Name>New</Name>"), "got: {}", out_str);
    }

    #[test]
    fn set_attr_creates_when_missing() {
        let xml = br#"<Root><Item id="42"/></Root>"#;
        let patch = XmlPatch {
            target: "foo.xml".into(),
            description: String::new(),
            ops: vec![XmlOp::SetAttr {
                path: "Root/Item".into(),
                attr: "name".into(),
                value: "hello".into(),
            }],
        };
        let out = apply_patch(xml, &patch).unwrap();
        let out_str = s(&out);
        assert!(out_str.contains("name=\"hello\""), "got: {}", out_str);
        assert!(out_str.contains("id=\"42\""), "got: {}", out_str);
    }

    #[test]
    fn set_attr_overwrites_when_present() {
        let xml = br#"<Root><Item name="old"/></Root>"#;
        let patch = XmlPatch {
            target: "foo.xml".into(),
            description: String::new(),
            ops: vec![XmlOp::SetAttr {
                path: "Root/Item".into(),
                attr: "name".into(),
                value: "new".into(),
            }],
        };
        let out = apply_patch(xml, &patch).unwrap();
        let out_str = s(&out);
        assert!(out_str.contains("name=\"new\""), "got: {}", out_str);
        assert!(!out_str.contains("name=\"old\""), "got: {}", out_str);
    }

    #[test]
    fn append_child_adds_under_target() {
        let xml = br#"<Root><Items/></Root>"#;
        let patch = XmlPatch {
            target: "foo.xml".into(),
            description: String::new(),
            ops: vec![XmlOp::AppendChild {
                path: "Root/Items".into(),
                fragment: r#"<Item id="1"/>"#.into(),
            }],
        };
        let out = apply_patch(xml, &patch).unwrap();
        let out_str = s(&out);
        assert!(out_str.contains("<Item id=\"1\""), "got: {}", out_str);
    }

    #[test]
    fn missing_path_is_an_error() {
        let xml = br#"<Root><Item/></Root>"#;
        let patch = XmlPatch {
            target: "foo.xml".into(),
            description: String::new(),
            ops: vec![XmlOp::SetText {
                path: "Root/DoesNotExist".into(),
                value: "x".into(),
            }],
        };
        let err = apply_patch(xml, &patch).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn root_mismatch_is_an_error() {
        let xml = br#"<Foo/>"#;
        let patch = XmlPatch {
            target: "foo.xml".into(),
            description: String::new(),
            ops: vec![XmlOp::SetText {
                path: "Bar".into(),
                value: "x".into(),
            }],
        };
        let err = apply_patch(xml, &patch).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn patch_roundtrips_through_json() {
        let p = XmlPatch {
            target: "gamedata/test.xml".into(),
            description: "demo".into(),
            ops: vec![
                XmlOp::SetText {
                    path: "Root/A".into(),
                    value: "hi".into(),
                },
                XmlOp::SetAttr {
                    path: "Root/B".into(),
                    attr: "k".into(),
                    value: "v".into(),
                },
            ],
        };
        let j = serde_json::to_string(&p).unwrap();
        let back: XmlPatch = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }
}
