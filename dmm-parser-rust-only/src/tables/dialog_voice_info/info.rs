//! IDA-derived parser for `DialogVoiceInfo.pabgb`.
//!
//! Field layout extracted from Hex-Rays decompile of the parse function
//! in the current Win exe (CrimsonDesert.exe). Field NAMES paired with
//! Mac binary __cstring declaration order. Round-trip-validated against
//! the vanilla pabgb dump from the live game install.
//!
//! DO NOT EDIT BY HAND - regenerate via tools/ida_extract.py.


// ─────────────────────────────────────────────────────────────────────────
// CANONICAL FIELD CATALOG — pa::DialogVoiceInfo
// ─────────────────────────────────────────────────────────────────────────
//
// Schema source: NattKh/CrimsonDesertModdingTools `pabgb_complete_schema.json`
// (canonical PA names extracted from Korean error strings in CrimsonDesert.exe).
//
// Total canonical fields:  13
// Decoded by dmm-parser:   13
// Missing in this struct:  0
//
// ✅ = present in this struct (round-trips via shape='v3.1')
// ⏳ = in canonical schema but not yet decoded by dmm-parser
//
// ✅ _footStepGroundSoundOffset (direct_u8, stream=1)
// ✅ _footStepLandSoundOffset (direct_u8, stream=1)
// ✅ _jobInfoList (reader_2B, stream=2)
// ✅ _soundEvent
// ✅ _isBlocked (direct_u8, stream=1)
// ✅ _footStepCrouchSoundEvent
// ✅ _footStepSoundEvent
// ✅ _footStepGroundSoundEvent
// ✅ _footStepLandSoundEvent
// ✅ _footStepCrouchSoundOffset (direct_u8, stream=1)
// ✅ _footStepSoundOffset (direct_u8, stream=1)
// ✅ _stringKey
// ✅ _key (reader_2B, stream=2)

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct DialogVoiceInfo<'a> {
        pub key: u16,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub sound_event: CString<'a>,
        pub foot_step_sound_event: CString<'a>,
        pub foot_step_crouch_sound_event: CString<'a>,
        pub foot_step_land_sound_event: CString<'a>,
        pub foot_step_ground_sound_event: CString<'a>,
        pub foot_step_sound_offset: u8,
        pub foot_step_crouch_sound_offset: u8,
        pub foot_step_land_sound_offset: u8,
        pub foot_step_ground_sound_offset: u8,
        pub gender: u8,
        pub character_age: u8,
        pub unk_106: u8,
        pub job_info_list: CArray<u16>,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"/mnt/c/temp/GIT/CrimsonDesertUpdates/pabgb/2026-5-1/dialogvoiceinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(DialogVoiceInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "dialogvoiceinfo roundtrip bytes mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(DialogVoiceInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            DialogVoiceInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
