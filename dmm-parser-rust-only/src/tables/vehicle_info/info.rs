// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Hand-corrected: IDA-derived parser for `VehicleInfo.pabgb`.
//!
//! Per IDA sub_1410FE440: 22 fields matching mac binary __cstring order.
//! Two fixed-loop "list" fields (vehicle_seat_data_list × 16, parent_link × 2)
//! and one CArray<u8> (cargo_seat_index_list).
//!
//! All "_*Action" / "_*Hash" / "_*VoxelType" reads are 4-byte u32s on disk
//! (some flow through u16 dictionary lookups in memory). For round-trip
//! preservation we keep the u32 file representation everywhere.

use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct VehicleInfo<'a> {
        pub key: u16,
        pub string_key: CString<'a>,
        pub is_blocked: u8,
        pub vehicle_type_name_hash: u32,
        pub icon_path: u32,
        pub max_vehicle_seat: u8,
        // 16 × u64 fixed-loop slots per docstring's "× 16" annotation.
        // Split into individual named fields for JSON-addressable access.
        pub vehicle_seat_data_00: u64,
        pub vehicle_seat_data_01: u64,
        pub vehicle_seat_data_02: u64,
        pub vehicle_seat_data_03: u64,
        pub vehicle_seat_data_04: u64,
        pub vehicle_seat_data_05: u64,
        pub vehicle_seat_data_06: u64,
        pub vehicle_seat_data_07: u64,
        pub vehicle_seat_data_08: u64,
        pub vehicle_seat_data_09: u64,
        pub vehicle_seat_data_10: u64,
        pub vehicle_seat_data_11: u64,
        pub vehicle_seat_data_12: u64,
        pub vehicle_seat_data_13: u64,
        pub vehicle_seat_data_14: u64,
        pub vehicle_seat_data_15: u64,
        pub max_parent_link_attach_count: u8,
        // Split 2 × 8-byte fixed-loop slots (per docstring "× 2") into u64 pair.
        pub parent_link_attach_data_a: u64,
        pub parent_link_attach_data_b: u64,
        pub rider_spawn_upper_action: u32,
        pub rider_spawn_lower_action: u32,
        pub vehicle_spawn_upper_action: u32,
        pub escape_road_group_type: u8,
        pub cargo_seat_index_list: CArray<u8>,
        pub call_vehicle_voxel_type: u32,
        pub is_main_dischargeable: u8,
        pub show_count_on_ui: u8,
        pub ui_map_texture_info: u32,
        pub rider_detect_info: u16,
        pub send_damage_to: u8,
        pub character_switchable: u8,
        pub max_allowable_height: u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PABGB_PATH: &str = r"C:\\Users\\corin\\Desktop\\CD DUMPING TOOLS\\dmm-pabgb-aio\\vanilla_dumps\\vehicleinfo.pabgb";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB_PATH) else {
            eprintln!("SKIP: missing fixture {}", PABGB_PATH);
            return;
        };
        let mut offset = 0;
        let mut items = Vec::new();
        while offset < data.len() {
            items.push(VehicleInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");
        let mut out = Vec::with_capacity(data.len());
        for item in &items {
            item.write_to(&mut out).unwrap();
        }
        assert_eq!(out, data, "vehicleinfo roundtrip bytes mismatch");
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
            items.push(VehicleInfo::read_from(&data, &mut offset).unwrap());
        }
        assert_eq!(offset, data.len(), "did not consume all bytes");

        for (i, item) in items.iter().enumerate() {
            let _ = &item;
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            VehicleInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, item.key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write",
                i, item.key
            );
        }
    }
}
