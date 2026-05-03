// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Tier 1 — fully typed (no _tail_b64).
//!
//! Reader: `sub_1410FCD20` in CrimsonDesert.exe (Win build).
//!
//! Wire reads, in order (canonical names from Mac Korean error strings):
//!   1. u16 key                                  (_key, pabgh format 2)
//!   2. CString string_key                       (_stringKey)
//!   3. u8 is_blocked                            (_isBlocked)
//!   4. u32 exchange_item_info_for_buy           (_exchangeItemInfoForBuy,
//!      sub_1410FF5C0 wire u32)
//!   5. CArray<u32> exchange_item_info_list_for_sell
//!      (_exchangeItemInfoListForSell, sub_1410FFF10 wire u32)
//!   6. u64 sell_percents                        (_sellPercents)
//!   7. u8 store_type                            (_storeType)
//!   8. CArray<u64> price_increase_percent_list  (_priceIncreasePercentList,
//!      inline u32 count + N×u64)
//!   9. u32 sellable_character_condition_logic   (_sellableCharacterConditionLogic,
//!      sub_1410FF430 wire u32)
//!  10. u32 reset_hour                           (_resetHour)
//!  11. u32 reset_day                            (_resetDay)
//!  12. u32 buyable_stock_count                  (_buyableStockCount)
//!  13. u32 sellable_stock_count                 (_sellableStockCount)
//!  14. u8 sellable_type                         (_sellableType)
//!  15. CArray<StoreStockData> stock_data_list   (_stockDataList,
//!      sub_1410FC8F0; per element 88 mem bytes / variable wire incl.
//!      Optional<StoreStockDataValue> 14-arm polymorphic)
//!  16. CArray<u8> raw_list_a                    (sub_1411002A0)
//!  17. CArray<u8> raw_list_b                    (sub_1411002A0)
//!  18. u32 raw_a                                (mem a2+144)
//!  19. u8 flag_a                                (mem a2+148)
//!  20. u8 flag_b                                (mem a2+149)
//!  21. u8 flag_c                                (mem a2+150)
//!
//! All 21 wire fields typed.

use crate::binary::*;
use crate::json_traits::{ToJsonValue, WriteJsonValue, get_field as json_get_field};
use crate::py_binary_struct;
use serde_json::{Map, Value};
use std::io::{self, Write};

// ── StoreStockDataValue 14-arm polymorphic ─────────────────────────────────
//
// Per `sub_141600210` dispatcher. Common header (63 wire bytes) + per-disc
// payload (0-42 wire bytes). Disc 11 (0xB) is the empty variant.

py_binary_struct! {
    pub struct StoreStockDataValueDisc7 {
        pub flag_a: u8,
        pub raw_a: u64,
        pub lookup_a: u32,    // sub_141100860 wire u32
        pub lookup_b: u32,    // sub_1410FF340 wire u32
        pub flag_b: u8,
        pub lookup_c: u32,    // sub_1411026F0 wire u32
        pub raw_b: u64,
        pub flag_c: u8,
        pub flag_d: u8,
    }
}

#[derive(Debug)]
pub enum StoreStockDataValuePayload {
    Disc0(u32),                          // sub_1410FF5C0
    Disc1(u32),                          // sub_1410FF340
    Disc2(u32),
    Disc3(u32),
    Disc4(u32),                          // sub_1411006D0
    Disc5(u32),                          // sub_1411060F0
    Disc6(u32),                          // sub_141103770
    Disc7(StoreStockDataValueDisc7),
    Disc8(StoreStockDataValueDisc7),
    Disc9(u32),                          // sub_141100740
    DiscA { lookup_a: u32, lookup_b: u32 },
    DiscB,
    DiscC(u32),                          // sub_1410FEBE0
    DiscD { lookup: u32, flag: u8 },     // sub_141102E00 + u8
}

impl StoreStockDataValuePayload {
    pub fn read_from(disc: u8, data: &[u8], offset: &mut usize) -> io::Result<Self> {
        Ok(match disc {
            0 => Self::Disc0(u32::read_from(data, offset)?),
            1 => Self::Disc1(u32::read_from(data, offset)?),
            2 => Self::Disc2(u32::read_from(data, offset)?),
            3 => Self::Disc3(u32::read_from(data, offset)?),
            4 => Self::Disc4(u32::read_from(data, offset)?),
            5 => Self::Disc5(u32::read_from(data, offset)?),
            6 => Self::Disc6(u32::read_from(data, offset)?),
            7 => Self::Disc7(StoreStockDataValueDisc7::read_from(data, offset)?),
            8 => Self::Disc8(StoreStockDataValueDisc7::read_from(data, offset)?),
            9 => Self::Disc9(u32::read_from(data, offset)?),
            10 => {
                let lookup_a = u32::read_from(data, offset)?;
                let lookup_b = u32::read_from(data, offset)?;
                Self::DiscA { lookup_a, lookup_b }
            }
            11 => Self::DiscB,
            12 => Self::DiscC(u32::read_from(data, offset)?),
            13 => {
                let lookup = u32::read_from(data, offset)?;
                let flag = u8::read_from(data, offset)?;
                Self::DiscD { lookup, flag }
            }
            other => return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("StoreStockDataValuePayload: unknown disc {}", other),
            )),
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match self {
            Self::Disc0(v) | Self::Disc1(v) | Self::Disc2(v) | Self::Disc3(v)
            | Self::Disc4(v) | Self::Disc5(v) | Self::Disc6(v) | Self::Disc9(v)
            | Self::DiscC(v) => v.write_to(w),
            Self::Disc7(p) | Self::Disc8(p) => p.write_to(w),
            Self::DiscA { lookup_a, lookup_b } => {
                lookup_a.write_to(w)?;
                lookup_b.write_to(w)
            }
            Self::DiscB => Ok(()),
            Self::DiscD { lookup, flag } => {
                lookup.write_to(w)?;
                flag.write_to(w)
            }
        }
    }

    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::Disc0(_) => "Disc0",
            Self::Disc1(_) => "Disc1",
            Self::Disc2(_) => "Disc2",
            Self::Disc3(_) => "Disc3",
            Self::Disc4(_) => "Disc4",
            Self::Disc5(_) => "Disc5",
            Self::Disc6(_) => "Disc6",
            Self::Disc7(_) => "Disc7",
            Self::Disc8(_) => "Disc8",
            Self::Disc9(_) => "Disc9",
            Self::DiscA { .. } => "DiscA",
            Self::DiscB => "DiscB",
            Self::DiscC(_) => "DiscC",
            Self::DiscD { .. } => "DiscD",
        }
    }

    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("type".to_string(), Value::String(self.variant_name().to_string()));
        match self {
            Self::Disc0(v) | Self::Disc1(v) | Self::Disc2(v) | Self::Disc3(v)
            | Self::Disc4(v) | Self::Disc5(v) | Self::Disc6(v) | Self::Disc9(v)
            | Self::DiscC(v) => { m.insert("body".to_string(), v.to_json_value()); }
            Self::Disc7(p) | Self::Disc8(p) => { m.insert("body".to_string(), Value::Object(p.to_json_dict())); }
            Self::DiscA { lookup_a, lookup_b } => {
                let mut body = Map::new();
                body.insert("lookup_a".to_string(), lookup_a.to_json_value());
                body.insert("lookup_b".to_string(), lookup_b.to_json_value());
                m.insert("body".to_string(), Value::Object(body));
            }
            Self::DiscB => { m.insert("body".to_string(), Value::Null); }
            Self::DiscD { lookup, flag } => {
                let mut body = Map::new();
                body.insert("lookup".to_string(), lookup.to_json_value());
                body.insert("flag".to_string(), flag.to_json_value());
                m.insert("body".to_string(), Value::Object(body));
            }
        }
        Value::Object(m)
    }

    pub fn write_from_json(disc: u8, w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "StoreStockDataValuePayload: expected object",
        ))?;
        let body = obj.get("body").ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            "StoreStockDataValuePayload: missing body",
        ))?;
        match disc {
            0..=6 | 9 | 12 => <u32 as WriteJsonValue>::write_from_json(w, body)?,
            7 | 8 => {
                let body_obj = body.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData, "Disc7/8: expected object body"))?;
                StoreStockDataValueDisc7::write_from_json_dict(w, body_obj)?;
            }
            10 => {
                let body_obj = body.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData, "DiscA: expected object body"))?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(body_obj, "lookup_a")?)?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(body_obj, "lookup_b")?)?;
            }
            11 => { /* empty */ }
            13 => {
                let body_obj = body.as_object().ok_or_else(|| io::Error::new(
                    io::ErrorKind::InvalidData, "DiscD: expected object body"))?;
                <u32 as WriteJsonValue>::write_from_json(w, json_get_field(body_obj, "lookup")?)?;
                <u8 as WriteJsonValue>::write_from_json(w, json_get_field(body_obj, "flag")?)?;
            }
            other => return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("StoreStockDataValuePayload: unknown disc {}", other),
            )),
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct StoreStockDataValue {
    pub raw_q: u64,
    pub disc: u8,
    pub lookup_a: u32,    // sub_1410FF430
    pub lookup_b: u32,    // sub_1410FF430
    pub lookup_c: u32,    // sub_1410FF430
    pub raw_a: u32,
    pub raw_b: u64,
    pub raw_c: u32,
    pub raw_d: u64,
    pub raw_e: u64,
    pub raw_f: u64,
    pub raw_g: u16,
    pub payload: StoreStockDataValuePayload,
}

impl StoreStockDataValue {
    pub fn read_from(data: &[u8], offset: &mut usize) -> io::Result<Self> {
        let raw_q = u64::read_from(data, offset)?;
        let disc = u8::read_from(data, offset)?;
        let lookup_a = u32::read_from(data, offset)?;
        let lookup_b = u32::read_from(data, offset)?;
        let lookup_c = u32::read_from(data, offset)?;
        let raw_a = u32::read_from(data, offset)?;
        let raw_b = u64::read_from(data, offset)?;
        let raw_c = u32::read_from(data, offset)?;
        let raw_d = u64::read_from(data, offset)?;
        let raw_e = u64::read_from(data, offset)?;
        let raw_f = u64::read_from(data, offset)?;
        let raw_g = u16::read_from(data, offset)?;
        let payload = StoreStockDataValuePayload::read_from(disc, data, offset)?;
        Ok(Self {
            raw_q, disc, lookup_a, lookup_b, lookup_c,
            raw_a, raw_b, raw_c, raw_d, raw_e, raw_f, raw_g, payload,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.raw_q.write_to(w)?;
        self.disc.write_to(w)?;
        self.lookup_a.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.lookup_c.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.raw_b.write_to(w)?;
        self.raw_c.write_to(w)?;
        self.raw_d.write_to(w)?;
        self.raw_e.write_to(w)?;
        self.raw_f.write_to(w)?;
        self.raw_g.write_to(w)?;
        self.payload.write_to(w)
    }

    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("raw_q".to_string(), self.raw_q.to_json_value());
        m.insert("disc".to_string(), self.disc.to_json_value());
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        m.insert("lookup_c".to_string(), self.lookup_c.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("raw_b".to_string(), self.raw_b.to_json_value());
        m.insert("raw_c".to_string(), self.raw_c.to_json_value());
        m.insert("raw_d".to_string(), self.raw_d.to_json_value());
        m.insert("raw_e".to_string(), self.raw_e.to_json_value());
        m.insert("raw_f".to_string(), self.raw_f.to_json_value());
        m.insert("raw_g".to_string(), self.raw_g.to_json_value());
        m.insert("payload".to_string(), self.payload.to_json_value());
        Value::Object(m)
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "StoreStockDataValue: expected object"))?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_q")?)?;
        let disc = json_get_field(obj, "disc")?
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "disc: expected u64"))?
            as u8;
        disc.write_to(w)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_c")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_d")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_e")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_f")?)?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_g")?)?;
        StoreStockDataValuePayload::write_from_json(disc, w, json_get_field(obj, "payload")?)?;
        Ok(())
    }
}

/// `u8 presence + (if presence: StoreStockDataValue)` — sub_141D03AA0.
#[derive(Debug)]
pub struct OptionalStoreStockDataValue {
    pub inner: Option<StoreStockDataValue>,
}

impl OptionalStoreStockDataValue {
    pub fn read_from(data: &[u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(StoreStockDataValue::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { inner })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(v) => { 1u8.write_to(w)?; v.write_to(w) }
            None => 0u8.write_to(w),
        }
    }

    pub fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(v) => v.to_json_value(),
            None => Value::Null,
        }
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            w.push(0);
            Ok(())
        } else {
            w.push(1);
            StoreStockDataValue::write_from_json(w, v)
        }
    }
}

// sub_1410D9E90 inner — 8 mem bytes / 4 wire fields = 13 wire bytes.
py_binary_struct! {
    pub struct StoreStockSubData {
        pub lookup_a: u32,    // sub_1410FF430 wire u32
        pub flag: u8,
        pub lookup_b: u32,    // sub_1410FF050 wire u32
        pub lookup_c: u32,    // sub_1410FF050 wire u32
    }
}

/// `u8 presence + (if presence: StoreStockSubData)`.
#[derive(Debug)]
pub struct OptionalStoreStockSubData {
    pub inner: Option<StoreStockSubData>,
}

impl OptionalStoreStockSubData {
    pub fn read_from(data: &[u8], offset: &mut usize) -> io::Result<Self> {
        let presence = u8::read_from(data, offset)?;
        let inner = if presence != 0 {
            Some(StoreStockSubData::read_from(data, offset)?)
        } else {
            None
        };
        Ok(Self { inner })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        match &self.inner {
            Some(v) => { 1u8.write_to(w)?; v.write_to(w) }
            None => 0u8.write_to(w),
        }
    }

    pub fn to_json_value(&self) -> Value {
        match &self.inner {
            Some(v) => Value::Object(v.to_json_dict()),
            None => Value::Null,
        }
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        if v.is_null() {
            w.push(0);
            Ok(())
        } else {
            w.push(1);
            let obj = v.as_object().ok_or_else(|| io::Error::new(
                io::ErrorKind::InvalidData, "OptionalStoreStockSubData: expected object"))?;
            StoreStockSubData::write_from_json_dict(w, obj)
        }
    }
}

// CArray inner element at StoreStockData a2+72: u32 lookup + u64 raw.
py_binary_struct! {
    pub struct StoreStockEffectEntry {
        pub lookup: u32,    // sub_1410FF430 wire u32
        pub raw: u64,
    }
}

/// `sub_1410FC8F0` — StoreStockData, 88 mem bytes per element.
#[derive(Debug)]
pub struct StoreStockData {
    pub lookup_a: u16,                                    // sub_141103610 wire u16
    pub raw_a: u64,
    pub raw_b: u64,
    pub raw_c: u32,
    pub raw_d: u32,
    pub raw_e: u32,
    pub flag_a: u8,
    pub flag_b: u8,
    pub flag_c: u8,
    pub value: OptionalStoreStockDataValue,
    pub lookup_b: u32,                                    // sub_1410FF430 wire u32
    pub sub_data: OptionalStoreStockSubData,
    pub effect_list: CArray<StoreStockEffectEntry>,
}

impl StoreStockData {
    pub fn read_from(data: &[u8], offset: &mut usize) -> io::Result<Self> {
        let lookup_a = u16::read_from(data, offset)?;
        let raw_a = u64::read_from(data, offset)?;
        let raw_b = u64::read_from(data, offset)?;
        let raw_c = u32::read_from(data, offset)?;
        let raw_d = u32::read_from(data, offset)?;
        let raw_e = u32::read_from(data, offset)?;
        let flag_a = u8::read_from(data, offset)?;
        let flag_b = u8::read_from(data, offset)?;
        let flag_c = u8::read_from(data, offset)?;
        let value = OptionalStoreStockDataValue::read_from(data, offset)?;
        let lookup_b = u32::read_from(data, offset)?;
        let sub_data = OptionalStoreStockSubData::read_from(data, offset)?;
        let effect_list = CArray::<StoreStockEffectEntry>::read_from(data, offset)?;
        Ok(Self {
            lookup_a, raw_a, raw_b, raw_c, raw_d, raw_e,
            flag_a, flag_b, flag_c, value, lookup_b, sub_data, effect_list,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.lookup_a.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.raw_b.write_to(w)?;
        self.raw_c.write_to(w)?;
        self.raw_d.write_to(w)?;
        self.raw_e.write_to(w)?;
        self.flag_a.write_to(w)?;
        self.flag_b.write_to(w)?;
        self.flag_c.write_to(w)?;
        self.value.write_to(w)?;
        self.lookup_b.write_to(w)?;
        self.sub_data.write_to(w)?;
        self.effect_list.write_to(w)
    }

    pub fn to_json_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("lookup_a".to_string(), self.lookup_a.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("raw_b".to_string(), self.raw_b.to_json_value());
        m.insert("raw_c".to_string(), self.raw_c.to_json_value());
        m.insert("raw_d".to_string(), self.raw_d.to_json_value());
        m.insert("raw_e".to_string(), self.raw_e.to_json_value());
        m.insert("flag_a".to_string(), self.flag_a.to_json_value());
        m.insert("flag_b".to_string(), self.flag_b.to_json_value());
        m.insert("flag_c".to_string(), self.flag_c.to_json_value());
        m.insert("value".to_string(), self.value.to_json_value());
        m.insert("lookup_b".to_string(), self.lookup_b.to_json_value());
        m.insert("sub_data".to_string(), self.sub_data.to_json_value());
        m.insert("effect_list".to_string(), self.effect_list.to_json_value());
        Value::Object(m)
    }

    pub fn write_from_json(w: &mut Vec<u8>, v: &Value) -> io::Result<()> {
        let obj = v.as_object().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData, "StoreStockData: expected object"))?;
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_a")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_c")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_d")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_e")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_c")?)?;
        OptionalStoreStockDataValue::write_from_json(w, json_get_field(obj, "value")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "lookup_b")?)?;
        OptionalStoreStockSubData::write_from_json(w, json_get_field(obj, "sub_data")?)?;
        <CArray<StoreStockEffectEntry> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "effect_list")?)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct StoreInfo<'a> {
    pub key: u16,
    pub string_key: CString<'a>,
    pub is_blocked: u8,
    pub exchange_item_info_for_buy: u32,
    pub exchange_item_info_list_for_sell: CArray<u32>,
    pub sell_percents: u64,
    pub store_type: u8,
    pub price_increase_percent_list: CArray<u64>,
    pub sellable_character_condition_logic: u32,
    pub reset_hour: u32,
    pub reset_day: u32,
    pub buyable_stock_count: u32,
    pub sellable_stock_count: u32,
    pub sellable_type: u8,
    pub stock_data_list: Vec<StoreStockData>,
    pub raw_list_a: CArray<u8>,
    pub raw_list_b: CArray<u8>,
    pub raw_a: u32,
    pub flag_a: u8,
    pub flag_b: u8,
    pub flag_c: u8,
}

impl<'a> StoreInfo<'a> {
    pub fn read_with_size(data: &'a [u8], offset: &mut usize, entry_size: usize) -> io::Result<Self> {
        let start = *offset;
        let item = Self::read_from(data, offset)?;
        let consumed = *offset - start;
        if consumed != entry_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("StoreInfo: consumed {} bytes, expected {}", consumed, entry_size),
            ));
        }
        Ok(item)
    }

    pub fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        let key = u16::read_from(data, offset)?;
        let string_key = CString::read_from(data, offset)?;
        let is_blocked = u8::read_from(data, offset)?;
        let exchange_item_info_for_buy = u32::read_from(data, offset)?;
        let exchange_item_info_list_for_sell = CArray::<u32>::read_from(data, offset)?;
        let sell_percents = u64::read_from(data, offset)?;
        let store_type = u8::read_from(data, offset)?;
        let price_increase_percent_list = CArray::<u64>::read_from(data, offset)?;
        let sellable_character_condition_logic = u32::read_from(data, offset)?;
        let reset_hour = u32::read_from(data, offset)?;
        let reset_day = u32::read_from(data, offset)?;
        let buyable_stock_count = u32::read_from(data, offset)?;
        let sellable_stock_count = u32::read_from(data, offset)?;
        let sellable_type = u8::read_from(data, offset)?;
        let count = u32::read_from(data, offset)?;
        let mut stock_data_list = Vec::with_capacity(count as usize);
        for _ in 0..count {
            stock_data_list.push(StoreStockData::read_from(data, offset)?);
        }
        let raw_list_a = CArray::<u8>::read_from(data, offset)?;
        let raw_list_b = CArray::<u8>::read_from(data, offset)?;
        let raw_a = u32::read_from(data, offset)?;
        let flag_a = u8::read_from(data, offset)?;
        let flag_b = u8::read_from(data, offset)?;
        let flag_c = u8::read_from(data, offset)?;
        Ok(Self {
            key, string_key, is_blocked,
            exchange_item_info_for_buy, exchange_item_info_list_for_sell,
            sell_percents, store_type, price_increase_percent_list,
            sellable_character_condition_logic, reset_hour, reset_day,
            buyable_stock_count, sellable_stock_count, sellable_type,
            stock_data_list, raw_list_a, raw_list_b, raw_a,
            flag_a, flag_b, flag_c,
        })
    }

    pub fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        self.key.write_to(w)?;
        self.string_key.write_to(w)?;
        self.is_blocked.write_to(w)?;
        self.exchange_item_info_for_buy.write_to(w)?;
        self.exchange_item_info_list_for_sell.write_to(w)?;
        self.sell_percents.write_to(w)?;
        self.store_type.write_to(w)?;
        self.price_increase_percent_list.write_to(w)?;
        self.sellable_character_condition_logic.write_to(w)?;
        self.reset_hour.write_to(w)?;
        self.reset_day.write_to(w)?;
        self.buyable_stock_count.write_to(w)?;
        self.sellable_stock_count.write_to(w)?;
        self.sellable_type.write_to(w)?;
        (self.stock_data_list.len() as u32).write_to(w)?;
        for sd in &self.stock_data_list { sd.write_to(w)?; }
        self.raw_list_a.write_to(w)?;
        self.raw_list_b.write_to(w)?;
        self.raw_a.write_to(w)?;
        self.flag_a.write_to(w)?;
        self.flag_b.write_to(w)?;
        self.flag_c.write_to(w)
    }

    pub fn to_json_dict(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("key".to_string(), self.key.to_json_value());
        m.insert("string_key".to_string(), self.string_key.to_json_value());
        m.insert("is_blocked".to_string(), self.is_blocked.to_json_value());
        m.insert("exchange_item_info_for_buy".to_string(), self.exchange_item_info_for_buy.to_json_value());
        m.insert("exchange_item_info_list_for_sell".to_string(), self.exchange_item_info_list_for_sell.to_json_value());
        m.insert("sell_percents".to_string(), self.sell_percents.to_json_value());
        m.insert("store_type".to_string(), self.store_type.to_json_value());
        m.insert("price_increase_percent_list".to_string(), self.price_increase_percent_list.to_json_value());
        m.insert("sellable_character_condition_logic".to_string(), self.sellable_character_condition_logic.to_json_value());
        m.insert("reset_hour".to_string(), self.reset_hour.to_json_value());
        m.insert("reset_day".to_string(), self.reset_day.to_json_value());
        m.insert("buyable_stock_count".to_string(), self.buyable_stock_count.to_json_value());
        m.insert("sellable_stock_count".to_string(), self.sellable_stock_count.to_json_value());
        m.insert("sellable_type".to_string(), self.sellable_type.to_json_value());
        let stock_list: Vec<Value> = self.stock_data_list.iter().map(|s| s.to_json_value()).collect();
        m.insert("stock_data_list".to_string(), Value::Array(stock_list));
        m.insert("raw_list_a".to_string(), self.raw_list_a.to_json_value());
        m.insert("raw_list_b".to_string(), self.raw_list_b.to_json_value());
        m.insert("raw_a".to_string(), self.raw_a.to_json_value());
        m.insert("flag_a".to_string(), self.flag_a.to_json_value());
        m.insert("flag_b".to_string(), self.flag_b.to_json_value());
        m.insert("flag_c".to_string(), self.flag_c.to_json_value());
        m
    }

    pub fn write_from_json_dict(w: &mut Vec<u8>, obj: &Map<String, Value>) -> io::Result<()> {
        <u16 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "key")?)?;
        <CString as WriteJsonValue>::write_from_json(w, json_get_field(obj, "string_key")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "is_blocked")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "exchange_item_info_for_buy")?)?;
        <CArray<u32> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "exchange_item_info_list_for_sell")?)?;
        <u64 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "sell_percents")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "store_type")?)?;
        <CArray<u64> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "price_increase_percent_list")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "sellable_character_condition_logic")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "reset_hour")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "reset_day")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "buyable_stock_count")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "sellable_stock_count")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "sellable_type")?)?;
        let arr = json_get_field(obj, "stock_data_list")?
            .as_array()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stock_data_list: expected array"))?;
        (arr.len() as u32).write_to(w)?;
        for v in arr { StoreStockData::write_from_json(w, v)?; }
        <CArray<u8> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_list_a")?)?;
        <CArray<u8> as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_list_b")?)?;
        <u32 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "raw_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_a")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_b")?)?;
        <u8 as WriteJsonValue>::write_from_json(w, json_get_field(obj, "flag_c")?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::variant::{entry_ranges, load_pabgh_offsets};
    const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\storeinfo.pabgb";
    const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\storeinfo.pabgh";

    #[test]
    fn roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        let mut items = Vec::new();
        for (i, (k, s, e)) in ranges.iter().enumerate() {
            let mut c = *s;
            items.push(
                StoreInfo::read_with_size(&data, &mut c, e - s)
                    .unwrap_or_else(|er| panic!("e{} k=0x{:x}: {}", i, k, er)),
            );
            assert_eq!(c, *e);
        }
        let mut out = Vec::with_capacity(data.len());
        for it in &items { it.write_to(&mut out).unwrap(); }
        assert_eq!(out, data, "storeinfo roundtrip mismatch");
    }

    #[test]
    fn json_roundtrip() {
        let Ok(data) = std::fs::read(PABGB) else { eprintln!("SKIP"); return; };
        let Some(entries) = load_pabgh_offsets(PABGH) else { eprintln!("SKIP"); return; };
        let ranges = entry_ranges(&entries, data.len());
        for (i, (key, start, end)) in ranges.iter().enumerate() {
            let mut cursor = *start;
            let item = StoreInfo::read_with_size(&data, &mut cursor, end - start).unwrap();
            assert_eq!(cursor, *end, "entry {} key=0x{:x}: under/over-read", i, key);
            let dict = item.to_json_dict();
            let mut from_typed = Vec::new();
            item.write_to(&mut from_typed).unwrap();
            let mut from_json = Vec::new();
            StoreInfo::write_from_json_dict(&mut from_json, &dict)
                .unwrap_or_else(|e| panic!("entry {} key=0x{:x}: write_from_json_dict: {}", i, key, e));
            assert_eq!(
                from_json, from_typed,
                "entry {} key=0x{:x}: JSON round-trip diverges from typed write", i, key
            );
        }
    }
}
