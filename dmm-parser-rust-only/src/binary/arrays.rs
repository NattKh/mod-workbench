// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

use std::io::{self, Write};

use super::{BinaryRead, BinaryReadTracked, BinaryWrite, FieldRange, pop_path, push_index};
use crate::json_traits::{ToJsonValue, WriteJsonValue};

// Generic [u8; N] — covers any const-size byte array. Used by tables/* for
// directly-read bytes that aren't lookups or strings.
impl<'a, const N: usize> BinaryRead<'a> for [u8; N] {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        super::check_remaining(data, *offset, N)?;
        let arr: [u8; N] = data[*offset..*offset + N].try_into().unwrap();
        *offset += N;
        Ok(arr)
    }
}

impl<const N: usize> BinaryWrite for [u8; N] {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        w.write_all(self)
    }
}

impl<'a, const N: usize> BinaryReadTracked<'a> for [u8; N] {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        path: &mut String,
        ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        let mut out = [0u8; N];
        for (i, elem) in out.iter_mut().enumerate() {
            let saved = push_index(path, i);
            *elem = u8::read_tracked(data, offset, path, ranges)?;
            pop_path(path, saved);
        }
        Ok(out)
    }
}

impl<const N: usize> ToJsonValue for [u8; N] {
    fn to_json_value(&self) -> serde_json::Value {
        serde_json::Value::Array(self.iter().map(|x| serde_json::Value::from(*x)).collect())
    }
}

impl<const N: usize> WriteJsonValue for [u8; N] {
    fn write_from_json(w: &mut Vec<u8>, v: &serde_json::Value) -> io::Result<()> {
        let arr = v.as_array().ok_or_else(|| io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected array of {} u8, got non-array", N),
        ))?;
        if arr.len() != N {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                format!("expected {} elements for [u8; {}], got {}", N, N, arr.len())));
        }
        for elem in arr {
            <u8 as WriteJsonValue>::write_from_json(w, elem)?;
        }
        Ok(())
    }
}


impl<'a> BinaryRead<'a> for [f32; 2] {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok([f32::read_from(data, offset)?, f32::read_from(data, offset)?])
    }
}

impl BinaryWrite for [f32; 2] {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        for v in self {
            v.write_to(w)?;
        }
        Ok(())
    }
}

impl<'a> BinaryRead<'a> for [f32; 3] {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok([
            f32::read_from(data, offset)?,
            f32::read_from(data, offset)?,
            f32::read_from(data, offset)?,
        ])
    }
}

impl BinaryWrite for [f32; 3] {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        for v in self {
            v.write_to(w)?;
        }
        Ok(())
    }
}

impl<'a> BinaryRead<'a> for [f32; 4] {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok([
            f32::read_from(data, offset)?,
            f32::read_from(data, offset)?,
            f32::read_from(data, offset)?,
            f32::read_from(data, offset)?,
        ])
    }
}

impl BinaryWrite for [f32; 4] {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        for v in self {
            v.write_to(w)?;
        }
        Ok(())
    }
}

impl<'a> BinaryRead<'a> for [u32; 2] {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok([u32::read_from(data, offset)?, u32::read_from(data, offset)?])
    }
}

impl BinaryWrite for [u32; 2] {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        for v in self {
            v.write_to(w)?;
        }
        Ok(())
    }
}

impl<'a> BinaryRead<'a> for [u32; 4] {
    fn read_from(data: &'a [u8], offset: &mut usize) -> io::Result<Self> {
        Ok([
            u32::read_from(data, offset)?,
            u32::read_from(data, offset)?,
            u32::read_from(data, offset)?,
            u32::read_from(data, offset)?,
        ])
    }
}

impl BinaryWrite for [u32; 4] {
    fn write_to(&self, w: &mut dyn Write) -> io::Result<()> {
        for v in self {
            v.write_to(w)?;
        }
        Ok(())
    }
}

// [u8; 3] specific impls removed — covered by generic [u8; N] above.

// ── Fixed-size array tracked reads ──────────────────────────────────────────
// Each element is reported as `<path>[i]` so the byte layout is preserved.

impl<'a> BinaryReadTracked<'a> for [f32; 2] {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        path: &mut String,
        ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        let mut out = [0f32; 2];
        for (i, elem) in out.iter_mut().enumerate() {
            let saved = push_index(path, i);
            *elem = f32::read_tracked(data, offset, path, ranges)?;
            pop_path(path, saved);
        }
        Ok(out)
    }
}

impl<'a> BinaryReadTracked<'a> for [f32; 3] {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        path: &mut String,
        ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        let mut out = [0f32; 3];
        for (i, elem) in out.iter_mut().enumerate() {
            let saved = push_index(path, i);
            *elem = f32::read_tracked(data, offset, path, ranges)?;
            pop_path(path, saved);
        }
        Ok(out)
    }
}

impl<'a> BinaryReadTracked<'a> for [f32; 4] {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        path: &mut String,
        ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        let mut out = [0f32; 4];
        for (i, elem) in out.iter_mut().enumerate() {
            let saved = push_index(path, i);
            *elem = f32::read_tracked(data, offset, path, ranges)?;
            pop_path(path, saved);
        }
        Ok(out)
    }
}

impl<'a> BinaryReadTracked<'a> for [u32; 4] {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        path: &mut String,
        ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        let mut out = [0u32; 4];
        for (i, elem) in out.iter_mut().enumerate() {
            let saved = push_index(path, i);
            *elem = u32::read_tracked(data, offset, path, ranges)?;
            pop_path(path, saved);
        }
        Ok(out)
    }
}

impl<'a> BinaryReadTracked<'a> for [u32; 2] {
    fn read_tracked(
        data: &'a [u8],
        offset: &mut usize,
        path: &mut String,
        ranges: &mut Vec<FieldRange>,
    ) -> io::Result<Self> {
        let mut out = [0u32; 2];
        for (i, elem) in out.iter_mut().enumerate() {
            let saved = push_index(path, i);
            *elem = u32::read_tracked(data, offset, path, ranges)?;
            pop_path(path, saved);
        }
        Ok(out)
    }
}

// [u8; 3] BinaryReadTracked impl removed — covered by generic [u8; N] above.
#[allow(dead_code)]
fn _u8_3_tracked_placeholder(
    data: &[u8],
    offset: &mut usize,
    path: &mut String,
    ranges: &mut Vec<FieldRange>,
) -> io::Result<[u8; 3]> {
    {
        let mut out = [0u8; 3];
        for (i, elem) in out.iter_mut().enumerate() {
            let saved = push_index(path, i);
            *elem = u8::read_tracked(data, offset, path, ranges)?;
            pop_path(path, saved);
        }
        Ok(out)
    }
}
