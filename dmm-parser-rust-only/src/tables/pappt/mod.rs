// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Part-prefab table (`.pappt`) parser.
//!
//! `partprefabtable.pappt` is a single global build-time registry that
//! maps short part-prefab names plus per-character variants to interned
//! string IDs. The retail game loads exactly one of two paths at start:
//! `character/bin__/partprefabtable.pappt` or
//! `character/bindev__/partprefabtable.pappt`.
//!
//! Layout: opaque 8-byte header, `u32` primary count, N primary
//! entries, `u32` secondary count, M secondary entries. All strings
//! are length-prefixed by a single `u8` length byte (max 255 bytes,
//! no NUL terminator written by the file).
//!
//! Format reference: `tools/mod-workbench/PAPPT_FORMAT_RESEARCH.md`.

pub mod info;
pub use info::{PapptFile, PrimaryChild, PrimaryEntry, SecondaryEntry};
