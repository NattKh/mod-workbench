// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Model property header collection (`.pamhc`) parser.
//!
//! `miscellaneous/modelpropertyheadercollection.pamhc` is a single
//! per-build registry that holds five concatenated byte sections
//! prefixed by an opaque 8-byte header and five `u32` size fields.
//!
//! Layout: opaque 8-byte header, five `u32` section sizes
//! (`section_a` ... `section_e`), then payload — `section_a`,
//! `section_b`, `section_c`, `section_d`, `section_e` concatenated
//! in order. `section_a` is decoded as a `u32` array (entry count =
//! `section_a_size / 4`); the loader rejects files where
//! `section_a_size & 3 != 0`. The remaining four sections are kept
//! as opaque byte ranges since their element schemas haven't been
//! decoded.
//!
//! Format reference:
//! `tools/mod-workbench/PALEVEL_PAMHC_PAB_FORMAT_RESEARCH.md`.

pub mod info;
pub use info::PamhcFile;
