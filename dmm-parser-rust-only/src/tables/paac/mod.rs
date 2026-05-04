// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Action chart (`.paac`) parser.
//!
//! Crimson Desert action chart files (`commonactioninfo.paac`,
//! per-weapon `*_upper.paac`, etc.) describe the state machine that
//! drives every animation/ability the game's character controllers can
//! dispatch into.
//!
//! Three known sub-formats:
//!
//! - `info_table` — small files (e.g. `commonactioninfo.paac`) using
//!   the `0xA8B7DDAA` sentinel; no `M0%D` markers.
//! - `action_chart_v0` — chart with no `M0%D` markers; only inline
//!   transitions (e.g. `pistol_upper.paac`).
//! - `action_chart_v1` — chart with `M0%D` state records and (for the
//!   big weapon charts) a 260-byte condition graph (e.g. `fist_upper`,
//!   `sword_upper`).
//!
//! Field naming and parsing decisions mirror the Python reference at
//! `ResearchFolder/paac/paac_parser.py` (`PaacFile.parse`). Heuristic
//! rules in the Python (e.g. minimum condition-graph run length) are
//! preserved verbatim.

pub mod info;
pub use info::{
    ConditionRecord, Header, InlineTransition, PaacFile, PaacFormat, StateRecord,
    StringTableEntry, sniff_format,
};
