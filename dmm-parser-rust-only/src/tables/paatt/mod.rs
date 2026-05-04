// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Projectile attribute (`.paatt`) parser.
//!
//! Distinct from the per-weapon attack-info `.paatt` files in
//! `binary::paatt` (those live under `0010/actionchart/bin__/attackinfo/`).
//! This module parses the projectile-physics tables found at
//! `actionchart/projectileinfo*.paatt` — small files (~120-230 KB) holding
//! per-projectile physics: radius, lifetime, shape, sound refs, etc.
//!
//! Field naming mirrors the Python reference parser at
//! `ResearchFolder/paac/paatt_parser.py` (`PaattFile` dataclass).

pub mod info;
pub use info::PaattFile;
