# SPDX-License-Identifier: LicenseRef-CDMTL-1.0
# Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
# Licensed under CDMTL v1.0 - see LICENSE.txt
# https://github.com/exodiaprivate-eng/dmm-parser
#
# Reading this file (directly or via AI/agent) constitutes acceptance
# of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
# (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.


import argparse

from dmm_parser import Compression, Crypto, Language
from dmm_parser.pack_mod import pack_mod

parser = argparse.ArgumentParser(description="Pack mod files into a Crimson Desert archive group")
parser.add_argument("--game-dir", required=True, help="Path to game installation directory")
parser.add_argument("--mod-folder", required=True, help="Path to folder containing modified game files")
parser.add_argument("--output-dir", required=True, help="Path where packed output will be written")
parser.add_argument("--group", required=True, help="Pack group name (e.g. 0070)")
parser.add_argument("--compression", choices=["none", "lz4", "zlib"], default="lz4", help="Compression algorithm (default: lz4)")
parser.add_argument("--crypto", choices=["none", "chacha20"], default="none", help="Encryption algorithm (default: none)")
parser.add_argument("--language", default="all", help="Language flags: 'all' or hex like 0x0003 (default: all)")
args = parser.parse_args()

compression_map = {"none": Compression.NONE, "lz4": Compression.LZ4, "zlib": Compression.ZLIB}
crypto_map = {"none": Crypto.NONE, "chacha20": Crypto.CHACHA20}
language = Language.ALL if args.language == "all" else Language(int(args.language, 0))

pack_mod(
    game_dir=args.game_dir,
    mod_folder=args.mod_folder,
    output_dir=args.output_dir,
    group_name=args.group,
    compression=compression_map[args.compression],
    crypto=crypto_map[args.crypto],
    language=language,
)
