// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 - see LICENSE.txt
// https://github.com/exodiaprivate-eng/dmm-parser
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 §4.9 (No Competing Implementation) and §4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. §1202.

//! Count how many gimmick_info entries successfully decoded field 18
//! (gimmick_chart_parameter_list) and the size distribution of post_blob.

use dmm_parser::binary::variant::{entry_ranges, load_pabgh_offsets};
use dmm_parser::tables::gimmick_info::info::{GimmickInfo, GimmickTail};

const PABGB: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgb";
const PABGH: &str = r"C:\Users\corin\Desktop\CD DUMPING TOOLS\dmm-pabgb-aio\vanilla_dumps\gimmickinfo.pabgh";

fn main() {
    let data = std::fs::read(PABGB).expect("read");
    let entries = load_pabgh_offsets(PABGH).expect("pabgh");
    let ranges = entry_ranges(&entries, data.len());

    let mut decoded = 0usize;
    let mut raw = 0usize;
    let mut tgpehd_typed = 0usize;
    let mut chart_param_typed = 0usize;
    let mut field_19_typed = 0usize;
    let mut field_20_typed = 0usize;
    let mut field_21_typed = 0usize;
    let mut field_22_typed = 0usize;
    let mut field_23_typed = 0usize;
    let mut field_24_typed = 0usize;
    let mut field_25_typed = 0usize;
    let mut field_26_typed = 0usize;
    let mut field_27_typed = 0usize;
    let mut field_28_typed = 0usize;
    let mut field_29_typed = 0usize;
    let mut field_30_typed = 0usize;
    let mut field_31_typed = 0usize;
    let mut field_32_typed = 0usize;
    let mut field_33_typed = 0usize;
    let mut field_34_typed = 0usize;
    let mut field_35_typed = 0usize;
    let mut field_36_typed = 0usize;
    let mut field_37_typed = 0usize;
    let mut field_38_typed = 0usize;
    let mut field_39_typed = 0usize;
    let mut field_40_typed = 0usize;
    let mut field_41_typed = 0usize;
    let mut field_42_typed = 0usize;
    let mut field_43_typed = 0usize;
    let mut field_44_typed = 0usize;
    let mut field_45_typed = 0usize;
    let mut field_46_typed = 0usize;
    let mut field_47_typed = 0usize;
    let mut field_48_typed = 0usize;
    let mut field_49_typed = 0usize;
    let mut field_50_typed = 0usize;
    let mut field_51_typed = 0usize;
    let mut field_52_typed = 0usize;
    let mut field_53_typed = 0usize;
    let mut field_54_typed = 0usize;
    let mut field_55_typed = 0usize;
    let mut field_56_typed = 0usize;
    let mut field_57_typed = 0usize;
    let mut field_58_typed = 0usize;
    let mut field_59_typed = 0usize;
    let mut field_60_typed = 0usize;
    let mut field_61_typed = 0usize;
    let mut field_62_typed = 0usize;
    let mut field_63_typed = 0usize;
    let mut field_64_typed = 0usize;
    let mut field_65_typed = 0usize;
    let mut field_66_typed = 0usize;
    let mut field_67_typed = 0usize;
    let mut field_68_typed = 0usize;
    let mut field_69_typed = 0usize;
    let mut field_70_typed = 0usize;
    let mut field_71_typed = 0usize;
    let mut field_72_typed = 0usize;
    let mut field_73_typed = 0usize;
    let mut field_74_typed = 0usize;
    let mut field_75_typed = 0usize;
    let mut field_76_typed = 0usize;
    let mut field_77_typed = 0usize;
    let mut field_78_typed = 0usize;
    let mut field_79_typed = 0usize;
    let mut field_80_typed = 0usize;
    let mut field_81_typed = 0usize;
    let mut field_82_typed = 0usize;
    let mut field_83_typed = 0usize;
    let mut field_84_typed = 0usize;
    let mut field_85_typed = 0usize;
    let mut field_86_typed = 0usize;
    let mut field_87_typed = 0usize;
    let mut field_88_typed = 0usize;
    let mut field_89_typed = 0usize;
    let mut field_90_typed = 0usize;
    let mut field_91_typed = 0usize;
    let mut field_92_typed = 0usize;
    let mut field_93_typed = 0usize;
    let mut field_94_typed = 0usize;
    let mut field_95_typed = 0usize;
    let mut field_96_typed = 0usize;
    let mut field_97_typed = 0usize;
    let mut field_98_typed = 0usize;
    let mut field_99_typed = 0usize;
    let mut field_100_typed = 0usize;
    let mut field_101_typed = 0usize;
    let mut field_102_typed = 0usize;
    let mut field_103_typed = 0usize;
    let mut field_104_typed = 0usize;
    let mut field_105_typed = 0usize;
    let mut field_106_typed = 0usize;
    let mut field_107_typed = 0usize;
    let mut field_108_typed = 0usize;
    let mut field_109_typed = 0usize;
    let mut field_110_typed = 0usize;
    let mut field_111_typed = 0usize;
    let mut field_112_typed = 0usize;
    let mut field_113_typed = 0usize;
    let mut field_114_typed = 0usize;
    let mut field_115_typed = 0usize;
    let mut field_116_typed = 0usize;
    let mut field_117_typed = 0usize;
    let mut field_118_typed = 0usize;
    let mut field_119_typed = 0usize;
    let mut field_120_typed = 0usize;
    let mut field_121_typed = 0usize;
    let mut field_122_typed = 0usize;
    let mut field_123_typed = 0usize;
    let mut field_124_typed = 0usize;
    let mut field_125_typed = 0usize;
    let mut field_126_typed = 0usize;
    let mut field_127_typed = 0usize;
    let mut field_128_typed = 0usize;
    let mut field_129_typed = 0usize;
    let mut field_130_typed = 0usize;
    let mut field_131_typed = 0usize;
    let mut field_132_typed = 0usize;
    let mut field_133_typed = 0usize;
    let mut field_134_typed = 0usize;
    let mut field_135_typed = 0usize;
    let mut field_136_typed = 0usize;
    let mut field_137_typed = 0usize;
    let mut field_138_typed = 0usize;
    let mut field_139_typed = 0usize;
    let mut field_140_typed = 0usize;
    let mut field_141_typed = 0usize;
    let mut field_142_typed = 0usize;
    let mut field_143_typed = 0usize;
    let mut field_144_typed = 0usize;
    let mut field_145_typed = 0usize;
    let mut field_146_typed = 0usize;
    let mut field_147_typed = 0usize;
    let mut field_148_typed = 0usize;
    let mut field_149_typed = 0usize;
    let mut field_150_typed = 0usize;
    let mut field_151_typed = 0usize;
    let mut field_152_typed = 0usize;
    let mut field_153_typed = 0usize;
    let mut field_154_typed = 0usize;
    let mut field_155_typed = 0usize;
    let mut field_156_typed = 0usize;
    let mut field_157_typed = 0usize;
    let mut field_158_typed = 0usize;
    let mut field_159_typed = 0usize;
    let mut field_160_typed = 0usize;
    let mut field_161_typed = 0usize;
    let mut field_162_typed = 0usize;
    let mut field_163_typed = 0usize;
    let mut field_164_typed = 0usize;
    let mut field_165_typed = 0usize;
    let mut field_166_typed = 0usize;
    let mut field_167_typed = 0usize;
    let mut field_168_typed = 0usize;
    let mut field_169_typed = 0usize;
    let mut field_170_typed = 0usize;
    let mut field_171_typed = 0usize;
    let mut field_172_typed = 0usize;
    let mut field_173_typed = 0usize;
    let mut field_174_typed = 0usize;
    let mut field_175_typed = 0usize;
    let mut field_176_typed = 0usize;
    let mut field_177_typed = 0usize;
    let mut field_178_typed = 0usize;
    let mut field_179_typed = 0usize;
    let mut field_180_typed = 0usize;
    let mut field_181_typed = 0usize;
    let mut field_182_typed = 0usize;
    let mut field_183_typed = 0usize;
    let mut field_184_typed = 0usize;
    let mut field_185_typed = 0usize;
    let mut field_186_typed = 0usize;
    let mut field_187_typed = 0usize;
    let mut field_188_typed = 0usize;
    let mut field_189_typed = 0usize;
    let mut field_190_typed = 0usize;
    let mut field_191_typed = 0usize;
    let mut field_192_typed = 0usize;
    let mut field_193_typed = 0usize;
    let mut field_194_typed = 0usize;
    let mut field_195_typed = 0usize;
    let mut field_196_typed = 0usize;
    let mut field_197_typed = 0usize;
    let mut field_198_typed = 0usize;
    let mut field_199_typed = 0usize;
    let mut field_200_typed = 0usize;
    let mut field_201_typed = 0usize;
    let mut field_202_typed = 0usize;
    let mut field_203_typed = 0usize;
    let mut field_204_typed = 0usize;
    let mut field_205_typed = 0usize;
    let mut field_206_typed = 0usize;
    let mut field_207_typed = 0usize;
    let mut field_208_typed = 0usize;
    let mut field_209_typed = 0usize;
    let mut field_210_typed = 0usize;
    let mut field_211_typed = 0usize;
    let mut field_212_typed = 0usize;
    let mut field_213_typed = 0usize;
    let mut field_214_typed = 0usize;
    let mut field_215_typed = 0usize;
    let mut field_216_typed = 0usize;
    let mut field_217_typed = 0usize;
    let mut field_218_typed = 0usize;
    let mut field_219_typed = 0usize;
    let mut field_220_typed = 0usize;
    let mut field_221_typed = 0usize;
    let mut field_222_typed = 0usize;
    let mut field_223_typed = 0usize;
    let mut field_224_typed = 0usize;
    let mut field_225_typed = 0usize;
    let mut field_226_typed = 0usize;
    let mut field_227_typed = 0usize;
    let mut field_228_typed = 0usize;
    let mut field_229_typed = 0usize;
    let mut field_230_typed = 0usize;
    let mut field_231_typed = 0usize;
    let mut field_232_typed = 0usize;
    let mut field_233_typed = 0usize;
    let mut field_234_typed = 0usize;
    let mut field_235_typed = 0usize;
    let mut field_236_typed = 0usize;
    let mut field_237_typed = 0usize;
    let mut field_238_typed = 0usize;
    let mut field_239_typed = 0usize;
    let mut field_240_typed = 0usize;
    let mut field_241_typed = 0usize;
    let mut field_242_typed = 0usize;
    let mut field_243_typed = 0usize;
    let mut field_244_typed = 0usize;
    let mut field_245_typed = 0usize;
    let mut field_246_typed = 0usize;
    let mut field_247_typed = 0usize;
    let mut field_248_typed = 0usize;
    let mut field_249_typed = 0usize;
    let mut field_250_typed = 0usize;
    let mut field_251_typed = 0usize;
    let mut field_252_typed = 0usize;
    let mut field_253_typed = 0usize;
    let mut field_254_typed = 0usize;
    let mut field_255_typed = 0usize;
    let mut field_256_typed = 0usize;
    let mut field_257_typed = 0usize;
    let mut field_258_typed = 0usize;
    let mut field_259_typed = 0usize;
    let mut field_260_typed = 0usize;
    let mut field_261_typed = 0usize;
    let mut field_262_typed = 0usize;
    let mut field_263_typed = 0usize;
    let mut field_264_typed = 0usize;
    let mut field_265_typed = 0usize;
    let mut field_266_typed = 0usize;
    let mut field_267_typed = 0usize;
    let mut field_268_typed = 0usize;
    let mut field_269_typed = 0usize;
    let mut field_270_typed = 0usize;
    let mut field_271_typed = 0usize;
    let mut field_272_typed = 0usize;
    let mut field_273_typed = 0usize;
    let mut field_274_typed = 0usize;
    let mut field_275_typed = 0usize;
    let mut field_276_typed = 0usize;
    let mut field_277_typed = 0usize;
    let mut field_278_typed = 0usize;
    let mut field_279_typed = 0usize;
    let mut field_280_typed = 0usize;
    let mut field_281_typed = 0usize;
    let mut field_282_typed = 0usize;
    let mut field_283_typed = 0usize;
    let mut field_284_typed = 0usize;
    let mut field_285_typed = 0usize;
    let mut field_286_typed = 0usize;
    let mut field_287_typed = 0usize;
    let mut field_288_typed = 0usize;
    let mut field_289_typed = 0usize;
    let mut field_290_typed = 0usize;
    let mut field_291_typed = 0usize;
    let mut field_292_typed = 0usize;
    let mut field_293_typed = 0usize;
    let mut field_294_typed = 0usize;
    let mut field_295_typed = 0usize;
    let mut field_296_typed = 0usize;
    let mut field_297_typed = 0usize;
    let mut field_298_typed = 0usize;
    let mut field_299_typed = 0usize;
    let mut field_300_typed = 0usize;
    let mut field_301_typed = 0usize;
    let mut field_302_typed = 0usize;
    let mut field_303_typed = 0usize;
    let mut field_304_typed = 0usize;
    let mut field_305_typed = 0usize;
    let mut field_306_typed = 0usize;
    let mut field_307_typed = 0usize;
    let mut field_308_typed = 0usize;
    let mut field_309_typed = 0usize;
    let mut post_blob_sizes: Vec<usize> = vec![];

    for (_key, start, end) in &ranges {
        let mut cur = *start;
        let item = match GimmickInfo::read_with_size(&data, &mut cur, end - start) {
            Ok(it) => it,
            Err(_) => continue,
        };
        match &item.tail {
            GimmickTail::Decoded {
                trigger_event_handler_list,
                gimmick_chart_parameter_list,
                field_19_u32_list,
                field_20_u32_list,
                field_21_u32_list,
                field_22_u32_list,
                field_23_u32_list,
                field_24_u32_list,
                field_25_u32_list,
                field_26_u32,
                field_27_u32_list,
                field_28_u32,
                field_29_u32_list,
                field_30_u32_list,
                field_31_u32_list,
                field_32_u32_list,
                field_33_u32,
                field_34_u32,
                field_35_u32_list,
                field_36_u32,
                field_37_u32,
                field_38_u32,
                field_39_u32_list,
                field_40_u32_list,
                field_41_u32,
                field_42_u32,
                field_43_u32,
                field_44_u32,
                field_45_u32,
                field_46_u32,
                field_47_u32,
                field_48_u32,
                field_49_u32_list,
                field_50_u32_list,
                field_51_u32_list,
                field_52_u32_list,
                field_53_u32_list,
                field_54_u32_list,
                field_55_u32_list,
                field_56_u32_list,
                field_57_u32_list,
                field_58_u32_list,
                field_59_u32,
                field_60_u32,
                field_61_u32,
                field_62_u32,
                field_63_u32,
                field_64_u32,
                field_65_u32,
                field_66_u32,
                field_67_u32,
                field_68_u32,
                field_69_u32,
                field_70_u32,
                field_71_u32,
                field_72_u32,
                field_73_u32,
                field_74_u32,
                field_75_u32,
                field_76_u32,
                field_77_u32,
                field_78_u32,
                field_79_u32,
                field_80_u32,
                field_81_u32,
                field_82_u32,
                field_83_u32,
                field_84_u32,
                field_85_u32,
                field_86_u32,
                field_87_u32,
                field_88_u32,
                field_89_u32,
                field_90_u32,
                field_91_u32,
                field_92_u32,
                field_93_u32,
                field_94_u32,
                field_95_u32,
                field_96_u32,
                field_97_u32,
                field_98_u32,
                field_99_u32,
                field_100_u32,
                field_101_u32,
                field_102_u32,
                field_103_u32,
                field_104_u32,
                field_105_u32,
                field_106_u32,
                field_107_u32,
                field_108_u32,
                field_109_u32,
                field_110_u32,
                field_111_u32,
                field_112_u32,
                field_113_u32,
                field_114_u32,
                field_115_u32,
                field_116_u32,
                field_117_u32,
                field_118_u32,
                field_119_u32,
                field_120_u32,
                field_121_u32,
                field_122_u32,
                field_123_u32,
                field_124_u32,
                field_125_u32,
                field_126_u32,
                field_127_u32,
                field_128_u32,
                field_129_u32,
                field_130_u32,
                field_131_u32,
                field_132_u32,
                field_133_u32,
                field_134_u32,
                field_135_u32,
                field_136_u32,
                field_137_u32,
                field_138_u32,
                field_139_u32,
                field_140_u32,
                field_141_u32,
                field_142_u32,
                field_143_u32,
                field_144_u32,
                field_145_u32,
                field_146_u32,
                field_147_u32,
                field_148_u32,
                field_149_u32,
                field_150_u32,
                field_151_u32,
                field_152_u32,
                field_153_u32,
                field_154_u32,
                field_155_u32,
                field_156_u32,
                field_157_u32,
                field_158_u32,
                field_159_u32,
                field_160_u32,
                field_161_u32,
                field_162_u32,
                field_163_u32,
                field_164_u32,
                field_165_u32,
                field_166_u32,
                field_167_u32,
                field_168_u32,
                field_169_u32,
                field_170_u32,
                field_171_u32,
                field_172_u32,
                field_173_u32,
                field_174_u32,
                field_175_u32,
                field_176_u32,
                field_177_u32,
                field_178_u32,
                field_179_u32,
                field_180_u32,
                field_181_u32,
                field_182_u32,
                field_183_u32,
                field_184_u32,
                field_185_u32,
                field_186_u32,
                field_187_u32,
                field_188_u32,
                field_189_u32,
                field_190_u32,
                field_191_u32,
                field_192_u32,
                field_193_u32,
                field_194_u32,
                field_195_u32,
                field_196_u32,
                field_197_u32,
                field_198_u32,
                field_199_u32,
                field_200_u32,
                field_201_u32,
                field_202_u32,
                field_203_u32,
                field_204_u32,
                field_205_u32,
                field_206_u32,
                field_207_u32,
                field_208_u32,
                field_209_u32,
                field_210_u32,
                field_211_u32,
                field_212_u32,
                field_213_u32,
                field_214_u32,
                field_215_u32,
                field_216_u32,
                field_217_u32,
                field_218_u32,
                field_219_u32,
                field_220_u32,
                field_221_u32,
                field_222_u32,
                field_223_u32,
                field_224_u32,
                field_225_u32,
                field_226_u32,
                field_227_u32,
                field_228_u32,
                field_229_u32,
                field_230_u32,
                field_231_u32,
                field_232_u32,
                field_233_u32,
                field_234_u32,
                field_235_u32,
                field_236_u32,
                field_237_u32,
                field_238_u32,
                field_239_u32,
                field_240_u32,
                field_241_u32,
                field_242_u32,
                field_243_u32,
                field_244_u32,
                field_245_u32,
                field_246_u32,
                field_247_u32,
                field_248_u32,
                field_249_u32,
                field_250_u32,
                field_251_u32,
                field_252_u32,
                field_253_u32,
                field_254_u32,
                field_255_u32,
                field_256_u32,
                field_257_u32,
                field_258_u32,
                field_259_u32,
                field_260_u32,
                field_261_u32,
                field_262_u32,
                field_263_u32,
                field_264_u32,
                field_265_u32,
                field_266_u32,
                field_267_u32,
                field_268_u32,
                field_269_u32,
                field_270_u32,
                field_271_u32,
                field_272_u32,
                field_273_u32,
                field_274_u32,
                field_275_u32,
                field_276_u32,
                field_277_u32,
                field_278_u32,
                field_279_u32,
                field_280_u32,
                field_281_u32,
                field_282_u32,
                field_283_u32,
                field_284_u32,
                field_285_u32,
                field_286_u32,
                field_287_u32,
                field_288_u32,
                field_289_u32,
                field_290_u32,
                field_291_u32,
                field_292_u32,
                field_293_u32,
                field_294_u32,
                field_295_u32,
                field_296_u32,
                field_297_u32,
                field_298_u32,
                field_299_u32,
                field_300_u32,
                field_301_u32,
                field_302_u32,
                field_303_u32,
                field_304_u32,
                field_305_u32,
                field_306_u32,
                field_307_u32,
                field_308_u32,
                field_309_u32,
                post_blob, ..
            } => {
                decoded += 1;
                if trigger_event_handler_list.is_some() { tgpehd_typed += 1; }
                if gimmick_chart_parameter_list.is_some() { chart_param_typed += 1; }
                if field_19_u32_list.is_some() { field_19_typed += 1; }
                if field_20_u32_list.is_some() { field_20_typed += 1; }
                if field_21_u32_list.is_some() { field_21_typed += 1; }
                if field_22_u32_list.is_some() { field_22_typed += 1; }
                if field_23_u32_list.is_some() { field_23_typed += 1; }
                if field_24_u32_list.is_some() { field_24_typed += 1; }
                if field_25_u32_list.is_some() { field_25_typed += 1; }
                if field_26_u32.is_some() { field_26_typed += 1; }
                if field_27_u32_list.is_some() { field_27_typed += 1; }
                if field_28_u32.is_some() { field_28_typed += 1; }
                if field_29_u32_list.is_some() { field_29_typed += 1; }
                if field_30_u32_list.is_some() { field_30_typed += 1; }
                if field_31_u32_list.is_some() { field_31_typed += 1; }
                if field_32_u32_list.is_some() { field_32_typed += 1; }
                if field_33_u32.is_some() { field_33_typed += 1; }
                if field_34_u32.is_some() { field_34_typed += 1; }
                if field_35_u32_list.is_some() { field_35_typed += 1; }
                if field_36_u32.is_some() { field_36_typed += 1; }
                if field_37_u32.is_some() { field_37_typed += 1; }
                if field_38_u32.is_some() { field_38_typed += 1; }
                if field_39_u32_list.is_some() { field_39_typed += 1; }
                if field_40_u32_list.is_some() { field_40_typed += 1; }
                if field_41_u32.is_some() { field_41_typed += 1; }
                if field_42_u32.is_some() { field_42_typed += 1; }
                if field_43_u32.is_some() { field_43_typed += 1; }
                if field_44_u32.is_some() { field_44_typed += 1; }
                if field_45_u32.is_some() { field_45_typed += 1; }
                if field_46_u32.is_some() { field_46_typed += 1; }
                if field_47_u32.is_some() { field_47_typed += 1; }
                if field_48_u32.is_some() { field_48_typed += 1; }
                if field_49_u32_list.is_some() { field_49_typed += 1; }
                if field_50_u32_list.is_some() { field_50_typed += 1; }
                if field_51_u32_list.is_some() { field_51_typed += 1; }
                if field_52_u32_list.is_some() { field_52_typed += 1; }
                if field_53_u32_list.is_some() { field_53_typed += 1; }
                if field_54_u32_list.is_some() { field_54_typed += 1; }
                if field_55_u32_list.is_some() { field_55_typed += 1; }
                if field_56_u32_list.is_some() { field_56_typed += 1; }
                if field_57_u32_list.is_some() { field_57_typed += 1; }
                if field_58_u32_list.is_some() { field_58_typed += 1; }
                if field_59_u32.is_some() { field_59_typed += 1; }
                if field_60_u32.is_some() { field_60_typed += 1; }
                if field_61_u32.is_some() { field_61_typed += 1; }
                if field_62_u32.is_some() { field_62_typed += 1; }
                if field_63_u32.is_some() { field_63_typed += 1; }
                if field_64_u32.is_some() { field_64_typed += 1; }
                if field_65_u32.is_some() { field_65_typed += 1; }
                if field_66_u32.is_some() { field_66_typed += 1; }
                if field_67_u32.is_some() { field_67_typed += 1; }
                if field_68_u32.is_some() { field_68_typed += 1; }
                if field_69_u32.is_some() { field_69_typed += 1; }
                if field_70_u32.is_some() { field_70_typed += 1; }
                if field_71_u32.is_some() { field_71_typed += 1; }
                if field_72_u32.is_some() { field_72_typed += 1; }
                if field_73_u32.is_some() { field_73_typed += 1; }
                if field_74_u32.is_some() { field_74_typed += 1; }
                if field_75_u32.is_some() { field_75_typed += 1; }
                if field_76_u32.is_some() { field_76_typed += 1; }
                if field_77_u32.is_some() { field_77_typed += 1; }
                if field_78_u32.is_some() { field_78_typed += 1; }
                if field_79_u32.is_some() { field_79_typed += 1; }
                if field_80_u32.is_some() { field_80_typed += 1; }
                if field_81_u32.is_some() { field_81_typed += 1; }
                if field_82_u32.is_some() { field_82_typed += 1; }
                if field_83_u32.is_some() { field_83_typed += 1; }
                if field_84_u32.is_some() { field_84_typed += 1; }
                if field_85_u32.is_some() { field_85_typed += 1; }
                if field_86_u32.is_some() { field_86_typed += 1; }
                if field_87_u32.is_some() { field_87_typed += 1; }
                if field_88_u32.is_some() { field_88_typed += 1; }
                if field_89_u32.is_some() { field_89_typed += 1; }
                if field_90_u32.is_some() { field_90_typed += 1; }
                if field_91_u32.is_some() { field_91_typed += 1; }
                if field_92_u32.is_some() { field_92_typed += 1; }
                if field_93_u32.is_some() { field_93_typed += 1; }
                if field_94_u32.is_some() { field_94_typed += 1; }
                if field_95_u32.is_some() { field_95_typed += 1; }
                if field_96_u32.is_some() { field_96_typed += 1; }
                if field_97_u32.is_some() { field_97_typed += 1; }
                if field_98_u32.is_some() { field_98_typed += 1; }
                if field_99_u32.is_some() { field_99_typed += 1; }
                if field_100_u32.is_some() { field_100_typed += 1; }
                if field_101_u32.is_some() { field_101_typed += 1; }
                if field_102_u32.is_some() { field_102_typed += 1; }
                if field_103_u32.is_some() { field_103_typed += 1; }
                if field_104_u32.is_some() { field_104_typed += 1; }
                if field_105_u32.is_some() { field_105_typed += 1; }
                if field_106_u32.is_some() { field_106_typed += 1; }
                if field_107_u32.is_some() { field_107_typed += 1; }
                if field_108_u32.is_some() { field_108_typed += 1; }
                if field_109_u32.is_some() { field_109_typed += 1; }
                if field_110_u32.is_some() { field_110_typed += 1; }
                if field_111_u32.is_some() { field_111_typed += 1; }
                if field_112_u32.is_some() { field_112_typed += 1; }
                if field_113_u32.is_some() { field_113_typed += 1; }
                if field_114_u32.is_some() { field_114_typed += 1; }
                if field_115_u32.is_some() { field_115_typed += 1; }
                if field_116_u32.is_some() { field_116_typed += 1; }
                if field_117_u32.is_some() { field_117_typed += 1; }
                if field_118_u32.is_some() { field_118_typed += 1; }
                if field_119_u32.is_some() { field_119_typed += 1; }
                if field_120_u32.is_some() { field_120_typed += 1; }
                if field_121_u32.is_some() { field_121_typed += 1; }
                if field_122_u32.is_some() { field_122_typed += 1; }
                if field_123_u32.is_some() { field_123_typed += 1; }
                if field_124_u32.is_some() { field_124_typed += 1; }
                if field_125_u32.is_some() { field_125_typed += 1; }
                if field_126_u32.is_some() { field_126_typed += 1; }
                if field_127_u32.is_some() { field_127_typed += 1; }
                if field_128_u32.is_some() { field_128_typed += 1; }
                if field_129_u32.is_some() { field_129_typed += 1; }
                if field_130_u32.is_some() { field_130_typed += 1; }
                if field_131_u32.is_some() { field_131_typed += 1; }
                if field_132_u32.is_some() { field_132_typed += 1; }
                if field_133_u32.is_some() { field_133_typed += 1; }
                if field_134_u32.is_some() { field_134_typed += 1; }
                if field_135_u32.is_some() { field_135_typed += 1; }
                if field_136_u32.is_some() { field_136_typed += 1; }
                if field_137_u32.is_some() { field_137_typed += 1; }
                if field_138_u32.is_some() { field_138_typed += 1; }
                if field_139_u32.is_some() { field_139_typed += 1; }
                if field_140_u32.is_some() { field_140_typed += 1; }
                if field_141_u32.is_some() { field_141_typed += 1; }
                if field_142_u32.is_some() { field_142_typed += 1; }
                if field_143_u32.is_some() { field_143_typed += 1; }
                if field_144_u32.is_some() { field_144_typed += 1; }
                if field_145_u32.is_some() { field_145_typed += 1; }
                if field_146_u32.is_some() { field_146_typed += 1; }
                if field_147_u32.is_some() { field_147_typed += 1; }
                if field_148_u32.is_some() { field_148_typed += 1; }
                if field_149_u32.is_some() { field_149_typed += 1; }
                if field_150_u32.is_some() { field_150_typed += 1; }
                if field_151_u32.is_some() { field_151_typed += 1; }
                if field_152_u32.is_some() { field_152_typed += 1; }
                if field_153_u32.is_some() { field_153_typed += 1; }
                if field_154_u32.is_some() { field_154_typed += 1; }
                if field_155_u32.is_some() { field_155_typed += 1; }
                if field_156_u32.is_some() { field_156_typed += 1; }
                if field_157_u32.is_some() { field_157_typed += 1; }
                if field_158_u32.is_some() { field_158_typed += 1; }
                if field_159_u32.is_some() { field_159_typed += 1; }
                if field_160_u32.is_some() { field_160_typed += 1; }
                if field_161_u32.is_some() { field_161_typed += 1; }
                if field_162_u32.is_some() { field_162_typed += 1; }
                if field_163_u32.is_some() { field_163_typed += 1; }
                if field_164_u32.is_some() { field_164_typed += 1; }
                if field_165_u32.is_some() { field_165_typed += 1; }
                if field_166_u32.is_some() { field_166_typed += 1; }
                if field_167_u32.is_some() { field_167_typed += 1; }
                if field_168_u32.is_some() { field_168_typed += 1; }
                if field_169_u32.is_some() { field_169_typed += 1; }
                if field_170_u32.is_some() { field_170_typed += 1; }
                if field_171_u32.is_some() { field_171_typed += 1; }
                if field_172_u32.is_some() { field_172_typed += 1; }
                if field_173_u32.is_some() { field_173_typed += 1; }
                if field_174_u32.is_some() { field_174_typed += 1; }
                if field_175_u32.is_some() { field_175_typed += 1; }
                if field_176_u32.is_some() { field_176_typed += 1; }
                if field_177_u32.is_some() { field_177_typed += 1; }
                if field_178_u32.is_some() { field_178_typed += 1; }
                if field_179_u32.is_some() { field_179_typed += 1; }
                if field_180_u32.is_some() { field_180_typed += 1; }
                if field_181_u32.is_some() { field_181_typed += 1; }
                if field_182_u32.is_some() { field_182_typed += 1; }
                if field_183_u32.is_some() { field_183_typed += 1; }
                if field_184_u32.is_some() { field_184_typed += 1; }
                if field_185_u32.is_some() { field_185_typed += 1; }
                if field_186_u32.is_some() { field_186_typed += 1; }
                if field_187_u32.is_some() { field_187_typed += 1; }
                if field_188_u32.is_some() { field_188_typed += 1; }
                if field_189_u32.is_some() { field_189_typed += 1; }
                if field_190_u32.is_some() { field_190_typed += 1; }
                if field_191_u32.is_some() { field_191_typed += 1; }
                if field_192_u32.is_some() { field_192_typed += 1; }
                if field_193_u32.is_some() { field_193_typed += 1; }
                if field_194_u32.is_some() { field_194_typed += 1; }
                if field_195_u32.is_some() { field_195_typed += 1; }
                if field_196_u32.is_some() { field_196_typed += 1; }
                if field_197_u32.is_some() { field_197_typed += 1; }
                if field_198_u32.is_some() { field_198_typed += 1; }
                if field_199_u32.is_some() { field_199_typed += 1; }
                if field_200_u32.is_some() { field_200_typed += 1; }
                if field_201_u32.is_some() { field_201_typed += 1; }
                if field_202_u32.is_some() { field_202_typed += 1; }
                if field_203_u32.is_some() { field_203_typed += 1; }
                if field_204_u32.is_some() { field_204_typed += 1; }
                if field_205_u32.is_some() { field_205_typed += 1; }
                if field_206_u32.is_some() { field_206_typed += 1; }
                if field_207_u32.is_some() { field_207_typed += 1; }
                if field_208_u32.is_some() { field_208_typed += 1; }
                if field_209_u32.is_some() { field_209_typed += 1; }
                if field_210_u32.is_some() { field_210_typed += 1; }
                if field_211_u32.is_some() { field_211_typed += 1; }
                if field_212_u32.is_some() { field_212_typed += 1; }
                if field_213_u32.is_some() { field_213_typed += 1; }
                if field_214_u32.is_some() { field_214_typed += 1; }
                if field_215_u32.is_some() { field_215_typed += 1; }
                if field_216_u32.is_some() { field_216_typed += 1; }
                if field_217_u32.is_some() { field_217_typed += 1; }
                if field_218_u32.is_some() { field_218_typed += 1; }
                if field_219_u32.is_some() { field_219_typed += 1; }
                if field_220_u32.is_some() { field_220_typed += 1; }
                if field_221_u32.is_some() { field_221_typed += 1; }
                if field_222_u32.is_some() { field_222_typed += 1; }
                if field_223_u32.is_some() { field_223_typed += 1; }
                if field_224_u32.is_some() { field_224_typed += 1; }
                if field_225_u32.is_some() { field_225_typed += 1; }
                if field_226_u32.is_some() { field_226_typed += 1; }
                if field_227_u32.is_some() { field_227_typed += 1; }
                if field_228_u32.is_some() { field_228_typed += 1; }
                if field_229_u32.is_some() { field_229_typed += 1; }
                if field_230_u32.is_some() { field_230_typed += 1; }
                if field_231_u32.is_some() { field_231_typed += 1; }
                if field_232_u32.is_some() { field_232_typed += 1; }
                if field_233_u32.is_some() { field_233_typed += 1; }
                if field_234_u32.is_some() { field_234_typed += 1; }
                if field_235_u32.is_some() { field_235_typed += 1; }
                if field_236_u32.is_some() { field_236_typed += 1; }
                if field_237_u32.is_some() { field_237_typed += 1; }
                if field_238_u32.is_some() { field_238_typed += 1; }
                if field_239_u32.is_some() { field_239_typed += 1; }
                if field_240_u32.is_some() { field_240_typed += 1; }
                if field_241_u32.is_some() { field_241_typed += 1; }
                if field_242_u32.is_some() { field_242_typed += 1; }
                if field_243_u32.is_some() { field_243_typed += 1; }
                if field_244_u32.is_some() { field_244_typed += 1; }
                if field_245_u32.is_some() { field_245_typed += 1; }
                if field_246_u32.is_some() { field_246_typed += 1; }
                if field_247_u32.is_some() { field_247_typed += 1; }
                if field_248_u32.is_some() { field_248_typed += 1; }
                if field_249_u32.is_some() { field_249_typed += 1; }
                if field_250_u32.is_some() { field_250_typed += 1; }
                if field_251_u32.is_some() { field_251_typed += 1; }
                if field_252_u32.is_some() { field_252_typed += 1; }
                if field_253_u32.is_some() { field_253_typed += 1; }
                if field_254_u32.is_some() { field_254_typed += 1; }
                if field_255_u32.is_some() { field_255_typed += 1; }
                if field_256_u32.is_some() { field_256_typed += 1; }
                if field_257_u32.is_some() { field_257_typed += 1; }
                if field_258_u32.is_some() { field_258_typed += 1; }
                if field_259_u32.is_some() { field_259_typed += 1; }
                if field_260_u32.is_some() { field_260_typed += 1; }
                if field_261_u32.is_some() { field_261_typed += 1; }
                if field_262_u32.is_some() { field_262_typed += 1; }
                if field_263_u32.is_some() { field_263_typed += 1; }
                if field_264_u32.is_some() { field_264_typed += 1; }
                if field_265_u32.is_some() { field_265_typed += 1; }
                if field_266_u32.is_some() { field_266_typed += 1; }
                if field_267_u32.is_some() { field_267_typed += 1; }
                if field_268_u32.is_some() { field_268_typed += 1; }
                if field_269_u32.is_some() { field_269_typed += 1; }
                if field_270_u32.is_some() { field_270_typed += 1; }
                if field_271_u32.is_some() { field_271_typed += 1; }
                if field_272_u32.is_some() { field_272_typed += 1; }
                if field_273_u32.is_some() { field_273_typed += 1; }
                if field_274_u32.is_some() { field_274_typed += 1; }
                if field_275_u32.is_some() { field_275_typed += 1; }
                if field_276_u32.is_some() { field_276_typed += 1; }
                if field_277_u32.is_some() { field_277_typed += 1; }
                if field_278_u32.is_some() { field_278_typed += 1; }
                if field_279_u32.is_some() { field_279_typed += 1; }
                if field_280_u32.is_some() { field_280_typed += 1; }
                if field_281_u32.is_some() { field_281_typed += 1; }
                if field_282_u32.is_some() { field_282_typed += 1; }
                if field_283_u32.is_some() { field_283_typed += 1; }
                if field_284_u32.is_some() { field_284_typed += 1; }
                if field_285_u32.is_some() { field_285_typed += 1; }
                if field_286_u32.is_some() { field_286_typed += 1; }
                if field_287_u32.is_some() { field_287_typed += 1; }
                if field_288_u32.is_some() { field_288_typed += 1; }
                if field_289_u32.is_some() { field_289_typed += 1; }
                if field_290_u32.is_some() { field_290_typed += 1; }
                if field_291_u32.is_some() { field_291_typed += 1; }
                if field_292_u32.is_some() { field_292_typed += 1; }
                if field_293_u32.is_some() { field_293_typed += 1; }
                if field_294_u32.is_some() { field_294_typed += 1; }
                if field_295_u32.is_some() { field_295_typed += 1; }
                if field_296_u32.is_some() { field_296_typed += 1; }
                if field_297_u32.is_some() { field_297_typed += 1; }
                if field_298_u32.is_some() { field_298_typed += 1; }
                if field_299_u32.is_some() { field_299_typed += 1; }
                if field_300_u32.is_some() { field_300_typed += 1; }
                if field_301_u32.is_some() { field_301_typed += 1; }
                if field_302_u32.is_some() { field_302_typed += 1; }
                if field_303_u32.is_some() { field_303_typed += 1; }
                if field_304_u32.is_some() { field_304_typed += 1; }
                if field_305_u32.is_some() { field_305_typed += 1; }
                if field_306_u32.is_some() { field_306_typed += 1; }
                if field_307_u32.is_some() { field_307_typed += 1; }
                if field_308_u32.is_some() { field_308_typed += 1; }
                if field_309_u32.is_some() { field_309_typed += 1; }
                post_blob_sizes.push(post_blob.len());
            }
            GimmickTail::Raw(_) => { raw += 1; }
        }
    }

    println!("Total entries: {}", ranges.len());
    println!("Decoded:       {}", decoded);
    println!("Raw:           {}", raw);
    println!("TGPEHD typed:  {} / {}", tgpehd_typed, decoded);
    println!("Field 18 (gimmick_chart_parameter_list) typed: {} / {}", chart_param_typed, decoded);
    println!("Field 19 (field_19_u32_list) typed:            {} / {}", field_19_typed, decoded);
    println!("Field 20 (field_20_u32_list) typed:            {} / {}", field_20_typed, decoded);
    println!("Field 21 (field_21_u32_list) typed:            {} / {}", field_21_typed, decoded);
    println!("Field 22 (field_22_u32_list) typed:            {} / {}", field_22_typed, decoded);
    println!("Field 23 (field_23_u32_list) typed:            {} / {}", field_23_typed, decoded);
    println!("Field 24 (field_24_u32_list) typed:            {} / {}", field_24_typed, decoded);
    println!("Field 25 (field_25_u32_list) typed:            {} / {}", field_25_typed, decoded);
    println!("Field 26 (field_26_u32 single u32)  typed:     {} / {}", field_26_typed, decoded);
    println!("Field 27 (field_27_u32_list)         typed:     {} / {}", field_27_typed, decoded);
    println!("Field 28 (field_28_u32 single u32)   typed:     {} / {}", field_28_typed, decoded);
    println!("Field 29 (field_29_u32_list)         typed:     {} / {}", field_29_typed, decoded);
    println!("Field 30 (field_30_u32_list)         typed:     {} / {}", field_30_typed, decoded);
    println!("Field 31 (field_31_u32_list)         typed:     {} / {}", field_31_typed, decoded);
    println!("Field 32 (field_32_u32_list)         typed:     {} / {}", field_32_typed, decoded);
    println!("Field 33 (field_33_u32 single u32)   typed:     {} / {}", field_33_typed, decoded);
    println!("Field 34 (field_34_u32 single u32)   typed:     {} / {}", field_34_typed, decoded);
    println!("Field 35 (field_35_u32_list)         typed:     {} / {}", field_35_typed, decoded);
    println!("Field 36 (field_36_u32 single u32)   typed:     {} / {}", field_36_typed, decoded);
    println!("Field 37 (field_37_u32 single u32)   typed:     {} / {}", field_37_typed, decoded);
    println!("Field 38 (field_38_u32 single u32)   typed:     {} / {}", field_38_typed, decoded);
    println!("Field 39 (field_39_u32_list)         typed:     {} / {}", field_39_typed, decoded);
    println!("Field 40 (field_40_u32_list)         typed:     {} / {}", field_40_typed, decoded);
    println!("Field 41 (field_41_u32 single u32)   typed:     {} / {}", field_41_typed, decoded);
    println!("Field 42 (field_42_u32 single u32)   typed:     {} / {}", field_42_typed, decoded);
    println!("Field 43 (field_43_u32 single u32)   typed:     {} / {}", field_43_typed, decoded);
    println!("Field 44 (field_44_u32 single u32)   typed:     {} / {}", field_44_typed, decoded);
    println!("Field 45 (field_45_u32 single u32)   typed:     {} / {}", field_45_typed, decoded);
    println!("Field 46 (field_46_u32 single u32)   typed:     {} / {}", field_46_typed, decoded);
    println!("Field 47 (field_47_u32 single u32)   typed:     {} / {}", field_47_typed, decoded);
    println!("Field 48 (field_48_u32 single u32)   typed:     {} / {}", field_48_typed, decoded);
    println!("Field 49 (field_49_u32_list)          typed:     {} / {}", field_49_typed, decoded);
    println!("Field 50 (field_50_u32_list)          typed:     {} / {}", field_50_typed, decoded);
    println!("Field 51 (field_51_u32_list)          typed:     {} / {}", field_51_typed, decoded);
    println!("Field 52 (field_52_u32_list)          typed:     {} / {}", field_52_typed, decoded);
    println!("Field 53 (field_53_u32_list)          typed:     {} / {}", field_53_typed, decoded);
    println!("Field 54 (field_54_u32_list)          typed:     {} / {}", field_54_typed, decoded);
    println!("Field 55 (field_55_u32_list)          typed:     {} / {}", field_55_typed, decoded);
    println!("Field 56 (field_56_u32_list)          typed:     {} / {}", field_56_typed, decoded);
    println!("Field 57 (field_57_u32_list)          typed:     {} / {}", field_57_typed, decoded);
    println!("Field 58 (field_58_u32_list)          typed:     {} / {}", field_58_typed, decoded);
    println!("Field 59 (field_59_u32 = f32 0.5)     typed:     {} / {}", field_59_typed, decoded);
    println!("Field 60 (field_60_u32 = f32 0.1)     typed:     {} / {}", field_60_typed, decoded);
    println!("Field 61 (field_61_u32 = f32 0.1)     typed:     {} / {}", field_61_typed, decoded);
    println!("Field 62 (field_62_u32 = 257 flag)    typed:     {} / {}", field_62_typed, decoded);
    println!("Field 63 (field_63_u32 = 0)           typed:     {} / {}", field_63_typed, decoded);
    println!("Field 64 (field_64_u32 = 0)           typed:     {} / {}", field_64_typed, decoded);
    println!("Field 65 (field_65_u32 = f32 5.0)     typed:     {} / {}", field_65_typed, decoded);
    println!("Field 66 (field_66_u32 = f32 1.0)     typed:     {} / {}", field_66_typed, decoded);
    for (i, count) in [(67usize, field_67_typed), (68, field_68_typed), (69, field_69_typed),
                       (70, field_70_typed), (71, field_71_typed), (72, field_72_typed),
                       (73, field_73_typed), (74, field_74_typed),
                       (75, field_75_typed), (76, field_76_typed), (77, field_77_typed),
                       (78, field_78_typed), (79, field_79_typed), (80, field_80_typed),
                       (81, field_81_typed), (82, field_82_typed),
                       (83, field_83_typed), (84, field_84_typed), (85, field_85_typed),
                       (86, field_86_typed), (87, field_87_typed), (88, field_88_typed),
                       (89, field_89_typed), (90, field_90_typed),
                       (91, field_91_typed), (92, field_92_typed),
                       (93, field_93_typed), (94, field_94_typed),
                       (95, field_95_typed), (96, field_96_typed),
                       (97, field_97_typed), (98, field_98_typed),
                       (99, field_99_typed), (100, field_100_typed),
                       (101, field_101_typed), (102, field_102_typed),
                       (103, field_103_typed), (104, field_104_typed),
                       (105, field_105_typed), (106, field_106_typed),
                       (107, field_107_typed), (108, field_108_typed),
                       (109, field_109_typed), (110, field_110_typed),
                       (111, field_111_typed), (112, field_112_typed),
                       (113, field_113_typed), (114, field_114_typed),
                       (115, field_115_typed), (116, field_116_typed),
                       (117, field_117_typed), (118, field_118_typed),
                       (119, field_119_typed), (120, field_120_typed),
                       (121, field_121_typed), (122, field_122_typed),
                       (123, field_123_typed), (124, field_124_typed),
                       (125, field_125_typed), (126, field_126_typed),
                       (127, field_127_typed), (128, field_128_typed),
                       (129, field_129_typed), (130, field_130_typed),
                       (131, field_131_typed), (132, field_132_typed),
                       (133, field_133_typed), (134, field_134_typed),
                       (135, field_135_typed), (136, field_136_typed),
                       (137, field_137_typed), (138, field_138_typed),
                       (139, field_139_typed), (140, field_140_typed),
                       (141, field_141_typed), (142, field_142_typed),
                       (143, field_143_typed), (144, field_144_typed),
                       (145, field_145_typed), (146, field_146_typed),
                       (147, field_147_typed), (148, field_148_typed),
                       (149, field_149_typed), (150, field_150_typed),
                       (151, field_151_typed), (152, field_152_typed),
                       (153, field_153_typed), (154, field_154_typed),
                       (155, field_155_typed), (156, field_156_typed),
                       (157, field_157_typed), (158, field_158_typed),
                       (159, field_159_typed), (160, field_160_typed),
                       (161, field_161_typed), (162, field_162_typed),
                       (163, field_163_typed), (164, field_164_typed),
                       (165, field_165_typed), (166, field_166_typed),
                       (167, field_167_typed), (168, field_168_typed),
                       (169, field_169_typed), (170, field_170_typed),
                       (171, field_171_typed), (172, field_172_typed),
                       (173, field_173_typed), (174, field_174_typed),
                       (175, field_175_typed), (176, field_176_typed),
                       (177, field_177_typed), (178, field_178_typed),
                       (179, field_179_typed), (180, field_180_typed),
                       (181, field_181_typed), (182, field_182_typed),
                       (183, field_183_typed), (184, field_184_typed),
                       (185, field_185_typed), (186, field_186_typed),
                       (187, field_187_typed), (188, field_188_typed),
                       (189, field_189_typed), (190, field_190_typed),
                       (191, field_191_typed), (192, field_192_typed),
                       (193, field_193_typed), (194, field_194_typed),
                       (195, field_195_typed), (196, field_196_typed),
                       (197, field_197_typed), (198, field_198_typed),
                       (199, field_199_typed), (200, field_200_typed),
                       (201, field_201_typed), (202, field_202_typed),
                       (203, field_203_typed), (204, field_204_typed),
                       (205, field_205_typed), (206, field_206_typed),
                       (207, field_207_typed), (208, field_208_typed),
                       (209, field_209_typed), (210, field_210_typed),
                       (211, field_211_typed), (212, field_212_typed),
                       (213, field_213_typed), (214, field_214_typed),
                       (215, field_215_typed), (216, field_216_typed),
                       (217, field_217_typed), (218, field_218_typed),
                       (219, field_219_typed), (220, field_220_typed),
                       (221, field_221_typed), (222, field_222_typed),
                       (223, field_223_typed), (224, field_224_typed),
                       (225, field_225_typed), (226, field_226_typed),
                       (227, field_227_typed), (228, field_228_typed),
                       (229, field_229_typed), (230, field_230_typed),
                       (231, field_231_typed), (232, field_232_typed),
                       (233, field_233_typed), (234, field_234_typed),
                       (235, field_235_typed), (236, field_236_typed),
                       (237, field_237_typed), (238, field_238_typed),
                       (239, field_239_typed), (240, field_240_typed),
                       (241, field_241_typed), (242, field_242_typed),
                       (243, field_243_typed), (244, field_244_typed),
                       (245, field_245_typed), (246, field_246_typed),
                       (247, field_247_typed), (248, field_248_typed),
                       (249, field_249_typed), (250, field_250_typed),
                       (251, field_251_typed), (252, field_252_typed),
                       (253, field_253_typed), (254, field_254_typed),
                       (255, field_255_typed), (256, field_256_typed),
                       (257, field_257_typed), (258, field_258_typed),
                       (259, field_259_typed), (260, field_260_typed),
                       (261, field_261_typed), (262, field_262_typed),
                       (263, field_263_typed), (264, field_264_typed),
                       (265, field_265_typed), (266, field_266_typed),
                       (267, field_267_typed), (268, field_268_typed),
                       (269, field_269_typed), (270, field_270_typed),
                       (271, field_271_typed), (272, field_272_typed),
                       (273, field_273_typed), (274, field_274_typed),
                       (275, field_275_typed), (276, field_276_typed),
                       (277, field_277_typed), (278, field_278_typed),
                       (279, field_279_typed), (280, field_280_typed),
                       (281, field_281_typed), (282, field_282_typed),
                       (283, field_283_typed), (284, field_284_typed),
                       (285, field_285_typed), (286, field_286_typed),
                       (287, field_287_typed), (288, field_288_typed),
                       (289, field_289_typed), (290, field_290_typed),
                       (291, field_291_typed), (292, field_292_typed),
                       (293, field_293_typed), (294, field_294_typed),
                       (295, field_295_typed), (296, field_296_typed),
                       (297, field_297_typed), (298, field_298_typed),
                       (299, field_299_typed), (300, field_300_typed),
                       (301, field_301_typed), (302, field_302_typed),
                       (303, field_303_typed), (304, field_304_typed),
                       (305, field_305_typed), (306, field_306_typed),
                       (307, field_307_typed), (308, field_308_typed),
                       (309, field_309_typed)] {
        println!("Field {} (field_{}_u32)                  typed:     {} / {}", i, i, count, decoded);
    }

    post_blob_sizes.sort();
    if !post_blob_sizes.is_empty() {
        let n = post_blob_sizes.len();
        println!("\npost_blob size distribution:");
        println!("  min={}", post_blob_sizes[0]);
        println!("  p25={}", post_blob_sizes[n/4]);
        println!("  p50={}", post_blob_sizes[n/2]);
        println!("  p75={}", post_blob_sizes[3*n/4]);
        println!("  max={}", post_blob_sizes[n-1]);
        println!("  avg={}", post_blob_sizes.iter().sum::<usize>() / n);
        println!("  total bytes: {}", post_blob_sizes.iter().sum::<usize>());
    }
}
