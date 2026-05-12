use crate::binary::*;
use crate::py_binary_struct;

py_binary_struct! {
    pub struct NpcActivityInfo<'a> {
        pub key: u32,
        pub activity_key: CString<'a>,
        pub is_blocked: u8,
        pub unk_a: u32,
        pub unk_b: u32,
        pub unk_c: u32,
        pub unk_d: u8,
        pub linked_activity_key: CString<'a>,
    }
}
