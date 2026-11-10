//! Decodes the jump an inline hook writes over a function's first bytes, so a finding can
//! say where control goes (an overlay module, a cheat module, or unbacked memory).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Patch {
    /// Control transfers to this address.
    Jump(u64),
    /// `int3` breakpoint byte (software breakpoint or a VEH-based hook).
    Breakpoint,
    /// Bytes differ but don't form a recognised jump.
    Unknown,
}

/// `code` is memory at `addr`. `read_ptr` reads an 8-byte pointer (for `jmp [rip+disp]`).
pub fn decode(code: &[u8], addr: u64, read_ptr: impl Fn(u64) -> Option<u64>) -> Patch {
    let b = |i: usize| code.get(i).copied();
    let i32_at = |i: usize| code.get(i..i + 4).map(|s| i32::from_le_bytes(s.try_into().unwrap()));
    let u32_at = |i: usize| code.get(i..i + 4).map(|s| u32::from_le_bytes(s.try_into().unwrap()));
    let u64_at = |i: usize| code.get(i..i + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap()));
    match (b(0), b(1)) {
        // jmp rel32
        (Some(0xE9), _) => i32_at(1).map_or(Patch::Unknown, |r| Patch::Jump(addr.wrapping_add(5).wrapping_add(r as i64 as u64))),
        // jmp rel8 (usually to a longer jump placed nearby)
        (Some(0xEB), Some(r)) => Patch::Jump(addr.wrapping_add(2).wrapping_add(r as i8 as i64 as u64)),
        // jmp qword ptr [rip+disp32]
        (Some(0xFF), Some(0x25)) => match i32_at(2) {
            Some(d) => read_ptr(addr.wrapping_add(6).wrapping_add(d as i64 as u64)).map_or(Patch::Unknown, Patch::Jump),
            None => Patch::Unknown,
        },
        // mov rax, imm64; jmp rax
        (Some(0x48), Some(0xB8)) if code.get(10..12) == Some(&[0xFF, 0xE0]) => u64_at(2).map_or(Patch::Unknown, Patch::Jump),
        // mov r11, imm64; jmp r11
        (Some(0x49), Some(0xBB)) if code.get(10..13) == Some(&[0x41, 0xFF, 0xE3]) => u64_at(2).map_or(Patch::Unknown, Patch::Jump),
        // push imm32; mov dword ptr [rsp+4], imm32; ret
        (Some(0x68), _) if code.get(5..9) == Some(&[0xC7, 0x44, 0x24, 0x04]) && b(13) == Some(0xC3) => {
            match (u32_at(1), u32_at(9)) {
                (Some(lo), Some(hi)) => Patch::Jump((hi as u64) << 32 | lo as u64),
                _ => Patch::Unknown,
            }
        }
        // push imm32; ret
        (Some(0x68), _) if b(5) == Some(0xC3) => u32_at(1).map_or(Patch::Unknown, |v| Patch::Jump(v as i32 as i64 as u64)),
        (Some(0xCC), _) => Patch::Breakpoint,
        _ => Patch::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: u64 = 0x7ff8_0000_1000;

    #[test]
    fn decodes_common_trampolines() {
        let none = |_| None;
        assert_eq!(decode(&[0xE9, 0xFB, 0xFF, 0xFF, 0xFF], AT, none), Patch::Jump(AT));
        assert_eq!(decode(&[0xE9, 0x10, 0x00, 0x00, 0x00], AT, none), Patch::Jump(AT + 0x15));
        assert_eq!(decode(&[0xEB, 0xFE], AT, none), Patch::Jump(AT));
        let mut movjmp = vec![0x48, 0xB8];
        movjmp.extend_from_slice(&0x1234_5678_9abc_u64.to_le_bytes());
        movjmp.extend_from_slice(&[0xFF, 0xE0]);
        assert_eq!(decode(&movjmp, AT, none), Patch::Jump(0x1234_5678_9abc));
        let mut r11 = vec![0x49, 0xBB];
        r11.extend_from_slice(&0x2000_0000_u64.to_le_bytes());
        r11.extend_from_slice(&[0x41, 0xFF, 0xE3]);
        assert_eq!(decode(&r11, AT, none), Patch::Jump(0x2000_0000));
        let pushret = [0x68, 0x78, 0x56, 0x34, 0x12, 0xC7, 0x44, 0x24, 0x04, 0x01, 0x00, 0x00, 0x00, 0xC3];
        assert_eq!(decode(&pushret, AT, none), Patch::Jump(0x1_1234_5678));
        assert_eq!(decode(&[0xCC, 0x90], AT, none), Patch::Breakpoint);
        assert_eq!(decode(&[0x48, 0x83, 0xEC, 0x28], AT, none), Patch::Unknown);
    }

    #[test]
    fn follows_rip_relative_indirect_jump() {
        let code = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
        let slot = AT + 6;
        assert_eq!(decode(&code, AT, |p| (p == slot).then_some(0xdead_0000)), Patch::Jump(0xdead_0000));
        assert_eq!(decode(&code, AT, |_| None), Patch::Unknown);
    }

    #[test]
    fn truncated_input_is_unknown() {
        assert_eq!(decode(&[0xE9, 0x00], AT, |_| None), Patch::Unknown);
        assert_eq!(decode(&[], AT, |_| None), Patch::Unknown);
    }
}
