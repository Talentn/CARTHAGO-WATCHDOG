//! Minimal PE32+ reader over positioned reads, for comparing loaded code with the on-disk
//! image. It reads headers, the section table, exports and base relocations, and never
//! loads a whole file: a scan step reads only the window it compares.

/// Positioned reads. For a [`DiskImage`] offsets are file offsets; for a mapped image they
/// are RVAs. `false` on a short or failed read.
pub trait Reader {
    fn read(&self, off: u64, buf: &mut [u8]) -> bool;
}

impl Reader for [u8] {
    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        let Ok(off) = usize::try_from(off) else { return false };
        match off.checked_add(buf.len()).and_then(|end| self.get(off..end)) {
            Some(src) => {
                buf.copy_from_slice(src);
                true
            }
            None => false,
        }
    }
}

impl Reader for Vec<u8> {
    fn read(&self, off: u64, buf: &mut [u8]) -> bool {
        self.as_slice().read(off, buf)
    }
}

fn rd<const N: usize>(r: &(impl Reader + ?Sized), off: u64) -> Option<[u8; N]> {
    let mut b = [0u8; N];
    r.read(off, &mut b).then_some(b)
}

fn u16_at(r: &(impl Reader + ?Sized), off: u64) -> Option<u16> {
    rd::<2>(r, off).map(u16::from_le_bytes)
}

fn u32_at(r: &(impl Reader + ?Sized), off: u64) -> Option<u32> {
    rd::<4>(r, off).map(u32::from_le_bytes)
}

fn u64_at(r: &(impl Reader + ?Sized), off: u64) -> Option<u64> {
    rd::<8>(r, off).map(u64::from_le_bytes)
}

pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const DIR_EXPORT: usize = 0;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_IAT: usize = 12;

const MAX_SECTIONS: u16 = 96;
const MAX_RELOCS: usize = 1 << 20;
/// Largest relocation directory read: enough for `MAX_RELOCS` entries plus block headers.
/// The size comes from the file, so it bounds an allocation a crafted image would choose.
const MAX_RELOC_DIR: u32 = 4 << 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dir {
    pub rva: u32,
    pub size: u32,
}

impl Dir {
    pub fn contains(&self, rva: u32) -> bool {
        rva >= self.rva && rva - self.rva < self.size
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub name: [u8; 8],
    pub va: u32,
    pub vsize: u32,
    pub raw_off: u32,
    pub raw_size: u32,
    pub chars: u32,
}

impl Section {
    pub fn is_exec(&self) -> bool {
        self.chars & SCN_MEM_EXECUTE != 0
    }
    pub fn span(&self) -> u32 {
        self.vsize.max(self.raw_size)
    }
}

#[derive(Debug, Clone)]
pub struct Headers {
    pub image_base: u64,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub sections: Vec<Section>,
    pub dirs: [Dir; 16],
}

impl Headers {
    /// Parses DOS, NT and optional headers plus the section table. Header offsets are the
    /// same in a file and in a mapped image, so this works on both. PE32+ only.
    pub fn parse(r: &(impl Reader + ?Sized)) -> Option<Self> {
        if rd::<2>(r, 0)? != *b"MZ" {
            return None;
        }
        let nt = u32_at(r, 0x3c)? as u64;
        if nt > 0x1000 || rd::<4>(r, nt)? != *b"PE\0\0" {
            return None;
        }
        let nsec = u16_at(r, nt + 6)?;
        let opt_size = u16_at(r, nt + 20)? as u64;
        let opt = nt + 24;
        if u16_at(r, opt)? != 0x20b || nsec > MAX_SECTIONS {
            return None;
        }
        let image_base = u64_at(r, opt + 24)?;
        let size_of_image = u32_at(r, opt + 56)?;
        let size_of_headers = u32_at(r, opt + 60)?;
        let ndirs = u32_at(r, opt + 108)?.min(16) as u64;
        let mut dirs = [Dir::default(); 16];
        for (i, d) in dirs.iter_mut().enumerate().take(ndirs as usize) {
            let o = opt + 112 + i as u64 * 8;
            *d = Dir { rva: u32_at(r, o)?, size: u32_at(r, o + 4)? };
        }
        let mut sections = Vec::with_capacity(nsec as usize);
        let st = opt + opt_size;
        for i in 0..nsec as u64 {
            let s = st + i * 40;
            sections.push(Section {
                name: rd::<8>(r, s)?,
                vsize: u32_at(r, s + 8)?,
                va: u32_at(r, s + 12)?,
                raw_size: u32_at(r, s + 16)?,
                raw_off: u32_at(r, s + 20)?,
                chars: u32_at(r, s + 36)?,
            });
        }
        Some(Self { image_base, size_of_image, size_of_headers, sections, dirs })
    }

    pub fn section_of(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| rva >= s.va && rva - s.va < s.span())
    }

    pub fn exec_sections(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter().filter(|s| s.is_exec())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Export {
    Code { rva: u32, eat_slot_rva: u32 },
    Forwarded,
}

/// An on-disk image read through file offsets, presented by RVA.
pub struct DiskImage<R: Reader> {
    r: R,
    pub h: Headers,
    /// Sorted RVAs of DIR64 relocations, loaded on demand.
    relocs: Vec<u32>,
    relocs_loaded: bool,
    /// False until the whole relocation directory has been parsed; without it the bytes of
    /// a rebased image cannot be predicted.
    relocs_ok: bool,
}

impl<R: Reader> DiskImage<R> {
    pub fn open(r: R) -> Option<Self> {
        let h = Headers::parse(&r)?;
        Some(Self { r, h, relocs: Vec::new(), relocs_loaded: false, relocs_ok: false })
    }

    /// Fills `buf` with what the loader maps at `rva` (before relocation): file bytes, zero
    /// beyond a section's raw data.
    pub fn read_rva(&self, rva: u32, buf: &mut [u8]) -> bool {
        if rva < self.h.size_of_headers {
            return buf.len() as u64 <= (self.h.size_of_headers - rva) as u64 && self.r.read(rva as u64, buf);
        }
        let Some(s) = self.h.section_of(rva) else { return false };
        let off_in = rva - s.va;
        let end = off_in as u64 + buf.len() as u64;
        if end > s.span() as u64 {
            return false;
        }
        let raw_avail = s.raw_size.saturating_sub(off_in) as usize;
        let n = raw_avail.min(buf.len());
        if n > 0 && !self.r.read(s.raw_off as u64 + off_in as u64, &mut buf[..n]) {
            return false;
        }
        buf[n..].fill(0);
        true
    }

    fn u32_rva(&self, rva: u32) -> Option<u32> {
        let mut b = [0u8; 4];
        self.read_rva(rva, &mut b).then(|| u32::from_le_bytes(b))
    }

    fn u16_rva(&self, rva: u32) -> Option<u16> {
        let mut b = [0u8; 2];
        self.read_rva(rva, &mut b).then(|| u16::from_le_bytes(b))
    }

    /// Looks an export up by name (binary search over the sorted name table).
    pub fn export(&self, name: &str) -> Option<Export> {
        let d = self.h.dirs[DIR_EXPORT];
        if d.size == 0 {
            return None;
        }
        // Every offset below comes from the file: a crafted image must not overflow them.
        let field = |off: u32| self.u32_rva(d.rva.checked_add(off)?);
        let nfuncs = field(20)?;
        let nnames = field(24)?;
        let funcs = field(28)?;
        let names = field(32)?;
        let ords = field(36)?;
        let (mut lo, mut hi) = (0u32, nnames.min(1 << 16));
        let mut buf = [0u8; 96];
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let nrva = self.u32_rva(names.checked_add(mid * 4)?)?;
            let cand = self.c_str(nrva, &mut buf)?;
            match cand.cmp(name.as_bytes()) {
                std::cmp::Ordering::Equal => {
                    let ord = self.u16_rva(ords.checked_add(mid * 2)?)? as u32;
                    if ord >= nfuncs {
                        return None;
                    }
                    let slot = funcs.checked_add(ord * 4)?;
                    let rva = self.u32_rva(slot)?;
                    return Some(if d.contains(rva) { Export::Forwarded } else { Export::Code { rva, eat_slot_rva: slot } });
                }
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    fn c_str<'b>(&self, rva: u32, buf: &'b mut [u8; 96]) -> Option<&'b [u8]> {
        // Names can sit near the end of a section, so read byte runs that may come up short.
        let mut n = 0;
        while n < buf.len() {
            let chunk = 16.min(buf.len() - n);
            let at = rva.checked_add(n as u32)?;
            if !self.read_rva(at, &mut buf[n..n + chunk]) {
                if !self.read_rva(at, &mut buf[n..n + 1]) {
                    return None;
                }
                if buf[n] == 0 {
                    return Some(&buf[..n]);
                }
                n += 1;
                continue;
            }
            if let Some(z) = buf[n..n + chunk].iter().position(|&c| c == 0) {
                return Some(&buf[..n + z]);
            }
            n += chunk;
        }
        None
    }

    /// Parses the base relocation directory once (DIR64 entries only; x64 images use no
    /// other kind). `false` if the directory is missing from the file, malformed or larger
    /// than this reader accepts; [`Self::expected`] then refuses a rebased image.
    pub fn load_relocs(&mut self) -> bool {
        if !self.relocs_loaded {
            self.relocs_loaded = true;
            self.relocs_ok = self.parse_relocs().is_some();
            if !self.relocs_ok {
                self.relocs = Vec::new();
            }
        }
        self.relocs_ok
    }

    fn parse_relocs(&mut self) -> Option<()> {
        let d = self.h.dirs[DIR_BASERELOC];
        if d.size == 0 {
            return Some(());
        }
        if d.size > MAX_RELOC_DIR {
            return None;
        }
        let mut data = vec![0u8; d.size as usize];
        if !self.read_rva(d.rva, &mut data) {
            return None;
        }
        let mut off = 0usize;
        while off + 8 <= data.len() {
            let page = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
            let size = u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()) as usize;
            // Zero padding ends the directory; any other block that does not fit is damage.
            if size == 0 {
                break;
            }
            if size < 8 || size > data.len() - off {
                return None;
            }
            for e in data[off + 8..off + size].as_chunks::<2>().0 {
                let e = u16::from_le_bytes([e[0], e[1]]);
                if e >> 12 == 10 {
                    if self.relocs.len() >= MAX_RELOCS {
                        return None;
                    }
                    self.relocs.push(page.checked_add((e & 0xfff) as u32)?);
                }
            }
            off += size;
        }
        self.relocs.sort_unstable();
        Some(())
    }

    pub fn reloc_count(&self) -> usize {
        self.relocs.len()
    }

    /// What should be in memory at `rva` when the image is loaded at `actual_base`: the
    /// disk bytes with every overlapping DIR64 relocation applied. Needs [`Self::load_relocs`].
    pub fn expected(&self, rva: u32, buf: &mut [u8], actual_base: u64) -> bool {
        if !self.read_rva(rva, buf) {
            return false;
        }
        let delta = actual_base.wrapping_sub(self.h.image_base);
        if delta == 0 {
            return true;
        }
        if !self.relocs_ok {
            return false;
        }
        let (start, end) = (rva as u64, rva as u64 + buf.len() as u64);
        let first = self.relocs.partition_point(|&r| (r as u64) + 8 <= start);
        for &r in &self.relocs[first..] {
            let r = r as u64;
            if r >= end {
                break;
            }
            let mut v = [0u8; 8];
            if !self.read_rva(r as u32, &mut v) {
                continue;
            }
            let patched = u64::from_le_bytes(v).wrapping_add(delta).to_le_bytes();
            for (i, b) in patched.iter().enumerate() {
                let at = r + i as u64;
                if at >= start && at < end {
                    buf[(at - start) as usize] = *b;
                }
            }
        }
        true
    }
}

/// Largest executable section walked page by page (the graphics runtime DLLs this is used
/// on are a few MB). The size comes from the image's own headers.
pub const MAX_EXEC_SECTION: u32 = 256 << 20;

/// Splits a section into `(rva, len)` windows of at most `page` bytes. `false`, adding
/// nothing, if the section is larger than [`MAX_EXEC_SECTION`], lies outside the image or
/// its range overflows: the caller then skips the module.
pub fn section_pages(h: &Headers, s: &Section, page: u32, out: &mut Vec<(u32, u32)>) -> bool {
    let Some(end) = s.va.checked_add(s.vsize) else { return false };
    if s.vsize > MAX_EXEC_SECTION || end > h.size_of_image || page == 0 {
        return false;
    }
    let mut at = s.va;
    while at < end {
        let len = page.min(end - at);
        out.push((at, len));
        at += len;
    }
    true
}

/// First offset where `actual` and `expected` differ, skipping bytes whose RVA falls in a
/// masked range (the IAT, which the loader fills).
pub fn first_diff(actual: &[u8], expected: &[u8], rva: u32, masks: &[Dir]) -> Option<usize> {
    actual.iter().zip(expected).enumerate().find_map(|(i, (a, e))| {
        let at = rva.wrapping_add(i as u32);
        (a != e && !masks.iter().any(|m| m.contains(at))).then_some(i)
    })
}

#[cfg(test)]
pub(crate) mod testpe {
    //! Synthetic PE32+ builder for tests: headers, one executable section, an export table
    //! and a base relocation block.

    pub const BASE: u64 = 0x1_8000_0000;
    pub const TEXT_RVA: u32 = 0x1000;
    pub const TEXT_RAW: u32 = 0x400;
    pub const TEXT_SIZE: u32 = 0x1000;
    pub const EDATA_RVA: u32 = 0x2000;
    pub const EDATA_RAW: u32 = TEXT_RAW + TEXT_SIZE;
    pub const RELOC_RVA: u32 = 0x3000;
    pub const RELOC_RAW: u32 = EDATA_RAW + 0x200;

    pub struct Built {
        pub file: Vec<u8>,
        pub relocs: Vec<u32>,
    }

    fn put(b: &mut [u8], off: usize, v: &[u8]) {
        b[off..off + v.len()].copy_from_slice(v);
    }

    /// `exports` must be sorted by name. `text` is written at TEXT_RVA; `relocs` are text RVAs
    /// holding 8-byte absolute addresses.
    pub fn build(text: &[u8], exports: &[(&'static str, u32)], relocs: &[u32], forwarded: Option<&'static str>) -> Built {
        let mut f = vec![0u8; (RELOC_RAW + 0x200) as usize];
        put(&mut f, 0, b"MZ");
        put(&mut f, 0x3c, &0x80u32.to_le_bytes());
        let nt = 0x80;
        put(&mut f, nt, b"PE\0\0");
        put(&mut f, nt + 4, &0x8664u16.to_le_bytes());
        put(&mut f, nt + 6, &3u16.to_le_bytes());
        put(&mut f, nt + 20, &240u16.to_le_bytes());
        let opt = nt + 24;
        put(&mut f, opt, &0x20bu16.to_le_bytes());
        put(&mut f, opt + 24, &BASE.to_le_bytes());
        put(&mut f, opt + 56, &0x4000u32.to_le_bytes());
        put(&mut f, opt + 60, &0x400u32.to_le_bytes());
        put(&mut f, opt + 108, &16u32.to_le_bytes());
        put(&mut f, opt + 112, &EDATA_RVA.to_le_bytes());
        put(&mut f, opt + 116, &0x200u32.to_le_bytes());
        let reloc_size = 8 + 2 * relocs.len().next_multiple_of(2) as u32;
        put(&mut f, opt + 112 + 5 * 8, &RELOC_RVA.to_le_bytes());
        put(&mut f, opt + 116 + 5 * 8, &reloc_size.to_le_bytes());
        let st = opt + 240;
        for (i, (name, va, raw, size, chars)) in [
            (b".text\0\0\0", TEXT_RVA, TEXT_RAW, TEXT_SIZE, 0x6000_0020u32),
            (b".edata\0\0", EDATA_RVA, EDATA_RAW, 0x200, 0x4000_0040),
            (b".reloc\0\0", RELOC_RVA, RELOC_RAW, 0x200, 0x4200_0040),
        ]
        .into_iter()
        .enumerate()
        {
            let s = st + i * 40;
            put(&mut f, s, name);
            put(&mut f, s + 8, &size.to_le_bytes());
            put(&mut f, s + 12, &va.to_le_bytes());
            put(&mut f, s + 16, &size.to_le_bytes());
            put(&mut f, s + 20, &raw.to_le_bytes());
            put(&mut f, s + 36, &chars.to_le_bytes());
        }
        put(&mut f, TEXT_RAW as usize, text);

        // Export directory: 40 bytes, then funcs, names, ordinals, name strings.
        let e = EDATA_RAW as usize;
        let n = exports.len() as u32;
        let funcs = EDATA_RVA + 40;
        let names = funcs + 4 * n;
        let ords = names + 4 * n;
        let mut strs = ords + 2 * n;
        put(&mut f, e + 20, &n.to_le_bytes());
        put(&mut f, e + 24, &n.to_le_bytes());
        put(&mut f, e + 28, &funcs.to_le_bytes());
        put(&mut f, e + 32, &names.to_le_bytes());
        put(&mut f, e + 36, &ords.to_le_bytes());
        let raw = |rva: u32| (rva - EDATA_RVA + EDATA_RAW) as usize;
        for (i, (name, rva)) in exports.iter().enumerate() {
            let target = if Some(*name) == forwarded { strs } else { *rva };
            put(&mut f, raw(funcs + 4 * i as u32), &target.to_le_bytes());
            put(&mut f, raw(names + 4 * i as u32), &strs.to_le_bytes());
            put(&mut f, raw(ords + 2 * i as u32), &(i as u16).to_le_bytes());
            put(&mut f, raw(strs), name.as_bytes());
            strs += name.len() as u32 + 1;
        }

        let r = RELOC_RAW as usize;
        put(&mut f, r, &TEXT_RVA.to_le_bytes());
        put(&mut f, r + 4, &reloc_size.to_le_bytes());
        for (i, rv) in relocs.iter().enumerate() {
            put(&mut f, r + 8 + 2 * i, &((10u16 << 12) | (rv - TEXT_RVA) as u16).to_le_bytes());
        }
        Built { file: f, relocs: relocs.to_vec() }
    }

    /// The image as the loader would map it at `base` (sections at their RVAs, relocated).
    pub fn map(b: &Built, base: u64) -> Vec<u8> {
        let mut m = vec![0u8; 0x4000];
        m[..0x400].copy_from_slice(&b.file[..0x400]);
        for (va, raw, size) in [(TEXT_RVA, TEXT_RAW, TEXT_SIZE), (EDATA_RVA, EDATA_RAW, 0x200), (RELOC_RVA, RELOC_RAW, 0x200)] {
            m[va as usize..(va + size) as usize].copy_from_slice(&b.file[raw as usize..(raw + size) as usize]);
        }
        let delta = base.wrapping_sub(BASE);
        for &r in &b.relocs {
            let r = r as usize;
            let v = u64::from_le_bytes(m[r..r + 8].try_into().unwrap()).wrapping_add(delta);
            m[r..r + 8].copy_from_slice(&v.to_le_bytes());
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::testpe::*;
    use super::*;

    fn sample() -> Built {
        let mut text = vec![0xCCu8; 0x200];
        text[0..4].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28]); // sub rsp, 28h
        text[0x10..0x12].copy_from_slice(&[0x48, 0xB8]); // mov rax, imm64 (relocated)
        text[0x12..0x1A].copy_from_slice(&(BASE + 0x1100).to_le_bytes());
        text[0xFE..0x106].copy_from_slice(&(BASE + 0x1180).to_le_bytes()); // spans a window edge in tests
        build(&text, &[("Alpha", 0x1000), ("Beta", 0x1010), ("Gamma", 0x1040)], &[0x1012, 0x10FE], Some("Gamma"))
    }

    #[test]
    fn parses_headers_and_sections() {
        let b = sample();
        let h = Headers::parse(&b.file).unwrap();
        assert_eq!(h.image_base, BASE);
        assert_eq!(h.sections.len(), 3);
        assert_eq!(h.exec_sections().count(), 1);
        assert_eq!(h.section_of(0x1234).unwrap().va, TEXT_RVA);
        assert!(h.section_of(0x5000).is_none());
        // the mapped view has identical headers
        let m = map(&b, 0x7ff0_0000_0000);
        assert_eq!(Headers::parse(&m).unwrap().sections, h.sections);
    }

    #[test]
    fn rejects_non_pe() {
        assert!(Headers::parse(&b"not a pe file at all".to_vec()).is_none());
        let mut b = sample().file;
        b[0x80 + 24] = 0x0b; // PE32 magic
        b[0x80 + 25] = 0x01;
        assert!(Headers::parse(&b).is_none());
    }

    #[test]
    fn finds_exports_and_forwarders() {
        let d = DiskImage::open(sample().file).unwrap();
        assert!(matches!(d.export("Alpha"), Some(Export::Code { rva: 0x1000, .. })));
        assert!(matches!(d.export("Beta"), Some(Export::Code { rva: 0x1010, .. })));
        assert_eq!(d.export("Gamma"), Some(Export::Forwarded));
        assert_eq!(d.export("Delta"), None);
        assert_eq!(d.export("Alph"), None);
    }

    #[test]
    fn expected_bytes_match_a_relocated_mapping() {
        let b = sample();
        let mut d = DiskImage::open(b.file.clone()).unwrap();
        assert!(d.load_relocs());
        assert_eq!(d.reloc_count(), 2);
        for base in [BASE, 0x7ff6_1234_0000, 0x1000_0000] {
            let m = map(&b, base);
            // windows aligned and misaligned to the relocation at 0x10FE
            for (rva, len) in [(0x1000u32, 0x100usize), (0x1100, 0x100), (0x1000, 0x200), (0x1013, 3), (0x1101, 5)] {
                let mut exp = vec![0u8; len];
                assert!(d.expected(rva, &mut exp, base));
                assert_eq!(&m[rva as usize..rva as usize + len], &exp[..], "base {base:#x} rva {rva:#x}");
            }
        }
    }

    #[test]
    fn detects_an_inline_patch_but_not_relocations() {
        let b = sample();
        let mut d = DiskImage::open(b.file.clone()).unwrap();
        d.load_relocs();
        let base = 0x7ff6_0000_0000;
        let mut m = map(&b, base);
        let mut exp = vec![0u8; 0x100];
        d.expected(0x1000, &mut exp, base);
        assert_eq!(first_diff(&m[0x1000..0x1100], &exp, 0x1000, &[]), None);
        m[0x1010] = 0xE9; // jmp rel32 over Beta
        assert_eq!(first_diff(&m[0x1000..0x1100], &exp, 0x1000, &[]), Some(0x10));
        assert_eq!(first_diff(&m[0x1000..0x1100], &exp, 0x1000, &[Dir { rva: 0x1010, size: 4 }]), None);
    }

    #[test]
    fn reads_past_raw_data_as_zero_and_bounds_checks() {
        let mut file = sample().file;
        // shrink .text raw data to 0x100 bytes: the rest of the section maps as zeros
        let raw_size_off = 0x80 + 24 + 240 + 16;
        file[raw_size_off..raw_size_off + 4].copy_from_slice(&0x100u32.to_le_bytes());
        let d = DiskImage::open(file).unwrap();
        let mut b = [1u8; 4];
        assert!(d.read_rva(0x10FE, &mut b));
        assert_eq!(&b[2..], &[0, 0]);
        assert!(d.read_rva(0x31FC, &mut b));
        assert!(!d.read_rva(0x31FE, &mut b), "crosses the end of the last section");
        assert!(!d.read_rva(0x9000, &mut b));
    }

    /// Rewrites the relocation directory entry (rva, size) of a built image.
    fn set_reloc_dir(file: &mut [u8], rva: u32, size: u32) {
        let o = 0x80 + 24 + 112 + 5 * 8;
        file[o..o + 4].copy_from_slice(&rva.to_le_bytes());
        file[o + 4..o + 8].copy_from_slice(&size.to_le_bytes());
    }

    #[test]
    fn a_crafted_relocation_directory_is_refused_not_allocated() {
        let base = 0x7ff6_0000_0000;
        let mut buf = [0u8; 16];

        // A directory size of 4 GB must not be allocated (it used to be, before any read).
        let mut file = sample().file;
        set_reloc_dir(&mut file, RELOC_RVA, u32::MAX);
        let mut d = DiskImage::open(file).unwrap();
        assert!(!d.load_relocs());
        assert!(!d.load_relocs(), "the failure is remembered");
        assert_eq!(d.reloc_count(), 0);
        assert!(!d.expected(0x1010, &mut buf, base), "a rebased image cannot be predicted without relocations");
        assert!(d.expected(0x1010, &mut buf, BASE), "at its preferred base no relocation applies");

        // A directory that is not in the file.
        let mut file = sample().file;
        set_reloc_dir(&mut file, 0x9000, 16);
        let mut d = DiskImage::open(file).unwrap();
        assert!(!d.load_relocs());

        // A block whose size runs past the directory, and one whose page overflows.
        for (page, size) in [(TEXT_RVA, 0x400u32), (u32::MAX, 12)] {
            let mut file = sample().file;
            let r = RELOC_RAW as usize;
            file[r..r + 4].copy_from_slice(&page.to_le_bytes());
            file[r + 4..r + 8].copy_from_slice(&size.to_le_bytes());
            let mut d = DiskImage::open(file).unwrap();
            assert!(!d.load_relocs(), "page {page:#x} size {size:#x}");
            assert!(!d.expected(0x1010, &mut buf, base));
        }

        // Zero padding after the last block is how linkers end the directory.
        let mut file = sample().file;
        set_reloc_dir(&mut file, RELOC_RVA, 0x40);
        let mut d = DiskImage::open(file).unwrap();
        assert!(d.load_relocs());
        assert_eq!(d.reloc_count(), 2);
    }

    #[test]
    fn a_crafted_export_directory_does_not_overflow() {
        let edata = |file: &mut Vec<u8>, off: usize, v: u32| file[EDATA_RAW as usize + off..EDATA_RAW as usize + off + 4].copy_from_slice(&v.to_le_bytes());
        // names, ordinals and functions tables at the top of the address space
        for off in [28, 32, 36] {
            let mut file = sample().file;
            edata(&mut file, off, u32::MAX - 1);
            let d = DiskImage::open(file).unwrap();
            for name in ["Alpha", "Beta", "Gamma", "Zeta"] {
                let _ = d.export(name);
            }
        }
        // the export directory itself at the top of the address space
        let mut file = sample().file;
        let o = 0x80 + 24 + 112;
        file[o..o + 4].copy_from_slice(&(u32::MAX - 8).to_le_bytes());
        assert_eq!(DiskImage::open(file).unwrap().export("Alpha"), None);
        // a name pointer at the top of the address space
        let mut file = sample().file;
        for i in 0..3 {
            edata(&mut file, 40 + 12 + 4 * i, u32::MAX - 3);
        }
        assert_eq!(DiskImage::open(file).unwrap().export("Alpha"), None);
    }

    #[test]
    fn section_pages_are_bounded() {
        let h = Headers::parse(&sample().file).unwrap();
        let text = *h.exec_sections().next().unwrap();
        let mut pages = Vec::new();
        assert!(section_pages(&h, &text, 4096, &mut pages));
        assert_eq!(pages, vec![(TEXT_RVA, 4096)]);
        pages.clear();
        assert!(section_pages(&h, &Section { vsize: 0x1801, ..text }, 4096, &mut pages));
        assert_eq!(pages, vec![(0x1000, 4096), (0x2000, 0x801)]);

        // A section header claiming almost 4 GB used to wrap the page offset and never end.
        for bad in [
            Section { vsize: u32::MAX - 0x800, ..text },
            Section { va: u32::MAX - 0x100, vsize: 0x1000, ..text },
            Section { vsize: h.size_of_image, ..text },
            Section { vsize: MAX_EXEC_SECTION + 1, ..text },
        ] {
            let mut pages = Vec::new();
            assert!(!section_pages(&h, &bad, 4096, &mut pages), "{bad:?}");
            assert!(pages.is_empty());
        }
    }
}
